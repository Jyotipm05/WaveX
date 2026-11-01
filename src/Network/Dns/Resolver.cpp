// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
/**
 * @file Resolver.cpp
 * @brief Native stub resolver: configuration parsing, UDP/TCP transport, cache, coalescing.
 */

#include <wavex/Network/Dns/Resolver.hpp>

#include <wavex/Base/Executor.hpp>

#include <asio/as_tuple.hpp>
#include <asio/connect.hpp>
#include <asio/experimental/awaitable_operators.hpp>
#include <asio/experimental/concurrent_channel.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/ip/udp.hpp>
#include <asio/read.hpp>
#include <asio/steady_timer.hpp>
#include <asio/this_coro.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/write.hpp>

#include <algorithm>
#include <charconv>
#include <cstdlib>
#include <fstream>
#include <random>
#include <sstream>

#if defined(_WIN32)
#include <asio/detail/socket_types.hpp>
#include <iphlpapi.h>
#endif

namespace wavex::dns {
    namespace {
        class dns_category final : public std::error_category {
        public:
            [[nodiscard]] const char *name() const noexcept override { return "wavex.dns"; }

            [[nodiscard]] std::string message(const int c) const override {
                switch (static_cast<errc>(c)) {
                    case errc::name_not_found: return "name not found";
                    case errc::no_data: return "name has no records of the requested type";
                    case errc::server_failure: return "DNS server failure";
                    case errc::timeout: return "DNS query timed out";
                    case errc::malformed_response: return "malformed DNS response";
                    case errc::refused: return "DNS query refused";
                    case errc::invalid_name: return "invalid host name";
                    case errc::no_servers: return "no DNS server configured";
                }
                return "unknown DNS error";
            }
        };

        using udp = asio::ip::udp;
        using tcp = asio::ip::tcp;
        using msg_result = std::expected<message, std::error_code>;

        std::uint16_t random_id() {
            static thread_local std::random_device rd; // OS entropy: the ID is an anti-spoofing secret
            return static_cast<std::uint16_t>(rd());
        }

        bool matches(const message &m, const std::uint16_t id, const std::string &qname, const std::uint16_t qtype) {
            return m.response && m.id == id && m.questions.size() == 1 && m.questions[0].type == qtype &&
                   m.questions[0].cls == class_in && names_equal(m.questions[0].name, qname);
        }

        std::vector<std::string_view> split_ws(const std::string_view line) {
            std::vector<std::string_view> out;
            std::size_t i = 0;
            while (i < line.size()) {
                while (i < line.size() && (line[i] == ' ' || line[i] == '\t' || line[i] == '\r')) ++i;
                const auto start = i;
                while (i < line.size() && line[i] != ' ' && line[i] != '\t' && line[i] != '\r') ++i;
                if (i > start) out.push_back(line.substr(start, i - start));
            }
            return out;
        }

        bool parse_uint(const std::string_view s, unsigned &out) {
            unsigned v{};
            const auto [p, ec] = std::from_chars(s.data(), s.data() + s.size(), v);
            if (ec != std::errc{} || p != s.data() + s.size()) return false;
            out = v;
            return true;
        }

        template<typename Fn>
        void for_each_line(const std::string_view text, Fn &&fn) {
            std::size_t pos = 0;
            while (pos <= text.size()) {
                auto nl = text.find('\n', pos);
                if (nl == std::string_view::npos) nl = text.size();
                auto line = text.substr(pos, nl - pos);
                if (const auto c = line.find_first_of("#;"); c != std::string_view::npos) line = line.substr(0, c);
                fn(line);
                pos = nl + 1;
            }
        }

        std::string read_file(const std::string &path) {
            std::ifstream f(path, std::ios::binary);
            if (!f) return {};
            std::ostringstream ss;
            ss << f.rdbuf();
            return ss.str();
        }

        /// UDP round trip on a fresh connected socket (the kernel drops datagrams from other sources).
        task<msg_result> udp_roundtrip(const udp::endpoint ep, const std::vector<std::uint8_t> &pkt,
                                       const std::uint16_t id, const std::string &qname, const std::uint16_t qtype,
                                       const std::chrono::milliseconds timeout) {
            using namespace asio::experimental::awaitable_operators;
            const auto ex = co_await asio::this_coro::executor;
            udp::socket sock(ex);
            std::error_code ec;
            sock.open(ep.protocol(), ec);
            if (!ec) sock.connect(ep, ec);
            if (ec) co_return std::unexpected(ec);

            auto [sec, sent] = co_await sock.async_send(asio::buffer(pkt), asio::as_tuple(asio::use_awaitable));
            if (sec) co_return std::unexpected(sec);

            asio::steady_timer timer(ex, timeout);
            std::vector<std::uint8_t> buf(4096);
            for (;;) {
                auto r = co_await (sock.async_receive(asio::buffer(buf), asio::as_tuple(asio::use_awaitable)) ||
                                   timer.async_wait(asio::as_tuple(asio::use_awaitable)));
                if (r.index() == 1) co_return std::unexpected(make_error_code(errc::timeout));
                auto &[rec, len] = std::get<0>(r);
                if (rec) co_return std::unexpected(rec);
                auto m = parse_message(std::span<const std::uint8_t>(buf.data(), len));
                if (!m || !matches(*m, id, qname, qtype)) continue; // spoofed or stray: keep waiting
                co_return std::move(*m);
            }
        }

        task<msg_result> tcp_inner(const tcp::endpoint ep, const std::vector<std::uint8_t> &pkt, const std::uint16_t id,
                                   const std::string &qname, const std::uint16_t qtype) {
            const auto ex = co_await asio::this_coro::executor;
            tcp::socket sock(ex);
            auto [cec] = co_await sock.async_connect(ep, asio::as_tuple(asio::use_awaitable));
            if (cec) co_return std::unexpected(cec);

            std::vector<std::uint8_t> framed;
            framed.reserve(pkt.size() + 2);
            framed.push_back(static_cast<std::uint8_t>(pkt.size() >> 8));
            framed.push_back(static_cast<std::uint8_t>(pkt.size() & 0xFF));
            framed.insert(framed.end(), pkt.begin(), pkt.end());
            auto [wec, wn] = co_await asio::async_write(sock, asio::buffer(framed), asio::as_tuple(asio::use_awaitable));
            if (wec) co_return std::unexpected(wec);

            std::uint8_t hdr[2];
            auto [hec, hn] = co_await asio::async_read(sock, asio::buffer(hdr), asio::as_tuple(asio::use_awaitable));
            if (hec) co_return std::unexpected(hec);
            const std::size_t len = (static_cast<std::size_t>(hdr[0]) << 8) | hdr[1];
            if (len < 12) co_return std::unexpected(make_error_code(errc::malformed_response));
            std::vector<std::uint8_t> body(len);
            auto [bec, bn] = co_await asio::async_read(sock, asio::buffer(body), asio::as_tuple(asio::use_awaitable));
            if (bec) co_return std::unexpected(bec);
            auto m = parse_message(body);
            if (!m || !matches(*m, id, qname, qtype)) co_return std::unexpected(make_error_code(errc::malformed_response));
            co_return std::move(*m);
        }

        task<msg_result> tcp_roundtrip(const tcp::endpoint ep, const std::vector<std::uint8_t> &pkt,
                                       const std::uint16_t id, const std::string &qname, const std::uint16_t qtype,
                                       const std::chrono::milliseconds timeout) {
            using namespace asio::experimental::awaitable_operators;
            const auto ex = co_await asio::this_coro::executor;
            asio::steady_timer timer(ex, timeout);
            auto r = co_await (tcp_inner(ep, pkt, id, qname, qtype) ||
                               timer.async_wait(asio::as_tuple(asio::use_awaitable)));
            if (r.index() == 1) co_return std::unexpected(make_error_code(errc::timeout));
            co_return std::move(std::get<0>(r));
        }

        /// Ask one server: UDP, retry without EDNS0 on FORMERR, TCP when truncated.
        task<msg_result> query_server(const asio::ip::address addr, const std::uint16_t port, const std::string &name,
                                      const std::uint16_t type, std::uint16_t edns,
                                      const std::chrono::milliseconds timeout) {
            bool retried = false;
            for (;;) {
                const auto id = random_id();
                const auto pkt = build_query(id, name, type, edns);
                if (!pkt) co_return std::unexpected(make_error_code(errc::invalid_name));

                auto r = co_await udp_roundtrip(udp::endpoint(addr, port), *pkt, id, name, type, timeout);
                if (!r) co_return r;
                if (r->truncated) {
                    r = co_await tcp_roundtrip(tcp::endpoint(addr, port), *pkt, id, name, type, timeout);
                    if (!r) co_return r;
                }
                if ((r->code == rcode::format_error || r->code == rcode::not_implemented) && edns != 0 && !retried) {
                    edns = 0;
                    retried = true;
                    continue;
                }
                co_return r;
            }
        }

        std::uint32_t negative_ttl(const message &m, const std::uint32_t fallback) {
            for (const auto &rec: m.authority) {
                if (const auto *soa = std::get_if<soa_data>(&rec.data)) return std::min(rec.ttl, soa->minimum);
            }
            return fallback;
        }
    } // namespace

    const std::error_category &category() noexcept {
        static const dns_category c;
        return c;
    }

    // ---------------------------------------------------------------- configuration

    config parse_resolv_conf(const std::string_view text) {
        config cfg;
        for_each_line(text, [&](const std::string_view line) {
            const auto t = split_ws(line);
            if (t.size() < 2) {
                if (t.size() == 1 && t[0] == "options") return;
                return;
            }
            if (t[0] == "nameserver") {
                std::error_code ec;
                auto a = asio::ip::make_address(std::string(t[1]), ec);
                if (!ec && cfg.servers.size() < 4) cfg.servers.push_back(a);
            } else if (t[0] == "search" || t[0] == "domain") {
                cfg.search.clear();
                const std::size_t n = (t[0] == "domain") ? 2 : t.size();
                for (std::size_t i = 1; i < n && cfg.search.size() < 6; ++i) {
                    auto d = normalize_name(t[i]);
                    if (is_valid_name(d)) cfg.search.push_back(std::move(d));
                }
            } else if (t[0] == "options") {
                for (std::size_t i = 1; i < t.size(); ++i) {
                    unsigned v{};
                    if (t[i] == "rotate") cfg.rotate = true;
                    else if (t[i].starts_with("ndots:") && parse_uint(t[i].substr(6), v)) cfg.ndots = std::min(v, 15u);
                    else if (t[i].starts_with("timeout:") && parse_uint(t[i].substr(8), v)) {
                        cfg.timeout = std::chrono::seconds(std::clamp(v, 1u, 30u));
                    } else if (t[i].starts_with("attempts:") && parse_uint(t[i].substr(9), v)) {
                        cfg.attempts = std::clamp(v, 1u, 5u);
                    }
                }
            }
        });
        return cfg;
    }

    void parse_hosts(const std::string_view text,
                     std::unordered_map<std::string, std::vector<asio::ip::address> > &out) {
        for_each_line(text, [&](const std::string_view line) {
            const auto t = split_ws(line);
            if (t.size() < 2) return;
            std::error_code ec;
            const auto a = asio::ip::make_address(std::string(t[0]), ec);
            if (ec) return;
            for (std::size_t i = 1; i < t.size(); ++i) {
                if (!is_valid_name(t[i])) continue;
                auto &v = out[normalize_name(t[i])];
                if (std::ranges::find(v, a) == v.end()) v.push_back(a);
            }
        });
    }

    config system_config() {
        config cfg;
#if defined(_WIN32)
        ULONG size = 16384;
        std::vector<std::uint8_t> buf;
        ULONG rc = ERROR_BUFFER_OVERFLOW;
        for (int i = 0; i < 3 && rc == ERROR_BUFFER_OVERFLOW; ++i) {
            buf.resize(size);
            rc = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
                                                 GAA_FLAG_SKIP_FRIENDLY_NAME,
                                      nullptr, reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buf.data()), &size);
        }
        if (rc == NO_ERROR) {
            for (auto *aa = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buf.data()); aa; aa = aa->Next) {
                if (aa->OperStatus != IfOperStatusUp || aa->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;
                for (auto *ds = aa->FirstDnsServerAddress; ds; ds = ds->Next) {
                    const auto *sa = ds->Address.lpSockaddr;
                    if (!sa) continue;
                    asio::ip::address a;
                    if (sa->sa_family == AF_INET) {
                        asio::ip::address_v4::bytes_type b{};
                        std::memcpy(b.data(), &reinterpret_cast<const sockaddr_in *>(sa)->sin_addr, 4);
                        a = asio::ip::address_v4(b);
                    } else if (sa->sa_family == AF_INET6) {
                        const auto *s6 = reinterpret_cast<const sockaddr_in6 *>(sa);
                        asio::ip::address_v6::bytes_type b{};
                        std::memcpy(b.data(), &s6->sin6_addr, 16);
                        if (b[0] == 0xfe && b[1] == 0xc0) continue; // deprecated site-local fec0::/10 placeholders
                        a = asio::ip::address_v6(b, s6->sin6_scope_id);
                    } else {
                        continue;
                    }
                    if (std::ranges::find(cfg.servers, a) == cfg.servers.end() &&
                        cfg.servers.size() < 4) {
                        cfg.servers.push_back(a);
                    }
                }
                if (aa->DnsSuffix && *aa->DnsSuffix && cfg.search.size() < 6) {
                    std::string d;
                    for (const wchar_t *p = aa->DnsSuffix; *p; ++p) {
                        if (*p < 128) d.push_back(static_cast<char>(*p));
                    }
                    d = normalize_name(d);
                    if (is_valid_name(d) && std::ranges::find(cfg.search, d) == cfg.search.end()) {
                        cfg.search.push_back(std::move(d));
                    }
                }
            }
        }
        const char *root = std::getenv("SystemRoot");
        parse_hosts(read_file(std::string(root ? root : "C:\\Windows") + "\\System32\\drivers\\etc\\hosts"), cfg.hosts);
#else
        cfg = parse_resolv_conf(read_file("/etc/resolv.conf"));
        parse_hosts(read_file("/etc/hosts"), cfg.hosts);
#endif
        if (cfg.servers.empty()) cfg.servers.push_back(asio::ip::make_address("127.0.0.1"));
        return cfg;
    }

    // ---------------------------------------------------------------- resolver

    struct resolver::inflight {
        explicit inflight(const wavex::executor &ex) : ch(ex) {}
        asio::experimental::concurrent_channel<void(std::error_code)> ch;
        lookup_result result;
    };

    resolver::resolver(config cfg, const resolver_options &opts) : cfg_(std::move(cfg)), opts_(opts) {}

    std::shared_ptr<resolver> resolver::shared() {
        static const auto instance = std::make_shared<resolver>(system_config());
        return instance;
    }

    void resolver::clear_cache() {
        std::scoped_lock lk(mu_);
        cache_.clear();
    }

    std::size_t resolver::cache_size() const {
        std::scoped_lock lk(mu_);
        return cache_.size();
    }

    task<std::expected<message, std::error_code> > resolver::exchange(std::string name, const std::uint16_t type) {
        const auto n = cfg_.servers.size();
        if (n == 0) co_return std::unexpected(make_error_code(errc::no_servers));
        std::size_t start = 0;
        if (cfg_.rotate) {
            std::scoped_lock lk(mu_);
            start = next_server_++ % n;
        }
        std::error_code last = make_error_code(errc::timeout);
        for (unsigned attempt = 0; attempt < std::max(1u, cfg_.attempts); ++attempt) {
            auto t = cfg_.timeout * (1u << attempt);
            if (n > 1) t /= static_cast<long>(n);
            t = std::max(t, std::min(cfg_.timeout, std::chrono::milliseconds(1000)));
            for (std::size_t i = 0; i < n; ++i) {
                auto r = co_await query_server(cfg_.servers[(start + i) % n], cfg_.port, name, type,
                                               cfg_.edns_udp_payload, t);
                if (!r) {
                    if (r.error() == make_error_code(errc::invalid_name)) co_return r;
                    last = r.error();
                    continue;
                }
                switch (r->code) {
                    case rcode::no_error:
                    case rcode::name_error:
                        co_return r;
                    case rcode::refused:
                        last = make_error_code(errc::refused);
                        break;
                    default:
                        last = make_error_code(errc::server_failure);
                        break;
                }
            }
        }
        co_return std::unexpected(last);
    }

    task<resolver::lookup_result> resolver::query_network(std::string name, const std::uint16_t type) {
        std::string cur = name;
        for (int hop = 0; hop < 5; ++hop) {
            auto r = co_await exchange(cur, type);
            if (!r) co_return lookup_result{{}, r.error()};
            const auto &m = *r;

            if (m.code == rcode::name_error) {
                answer a;
                a.ttl = std::chrono::seconds(negative_ttl(m, static_cast<std::uint32_t>(opts_.negative_ttl.count())));
                co_return lookup_result{std::move(a), make_error_code(errc::name_not_found)};
            }

            // Follow the CNAME chain inside this packet; only records owned by names on the chain are trusted.
            std::string owner = cur;
            std::uint32_t ttl = UINT32_MAX;
            for (int i = 0; i < 10; ++i) {
                bool found = false;
                for (const auto &rec: m.answers) {
                    if (rec.type != static_cast<std::uint16_t>(rr_type::CNAME) || !names_equal(rec.name, owner)) continue;
                    if (const auto *t = std::get_if<std::string>(&rec.data)) {
                        owner = *t;
                        ttl = std::min(ttl, rec.ttl);
                        found = true;
                        break;
                    }
                }
                if (!found) break;
            }

            answer a;
            a.canonical = normalize_name(owner);
            for (const auto &rec: m.answers) {
                if (rec.type != type || rec.cls != class_in || !names_equal(rec.name, owner)) continue;
                if (const auto *v4 = std::get_if<asio::ip::address_v4>(&rec.data)) a.addrs.emplace_back(*v4);
                else if (const auto *v6 = std::get_if<asio::ip::address_v6>(&rec.data)) a.addrs.emplace_back(*v6);
                else if (const auto *s = std::get_if<svcb_data>(&rec.data)) a.svcb.push_back(*s);
                else continue;
                ttl = std::min(ttl, rec.ttl);
            }

            if (!a.addrs.empty() || !a.svcb.empty()) {
                a.ttl = std::chrono::seconds(ttl);
                co_return lookup_result{std::move(a), {}};
            }
            if (!names_equal(owner, cur)) { // CNAME without the target's data in the packet: ask for the target
                cur = owner;
                continue;
            }
            a.ttl = std::chrono::seconds(negative_ttl(m, static_cast<std::uint32_t>(opts_.negative_ttl.count())));
            co_return lookup_result{std::move(a), make_error_code(errc::no_data)};
        }
        co_return lookup_result{{}, make_error_code(errc::malformed_response)}; // CNAME chain too long
    }

    void resolver::finish(const std::string &key, const std::shared_ptr<inflight> &inf, lookup_result r) {
        {
            std::scoped_lock lk(mu_);
            const bool negative = r.err == errc::name_not_found || r.err == errc::no_data;
            if ((!r.err || negative) && r.ans.ttl.count() > 0) {
                const auto ttl = std::min(r.ans.ttl, negative ? std::max(r.ans.ttl, std::chrono::seconds(0))
                                                              : opts_.max_ttl);
                if (cache_.size() >= opts_.max_cache_entries) {
                    const auto now = std::chrono::steady_clock::now();
                    std::erase_if(cache_, [&](const auto &kv) { return kv.second.expires <= now; });
                    if (cache_.size() >= opts_.max_cache_entries && !cache_.empty()) cache_.erase(cache_.begin());
                }
                cache_[key] = cache_entry{r.ans, r.err, std::chrono::steady_clock::now() + ttl};
            }
            inflight_.erase(key);
            inf->result = std::move(r);
        }
        inf->ch.close(); // wakes every waiter, each on its own executor
    }

    task<resolver::lookup_result> resolver::lookup(std::string name, const std::uint16_t type) {
        const auto key = std::to_string(type) + ':' + normalize_name(name);
        std::shared_ptr<inflight> inf;
        bool leader = false;
        {
            std::scoped_lock lk(mu_);
            if (const auto it = cache_.find(key); it != cache_.end()) {
                if (it->second.expires > std::chrono::steady_clock::now()) {
                    co_return lookup_result{it->second.ans, it->second.err};
                }
                cache_.erase(it);
            }
            if (const auto it = inflight_.find(key); it != inflight_.end()) {
                inf = it->second;
            } else {
                inf = std::make_shared<inflight>(co_await asio::this_coro::executor);
                inflight_.emplace(key, inf);
                leader = true;
            }
        }

        if (!leader) {
            co_await inf->ch.async_receive(asio::as_tuple(asio::use_awaitable)); // completes when closed
            std::scoped_lock lk(mu_);
            co_return inf->result;
        }

        // If this coroutine is destroyed mid-query (cancellation), release the waiters with an error.
        struct guard {
            resolver *self;
            const std::string &key;
            std::shared_ptr<inflight> inf;
            bool done{false};

            ~guard() {
                if (!done) self->finish(key, inf, lookup_result{{}, std::make_error_code(std::errc::operation_canceled)});
            }
        } g{this, key, inf};

        auto result = co_await query_network(std::move(name), type);
        g.done = true;
        finish(key, inf, result);
        co_return result;
    }

    std::vector<std::string> resolver::candidates(const std::string_view host) const {
        std::vector<std::string> out;
        if (host.ends_with('.')) {
            out.emplace_back(host.substr(0, host.size() - 1));
            return out;
        }
        const auto dots = static_cast<unsigned>(std::ranges::count(host, '.'));
        const std::string h(host);
        if (dots >= cfg_.ndots) out.push_back(h);
        for (const auto &s: cfg_.search) out.push_back(h + '.' + s);
        if (dots < cfg_.ndots) out.push_back(h);
        return out;
    }

    task<std::expected<addresses, std::error_code> > resolver::resolve(std::string host, const resolve_options o) {
        using namespace asio::experimental::awaitable_operators;
        if (host.size() >= 2 && host.front() == '[' && host.back() == ']') host = host.substr(1, host.size() - 2);
        if (host.empty()) co_return std::unexpected(make_error_code(errc::invalid_name));

        const auto family_ok = [&](const asio::ip::address &a) { return a.is_v4() ? o.ipv4 : o.ipv6; };
        const auto interleave = [&](const std::vector<asio::ip::address> &v6, const std::vector<asio::ip::address> &v4) {
            std::vector<asio::ip::address> out;
            out.reserve(v6.size() + v4.size());
            for (std::size_t i = 0; i < std::max(v6.size(), v4.size()); ++i) {
                if (i < v6.size()) out.push_back(v6[i]);
                if (i < v4.size()) out.push_back(v4[i]);
            }
            return out;
        };
        const auto split_filter = [&](const std::vector<asio::ip::address> &in) {
            std::vector<asio::ip::address> v6, v4;
            for (const auto &a: in) {
                if (!family_ok(a)) continue;
                (a.is_v4() ? v4 : v6).push_back(a);
            }
            return interleave(std::move(v6), std::move(v4));
        };

        {
            std::error_code ec;
            if (const auto ip = asio::ip::make_address(host, ec); !ec) {
                if (!family_ok(ip)) co_return std::unexpected(make_error_code(errc::no_data));
                co_return addresses{{ip}, host};
            }
        }

        const auto norm = normalize_name(host);
        if (norm == "localhost" || norm.ends_with(".localhost")) { // RFC 6761
            auto l = split_filter({asio::ip::address_v6::loopback(), asio::ip::address_v4::loopback()});
            if (l.empty()) co_return std::unexpected(make_error_code(errc::no_data));
            co_return addresses{std::move(l), norm};
        }
        if (const auto it = cfg_.hosts.find(norm); it != cfg_.hosts.end()) {
            if (auto l = split_filter(it->second); !l.empty()) co_return addresses{std::move(l), norm};
        }
        if (!is_valid_name(host)) co_return std::unexpected(make_error_code(errc::invalid_name));

        const auto is_negative = [](const std::error_code &e) {
            return e == errc::name_not_found || e == errc::no_data;
        };
        std::error_code last = make_error_code(errc::name_not_found);
        for (const auto &cand: candidates(host)) {
            lookup_result r4, r6;
            if (o.ipv4 && o.ipv6) {
                auto [a, b] = co_await (lookup(cand, static_cast<std::uint16_t>(rr_type::A)) &&
                                        lookup(cand, static_cast<std::uint16_t>(rr_type::AAAA)));
                r4 = std::move(a);
                r6 = std::move(b);
            } else if (o.ipv4) {
                r4 = co_await lookup(cand, static_cast<std::uint16_t>(rr_type::A));
                r6.err = make_error_code(errc::no_data);
            } else {
                r6 = co_await lookup(cand, static_cast<std::uint16_t>(rr_type::AAAA));
                r4.err = make_error_code(errc::no_data);
            }

            auto list = interleave(r6.err ? std::vector<asio::ip::address>{} : r6.ans.addrs,
                                   r4.err ? std::vector<asio::ip::address>{} : r4.ans.addrs);
            if (!list.empty()) {
                co_return addresses{std::move(list), !r4.err && !r4.ans.canonical.empty() ? r4.ans.canonical
                                                                                           : r6.ans.canonical};
            }
            if (!is_negative(r4.err)) co_return std::unexpected(r4.err);
            if (!is_negative(r6.err)) co_return std::unexpected(r6.err);
            last = (r4.err == errc::no_data || r6.err == errc::no_data) ? make_error_code(errc::no_data)
                                                                          : make_error_code(errc::name_not_found);
        }
        co_return std::unexpected(last);
    }

    task<std::expected<std::vector<svcb_data>, std::error_code> > resolver::resolve_https(std::string host) {
        if (host.empty() || !is_valid_name(host)) co_return std::unexpected(make_error_code(errc::invalid_name));
        std::error_code ec;
        if (asio::ip::make_address(host, ec); !ec) co_return std::unexpected(make_error_code(errc::no_data));

        std::string name = host;
        for (int depth = 0; depth < 4; ++depth) {
            auto r = co_await lookup(name, static_cast<std::uint16_t>(rr_type::HTTPS));
            if (r.err) co_return std::unexpected(r.err);

            std::vector<svcb_data> service;
            const svcb_data *alias = nullptr;
            for (const auto &s: r.ans.svcb) {
                if (s.is_alias()) alias = alias ? alias : &s;
                else service.push_back(s);
            }
            if (!service.empty()) {
                std::ranges::stable_sort(service,
                                         [](const svcb_data &a, const svcb_data &b) { return a.priority < b.priority; });
                co_return service;
            }
            if (!alias || alias->target.empty()) co_return std::unexpected(make_error_code(errc::no_data));
            name = alias->target;
        }
        co_return std::unexpected(make_error_code(errc::no_data));
    }

} // namespace wavex::dns
