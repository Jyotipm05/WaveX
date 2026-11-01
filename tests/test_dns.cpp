/**
 * @file test_dns.cpp
 * @brief Tests for the native DNS resolver: wire format, hostile packets, configuration parsing and end-to-end
 *        resolution against an in-process fake DNS server (UDP + TCP on loopback).
 */

#include <wavex/Network/Dns/DnsMessage.hpp>
#include <wavex/Network/Dns/Resolver.hpp>

#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/ip/udp.hpp>
#include <asio/read.hpp>
#include <asio/steady_timer.hpp>
#include <asio/write.hpp>

#include <atomic>
#include <chrono>
#include <functional>
#include <iostream>
#include <map>
#include <mutex>
#include <random>
#include <thread>

using namespace wavex::dns;
using namespace std::chrono_literals;

namespace {
    int tests_run{0};
    int tests_failed{0};

    void check(const bool condition, const char *name) {
        ++tests_run;
        if (!condition) ++tests_failed;
        std::cout << (condition ? "  [PASS] " : "  [FAIL] ") << name << "\n";
    }

    using bytes = std::vector<std::uint8_t>;

    void put16(bytes &v, const std::uint16_t x) {
        v.push_back(static_cast<std::uint8_t>(x >> 8));
        v.push_back(static_cast<std::uint8_t>(x));
    }

    void put32(bytes &v, const std::uint32_t x) {
        put16(v, static_cast<std::uint16_t>(x >> 16));
        put16(v, static_cast<std::uint16_t>(x));
    }

    struct rr {
        std::string name; ///< "" = the question name (compression pointer to offset 12)
        std::uint16_t type{};
        std::uint32_t ttl{300};
        bytes rdata;
    };

    bytes a4(const char *ip) {
        const auto b = asio::ip::make_address_v4(ip).to_bytes();
        return {b.begin(), b.end()};
    }

    bytes a6(const char *ip) {
        const auto b = asio::ip::make_address_v6(ip).to_bytes();
        return {b.begin(), b.end()};
    }

    bytes nm(const std::string &n) { return *encode_name(n); }

    bytes soa_rdata(const std::uint32_t minimum) {
        bytes r = nm("ns.test");
        const auto rn = nm("admin.test");
        r.insert(r.end(), rn.begin(), rn.end());
        for (const std::uint32_t v: {1u, 2u, 3u, 4u, minimum}) put32(r, v);
        return r;
    }

    bytes https_rdata(const std::uint16_t prio, const std::string &target, const std::vector<std::string> &alpn,
                      const std::uint16_t port = 0) {
        bytes r;
        put16(r, prio);
        const auto t = target.empty() ? bytes{0} : nm(target);
        r.insert(r.end(), t.begin(), t.end());
        if (!alpn.empty()) {
            bytes v;
            for (const auto &a: alpn) {
                v.push_back(static_cast<std::uint8_t>(a.size()));
                v.insert(v.end(), a.begin(), a.end());
            }
            put16(r, 1);
            put16(r, static_cast<std::uint16_t>(v.size()));
            r.insert(r.end(), v.begin(), v.end());
        }
        if (port) {
            put16(r, 3);
            put16(r, 2);
            put16(r, port);
        }
        return r;
    }

    void put_rr(bytes &p, const rr &x) {
        if (x.name.empty()) {
            p.push_back(0xC0);
            p.push_back(0x0C);
        } else {
            const auto n = nm(x.name);
            p.insert(p.end(), n.begin(), n.end());
        }
        put16(p, x.type);
        put16(p, class_in);
        put32(p, x.ttl);
        put16(p, static_cast<std::uint16_t>(x.rdata.size()));
        p.insert(p.end(), x.rdata.begin(), x.rdata.end());
    }

    struct qinfo {
        std::string name;
        std::uint16_t type{};
        bool ok{false};
    };

    qinfo question_of(const bytes &req) {
        const auto m = parse_message(req);
        if (!m || m->questions.size() != 1) return {};
        return {normalize_name(m->questions[0].name), m->questions[0].type, true};
    }

    bytes reply(const bytes &req, const std::vector<rr> &an, const std::vector<rr> &ns = {}, const int rc = 0,
                const bool tc = false, const std::optional<std::uint16_t> id = std::nullopt) {
        const auto m = *parse_message(req);
        bytes p;
        put16(p, id.value_or(m.id));
        put16(p, static_cast<std::uint16_t>(0x8180 | (tc ? 0x0200 : 0) | rc));
        put16(p, 1);
        put16(p, static_cast<std::uint16_t>(an.size()));
        put16(p, static_cast<std::uint16_t>(ns.size()));
        put16(p, 0);
        const auto qn = nm(m.questions[0].name);
        p.insert(p.end(), qn.begin(), qn.end());
        put16(p, m.questions[0].type);
        put16(p, class_in);
        for (const auto &x: an) put_rr(p, x);
        for (const auto &x: ns) put_rr(p, x);
        return p;
    }

    /// In-process DNS server on 127.0.0.1 (UDP and TCP share one port). The handler returns the packets to send.
    class fake_dns {
    public:
        using handler = std::function<std::vector<bytes>(const bytes &, bool tcp)>;

        explicit fake_dns(handler h) : handler_(std::move(h)), udp_(io_), tcp_(io_) {
            for (int i = 0; i < 50; ++i) {
                asio::error_code ec;
                udp_.close(ec);
                tcp_.close(ec);
                udp_.open(asio::ip::udp::v4());
                udp_.bind({asio::ip::address_v4::loopback(), 0});
                port_ = udp_.local_endpoint().port();
                tcp_.open(asio::ip::tcp::v4());
                tcp_.set_option(asio::socket_base::reuse_address(true));
                tcp_.bind({asio::ip::address_v4::loopback(), port_}, ec);
                if (!ec) break;
            }
            tcp_.listen();
            udp_thread_ = std::thread([this] { udp_loop(); });
            tcp_thread_ = std::thread([this] { tcp_loop(); });
        }

        ~fake_dns() {
            stop_ = true;
            asio::error_code ec;
            { // blocking calls are not interrupted by close(): wake both loops with a packet / a connection
                asio::io_context wake;
                asio::ip::udp::socket u(wake, asio::ip::udp::v4());
                u.send_to(asio::buffer("x", 1), {asio::ip::address_v4::loopback(), port_}, 0, ec);
                asio::ip::tcp::socket t(wake);
                t.connect({asio::ip::address_v4::loopback(), port_}, ec);
            }
            udp_thread_.join();
            tcp_thread_.join();
            udp_.close(ec);
            tcp_.close(ec);
        }

        [[nodiscard]] std::uint16_t port() const { return port_; }

        int count(const std::uint16_t type) {
            std::scoped_lock lk(mu_);
            return counts_[type];
        }

        int total() {
            std::scoped_lock lk(mu_);
            int n = 0;
            for (auto &[k, v]: counts_) n += v;
            return n;
        }

    private:
        void record(const bytes &req) {
            const auto q = question_of(req);
            std::scoped_lock lk(mu_);
            if (q.ok) ++counts_[q.type];
        }

        void udp_loop() {
            while (!stop_) {
                bytes buf(4096);
                asio::ip::udp::endpoint from;
                asio::error_code ec;
                const auto n = udp_.receive_from(asio::buffer(buf), from, 0, ec);
                if (ec) return;
                buf.resize(n);
                if (!question_of(buf).ok) continue;
                record(buf);
                for (const auto &p: handler_(buf, false)) udp_.send_to(asio::buffer(p), from, 0, ec);
            }
        }

        void tcp_loop() {
            while (!stop_) {
                asio::ip::tcp::socket s(io_);
                asio::error_code ec;
                tcp_.accept(s, ec);
                if (ec) return;
                std::uint8_t h[2];
                asio::read(s, asio::buffer(h), ec);
                if (ec) continue;
                bytes req((static_cast<std::size_t>(h[0]) << 8) | h[1]);
                asio::read(s, asio::buffer(req), ec);
                if (ec || !question_of(req).ok) continue;
                record(req);
                for (const auto &p: handler_(req, true)) {
                    bytes f;
                    put16(f, static_cast<std::uint16_t>(p.size()));
                    f.insert(f.end(), p.begin(), p.end());
                    asio::write(s, asio::buffer(f), ec);
                }
            }
        }

        handler handler_;
        asio::io_context io_;
        asio::ip::udp::socket udp_;
        asio::ip::tcp::acceptor tcp_;
        std::uint16_t port_{};
        std::atomic<bool> stop_{false};
        std::thread udp_thread_, tcp_thread_;
        std::mutex mu_;
        std::map<std::uint16_t, int> counts_;
    };

    config cfg_for(const fake_dns &srv) {
        config c;
        c.servers.push_back(asio::ip::address_v4::loopback());
        c.port = srv.port();
        c.timeout = 300ms;
        c.attempts = 2;
        return c;
    }

    using res_t = std::expected<addresses, std::error_code>;

    /// Run `n` concurrent resolutions of `host` on `threads` threads.
    std::vector<res_t> resolve_many(resolver &r, const std::string &host, const int n, const int threads = 1) {
        asio::io_context io;
        std::vector<res_t> out(n, std::unexpected(std::error_code{}));
        for (int i = 0; i < n; ++i) {
            asio::co_spawn(io, [&r, &host, &out, i]() -> wavex::task<void> {
                out[i] = co_await r.resolve(host);
            }, asio::detached);
        }
        std::vector<std::thread> ts;
        for (int i = 1; i < threads; ++i) ts.emplace_back([&io] { io.run(); });
        io.run();
        for (auto &t: ts) t.join();
        return out;
    }

    res_t resolve_one(resolver &r, const std::string &host) { return resolve_many(r, host, 1)[0]; }

    bool has(const addresses &a, const char *ip) {
        return std::find(a.list.begin(), a.list.end(), asio::ip::make_address(ip)) != a.list.end();
    }

    // ------------------------------------------------------------------ wire format

    void test_wire_format() {
        std::cout << "wire format\n";
        const auto q = build_query(0x1234, "Example.COM.", static_cast<std::uint16_t>(rr_type::A));
        check(q.has_value(), "build_query accepts a valid name");
        const auto m = parse_message(*q);
        check(m && m->id == 0x1234 && !m->response && m->recursion_desired, "query header round-trips");
        check(m && m->questions.size() == 1 && names_equal(m->questions[0].name, "example.com"),
              "question name round-trips (case-insensitive)");
        check(m && m->additional.size() == 1 && m->additional[0].type == 41 && m->additional[0].cls == 1232,
              "EDNS0 OPT advertises UDP payload 1232");
        check(build_query(1, "a.b", 1, 0)->size() < q->size(), "edns_udp_payload=0 omits OPT");

        check(!build_query(1, "", 1), "empty name rejected");
        check(!build_query(1, "a..b", 1), "empty label rejected");
        check(!build_query(1, std::string(64, 'a') + ".com", 1), "label > 63 rejected");
        check(!build_query(1, "bad name.com", 1), "space in name rejected");
        std::string longname;
        for (int i = 0; i < 9; ++i) longname += std::string(30, 'a') + ".";
        check(!is_valid_name(longname), "name > 253 rejected");
        check(is_valid_name("_dmarc.example.com") && is_valid_name("xn--bcher-kva.example"), "underscore/punycode ok");
        check(names_equal("WWW.Example.com.", "www.example.COM"), "names_equal ignores case and trailing dot");
        check(normalize_name("A.B.") == "a.b", "normalize_name");

        // Name compression and answers
        const auto req = *build_query(7, "www.example.com", static_cast<std::uint16_t>(rr_type::A));
        const auto resp = reply(req, {{"", 5, 60, nm("host.example.com")}, {"host.example.com", 1, 120, a4("192.0.2.9")}});
        const auto pm = parse_message(resp);
        check(pm && pm->answers.size() == 2, "compressed response parses");
        check(pm && pm->answers[0].name == "www.example.com" && std::get<std::string>(pm->answers[0].data) == "host.example.com",
              "pointer owner + CNAME rdata");
        check(pm && std::get<asio::ip::address_v4>(pm->answers[1].data) == asio::ip::make_address_v4("192.0.2.9"),
              "A rdata");

        const auto v6 = parse_message(reply(req, {{"", 28, 60, a6("2001:db8::1")}}));
        check(v6 && std::get<asio::ip::address_v6>(v6->answers[0].data) == asio::ip::make_address_v6("2001:db8::1"),
              "AAAA rdata");

        const auto h = parse_message(reply(req, {{"", 65, 60, https_rdata(1, "", {"h3", "h2"}, 8443)}}));
        const auto *sv = h ? std::get_if<svcb_data>(&h->answers[0].data) : nullptr;
        check(sv && sv->priority == 1 && sv->alpn.size() == 2 && sv->alpn[0] == "h3" && sv->port == 8443 &&
              !sv->is_alias(), "HTTPS RR alpn/port");

        const auto soa = parse_message(reply(req, {}, {{"example.com", 6, 900, soa_rdata(42)}}));
        check(soa && std::get<soa_data>(soa->authority[0].data).minimum == 42, "SOA minimum");
    }

    void test_hostile_packets() {
        std::cout << "hostile packets\n";
        const auto req = *build_query(7, "www.example.com", 1);
        const auto good = reply(req, {{"", 1, 60, a4("192.0.2.1")}, {"", 28, 60, a6("::1")}});

        bool any_crash_free = true;
        int accepted_prefix = 0;
        for (std::size_t n = 0; n < good.size(); ++n) {
            if (parse_message(std::span<const std::uint8_t>(good.data(), n))) ++accepted_prefix;
        }
        check(any_crash_free && accepted_prefix == 0, "every strict prefix of a response is rejected");

        auto self_ptr = good;
        self_ptr[12] = 0xC0;
        self_ptr[13] = 0x0C; // question name points at itself
        check(!parse_message(self_ptr), "self-referential pointer rejected");

        auto fwd = good;
        fwd[12] = 0xC0;
        fwd[13] = 0xFF; // forward pointer
        check(!parse_message(fwd), "forward pointer rejected");

        auto reserved = good;
        reserved[12] = 0x40; // reserved label type
        check(!parse_message(reserved), "reserved label type rejected");

        bytes inflated(12, 0);
        inflated[4] = 0xFF;
        inflated[5] = 0xFF; // QDCOUNT 65535 in a 12-byte packet
        check(parse_message(inflated).error() == parse_error::too_many_records, "inflated counts rejected up front");

        auto badlen = good;
        // Make the first answer's RDLENGTH (A record) 5 instead of 4.
        const auto qlen = nm("www.example.com").size() + 4;
        const std::size_t rdlen_at = 12 + qlen + 2 + 2 + 2 + 4;
        badlen[rdlen_at + 1] = 5;
        check(!parse_message(badlen), "A record with RDLENGTH != 4 rejected");

        std::mt19937 rng(12345);
        int parsed = 0;
        for (int i = 0; i < 20000; ++i) {
            auto p = good;
            const int flips = 1 + static_cast<int>(rng() % 4);
            for (int f = 0; f < flips; ++f) p[rng() % p.size()] = static_cast<std::uint8_t>(rng());
            if (rng() % 3 == 0) p.resize(rng() % (p.size() + 1));
            parsed += parse_message(p).has_value();
        }
        for (int i = 0; i < 20000; ++i) {
            bytes p(rng() % 200);
            for (auto &b: p) b = static_cast<std::uint8_t>(rng());
            (void) parse_message(p);
        }
        check(true, "40000 mutated/random packets parsed without crashing (ASan/UBSan clean)");
        (void) parsed;
    }

    void test_config_parsing() {
        std::cout << "configuration parsing\n";
        const auto c = parse_resolv_conf(
            "# comment\nnameserver 192.0.2.53\nnameserver 2001:db8::53 ; trailing\nnameserver nonsense\n"
            "search corp.example. lab.example\noptions ndots:3 timeout:4 attempts:3 rotate edns0\n");
        check(c.servers.size() == 2 && c.servers[0] == asio::ip::make_address("192.0.2.53") &&
              c.servers[1] == asio::ip::make_address("2001:db8::53"), "nameserver lines (invalid skipped)");
        check(c.search.size() == 2 && c.search[0] == "corp.example" && c.search[1] == "lab.example", "search list");
        check(c.ndots == 3 && c.timeout == 4s && c.attempts == 3 && c.rotate, "options");

        const auto d = parse_resolv_conf("domain a.example\nsearch b.example\n");
        check(d.search.size() == 1 && d.search[0] == "b.example", "last of search/domain wins");
        const auto e = parse_resolv_conf("options ndots:99 timeout:0 attempts:99\n");
        check(e.ndots == 15 && e.timeout == 1s && e.attempts == 5, "options are clamped");

        std::unordered_map<std::string, std::vector<asio::ip::address> > hosts;
        parse_hosts("127.0.0.1 localhost loopback\n::1 localhost # c\n10.0.0.5 Box.Example box\nbad line\n", hosts);
        check(hosts["localhost"].size() == 2 && hosts["box.example"].size() == 1 && hosts.count("box") == 1 &&
              hosts.count("loopback") == 1, "hosts file");
        check(!system_config().servers.empty(), "system_config always has a server");
    }

    // ------------------------------------------------------------------ end to end

    void test_basic_resolution_and_cache() {
        std::cout << "resolution + cache\n";
        fake_dns srv([](const bytes &req, bool) -> std::vector<bytes> {
            const auto q = question_of(req);
            if (q.name != "www.example.test") return {reply(req, {}, {{"example.test", 6, 900, soa_rdata(30)}}, 3)};
            if (q.type == 1) return {reply(req, {{"", 1, 300, a4("192.0.2.1")}, {"", 1, 300, a4("192.0.2.2")}})};
            if (q.type == 28) return {reply(req, {{"", 28, 300, a6("2001:db8::1")}})};
            return {reply(req, {})};
        });
        resolver r(cfg_for(srv));
        const auto a = resolve_one(r, "www.example.test");
        check(a && a->list.size() == 3 && has(*a, "192.0.2.1") && has(*a, "2001:db8::1"), "A + AAAA combined");
        check(a && a->list[0].is_v6() && a->list[1].is_v4(), "IPv6 first, interleaved with IPv4");
        check(srv.count(1) == 1 && srv.count(28) == 1, "one A and one AAAA query on the wire");

        resolve_one(r, "WWW.Example.TEST");
        check(srv.total() == 2, "second lookup (different case) served from cache");
        check(r.cache_size() == 2, "cache holds both record sets");

        r.clear_cache();
        resolve_one(r, "www.example.test");
        check(srv.total() == 4, "clear_cache forces a new query");

        const auto n1 = resolve_one(r, "nope.example.test");
        check(!n1 && n1.error() == errc::name_not_found, "NXDOMAIN -> name_not_found");
        const int before = srv.total();
        resolve_one(r, "nope.example.test");
        check(srv.total() == before, "negative answer cached (RFC 2308)");

        wavex::dns::resolve_options v4only;
        v4only.ipv6 = false;
        asio::io_context io;
        res_t only4 = std::unexpected(std::error_code{});
        asio::co_spawn(io, [&]() -> wavex::task<void> { only4 = co_await r.resolve("www.example.test", v4only); },
                       asio::detached);
        io.run();
        check(only4 && only4->list.size() == 2 && only4->list[0].is_v4(), "ipv6=false returns only IPv4");
    }

    void test_local_names() {
        std::cout << "literals, localhost, hosts\n";
        fake_dns srv([](const bytes &req, bool) -> std::vector<bytes> { return {reply(req, {}, {}, 2)}; });
        auto c = cfg_for(srv);
        c.hosts["box.lan"] = {asio::ip::make_address("10.1.2.3")};
        resolver r(c);
        const auto a = resolve_one(r, "192.0.2.77");
        check(a && a->list.size() == 1 && a->list[0] == asio::ip::make_address("192.0.2.77"), "IPv4 literal");
        const auto b = resolve_one(r, "[2001:db8::7]");
        check(b && b->list.size() == 1 && b->list[0].is_v6(), "bracketed IPv6 literal");
        const auto l = resolve_one(r, "LocalHost");
        check(l && l->list.size() == 2 && l->list[0].is_loopback(), "localhost");
        check(resolve_one(r, "api.localhost").has_value(), "*.localhost");
        const auto h = resolve_one(r, "box.lan");
        check(h && h->list[0] == asio::ip::make_address("10.1.2.3"), "hosts file entry");
        check(srv.total() == 0, "none of these touched the network");
        check(resolve_one(r, "a..b").error() == errc::invalid_name, "invalid name");
    }

    void test_search_list() {
        std::cout << "search list / ndots\n";
        fake_dns srv([](const bytes &req, bool) -> std::vector<bytes> {
            const auto q = question_of(req);
            if (q.name == "web.corp.test" && q.type == 1) return {reply(req, {{"", 1, 60, a4("10.9.8.7")}})};
            if (q.name == "web.corp.test") return {reply(req, {})};
            return {reply(req, {}, {{"test", 6, 900, soa_rdata(5)}}, 3)};
        });
        auto c = cfg_for(srv);
        c.search = {"other.test", "corp.test"};
        resolver r(c);
        const auto a = resolve_one(r, "web");
        check(a && has(*a, "10.9.8.7") && a->canonical == "web.corp.test", "short name expanded through the search list");
        const auto abs = resolve_one(r, "web.");
        check(!abs && abs.error() == errc::name_not_found, "trailing dot = absolute, no search expansion");
    }

    void test_cname_chain() {
        std::cout << "CNAME chains\n";
        fake_dns srv([](const bytes &req, bool) -> std::vector<bytes> {
            const auto q = question_of(req);
            if (q.type != 1) return {reply(req, {}, {{"example.test", 6, 900, soa_rdata(5)}})};
            if (q.name == "alias.example.test") {
                return {reply(req, {{"", 5, 100, nm("mid.example.test")},
                                    {"mid.example.test", 5, 200, nm("real.example.test")},
                                    {"real.example.test", 1, 300, a4("192.0.2.44")}})};
            }
            if (q.name == "cut.example.test") { // CNAME only: the resolver must ask for the target itself
                return {reply(req, {{"", 5, 100, nm("real.example.test")}})};
            }
            if (q.name == "real.example.test") return {reply(req, {{"", 1, 300, a4("192.0.2.44")}})};
            if (q.name == "evil.example.test") { // unrelated record in the answer must be ignored
                return {reply(req, {{"other.example.test", 1, 300, a4("6.6.6.6")}})};
            }
            return {reply(req, {})};
        });
        resolver r(cfg_for(srv));
        const auto a = resolve_one(r, "alias.example.test");
        check(a && a->list.size() == 1 && has(*a, "192.0.2.44") && a->canonical == "real.example.test",
              "CNAME chain inside one packet");
        const auto c = resolve_one(r, "cut.example.test");
        check(c && has(*c, "192.0.2.44"), "dangling CNAME is followed with a new query");
        const auto e = resolve_one(r, "evil.example.test");
        check(!e && e.error() == errc::no_data, "records for unrelated owners are ignored");
    }

    void test_tcp_fallback() {
        std::cout << "TC -> TCP fallback\n";
        fake_dns srv([](const bytes &req, bool tcp) -> std::vector<bytes> {
            const auto q = question_of(req);
            if (q.type != 1) return {reply(req, {}, {{"t.test", 6, 900, soa_rdata(5)}})};
            if (!tcp) return {reply(req, {}, {}, 0, true)};
            return {reply(req, {{"", 1, 60, a4("192.0.2.200")}})};
        });
        resolver r(cfg_for(srv));
        const auto a = resolve_one(r, "big.t.test");
        check(a && has(*a, "192.0.2.200"), "truncated UDP answer retried over TCP");
    }

    void test_retry_and_spoofing() {
        std::cout << "retries and spoofing resistance\n";
        std::atomic<int> a_queries{0};
        fake_dns flaky([&](const bytes &req, bool) -> std::vector<bytes> {
            const auto q = question_of(req);
            if (q.type != 1) return {reply(req, {}, {{"f.test", 6, 900, soa_rdata(5)}})};
            if (a_queries++ == 0) return {reply(req, {}, {}, 2)}; // SERVFAIL first
            return {reply(req, {{"", 1, 60, a4("192.0.2.5")}})};
        });
        resolver r1(cfg_for(flaky));
        const auto a = resolve_one(r1, "x.f.test");
        check(a && has(*a, "192.0.2.5"), "SERVFAIL is retried and the next answer used");

        fake_dns spoof([](const bytes &req, bool) -> std::vector<bytes> {
            const auto q = question_of(req);
            if (q.type != 1) return {reply(req, {}, {{"s.test", 6, 900, soa_rdata(5)}})};
            const auto m = *parse_message(req);
            auto wrong_id = reply(req, {{"", 1, 60, a4("6.6.6.6")}}, {}, 0, false, static_cast<std::uint16_t>(m.id ^ 0x5555));
            // Right ID but a different question name.
            auto other = build_query(m.id, "other.s.test", 1);
            auto wrong_q = reply(*other, {{"", 1, 60, a4("6.6.6.7")}});
            return {wrong_id, wrong_q, reply(req, {{"", 1, 60, a4("192.0.2.6")}})};
        });
        resolver r2(cfg_for(spoof));
        const auto b = resolve_one(r2, "x.s.test");
        check(b && b->list.size() == 1 && has(*b, "192.0.2.6"), "wrong-ID and wrong-question packets are ignored");

        fake_dns silent([](const bytes &, bool) -> std::vector<bytes> { return {}; });
        auto c = cfg_for(silent);
        c.timeout = 100ms;
        c.attempts = 1;
        resolver r3(c);
        const auto t0 = std::chrono::steady_clock::now();
        const auto t = resolve_one(r3, "x.silent.test");
        check(!t && t.error() == errc::timeout, "no answer -> timeout");
        check(std::chrono::steady_clock::now() - t0 < 3s, "timeout is bounded");

        fake_dns refusing([](const bytes &req, bool) -> std::vector<bytes> { return {reply(req, {}, {}, 5)}; });
        resolver r4(cfg_for(refusing));
        check(resolve_one(r4, "x.refused.test").error() == errc::refused, "REFUSED surfaces as refused");

        resolver r5(config{});
        check(resolve_one(r5, "x.nowhere.test").error() == errc::no_servers, "no servers configured");
    }

    void test_coalescing() {
        std::cout << "request coalescing\n";
        fake_dns srv([](const bytes &req, bool) -> std::vector<bytes> {
            const auto q = question_of(req);
            std::this_thread::sleep_for(150ms); // keep the query in flight while the others arrive
            if (q.type == 1) return {reply(req, {{"", 1, 60, a4("192.0.2.123")}})};
            return {reply(req, {}, {{"c.test", 6, 900, soa_rdata(5)}})};
        });
        auto c = cfg_for(srv);
        c.timeout = 2s;
        resolver r(c);
        const auto results = resolve_many(r, "hot.c.test", 16, 3);
        int ok = 0;
        for (const auto &x: results) ok += (x && has(*x, "192.0.2.123"));
        check(ok == 16, "all 16 concurrent callers get the answer");
        check(srv.count(1) == 1 && srv.count(28) == 1, "only one A and one AAAA query reached the server");
    }

    void test_https_records() {
        std::cout << "HTTPS / SVCB records\n";
        fake_dns srv([](const bytes &req, bool) -> std::vector<bytes> {
            const auto q = question_of(req);
            if (q.type != 65) return {reply(req, {}, {{"h.test", 6, 900, soa_rdata(5)}})};
            if (q.name == "www.h.test") {
                return {reply(req, {{"", 65, 60, https_rdata(2, "", {"h2"})},
                                    {"", 65, 60, https_rdata(1, "", {"h3", "h2"}, 8443)}})};
            }
            if (q.name == "alias.h.test") return {reply(req, {{"", 65, 60, https_rdata(0, "www.h.test", {})}})};
            return {reply(req, {}, {{"h.test", 6, 900, soa_rdata(5)}}, 3)};
        });
        resolver r(cfg_for(srv));
        asio::io_context io;
        std::expected<std::vector<svcb_data>, std::error_code> a = std::unexpected(std::error_code{}), b = a, c = a;
        asio::co_spawn(io, [&]() -> wavex::task<void> {
            a = co_await r.resolve_https("www.h.test");
            b = co_await r.resolve_https("alias.h.test");
            c = co_await r.resolve_https("missing.h.test");
        }, asio::detached);
        io.run();
        check(a && a->size() == 2 && (*a)[0].priority == 1 && (*a)[0].alpn[0] == "h3" && (*a)[0].port == 8443,
              "service records sorted by priority");
        check(b && b->size() == 2, "AliasMode is followed to its target");
        check(!c && c.error() == errc::name_not_found, "missing name");
    }
} // namespace

int main() {
    test_wire_format();
    test_hostile_packets();
    test_config_parsing();
    test_basic_resolution_and_cache();
    test_local_names();
    test_search_list();
    test_cname_chain();
    test_tcp_fallback();
    test_retry_and_spoofing();
    test_coalescing();
    test_https_records();
    std::cout << "\n" << (tests_run - tests_failed) << "/" << tests_run << " passed\n";
    return tests_failed == 0 ? 0 : 1;
}
