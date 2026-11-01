// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
/**
 * @file Resolver.hpp
 * @brief Native asynchronous stub DNS resolver (a dependency-free alternative to c-ares).
 *
 * Features: UDP with EDNS0 and automatic TCP fallback on truncation, retries across servers, anti-spoofing
 * (random 16-bit ID + connected UDP socket on an OS-chosen ephemeral port + question check), `/etc/hosts`,
 * `resolv.conf` search list / `ndots`, `localhost`, CNAME chains, A + AAAA queried in parallel, HTTPS/SVCB records
 * (RFC 9460), a TTL cache with negative caching (RFC 2308), and coalescing of identical in-flight queries.
 *
 * The resolver is thread-safe: one instance can be shared by every thread and executor in the process.
 * Sockets are created on the executor of the awaiting coroutine, so no executor is stored.
 *
 * @code
 * auto r = wavex::dns::resolver::shared();
 * auto res = co_await r->resolve("example.com");
 * if (res) for (auto &ip : res->list) std::cout << ip << "\n";
 * @endcode
 */
#pragma once

#include <wavex/Base/Task.hpp>
#include <wavex/Network/Dns/DnsMessage.hpp>

#include <chrono>
#include <cstdint>
#include <expected>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <system_error>
#include <unordered_map>
#include <vector>

#include <asio/ip/address.hpp>

namespace wavex::dns {

    /// Resolver errors (`std::error_code` with `dns::category()`).
    enum class errc {
        name_not_found = 1, ///< NXDOMAIN
        no_data = 2, ///< the name exists but has no record of the requested type
        server_failure = 3, ///< SERVFAIL (or other server-side failure) from every server
        timeout = 4, ///< no valid answer from any server in time
        malformed_response = 5,
        refused = 6, ///< REFUSED by every server
        invalid_name = 7,
        no_servers = 8, ///< no nameserver configured
    };

    [[nodiscard]] const std::error_category &category() noexcept;

    [[nodiscard]] inline std::error_code make_error_code(const errc e) noexcept {
        return {static_cast<int>(e), category()};
    }

    /// Resolver configuration: what `resolv.conf` + `hosts` describe.
    struct config {
        std::vector<asio::ip::address> servers;
        std::vector<std::string> search; ///< search domains (no trailing dot)
        unsigned ndots{1};
        std::chrono::milliseconds timeout{2000}; ///< per attempt, per server
        unsigned attempts{2}; ///< rounds over the server list
        bool rotate{false}; ///< start each query at a different server
        std::uint16_t port{53}; ///< server port (tests use others)
        std::uint16_t edns_udp_payload{default_edns_udp_payload}; ///< 0 disables EDNS0
        std::unordered_map<std::string, std::vector<asio::ip::address> > hosts; ///< normalized name -> addresses
    };

    /// Parse the text of a `resolv.conf` (nameserver, search/domain, options ndots/timeout/attempts/rotate).
    [[nodiscard]] config parse_resolv_conf(std::string_view text);

    /// Parse the text of a hosts file into `out` (appending; names normalized).
    void parse_hosts(std::string_view text, std::unordered_map<std::string, std::vector<asio::ip::address> > &out);

    /// Configuration of this machine: resolv.conf + hosts on Unix, adapter DNS servers + hosts on Windows.
    [[nodiscard]] config system_config();

    struct resolve_options {
        bool ipv4{true};
        bool ipv6{true};
    };

    struct resolver_options {
        std::size_t max_cache_entries{2048};
        std::chrono::seconds max_ttl{3600}; ///< upper bound for cached positive answers
        std::chrono::seconds negative_ttl{10}; ///< used when a negative answer carries no SOA
    };

    /// Result of `resolve`.
    struct addresses {
        std::vector<asio::ip::address> list; ///< IPv6 and IPv4 interleaved, IPv6 first
        std::string canonical; ///< final name after CNAMEs / search expansion
    };

    class resolver {
    public:
        explicit resolver(config cfg, const resolver_options &opts = {});

        resolver(const resolver &) = delete;
        resolver &operator=(const resolver &) = delete;

        /// Process-wide resolver using `system_config()` (created on first use).
        [[nodiscard]] static std::shared_ptr<resolver> shared();

        /// Resolve `host` (name, IP literal, "localhost") to addresses.
        [[nodiscard]] task<std::expected<addresses, std::error_code> > resolve(std::string host,
                                                                               resolve_options opts = {});

        /// Look up HTTPS (SVCB) service records for `host`, sorted by priority (ServiceMode first, lowest value).
        [[nodiscard]] task<std::expected<std::vector<svcb_data>, std::error_code> > resolve_https(std::string host);

        void clear_cache();
        [[nodiscard]] std::size_t cache_size() const;

        [[nodiscard]] const config &configuration() const noexcept { return cfg_; }

    private:
        struct answer {
            std::vector<asio::ip::address> addrs;
            std::vector<svcb_data> svcb;
            std::string canonical;
            std::chrono::seconds ttl{0};
        };
        struct cache_entry {
            answer ans;
            std::error_code err;
            std::chrono::steady_clock::time_point expires;
        };
        struct lookup_result {
            answer ans;
            std::error_code err; ///< success when clear; `ans.ttl` is the negative TTL on name_not_found/no_data
        };
        struct inflight;

        task<lookup_result> lookup(std::string name, std::uint16_t type);
        task<lookup_result> query_network(std::string name, std::uint16_t type);
        task<std::expected<message, std::error_code> > exchange(std::string name, std::uint16_t type);
        void finish(const std::string &key, const std::shared_ptr<inflight> &inf, lookup_result r);
        std::vector<std::string> candidates(std::string_view host) const;

        config cfg_;
        resolver_options opts_;
        mutable std::mutex mu_;
        std::unordered_map<std::string, cache_entry> cache_;
        std::unordered_map<std::string, std::shared_ptr<inflight> > inflight_;
        std::size_t next_server_{0};
    };

} // namespace wavex::dns

template<>
struct std::is_error_code_enum<wavex::dns::errc> : std::true_type {};
