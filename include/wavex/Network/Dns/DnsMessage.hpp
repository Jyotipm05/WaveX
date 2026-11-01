// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
/**
 * @file DnsMessage.hpp
 * @brief DNS wire format (RFC 1035, 3596, 6891, 9460): building queries and parsing untrusted responses.
 *
 * The parser treats every byte as hostile: all reads are bounds-checked, name compression pointers must point
 * strictly backwards (so loops are impossible), names are limited to 255 bytes and labels to 63, and the number of
 * records is capped by what the packet can actually hold. A malformed packet yields an error, never a crash.
 */
#pragma once

#if defined(__MINGW32__)||defined(__clang__)||defined(__GNUC__)
#include <cstddef>
#endif
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

#include <asio/ip/address.hpp>
#include <asio/ip/address_v4.hpp>
#include <asio/ip/address_v6.hpp>

namespace wavex::dns {
    /// Resource record types WaveX understands (others are kept as raw bytes).
    enum class rr_type : std::uint16_t {
        A = 1,
        NS = 2,
        CNAME = 5,
        SOA = 6,
        PTR = 12,
        MX = 15,
        TXT = 16,
        AAAA = 28,
        OPT = 41,
        SVCB = 64,
        HTTPS = 65,
    };

    inline constexpr std::uint16_t class_in = 1;

    /// Response codes (RFC 1035 §4.1.1, RFC 6895).
    enum class rcode : std::uint8_t {
        no_error = 0,
        format_error = 1,
        server_failure = 2,
        name_error = 3, ///< NXDOMAIN
        not_implemented = 4,
        refused = 5,
    };

    /// Why a packet could not be parsed.
    enum class parse_error {
        truncated, ///< ran past the end of the packet
        bad_name, ///< label > 63, name > 255, bad pointer, or reserved label type
        bad_record, ///< RDATA does not match its type/length
        too_many_records, ///< section counts exceed what the packet could hold
    };

    struct question {
        std::string name; ///< dotted, no trailing dot, as received
        std::uint16_t type{};
        std::uint16_t cls{class_in};
    };

    /// SVCB/HTTPS service parameters (RFC 9460 §7), the ones a client needs.
    struct svcb_data {
        std::uint16_t priority{}; ///< 0 = AliasMode, otherwise ServiceMode
        std::string target; ///< target name ("" for ".": same as owner)
        std::vector<std::string> alpn; ///< e.g. {"h3", "h2"}
        bool no_default_alpn{false};
        std::optional<std::uint16_t> port;
        std::vector<asio::ip::address_v4> ipv4_hint;
        std::vector<asio::ip::address_v6> ipv6_hint;
        std::vector<std::uint8_t> ech; ///< opaque ECHConfigList
        [[nodiscard]] bool is_alias() const noexcept { return priority == 0; }
    };

    struct soa_data {
        std::string mname;
        std::string rname;
        std::uint32_t serial{}, refresh{}, retry{}, expire{}, minimum{};
    };

    using rdata = std::variant<
        std::monostate, ///< unparsed / unknown type: see `raw`
        asio::ip::address_v4, ///< A
        asio::ip::address_v6, ///< AAAA
        std::string, ///< CNAME, NS, PTR (target name)
        soa_data, ///< SOA
        svcb_data ///< SVCB, HTTPS
    >;

    struct record {
        std::string name;
        std::uint16_t type{};
        std::uint16_t cls{class_in};
        std::uint32_t ttl{};
        rdata data;
        std::vector<std::uint8_t> raw; ///< RDATA bytes for types without a parsed form
    };

    struct message {
        std::uint16_t id{};
        bool response{false};
        bool authoritative{false};
        bool truncated{false};
        bool recursion_desired{false};
        bool recursion_available{false};
        std::uint8_t opcode{};
        rcode code{rcode::no_error};
        std::vector<question> questions;
        std::vector<record> answers;
        std::vector<record> authority;
        std::vector<record> additional;
    };

    /// Limits that keep a hostile packet from costing more than its own size.
    inline constexpr std::size_t max_name_length = 255;
    inline constexpr std::size_t max_label_length = 63;
    inline constexpr std::size_t min_udp_payload = 512;
    inline constexpr std::size_t default_edns_udp_payload = 1232; ///< DNS Flag Day 2020 recommendation

    /**
     * @brief Build a recursive query for one question.
     * @param id query ID (use a random value).
     * @param name dotted name; a trailing dot is allowed. IDNA/Unicode must already be converted to ASCII.
     * @param type record type.
     * @param edns_udp_payload advertise this UDP payload size with an EDNS0 OPT record; 0 omits EDNS0.
     * @return the packet, or std::nullopt when `name` is not a valid DNS name.
     */
    [[nodiscard]] std::optional<std::vector<std::uint8_t> > build_query(
        std::uint16_t id, std::string_view name, std::uint16_t type,
        std::uint16_t edns_udp_payload = default_edns_udp_payload);

    /// Parse a complete DNS packet (UDP payload, or a TCP message without its 2-byte length prefix).
    [[nodiscard]] std::expected<message, parse_error> parse_message(std::span<const std::uint8_t> packet);

    /// True when `name` is a syntactically valid hostname for lookup (labels 1..63, total <= 253, no empty label).
    [[nodiscard]] bool is_valid_name(std::string_view name) noexcept;

    /// Case-insensitive (ASCII) equality of two DNS names, ignoring one trailing dot.
    [[nodiscard]] bool names_equal(std::string_view a, std::string_view b) noexcept;

    /// ASCII-lowercased copy of `name` without a trailing dot (cache key form).
    [[nodiscard]] std::string normalize_name(std::string_view name);

    /// Encode a domain name (no compression). nullopt if invalid. Exposed for tests and server-side use.
    [[nodiscard]] std::optional<std::vector<std::uint8_t> > encode_name(std::string_view name);
} // namespace wavex::dns
