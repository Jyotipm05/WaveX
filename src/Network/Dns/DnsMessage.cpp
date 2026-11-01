// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
/**
 * @file DnsMessage.cpp
 * @brief DNS wire format: query building and hardened response parsing.
 */

#include <wavex/Network/Dns/DnsMessage.hpp>

#include <algorithm>
#include <array>
#if defined(__MINGW32__) || defined(__clang__) || defined(__GNUC__)
#include <cstring>
#endif

namespace wavex::dns {
    namespace {
        constexpr std::size_t kHeaderSize = 12;
        constexpr std::size_t kMinQuestionSize = 5; // root label + type + class
        constexpr std::size_t kMinRecordSize = 11; // root label + type + class + ttl + rdlength

        char lower(const char c) noexcept {
            return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
        }

        std::string_view strip_dot(std::string_view n) noexcept {
            if (!n.empty() && n.back() == '.') n.remove_suffix(1);
            return n;
        }

        bool valid_label_char(const char c) noexcept {
            return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' ||
                   c == '_' || c == '*';
        }

        /// Bounds-checked big-endian reader over one packet.
        class reader {
        public:
            explicit reader(const std::span<const std::uint8_t> data) noexcept : data_(data) {
            }

            [[nodiscard]] std::size_t pos() const noexcept { return pos_; }
            void seek(const std::size_t p) noexcept { pos_ = p; }
            [[nodiscard]] std::size_t size() const noexcept { return data_.size(); }
            [[nodiscard]] std::size_t remaining() const noexcept { return data_.size() - pos_; }
            [[nodiscard]] std::span<const std::uint8_t> data() const noexcept { return data_; }

            bool [[maybe_unused]]u8(std::uint8_t &v) noexcept {
                if (remaining() < 1) return false;
                v = data_[pos_++];
                return true;
            }

            bool u16(std::uint16_t &v) noexcept {
                if (remaining() < 2) return false;
                v = static_cast<std::uint16_t>((data_[pos_] << 8) | data_[pos_ + 1]);
                pos_ += 2;
                return true;
            }

            bool u32(std::uint32_t &v) noexcept {
                if (remaining() < 4) return false;
                v = (static_cast<std::uint32_t>(data_[pos_]) << 24) | (
                        static_cast<std::uint32_t>(data_[pos_ + 1]) << 16) |
                    (static_cast<std::uint32_t>(data_[pos_ + 2]) << 8) | static_cast<std::uint32_t>(data_[pos_ + 3]);
                pos_ += 4;
                return true;
            }

            bool bytes(const std::size_t n, std::span<const std::uint8_t> &out) noexcept {
                if (remaining() < n) return false;
                out = data_.subspan(pos_, n);
                pos_ += n;
                return true;
            }

        private:
            std::span<const std::uint8_t> data_;
            std::size_t pos_{0};
        };

        /**
         * Read a (possibly compressed) name starting at `r.pos()`; on success r.pos() is the byte after the name as
         * it appears at the starting position (after the first pointer, if any).
         * A pointer must target an offset strictly lower than the offset it sits at, so every jump moves backwards
         * and loops are impossible without a separate counter.
         */
        std::expected<std::string, parse_error> read_name(reader &r) {
            const auto data = r.data();
            std::string out;
            std::size_t p = r.pos();
            std::size_t resume = 0;
            bool jumped = false;

            for (;;) {
                if (p >= data.size()) return std::unexpected(parse_error::truncated);
                const std::uint8_t len = data[p];

                if ((len & 0xC0) == 0xC0) {
                    if (p + 1 >= data.size()) return std::unexpected(parse_error::truncated);
                    const std::size_t target = (static_cast<std::size_t>(len & 0x3F) << 8) | data[p + 1];
                    if (!jumped) {
                        resume = p + 2;
                        jumped = true;
                    }
                    if (target >= p) return std::unexpected(parse_error::bad_name); // forward/self pointer
                    p = target;
                    continue;
                }
                if ((len & 0xC0) != 0) return std::unexpected(parse_error::bad_name); // reserved label types

                if (len == 0) {
                    if (!jumped) resume = p + 1;
                    break;
                }
                if (p + 1 + len > data.size()) return std::unexpected(parse_error::truncated);
                if (out.size() + len + (out.empty() ? 0 : 1) > max_name_length - 2) {
                    return std::unexpected(parse_error::bad_name); // dotted form of a <= 255 byte wire name is <= 253
                }
                if (!out.empty()) out.push_back('.');
                for (std::size_t i = 0; i < len; ++i) {
                    const auto c = static_cast<char>(data[p + 1 + i]);
                    // '.' inside a label would make the dotted form ambiguous; control bytes are never legitimate.
                    if (c == '.' || static_cast<unsigned char>(c) < 0x20 || static_cast<unsigned char>(c) == 0x7F) {
                        return std::unexpected(parse_error::bad_name);
                    }
                    out.push_back(c);
                }
                p += 1 + len;
            }
            r.seek(resume);
            return out;
        }

        std::expected<question, parse_error> read_question(reader &r) {
            auto name = read_name(r);
            if (!name) return std::unexpected(name.error());
            question q;
            q.name = std::move(*name);
            if (!r.u16(q.type) || !r.u16(q.cls)) return std::unexpected(parse_error::truncated);
            return q;
        }

        std::expected<svcb_data, parse_error> parse_svcb(reader &r, const std::size_t end) {
            svcb_data s;
            if (!r.u16(s.priority)) return std::unexpected(parse_error::bad_record);
            auto target = read_name(r);
            if (!target) return std::unexpected(parse_error::bad_record);
            s.target = std::move(*target);

            int last_key = -1;
            while (r.pos() < end) {
                std::uint16_t key{}, len{};
                if (!r.u16(key) || !r.u16(len)) return std::unexpected(parse_error::bad_record);
                if (static_cast<int>(key) <= last_key) return std::unexpected(parse_error::bad_record); // must ascend
                last_key = key;
                if (r.pos() + len > end) return std::unexpected(parse_error::bad_record);
                std::span<const std::uint8_t> v;
                if (!r.bytes(len, v)) return std::unexpected(parse_error::bad_record);

                switch (key) {
                    case 1: {
                        // alpn: list of 1-byte-length ids that fills the value exactly
                        std::size_t i = 0;
                        while (i < v.size()) {
                            const std::size_t n = v[i++];
                            if (n == 0 || i + n > v.size()) return std::unexpected(parse_error::bad_record);
                            s.alpn.emplace_back(reinterpret_cast<const char *>(v.data() + i), n);
                            i += n;
                        }
                        break;
                    }
                    case 2:
                        if (!v.empty()) return std::unexpected(parse_error::bad_record);
                        s.no_default_alpn = true;
                        break;
                    case 3:
                        if (v.size() != 2) return std::unexpected(parse_error::bad_record);
                        s.port = static_cast<std::uint16_t>((v[0] << 8) | v[1]);
                        break;
                    case 4:
                        if (v.empty() || v.size() % 4 != 0) return std::unexpected(parse_error::bad_record);
                        for (std::size_t i = 0; i < v.size(); i += 4) {
                            s.ipv4_hint.emplace_back(asio::ip::address_v4::bytes_type{
                                v[i], v[i + 1], v[i + 2], v[i + 3]
                            });
                        }
                        break;
                    case 5:
                        s.ech.assign(v.begin(), v.end());
                        break;
                    case 6:
                        if (v.empty() || v.size() % 16 != 0) return std::unexpected(parse_error::bad_record);
                        for (std::size_t i = 0; i < v.size(); i += 16) {
                            asio::ip::address_v6::bytes_type b{};
                            std::memcpy(b.data(), v.data() + i, 16);
                            s.ipv6_hint.emplace_back(b);
                        }
                        break;
                    default: // mandatory (0) and unknown keys: ignored
                        break;
                }
            }
            if (r.pos() != end) return std::unexpected(parse_error::bad_record);
            return s;
        }

        std::expected<record, parse_error> read_record(reader &r) {
            record rec;
            auto name = read_name(r);
            if (!name) return std::unexpected(name.error());
            rec.name = std::move(*name);

            std::uint16_t rdlen{};
            if (!r.u16(rec.type) || !r.u16(rec.cls) || !r.u32(rec.ttl) || !r.u16(rdlen)) {
                return std::unexpected(parse_error::truncated);
            }
            if (r.remaining() < rdlen) return std::unexpected(parse_error::truncated);
            const std::size_t start = r.pos();
            const std::size_t end = start + rdlen;

            switch (static_cast<rr_type>(rec.type)) {
                case rr_type::A: {
                    if (rdlen != 4) return std::unexpected(parse_error::bad_record);
                    const auto d = r.data();
                    rec.data = asio::ip::address_v4(
                        asio::ip::address_v4::bytes_type{d[start], d[start + 1], d[start + 2], d[start + 3]});
                    r.seek(end);
                    break;
                }
                case rr_type::AAAA: {
                    if (rdlen != 16) return std::unexpected(parse_error::bad_record);
                    asio::ip::address_v6::bytes_type b{};
                    std::memcpy(b.data(), r.data().data() + start, 16);
                    rec.data = asio::ip::address_v6(b);
                    r.seek(end);
                    break;
                }
                case rr_type::CNAME:
                case rr_type::NS:
                case rr_type::PTR: {
                    auto target = read_name(r);
                    if (!target || r.pos() != end) return std::unexpected(parse_error::bad_record);
                    rec.data = std::move(*target);
                    break;
                }
                case rr_type::SOA: {
                    soa_data soa;
                    auto m = read_name(r);
                    if (!m) return std::unexpected(parse_error::bad_record);
                    auto rn = read_name(r);
                    if (!rn) return std::unexpected(parse_error::bad_record);
                    soa.mname = std::move(*m);
                    soa.rname = std::move(*rn);
                    if (!r.u32(soa.serial) || !r.u32(soa.refresh) || !r.u32(soa.retry) || !r.u32(soa.expire) ||
                        !r.u32(soa.minimum) || r.pos() != end) {
                        return std::unexpected(parse_error::bad_record);
                    }
                    rec.data = std::move(soa);
                    break;
                }
                case rr_type::SVCB:
                case rr_type::HTTPS: {
                    auto s = parse_svcb(r, end);
                    if (!s) return std::unexpected(s.error());
                    rec.data = std::move(*s);
                    break;
                }
                default: {
                    std::span<const std::uint8_t> raw;
                    if (!r.bytes(rdlen, raw)) return std::unexpected(parse_error::truncated);
                    rec.raw.assign(raw.begin(), raw.end());
                    break;
                }
            }
            return rec;
        }

        std::expected<void, parse_error> read_section(reader &r, const std::size_t count, std::vector<record> &out) {
            out.reserve(std::min<std::size_t>(count, r.remaining() / kMinRecordSize));
            for (std::size_t i = 0; i < count; ++i) {
                auto rec = read_record(r);
                if (!rec) return std::unexpected(rec.error());
                out.push_back(std::move(*rec));
            }
            return {};
        }

        void put16(std::vector<std::uint8_t> &v, const std::uint16_t x) {
            v.push_back(static_cast<std::uint8_t>(x >> 8));
            v.push_back(static_cast<std::uint8_t>(x & 0xFF));
        }
    } // namespace

    bool is_valid_name(std::string_view name) noexcept {
        name = strip_dot(name);
        if (name.empty() || name.size() > max_name_length - 2) return false;
        std::size_t label = 0;
        for (const char c: name) {
            if (c == '.') {
                if (label == 0) return false;
                label = 0;
                continue;
            }
            if (!valid_label_char(c) || ++label > max_label_length) return false;
        }
        return label > 0;
    }

    bool names_equal(std::string_view a, std::string_view b) noexcept {
        a = strip_dot(a);
        b = strip_dot(b);
        if (a.size() != b.size()) return false;
        for (std::size_t i = 0; i < a.size(); ++i) {
            if (lower(a[i]) != lower(b[i])) return false;
        }
        return true;
    }

    std::string normalize_name(const std::string_view name) {
        std::string out(strip_dot(name));
        for (char &c: out) c = lower(c);
        return out;
    }

    std::optional<std::vector<std::uint8_t> > encode_name(std::string_view name) {
        std::vector<std::uint8_t> out;
        if (name == ".") {
            out.push_back(0);
            return out;
        }
        if (!is_valid_name(name)) return std::nullopt;
        name = strip_dot(name);
        out.reserve(name.size() + 2);
        std::size_t start = 0;
        while (start <= name.size()) {
            auto dot = name.find('.', start);
            if (dot == std::string_view::npos) dot = name.size();
            const auto len = dot - start;
            out.push_back(static_cast<std::uint8_t>(len));
            out.insert(out.end(), name.begin() + static_cast<std::ptrdiff_t>(start),
                       name.begin() + static_cast<std::ptrdiff_t>(dot));
            start = dot + 1;
        }
        out.push_back(0);
        return out;
    }

    std::optional<std::vector<std::uint8_t> > build_query(const std::uint16_t id, const std::string_view name,
                                                          const std::uint16_t type,
                                                          const std::uint16_t edns_udp_payload) {
        auto qname = encode_name(name);
        if (!qname) return std::nullopt;

        std::vector<std::uint8_t> p;
        p.reserve(kHeaderSize + qname->size() + 4 + 11);
        put16(p, id);
        put16(p, 0x0100); // QR=0, opcode=0, RD=1
        put16(p, 1); // QDCOUNT
        put16(p, 0); // ANCOUNT
        put16(p, 0); // NSCOUNT
        put16(p, edns_udp_payload != 0 ? 1 : 0); // ARCOUNT
        p.insert(p.end(), qname->begin(), qname->end());
        put16(p, type);
        put16(p, class_in);
        if (edns_udp_payload != 0) {
            // OPT pseudo-record (RFC 6891): root name, type 41, class = UDP payload size, TTL = ext-rcode/version/flags.
            p.push_back(0);
            put16(p, static_cast<std::uint16_t>(rr_type::OPT));
            put16(p, std::max<std::uint16_t>(edns_udp_payload, static_cast<std::uint16_t>(min_udp_payload)));
            put16(p, 0);
            put16(p, 0);
            put16(p, 0); // RDLENGTH
        }
        return p;
    }

    std::expected<message, parse_error> parse_message(const std::span<const std::uint8_t> packet) {
        reader r(packet);
        std::uint16_t flags{}, qd{}, an{}, ns{}, ar{};
        message m;
        if (!r.u16(m.id) || !r.u16(flags) || !r.u16(qd) || !r.u16(an) || !r.u16(ns) || !r.u16(ar)) {
            return std::unexpected(parse_error::truncated);
        }
        m.response = (flags & 0x8000) != 0;
        m.opcode = static_cast<std::uint8_t>((flags >> 11) & 0x0F);
        m.authoritative = (flags & 0x0400) != 0;
        m.truncated = (flags & 0x0200) != 0;
        m.recursion_desired = (flags & 0x0100) != 0;
        m.recursion_available = (flags & 0x0080) != 0;
        m.code = static_cast<rcode>(flags & 0x0F);

        // A packet cannot hold more records than its remaining bytes allow; reject inflated counts up front so a
        // 12-byte packet claiming 65535 records never reserves memory or loops.
        const std::size_t needed = static_cast<std::size_t>(qd) * kMinQuestionSize +
                                   (static_cast<std::size_t>(an) + ns + ar) * kMinRecordSize;
        if (needed > r.remaining()) return std::unexpected(parse_error::too_many_records);

        m.questions.reserve(qd);
        for (std::size_t i = 0; i < qd; ++i) {
            auto q = read_question(r);
            if (!q) return std::unexpected(q.error());
            m.questions.push_back(std::move(*q));
        }
        if (auto e = read_section(r, an, m.answers); !e) return std::unexpected(e.error());
        if (auto e = read_section(r, ns, m.authority); !e) return std::unexpected(e.error());
        if (auto e = read_section(r, ar, m.additional); !e) return std::unexpected(e.error());
        return m;
    }
} // namespace wavex::dns
