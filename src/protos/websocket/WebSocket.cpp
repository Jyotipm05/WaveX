// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * @file WebSocket.cpp
 * @brief RFC 6455 frame codec, opening-handshake helpers and the WebSocket session.
 */

#include <wavex/protos/websocket/WebSocket.hpp>

#include <array>

#include "wavex/protos/http/http3tunnel.hpp"
#if defined(__MINGW32__) || defined(__clang__) || defined(__GNUC__)
#include <cstring>
#endif
#include <random>

#include <asio/as_tuple.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/steady_timer.hpp>
#include <asio/this_coro.hpp>
#include <asio/use_awaitable.hpp>

#include <wavex/Base/Logger.hpp>

namespace wavex::protos::websocket {
    // ─── Errors ──────────────────────────────────────────────────────────────
    namespace {
        class websocket_category final : public std::error_category {
        public:
            [[nodiscard]] const char *name() const noexcept override { return "wavex.websocket"; }

            [[nodiscard]] std::string message(const int ev) const override {
                switch (static_cast<error>(ev)) {
                    case error::closed: return "WebSocket connection closed";
                    case error::protocol_error: return "WebSocket protocol error";
                    case error::message_too_big: return "WebSocket message too big";
                    case error::invalid_utf8: return "WebSocket text is not valid UTF-8";
                    case error::read_timeout: return "WebSocket read timed out";
                }
                return "unknown WebSocket error";
            }
        };

        [[nodiscard]] uint32_t random_u32() {
            thread_local std::mt19937 rng{std::random_device{}()};
            return static_cast<uint32_t>(rng());
        }

        [[nodiscard]] constexpr char ascii_lower(const char c) noexcept {
            return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
        }

        [[nodiscard]] bool iequals(const std::string_view a, const std::string_view b) noexcept {
            if (a.size() != b.size()) return false;
            for (std::size_t i = 0; i < a.size(); ++i) {
                if (ascii_lower(a[i]) != ascii_lower(b[i])) return false;
            }
            return true;
        }

        [[nodiscard]] std::string_view trim(std::string_view s) noexcept {
            while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.remove_prefix(1);
            while (!s.empty() && (s.back() == ' ' || s.back() == '\t')) s.remove_suffix(1);
            return s;
        }

        template<typename Fn>
        void for_each_token(std::string_view list, Fn &&fn) {
            while (!list.empty()) {
                const auto comma = list.find(',');
                const auto token = trim(list.substr(0, comma));
                if (!token.empty() && fn(token)) return;
                if (comma == std::string_view::npos) break;
                list.remove_prefix(comma + 1);
            }
        }

        /// Largest prefix of `s` (≤ max bytes) that does not split a UTF-8 sequence.
        [[nodiscard]] std::string_view utf8_prefix(std::string_view s, std::size_t max) noexcept {
            if (s.size() <= max) return s;
            std::size_t cut = max;
            while (cut > 0 && (static_cast<unsigned char>(s[cut]) & 0xC0) == 0x80) --cut;
            return s.substr(0, cut);
        }
    } // namespace

    const std::error_category &error_category() noexcept {
        static const websocket_category category;
        return category;
    }

    std::error_code make_error_code(const error e) noexcept {
        return {static_cast<int>(e), error_category()};
    }

    // ─── Frame Codec ─────────────────────────────────────────────────────────
    parse_result codec::parse_header(const std::string_view in, frame_header &hdr) noexcept {
        if (in.size() < 2) return parse_result::incomplete;
        const auto b0 = static_cast<uint8_t>(in[0]);
        const auto b1 = static_cast<uint8_t>(in[1]);

        hdr.fin = (b0 & 0x80) != 0;
        hdr.rsv1 = (b0 & 0x40) != 0;
        hdr.rsv2 = (b0 & 0x20) != 0;
        hdr.rsv3 = (b0 & 0x10) != 0;
        const uint8_t op = b0 & 0x0F;
        // Opcodes 0x3-0x7 and 0xB-0xF are reserved (RFC 6455 §5.2).
        if ((op >= 0x3 && op <= 0x7) || op >= 0xB) return parse_result::error;
        hdr.op = static_cast<opcode>(op);
        hdr.masked = (b1 & 0x80) != 0;

        std::size_t pos = 2;
        uint64_t len = b1 & 0x7F;
        if (len == 126) {
            if (in.size() < pos + 2) return parse_result::incomplete;
            len = (static_cast<uint64_t>(static_cast<uint8_t>(in[2])) << 8) |
                  static_cast<uint64_t>(static_cast<uint8_t>(in[3]));
            pos += 2;
        } else if (len == 127) {
            if (in.size() < pos + 8) return parse_result::incomplete;
            len = 0;
            for (std::size_t i = 0; i < 8; ++i) {
                len = (len << 8) | static_cast<uint8_t>(in[pos + i]);
            }
            if (len > kMaxPayloadLength) return parse_result::error; // the most significant bit must be 0
            pos += 8;
        }

        hdr.masking_key = 0;
        if (hdr.masked) {
            if (in.size() < pos + 4) return parse_result::incomplete;
            for (std::size_t i = 0; i < 4; ++i) {
                hdr.masking_key = (hdr.masking_key << 8) | static_cast<uint8_t>(in[pos + i]);
            }
            pos += 4;
        }
        hdr.payload_length = len;
        hdr.header_size = static_cast<uint8_t>(pos);
        return parse_result::complete;
    }

    void codec::encode_frame(std::string &out, const opcode op, const std::string_view payload, const bool fin,
                             const std::optional<uint32_t> mask) {
        out.reserve(out.size() + payload.size() + 14);
        out.push_back(static_cast<char>((fin ? 0x80 : 0x00) | static_cast<uint8_t>(op)));
        const uint8_t mask_bit = mask ? 0x80 : 0x00;
        const uint64_t len = payload.size();
        if (len < 126) {
            out.push_back(static_cast<char>(mask_bit | static_cast<uint8_t>(len)));
        } else if (len <= 0xFFFF) {
            out.push_back(static_cast<char>(mask_bit | 126));
            out.push_back(static_cast<char>((len >> 8) & 0xFF));
            out.push_back(static_cast<char>(len & 0xFF));
        } else {
            out.push_back(static_cast<char>(mask_bit | 127));
            for (int shift = 56; shift >= 0; shift -= 8) {
                out.push_back(static_cast<char>((len >> shift) & 0xFF));
            }
        }
        if (mask) {
            for (int shift = 24; shift >= 0; shift -= 8) {
                out.push_back(static_cast<char>((*mask >> shift) & 0xFF));
            }
            const std::size_t start = out.size();
            out.append(payload);
            apply_mask(out.data() + start, payload.size(), *mask);
        } else {
            out.append(payload);
        }
    }

    void codec::apply_mask(char *data, const std::size_t len, const uint32_t key, const std::size_t offset) noexcept {
        const std::array<uint8_t, 4> k{
            static_cast<uint8_t>(key >> 24), static_cast<uint8_t>(key >> 16),
            static_cast<uint8_t>(key >> 8), static_cast<uint8_t>(key)
        };
        for (std::size_t i = 0; i < len; ++i) {
            data[i] = static_cast<char>(static_cast<uint8_t>(data[i]) ^ k[(offset + i) & 3]);
        }
    }

    std::string codec::close_payload(const uint16_t code, const std::string_view reason) {
        std::string out;
        if (code == close_code::no_status || code == close_code::abnormal) return out; // never on the wire
        const auto r = utf8_prefix(reason, 123); // control payloads are limited to 125 bytes
        out.reserve(2 + r.size());
        out.push_back(static_cast<char>((code >> 8) & 0xFF));
        out.push_back(static_cast<char>(code & 0xFF));
        out.append(r);
        return out;
    }

    bool codec::parse_close_payload(const std::string_view payload, uint16_t &code, std::string &reason) {
        reason.clear();
        if (payload.empty()) {
            code = close_code::no_status;
            return true;
        }
        if (payload.size() < 2) return false;
        code = static_cast<uint16_t>((static_cast<uint8_t>(payload[0]) << 8) | static_cast<uint8_t>(payload[1]));
        if (!is_valid_close_code(code)) return false;
        reason.assign(payload.substr(2));
        return true;
    }

    bool codec::is_valid_close_code(const uint16_t code) noexcept {
        if (code >= 1000 && code <= 1003) return true;
        if (code >= 1007 && code <= 1014) return true; // 1012-1014 are IANA-registered
        return code >= 3000 && code <= 4999;
    }

    // ─── Handshake Helpers ───────────────────────────────────────────────────
    namespace detail {
        std::string base64_encode(const std::string_view in) {
            static constexpr char kAlphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            std::string out;
            out.reserve(((in.size() + 2) / 3) * 4);
            std::size_t i = 0;
            for (; i + 3 <= in.size(); i += 3) {
                const uint32_t v = (static_cast<uint8_t>(in[i]) << 16) | (static_cast<uint8_t>(in[i + 1]) << 8) |
                                   static_cast<uint8_t>(in[i + 2]);
                out.push_back(kAlphabet[(v >> 18) & 0x3F]);
                out.push_back(kAlphabet[(v >> 12) & 0x3F]);
                out.push_back(kAlphabet[(v >> 6) & 0x3F]);
                out.push_back(kAlphabet[v & 0x3F]);
            }
            if (const std::size_t rest = in.size() - i; rest > 0) {
                uint32_t v = static_cast<uint8_t>(in[i]) << 16;
                if (rest == 2) v |= static_cast<uint8_t>(in[i + 1]) << 8;
                out.push_back(kAlphabet[(v >> 18) & 0x3F]);
                out.push_back(kAlphabet[(v >> 12) & 0x3F]);
                out.push_back(rest == 2 ? kAlphabet[(v >> 6) & 0x3F] : '=');
                out.push_back('=');
            }
            return out;
        }

        std::optional<std::string> base64_decode(const std::string_view in) {
            if (in.size() % 4 != 0) return std::nullopt;
            const auto value = [](const char c) -> int {
                if (c >= 'A' && c <= 'Z') return c - 'A';
                if (c >= 'a' && c <= 'z') return c - 'a' + 26;
                if (c >= '0' && c <= '9') return c - '0' + 52;
                if (c == '+') return 62;
                if (c == '/') return 63;
                return -1;
            };
            std::string out;
            out.reserve(in.size() / 4 * 3);
            for (std::size_t i = 0; i < in.size(); i += 4) {
                const bool last = (i + 4 == in.size());
                const int a = value(in[i]);
                const int b = value(in[i + 1]);
                const int c = in[i + 2] == '=' && last ? -2 : value(in[i + 2]);
                const int d = in[i + 3] == '=' && last ? -2 : value(in[i + 3]);
                if (a < 0 || b < 0 || c == -1 || d == -1 || (c == -2 && d != -2)) return std::nullopt;
                const uint32_t v = (static_cast<uint32_t>(a) << 18) | (static_cast<uint32_t>(b) << 12) |
                                   (c >= 0 ? static_cast<uint32_t>(c) << 6 : 0) | (d >= 0 ? static_cast<uint32_t>(d) : 0);
                out.push_back(static_cast<char>((v >> 16) & 0xFF));
                if (c >= 0) out.push_back(static_cast<char>((v >> 8) & 0xFF));
                if (d >= 0) out.push_back(static_cast<char>(v & 0xFF));
            }
            return out;
        }

        std::string sha1(const std::string_view in) {
            uint32_t h[5] = {0x67452301u, 0xEFCDAB89u, 0x98BADCFEu, 0x10325476u, 0xC3D2E1F0u};
            const auto rol = [](const uint32_t v, const int s) noexcept { return (v << s) | (v >> (32 - s)); };

            std::string msg(in);
            const uint64_t bit_len = static_cast<uint64_t>(in.size()) * 8;
            msg.push_back(static_cast<char>(0x80));
            while (msg.size() % 64 != 56) msg.push_back('\0');
            for (int shift = 56; shift >= 0; shift -= 8) msg.push_back(static_cast<char>((bit_len >> shift) & 0xFF));

            for (std::size_t chunk = 0; chunk < msg.size(); chunk += 64) {
                uint32_t w[80];
                for (int i = 0; i < 16; ++i) {
                    const auto *p = reinterpret_cast<const unsigned char *>(msg.data() + chunk + i * 4);
                    w[i] = (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
                           (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
                }
                for (int i = 16; i < 80; ++i) w[i] = rol(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);

                uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
                for (int i = 0; i < 80; ++i) {
                    uint32_t f;
                    uint32_t k;
                    if (i < 20) {
                        f = (b & c) | (~b & d);
                        k = 0x5A827999u;
                    } else if (i < 40) {
                        f = b ^ c ^ d;
                        k = 0x6ED9EBA1u;
                    } else if (i < 60) {
                        f = (b & c) | (b & d) | (c & d);
                        k = 0x8F1BBCDCu;
                    } else {
                        f = b ^ c ^ d;
                        k = 0xCA62C1D6u;
                    }
                    const uint32_t tmp = rol(a, 5) + f + e + k + w[i];
                    e = d;
                    d = c;
                    c = rol(b, 30);
                    b = a;
                    a = tmp;
                }
                h[0] += a;
                h[1] += b;
                h[2] += c;
                h[3] += d;
                h[4] += e;
            }

            std::string digest(20, '\0');
            for (int i = 0; i < 5; ++i) {
                digest[i * 4] = static_cast<char>((h[i] >> 24) & 0xFF);
                digest[i * 4 + 1] = static_cast<char>((h[i] >> 16) & 0xFF);
                digest[i * 4 + 2] = static_cast<char>((h[i] >> 8) & 0xFF);
                digest[i * 4 + 3] = static_cast<char>(h[i] & 0xFF);
            }
            return digest;
        }

        std::string select_subprotocol(const std::string_view offered, const std::vector<std::string> &supported) {
            for (const auto &candidate: supported) {
                bool found = false;
                for_each_token(offered, [&](const std::string_view token) {
                    found = (token == candidate); // subprotocol tokens are case-sensitive (RFC 6455 §4.1)
                    return found;
                });
                if (found) return candidate;
            }
            return {};
        }
    } // namespace detail

    std::string compute_accept_key(const std::string_view client_key) {
        std::string input;
        input.reserve(client_key.size() + kHandshakeGuid.size());
        input.append(client_key);
        input.append(kHandshakeGuid);
        return detail::base64_encode(detail::sha1(input));
    }

    bool is_valid_client_key(const std::string_view client_key) noexcept {
        if (client_key.size() != 24) return false;
        try {
            const auto decoded = detail::base64_decode(client_key);
            return decoded && decoded->size() == 16;
        } catch (...) {
            return false;
        }
    }

    std::string generate_client_key() {
        std::string raw(16, '\0');
        for (std::size_t i = 0; i < raw.size(); i += 4) {
            const uint32_t r = random_u32();
            std::memcpy(raw.data() + i, &r, 4);
        }
        return detail::base64_encode(raw);
    }

    bool header_contains_token(const std::string_view header_value, const std::string_view token) noexcept {
        bool found = false;
        for_each_token(header_value, [&](const std::string_view t) {
            found = iequals(t, token);
            return found;
        });
        return found;
    }

    bool is_valid_utf8(const std::string_view s) noexcept {
        const auto *p = reinterpret_cast<const unsigned char *>(s.data());
        const auto *const end = p + s.size();
        while (p < end) {
            const unsigned char c = *p;
            if (c < 0x80) {
                ++p;
                continue;
            }
            std::size_t n;
            uint32_t cp;
            if ((c & 0xE0) == 0xC0) {
                n = 1;
                cp = c & 0x1F;
                if (c < 0xC2) return false; // overlong 2-byte form
            } else if ((c & 0xF0) == 0xE0) {
                n = 2;
                cp = c & 0x0F;
            } else if ((c & 0xF8) == 0xF0) {
                n = 3;
                cp = c & 0x07;
                if (c > 0xF4) return false;
            } else {
                return false;
            }
            if (static_cast<std::size_t>(end - p) < n + 1) return false; // truncated sequence
            for (std::size_t i = 1; i <= n; ++i) {
                if ((p[i] & 0xC0) != 0x80) return false;
                cp = (cp << 6) | (p[i] & 0x3F);
            }
            if ((n == 2 && cp < 0x800) || (n == 3 && cp < 0x10000)) return false; // overlong
            if (cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) return false;  // out of range / surrogate
            p += n + 1;
        }
        return true;
    }

    // ─── Session ─────────────────────────────────────────────────────────────
    connection::connection(network::AnyStream stream, std::string leftover, options opts, const role r,
                           std::string subprotocol)
        : stream_(std::move(stream)),
          executor_(stream_.get_executor()),
          opts_(std::move(opts)),
          rbuf_(std::move(leftover)),
          message_(),
          subprotocol_(std::move(subprotocol)),
          close_reason_(),
          outbox_(),
          role_(r) {
    }

    connection::~connection() = default;

    std::size_t connection::buffered_amount() const noexcept {
        std::lock_guard lock(write_mtx_);
        return buffered_;
    }

    bool connection::writes_pending() const noexcept {
        std::lock_guard lock(write_mtx_);
        return writer_active_ || !outbox_.empty();
    }

    bool connection::send_text(const std::string_view text) {
        return enqueue(opcode::text, text);
    }

    bool connection::send_binary(const std::string_view data) {
        return enqueue(opcode::binary, data);
    }

    bool connection::ping(const std::string_view payload) {
        if (payload.size() > 125) return false;
        return enqueue(opcode::ping, payload);
    }

    bool connection::pong(const std::string_view payload) {
        if (payload.size() > 125) return false;
        return enqueue(opcode::pong, payload);
    }

    bool connection::close(const uint16_t code, const std::string_view reason) {
        if (!codec::is_valid_close_code(code) && code != close_code::no_status) return false;
        return enqueue(opcode::close, codec::close_payload(code, reason), true);
    }

    bool connection::enqueue(const opcode op, const std::string_view payload, const bool is_close) {
        std::string frame;
        std::optional<uint32_t> mask;
        if (role_ == role::client) mask = random_u32(); // RFC 6455 §5.3: a fresh key per frame
        codec::encode_frame(frame, op, payload, true, mask);

        bool start_writer = false; {
            std::lock_guard lock(write_mtx_);
            // Nothing may follow our close frame (RFC 6455 §5.5.1).
            if (write_failed_ || close_sent_.load(std::memory_order_relaxed)) return false;
            if (!is_control(op) && buffered_ + frame.size() > opts_.max_buffered_amount) return false;
            if (is_close) close_sent_.store(true, std::memory_order_release);
            buffered_ += frame.size();
            outbox_.push_back(std::move(frame));
            if (!writer_active_) {
                writer_active_ = true;
                start_writer = true;
            }
        }
        if (start_writer) {
            // The writer runs on the connection's executor, so every transport write is serialized with the
            // reads of the session coroutine regardless of which thread queued the frame.
            asio::co_spawn(executor_, [self = shared_from_this()]() -> asio::awaitable<void> {
                co_await self->drain();
            }, asio::detached);
        }
        return true;
    }

    asio::awaitable<void> connection::drain() {
        constexpr std::size_t kBatchBytes = 64 * 1024;
        for (;;) {
            std::string batch; {
                std::lock_guard lock(write_mtx_);
                if (outbox_.empty()) {
                    writer_active_ = false;
                    co_return;
                }
                batch = std::move(outbox_.front());
                outbox_.pop_front();
                while (!outbox_.empty() && batch.size() + outbox_.front().size() <= kBatchBytes) {
                    batch += outbox_.front();
                    outbox_.pop_front();
                }
            }

            std::error_code ec;
            try {
                ec = co_await stream_.write(asio::buffer(batch));
            } catch (...) {
                ec = std::make_error_code(std::errc::io_error);
            }

            std::lock_guard lock(write_mtx_);
            buffered_ -= (std::min)(buffered_, batch.size());
            if (ec) {
                write_failed_ = true;
                outbox_.clear();
                buffered_ = 0;
                writer_active_ = false;
                co_return;
            }
        }
    }

    std::error_code connection::fail(const uint16_t code, const error err) {
        close(code);
        close_code_.store(code, std::memory_order_release);
        read_closed_.store(true, std::memory_order_release);
        in_message_ = false;
        message_.clear();
        return make_error_code(err);
    }

    asio::awaitable<std::error_code> connection::fill(const std::chrono::milliseconds timeout) {
        constexpr std::size_t kReadChunk = 16384;
        if (rbuf_consumed_ > 0 && rbuf_consumed_ == rbuf_.size()) {
            rbuf_.clear();
            rbuf_consumed_ = 0;
        } else if (rbuf_consumed_ >= 65536 && rbuf_consumed_ >= rbuf_.size() / 2) {
            rbuf_.erase(0, rbuf_consumed_);
            rbuf_consumed_ = 0;
        }

        const std::size_t prev = rbuf_.size();
        rbuf_.resize(prev + kReadChunk);

        // The flag is shared with the timer handler, which may still run after this frame is gone.
        std::optional<asio::steady_timer> timer;
        auto timed_out = std::make_shared<bool>(false);
        if (timeout.count() > 0) {
            timer.emplace(co_await asio::this_coro::executor, timeout);
            timer->async_wait([timed_out, s = stream_](const std::error_code ec) {
                if (!ec) {
                    *timed_out = true;
                    s.cancel();
                }
            });
        }
        auto [ec, n] = co_await stream_.read_some(asio::buffer(rbuf_.data() + prev, kReadChunk));
        if (timer) timer->cancel();
        rbuf_.resize(prev + n);

        if (*timed_out) co_return make_error_code(error::read_timeout);
        if (ec) co_return ec;
        if (n == 0) co_return std::error_code(asio::error::eof);
        co_return std::error_code{};
    }

    asio::awaitable<std::expected<message, std::error_code> > connection::read() {
        auto self = shared_from_this(); // the session must outlive a suspended read

        for (;;) {
            if (read_closed_.load(std::memory_order_acquire)) {
                co_return std::unexpected(make_error_code(error::closed));
            }

            const std::string_view avail(rbuf_.data() + rbuf_consumed_, rbuf_.size() - rbuf_consumed_);
            frame_header h;
            const auto pr = codec::parse_header(avail, h);
            if (pr == parse_result::error) {
                co_return std::unexpected(fail(close_code::protocol_error, error::protocol_error));
            }

            if (pr == parse_result::complete) {
                // Everything that can be judged from the header is judged before buffering the payload.
                const bool control = is_control(h.op);
                if (h.rsv1 || h.rsv2 || h.rsv3 ||                         // no extension was negotiated
                    h.masked != (role_ == role::server) ||                // §5.1 masking direction
                    (control && (!h.fin || h.payload_length > 125)) ||    // §5.5
                    (!control && h.op == opcode::continuation && !in_message_) ||
                    (!control && h.op != opcode::continuation && in_message_)) {
                    co_return std::unexpected(fail(close_code::protocol_error, error::protocol_error));
                }
                if (!control && message_.size() + h.payload_length > opts_.max_message_size) {
                    co_return std::unexpected(fail(close_code::message_too_big, error::message_too_big));
                }

                if (avail.size() >= h.header_size + h.payload_length) {
                    char *payload_ptr = rbuf_.data() + rbuf_consumed_ + h.header_size;
                    const auto payload_len = static_cast<std::size_t>(h.payload_length);
                    if (h.masked) codec::apply_mask(payload_ptr, payload_len, h.masking_key);
                    const std::string_view payload(payload_ptr, payload_len);
                    rbuf_consumed_ += h.header_size + payload_len;

                    switch (h.op) {
                        case opcode::ping:
                            if (!close_sent_.load(std::memory_order_acquire)) enqueue(opcode::pong, payload);
                            continue;
                        case opcode::pong:
                            continue;
                        case opcode::close: {
                            uint16_t code = close_code::no_status;
                            std::string reason;
                            if (!codec::parse_close_payload(payload, code, reason)) {
                                co_return std::unexpected(fail(close_code::protocol_error, error::protocol_error));
                            }
                            if (opts_.validate_utf8 && !is_valid_utf8(reason)) {
                                co_return std::unexpected(fail(close_code::invalid_payload, error::invalid_utf8));
                            }
                            close_reason_ = std::move(reason);
                            close_code_.store(code, std::memory_order_release);
                            close_received_.store(true, std::memory_order_release);
                            // Echo the status code (RFC 6455 §5.5.1); a no-op if we initiated the close.
                            close(code);
                            read_closed_.store(true, std::memory_order_release);
                            co_return std::unexpected(make_error_code(error::closed));
                        }
                        default:
                            break;
                    }

                    if (h.op != opcode::continuation) {
                        in_message_ = true;
                        message_type_ = h.op;
                        message_.clear();
                    }
                    message_.append(payload);
                    if (h.fin) {
                        in_message_ = false;
                        message m{std::move(message_), message_type_};
                        message_.clear();
                        if (m.is_text() && opts_.validate_utf8 && !is_valid_utf8(m.data)) {
                            co_return std::unexpected(fail(close_code::invalid_payload, error::invalid_utf8));
                        }
                        co_return m;
                    }
                    continue;
                }
            }

            if (const auto ec = co_await fill(opts_.read_timeout)) {
                read_closed_.store(true, std::memory_order_release);
                if (!close_received_.load(std::memory_order_acquire)) {
                    close_code_.store(close_code::abnormal, std::memory_order_release);
                }
                co_return std::unexpected(ec);
            }
        }
    }

    asio::awaitable<void> connection::finish() {
        auto self = shared_from_this();
        const auto deadline = std::chrono::steady_clock::now() + opts_.close_timeout;
        const auto time_left = [&deadline] {
            return std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now());
        };

        if (!close_sent_.load(std::memory_order_acquire)) close(close_code::normal);

        // Wait for the peer's close (the reply to ours, unless it closed first), discarding late data.
        while (!read_closed_.load(std::memory_order_acquire) && time_left().count() > 0) {
            const auto saved = opts_.read_timeout;
            opts_.read_timeout = (std::max)(time_left(), std::chrono::milliseconds(1));
            const auto r = co_await read();
            opts_.read_timeout = saved;
            if (!r) break;
        }

        // Let the writer flush our close frame before the server tears the transport down.
        asio::steady_timer timer(co_await asio::this_coro::executor);
        while (writes_pending() && time_left().count() > 0) {
            timer.expires_after(std::chrono::milliseconds(2));
            co_await timer.async_wait(asio::as_tuple(asio::use_awaitable));
        }
        read_closed_.store(true, std::memory_order_release);
    }

    void connection::abort() noexcept {
        read_closed_.store(true, std::memory_order_release); {
            std::lock_guard lock(write_mtx_);
            write_failed_ = true;
            outbox_.clear();
            buffered_ = 0;
        }
        stream_.close();
    }

    // ─── Server Session ──────────────────────────────────────────────────────
    asio::awaitable<void> detail::run_server_session(network::AnyStream stream, std::string leftover, options opts,
                                                     std::string subprotocol, const bool http3_tunnel,
                                                     handler_fn handler) {
        network::AnyStream transport = std::move(stream);
#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
        if (http3_tunnel) {
            transport = http::http3::make_data_tunnel(std::move(transport), std::move(leftover));
            leftover = std::string{};
        }
#else
        (void) http3_tunnel;
#endif
        auto conn = std::make_shared<connection>(std::move(transport), std::move(leftover), std::move(opts),
                                                 role::server, std::move(subprotocol));
        try {
            co_await handler(conn);
        } catch (const std::exception &e) {
            wavex::log::error("[WebSocket] Unhandled exception in session handler: {}", e.what());
            conn->close(close_code::internal_error);
        } catch (...) {
            wavex::log::error("[WebSocket] Unknown exception in session handler");
            conn->close(close_code::internal_error);
        }
        co_await conn->finish();
    }
} // namespace wavex::protos::websocket
