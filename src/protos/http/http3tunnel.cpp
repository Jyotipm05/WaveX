// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * @file http3tunnel.cpp
 * @brief DATA-frame tunnel over an HTTP/3 extended CONNECT stream (RFC 9220 §3, RFC 9297 §3.1).
 */

#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL

#include <wavex/protos/http/http3tunnel.hpp>

#include <algorithm>
#if defined(__MINGW32__) || defined(__clang__) || defined(__GNUC__)
#include <cstring>
#endif
#include <memory>
#include <system_error>
#include <utility>

#include <wavex/Network/QUIC/VarInt.hpp>

namespace wavex::protos::http::http3 {
    namespace {
        using network::quic::VarInt;

        constexpr uint64_t kFrameData = 0x00;
        constexpr uint64_t kFrameHeaders = 0x01;

        /// Frames that may never appear on a request stream (RFC 9114 §7.2.3-7.2.7, §7.2.8).
        [[nodiscard]] constexpr bool is_forbidden_on_request_stream(const uint64_t type) noexcept {
            switch (type) {
                case 0x02: case 0x06: case 0x08: case 0x09: // reserved HTTP/2 types
                case 0x03: case 0x04: case 0x07: case 0x0d: // CANCEL_PUSH, SETTINGS, GOAWAY, MAX_PUSH_ID
                    return true;
                default:
                    return false;
            }
        }

        struct tunnel_state {
            // ─── 2. Member Variables (minimum padding) ──────────────────────
            network::AnyStream inner;
            std::string raw;                 ///< received frame bytes not yet consumed
            std::size_t offset{0};           ///< consumed prefix of `raw`
            uint64_t data_remaining{0};      ///< payload bytes left in the current DATA frame
            uint64_t skip_remaining{0};      ///< bytes left of a frame being skipped
            bool in_data{false};
            bool finished{false};            ///< trailing HEADERS seen: the data stream ended

            tunnel_state(network::AnyStream s, std::string leftover)
                : inner(std::move(s)), raw(std::move(leftover)) {
            }

            [[nodiscard]] std::size_t available() const noexcept { return raw.size() - offset; }

            void compact() {
                if (offset == raw.size()) {
                    raw.clear();
                    offset = 0;
                } else if (offset >= 16384 && offset >= raw.size() / 2) {
                    raw.erase(0, offset);
                    offset = 0;
                }
            }
        };

        asio::awaitable<network::AnyStream::read_result> tunnel_read_some(std::shared_ptr<tunnel_state> st,
                                                                         const asio::mutable_buffer out) {
            if (out.size() == 0) co_return network::AnyStream::read_result{std::error_code{}, 0};

            for (;;) {
                // 1. Skip the rest of an unknown frame.
                if (st->skip_remaining > 0 && st->available() > 0) {
                    const auto n = static_cast<std::size_t>(
                        (std::min)(st->skip_remaining, static_cast<uint64_t>(st->available())));
                    st->offset += n;
                    st->skip_remaining -= n;
                    st->compact();
                    continue;
                }

                // 2. Hand out DATA payload bytes.
                if (st->in_data && st->available() > 0) {
                    const auto n = static_cast<std::size_t>((std::min)({
                        static_cast<uint64_t>(out.size()), st->data_remaining, static_cast<uint64_t>(st->available())
                    }));
                    std::memcpy(out.data(), st->raw.data() + st->offset, n);
                    st->offset += n;
                    st->data_remaining -= n;
                    if (st->data_remaining == 0) st->in_data = false;
                    st->compact();
                    co_return network::AnyStream::read_result{std::error_code{}, n};
                }

                // 3. Decode the next frame header.
                if (!st->in_data && st->skip_remaining == 0 && st->available() > 0 && !st->finished) {
                    const std::string_view view(st->raw.data() + st->offset, st->available());
                    std::size_t cursor = 0;
                    uint64_t type = 0;
                    uint64_t length = 0;
                    if (VarInt::decode(view, cursor, type) && VarInt::decode(view, cursor, length)) {
                        st->offset += cursor;
                        if (type == kFrameData) {
                            st->in_data = length > 0;
                            st->data_remaining = length;
                        } else if (type == kFrameHeaders) {
                            st->finished = true; // trailers: the tunnel's data stream is over
                        } else if (is_forbidden_on_request_stream(type)) {
                            co_return network::AnyStream::read_result{
                                std::make_error_code(std::errc::protocol_error), 0
                            };
                        } else {
                            st->skip_remaining = length; // RFC 9114 §9: ignore unknown frame types
                        }
                        st->compact();
                        continue;
                    }
                    // A partial header: fall through and read more.
                }

                if (st->finished) {
                    co_return network::AnyStream::read_result{asio::error::eof, 0};
                }

                // 4. Need more bytes from the request stream.
                char buf[16384];
                auto [ec, n] = co_await st->inner.read_some(asio::buffer(buf));
                if (n > 0) st->raw.append(buf, n);
                if (ec) {
                    if (n > 0) continue; // deliver what arrived first; the error repeats on the next read
                    co_return network::AnyStream::read_result{ec, 0};
                }
                if (n == 0) {
                    co_return network::AnyStream::read_result{asio::error::eof, 0};
                }
            }
        }

        asio::awaitable<std::error_code> tunnel_write(std::shared_ptr<tunnel_state> st, const asio::const_buffer in) {
            // The frame lives in this coroutine frame until the inner write completes.
            const std::string frame = encode_tunnel_data_frame(
                std::string_view(static_cast<const char *>(in.data()), in.size()));
            co_return co_await st->inner.write(asio::buffer(frame));
        }
    } // namespace

    std::string encode_tunnel_data_frame(const std::string_view payload) {
        std::string frame;
        frame.reserve(payload.size() + 16);
        VarInt::encode(kFrameData, frame);
        VarInt::encode(payload.size(), frame);
        frame.append(payload);
        return frame;
    }

    network::AnyStream make_data_tunnel(network::AnyStream inner, std::string leftover) {
        auto ops = std::make_shared<network::AnyStream::operations>();
        if (const auto &inner_ops = inner.ops()) {
            ops->native = inner_ops->native;
            ops->native_type = inner_ops->native_type;
        }
        ops->executor = inner.get_executor();
        ops->shutdown_send = [inner] { inner.shutdown_send(); };
        ops->cancel = [inner] { inner.cancel(); };
        ops->close = [inner] { inner.close(); };

        auto st = std::make_shared<tunnel_state>(std::move(inner), std::move(leftover));
        ops->read_some = [st](const asio::mutable_buffer &b) { return tunnel_read_some(st, b); };
        ops->write = [st](const asio::const_buffer &b) { return tunnel_write(st, b); };
        return network::AnyStream(std::move(ops));
    }
} // namespace wavex::protos::http::http3

#endif // WAVEX_HAS_SSL
