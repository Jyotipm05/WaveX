// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * @file WebSocket.hpp
 * @brief WebSocket protocol (RFC 6455) over HTTP/1.1 Upgrade, and over the extended CONNECT of HTTP/2
 *        (RFC 8441) and HTTP/3 (RFC 9220).
 *
 * Layering (see .agents/rules/websocket-takeover-http2-session.md §C):
 *  - `codec`           — frame header parsing / encoding, masking, close payloads. Pure, allocation-light.
 *  - `connection`      — one WebSocket session over a type-erased `network::AnyStream`: message reassembly,
 *                        control frames, the close handshake, UTF-8 validation and a thread-safe send queue.
 *  - `accept()`        — validates the opening handshake on any `HttpRequest`/`HttpResponse`, answers
 *                        `101 Switching Protocols` (HTTP/1.1) or `200` (HTTP/2, HTTP/3), and installs a takeover
 *                        handler on the response. The generic server never names WebSocket: it reaches the
 *                        handler only through `protocol_traits<Codec>::wants_takeover` / `take_over`.
 *
 * Non-template implementations live in src/protos/websocket/WebSocket.cpp (MSVC C1001 mitigation).
 */

#pragma once

#include <atomic>
#include <chrono>
#if defined(__MINGW32__) || defined(__clang__) || defined(__GNUC__)
#include <cstddef>
#endif
#include <cstdint>
#include <deque>
#include <expected>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <type_traits>
#include <utility>
#include <vector>

#ifndef ASIO_HAS_CO_AWAIT
#define ASIO_HAS_CO_AWAIT 1
#endif
#include <asio/any_io_executor.hpp>
#include <asio/awaitable.hpp>

#include <wavex/Network/AnyStream.hpp>
#include <wavex/protos/http/Methods.hpp>

namespace wavex::protos::websocket {
    /// RFC 6455 §1.3: the GUID concatenated with Sec-WebSocket-Key before hashing.
    inline constexpr std::string_view kHandshakeGuid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

    /// The only protocol version defined by RFC 6455 (Sec-WebSocket-Version).
    inline constexpr std::string_view kProtocolVersion = "13";

    // ─── Opcodes (RFC 6455 §5.2) ─────────────────────────────────────────────
    enum class opcode : uint8_t {
        continuation = 0x0,
        text = 0x1,
        binary = 0x2,
        close = 0x8,
        ping = 0x9,
        pong = 0xA
    };

    [[nodiscard]] constexpr bool is_control(const opcode op) noexcept {
        return (static_cast<uint8_t>(op) & 0x08) != 0;
    }

    // ─── Close Status Codes (RFC 6455 §7.4.1) ────────────────────────────────
    namespace close_code {
        inline constexpr uint16_t normal = 1000;
        inline constexpr uint16_t going_away = 1001;
        inline constexpr uint16_t protocol_error = 1002;
        inline constexpr uint16_t unsupported_data = 1003;
        inline constexpr uint16_t no_status = 1005;       ///< never sent on the wire
        inline constexpr uint16_t abnormal = 1006;        ///< never sent on the wire
        inline constexpr uint16_t invalid_payload = 1007;
        inline constexpr uint16_t policy_violation = 1008;
        inline constexpr uint16_t message_too_big = 1009;
        inline constexpr uint16_t mandatory_extension = 1010;
        inline constexpr uint16_t internal_error = 1011;
    } // namespace close_code

    /// Which side of the connection this endpoint is. Servers require masked frames; clients mask theirs.
    enum class role : uint8_t { server, client };

    // ─── Errors ──────────────────────────────────────────────────────────────
    enum class error {
        closed = 1,        ///< the close handshake completed (or the peer closed); see connection::close_code()
        protocol_error,    ///< the peer violated RFC 6455; a 1002 close was sent
        message_too_big,   ///< a message exceeded options::max_message_size; a 1009 close was sent
        invalid_utf8,      ///< a text message or close reason was not UTF-8; a 1007 close was sent
        read_timeout       ///< nothing arrived within options::read_timeout
    };

    [[nodiscard]] const std::error_category &error_category() noexcept;

    [[nodiscard]] std::error_code make_error_code(error e) noexcept;

    // ─── Frame Codec (RFC 6455 §5.2) ─────────────────────────────────────────
    struct frame_header {
        // ─── 2. Member Variables (minimum padding) ──────────────────────────
        uint64_t payload_length{0};
        uint32_t masking_key{0};
        uint8_t header_size{0}; ///< bytes occupied by the header, including the masking key
        opcode op{opcode::continuation};
        bool fin{false};
        bool rsv1{false};
        bool rsv2{false};
        bool rsv3{false};
        bool masked{false};
    };

    enum class parse_result { complete, incomplete, error };

    class codec {
    public:
        /// Largest payload a single frame may announce (RFC 6455 §5.2: the MSB of the 64-bit length must be 0).
        static constexpr uint64_t kMaxPayloadLength = (uint64_t{1} << 63) - 1;

        /// Decode a frame header from the front of `in`. Does not require the payload to be present.
        [[nodiscard]] static parse_result parse_header(std::string_view in, frame_header &hdr) noexcept;

        /// Append one encoded frame. `mask` is required for client-to-server frames (RFC 6455 §5.3).
        static void encode_frame(std::string &out, opcode op, std::string_view payload, bool fin = true,
                                 std::optional<uint32_t> mask = std::nullopt);

        /// XOR `len` bytes with the 4-byte masking key, starting `offset` bytes into the key cycle.
        static void apply_mask(char *data, std::size_t len, uint32_t key, std::size_t offset = 0) noexcept;

        /// Build a close frame payload: 2-byte status code followed by an optional UTF-8 reason (≤ 123 bytes).
        [[nodiscard]] static std::string close_payload(uint16_t code, std::string_view reason = {});

        /// Validate and decode a received close payload. An empty payload yields code 1005 (no status).
        [[nodiscard]] static bool parse_close_payload(std::string_view payload, uint16_t &code, std::string &reason);

        /// RFC 6455 §7.4: whether a status code may appear in a close frame on the wire.
        [[nodiscard]] static bool is_valid_close_code(uint16_t code) noexcept;
    };

    // ─── Handshake Helpers (RFC 6455 §4) ─────────────────────────────────────

    /// base64(SHA-1(key + GUID)) — the Sec-WebSocket-Accept value for a Sec-WebSocket-Key.
    [[nodiscard]] std::string compute_accept_key(std::string_view client_key);

    /// A Sec-WebSocket-Key must be base64 for exactly 16 bytes (RFC 6455 §4.1).
    [[nodiscard]] bool is_valid_client_key(std::string_view client_key) noexcept;

    /// A fresh random Sec-WebSocket-Key (for clients and tests).
    [[nodiscard]] std::string generate_client_key();

    /// Case-insensitive search of a comma-separated header value for `token` (e.g. Connection: keep-alive, Upgrade).
    [[nodiscard]] bool header_contains_token(std::string_view header_value, std::string_view token) noexcept;

    /// Strict UTF-8 validation (no overlongs, no surrogates, ≤ U+10FFFF), as RFC 6455 §8.1 requires for text.
    [[nodiscard]] bool is_valid_utf8(std::string_view s) noexcept;

    namespace detail {
        [[nodiscard]] std::string base64_encode(std::string_view in);

        [[nodiscard]] std::optional<std::string> base64_decode(std::string_view in);

        /// FIPS 180-4 SHA-1 (self-contained so WebSocket works in builds without OpenSSL).
        [[nodiscard]] std::string sha1(std::string_view in);
    } // namespace detail

    // ─── Session ─────────────────────────────────────────────────────────────
    struct options {
        // ─── 2. Member Variables (minimum padding) ──────────────────────────
        std::vector<std::string> subprotocols{};               ///< server preference order
        std::size_t max_message_size{16 * 1024 * 1024};       ///< 1009 beyond this (whole reassembled message)
        std::size_t max_buffered_amount{64 * 1024 * 1024};    ///< sends fail while this much is queued
        std::chrono::milliseconds read_timeout{0};             ///< 0 = wait forever
        std::chrono::milliseconds close_timeout{5000};         ///< how long the close handshake may take
        bool validate_utf8{true};
    };

    struct message {
        // ─── 2. Member Variables ────────────────────────────────────────────
        std::string data{};
        opcode type{opcode::text};

        // ─── 4. Member Functions ────────────────────────────────────────────
        [[nodiscard]] bool is_text() const noexcept { return type == opcode::text; }
        [[nodiscard]] bool is_binary() const noexcept { return type == opcode::binary; }
    };

    /**
     * @class connection
     * @brief One WebSocket session.
     *
     * Reading is single-consumer: only one coroutine may `co_await read()` at a time; it must run on the
     * connection's executor (the coroutine the server hands the session to already does). Ping frames are
     * answered automatically, fragmented messages are reassembled and the close handshake is completed inside
     * `read()`.
     *
     * Sending is thread-safe and non-blocking: `send_text`/`send_binary`/`ping`/`close` queue a frame and
     * return immediately; a writer coroutine on the connection's executor drains the queue in order. This is
     * what makes broadcasting from other connections (other worker threads) safe.
     */
    class connection : public std::enable_shared_from_this<connection> {
    private:
        // ─── 2. Member Variables (minimum padding) ──────────────────────────
        network::AnyStream stream_;
        asio::any_io_executor executor_;
        options opts_;
        std::string rbuf_;                 ///< raw bytes received but not yet parsed
        std::string message_;              ///< fragments of the message being reassembled
        std::string subprotocol_;
        std::string close_reason_;
        mutable std::mutex write_mtx_;     ///< guards outbox_, buffered_, writer_active_, write_failed_
        std::deque<std::string> outbox_;
        std::size_t rbuf_consumed_{0};
        std::size_t buffered_{0};
        std::atomic<uint16_t> close_code_{close_code::no_status};
        opcode message_type_{opcode::text};
        role role_{role::server};
        bool in_message_{false};
        bool writer_active_{false};
        bool write_failed_{false};
        std::atomic<bool> close_sent_{false};
        std::atomic<bool> close_received_{false};
        std::atomic<bool> read_closed_{false};

    public:
        // ─── 3. Constructors & Destructor ───────────────────────────────────
        /**
         * @param stream      Transport after the opening handshake.
         * @param leftover    Bytes already read from the transport past the handshake (start of the first frame).
         * @param opts        Session limits.
         * @param r           Endpoint role (decides masking rules).
         * @param subprotocol Negotiated Sec-WebSocket-Protocol, if any.
         */
        connection(network::AnyStream stream, std::string leftover, options opts = {},
                   role r = role::server, std::string subprotocol = {});

        ~connection();

        connection(const connection &) = delete;

        connection &operator=(const connection &) = delete;

        connection(connection &&) = delete;

        connection &operator=(connection &&) = delete;

        // ─── 4. Member Functions ────────────────────────────────────────────

        /// Next complete data message. Fails with `error::closed` once the close handshake is done.
        [[nodiscard]] asio::awaitable<std::expected<message, std::error_code> > read();

        /// Queue a text message (must be valid UTF-8). Returns false if the connection can no longer send.
        bool send_text(std::string_view text);

        /// Queue a binary message.
        bool send_binary(std::string_view data);

        /// Queue a message of either type.
        bool send(const message &msg) {
            return msg.is_binary() ? send_binary(msg.data) : send_text(msg.data);
        }

        /// Queue a ping (payload ≤ 125 bytes).
        bool ping(std::string_view payload = {});

        /// Queue an unsolicited pong (payload ≤ 125 bytes).
        bool pong(std::string_view payload = {});

        /// Start the close handshake. Further sends fail; `read()` keeps returning data until the peer's close.
        bool close(uint16_t code = close_code::normal, std::string_view reason = {});

        /**
         * @brief Finish the session: close (1000) if not yet closing, wait for queued frames to be written and,
         *        within options::close_timeout, for the peer's close. The server calls this after the
         *        application's handler returns; applications may call it to end a session early.
         */
        [[nodiscard]] asio::awaitable<void> finish();

        /// Abort without a close handshake (closes the transport).
        void abort() noexcept;

        [[nodiscard]] bool is_open() const noexcept {
            return !close_sent_.load(std::memory_order_acquire) && !read_closed_.load(std::memory_order_acquire);
        }

        [[nodiscard]] bool close_sent() const noexcept { return close_sent_.load(std::memory_order_acquire); }
        [[nodiscard]] bool close_received() const noexcept { return close_received_.load(std::memory_order_acquire); }

        /// Status code of the peer's close frame (1005 if it carried none, 1006 if the transport just dropped).
        [[nodiscard]] uint16_t close_code() const noexcept { return close_code_.load(std::memory_order_acquire); }

        /// Reason of the peer's close frame. Read it from the reading coroutine once read() reported `closed`.
        [[nodiscard]] const std::string &close_reason() const noexcept { return close_reason_; }

        [[nodiscard]] const std::string &subprotocol() const noexcept { return subprotocol_; }
        [[nodiscard]] role endpoint_role() const noexcept { return role_; }
        [[nodiscard]] asio::any_io_executor get_executor() const noexcept { return executor_; }
        [[nodiscard]] const network::AnyStream &transport() const noexcept { return stream_; }

        /// Bytes queued for sending but not yet handed to the transport.
        [[nodiscard]] std::size_t buffered_amount() const noexcept;

    private:
        bool enqueue(opcode op, std::string_view payload, bool is_close = false);

        [[nodiscard]] asio::awaitable<void> drain();

        /// Send a close with `code` (if none was sent) and stop reading; returns `err` for read().
        std::error_code fail(uint16_t code, error err);

        [[nodiscard]] asio::awaitable<std::error_code> fill(std::chrono::milliseconds timeout);

        [[nodiscard]] bool writes_pending() const noexcept;
    };

    using handler_fn = std::function<asio::awaitable<void>(std::shared_ptr<connection>)>;

    namespace detail {
        /// Pick the first subprotocol the server supports from the client's comma-separated offer.
        [[nodiscard]] std::string select_subprotocol(std::string_view offered, const std::vector<std::string> &supported);

        /// Runs a server session: wraps the transport, calls the application, completes the close handshake.
        [[nodiscard]] asio::awaitable<void> run_server_session(network::AnyStream stream, std::string leftover,
                                                               options opts, std::string subprotocol,
                                                               bool http3_tunnel, handler_fn handler);

        template<typename Response>
        void reject(Response &res, const unsigned status, const std::string_view text) {
            res.cancel_upgrade();
            res.status(status);
            res.send(text);
        }
    } // namespace detail

    /**
     * @brief Validate a WebSocket opening handshake and switch the connection to WebSocket.
     *
     * HTTP/1.1 (RFC 6455 §4.2): requires `GET`, `Upgrade: websocket`, `Connection: Upgrade`,
     * `Sec-WebSocket-Version: 13` and a valid `Sec-WebSocket-Key`; answers `101 Switching Protocols`.
     * HTTP/2 (RFC 8441) and HTTP/3 (RFC 9220): requires an extended CONNECT with `:protocol = websocket`;
     * answers `200` and the stream becomes the WebSocket's byte stream (DATA frames).
     *
     * On failure the response is filled with the error (400 / 426 / 501) and false is returned. On success the
     * handler runs once the response is on the wire; it may keep using `req` until it returns.
     */
    template<typename Request, typename Response>
    bool accept(Request &req, Response &res, handler_fn handler, options opts = {}) {
        if (!handler) {
            detail::reject(res, 500, "WebSocket handler missing");
            return false;
        }
        const auto version = req.version_major();
        const auto header = [&req](const std::string_view name) -> std::string_view {
            const auto v = req.header(name);
            return v ? std::string_view(*v) : std::string_view{};
        };

        if (version == 1) {
            if (req.method_type() != http::method::GET || req.version_minor() < 1) {
                detail::reject(res, 400, "WebSocket handshake requires GET over HTTP/1.1");
                return false;
            }
            if (!header_contains_token(header("Upgrade"), "websocket") ||
                !header_contains_token(header("Connection"), "upgrade")) {
                res.set("Upgrade", "websocket");
                res.set("Connection", "Upgrade");
                detail::reject(res, 426, "WebSocket upgrade required");
                return false;
            }
        } else if (version == 2 || version == 3) {
            std::string_view proto;
            if constexpr (requires { req.connect_protocol(); }) proto = req.connect_protocol();
            if (req.method_type() != http::method::CONNECT || proto != "websocket") {
                detail::reject(res, 400, "WebSocket over HTTP/2 or HTTP/3 requires an extended CONNECT "
                                         "with :protocol = websocket (RFC 8441, RFC 9220)");
                return false;
            }
#if !(defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL)
            if (version == 3) {
                detail::reject(res, 501, "HTTP/3 is not available in this build");
                return false;
            }
#endif
        } else {
            detail::reject(res, 501, "Unsupported HTTP version for WebSocket");
            return false;
        }

        if (header("Sec-WebSocket-Version") != kProtocolVersion) {
            res.set(version >= 2 ? "sec-websocket-version" : "Sec-WebSocket-Version", kProtocolVersion);
            detail::reject(res, version >= 2 ? 400 : 426, "Unsupported Sec-WebSocket-Version");
            return false;
        }

        std::string subprotocol;
        if (const auto offered = header("Sec-WebSocket-Protocol"); !offered.empty() && !opts.subprotocols.empty()) {
            subprotocol = detail::select_subprotocol(offered, opts.subprotocols);
        }

        if (version == 1) {
            const auto key = header("Sec-WebSocket-Key");
            if (!is_valid_client_key(key)) {
                detail::reject(res, 400, "Invalid Sec-WebSocket-Key");
                return false;
            }
            res.status(101);
            res.set("Upgrade", "websocket");
            res.set("Connection", "Upgrade");
            res.set("Sec-WebSocket-Accept", compute_accept_key(key));
            if (!subprotocol.empty()) res.set("Sec-WebSocket-Protocol", subprotocol);
        } else {
            // HTTP/2 and HTTP/3 field names are lowercase. No key / accept exchange (RFC 8441 §5, RFC 9220 §3).
            res.status(200);
            if (!subprotocol.empty()) res.set("sec-websocket-protocol", subprotocol);
        }

        // HTTP/3 carries the bytes in DATA frames on a QUIC stream, which the session unwraps; the HTTP/2
        // session hands over an already de-framed stream.
        const bool tunnel = (version == 3);
        res.upgrade([handler = std::move(handler), opts = std::move(opts), subprotocol, tunnel](
            network::AnyStream stream, std::string leftover) -> asio::awaitable<void> {
                // Delegate to a plain function: the closure's captures stay in this lambda object (owned by
                // the server for the duration of the call) and are copied into that coroutine's frame.
                co_await detail::run_server_session(std::move(stream), std::move(leftover), opts, subprotocol,
                                                    tunnel, handler);
            });
        res.send();
        return true;
    }
} // namespace wavex::protos::websocket

template<>
struct std::is_error_code_enum<wavex::protos::websocket::error> : std::true_type {
};
