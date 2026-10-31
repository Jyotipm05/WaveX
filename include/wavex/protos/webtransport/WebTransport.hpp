// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * @file WebTransport.hpp
 * @brief WebTransport over HTTP/3 (draft-ietf-webtrans-http3, compatible with the draft-02 wire format that
 *        Chromium-based browsers speak).
 *
 * A session starts as an HTTP/3 extended CONNECT (`:protocol = webtransport`, RFC 9220) on a client
 * bidirectional stream; that stream's ID is the session ID. While the session lives:
 *  - client/server bidirectional streams start with the WT_STREAM signal (0x41) and the session ID;
 *  - unidirectional streams start with stream type 0x54 and the session ID;
 *  - datagrams are RFC 9297 HTTP datagrams (quarter session ID + payload) in RFC 9221 QUIC DATAGRAM frames;
 *  - the CONNECT stream itself carries capsules (RFC 9297): CLOSE_WEBTRANSPORT_SESSION and DRAIN.
 *
 * Integration points (no WebTransport code in the generic server):
 *  - `accept()` installs a takeover handler on the HTTP/3 response; `protocol_traits<http3codec>::
 *    wants_takeover` / `take_over` run it.
 *  - `dispatch_bidirectional_stream()` is called by the QUIC listeners before a client bidirectional stream is
 *    treated as an HTTP/3 request; `dispatch_unidirectional_stream()` by the HTTP/3 unidirectional stream handler.
 *  - Per-connection state lives in `http3::connection_context::webtransport` (QuicConnection::user_context()).
 */

#pragma once

#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL

#include <atomic>
#if defined(__MINGW32__) || defined(__clang__) || defined(__GNUC__)
#include <cstddef>
#endif
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <type_traits>
#include <unordered_map>
#include <utility>
#include <vector>

#ifndef ASIO_HAS_CO_AWAIT
#define ASIO_HAS_CO_AWAIT 1
#endif
#include <asio/any_io_executor.hpp>
#include <asio/awaitable.hpp>
#include <wavex/Base/Task.hpp>
#include <asio/buffer.hpp>
#include <asio/experimental/concurrent_channel.hpp>

#include <wavex/Network/AnyStream.hpp>
#include <wavex/protos/http/Methods.hpp>
#include <wavex/protos/http/http3codec.hpp>

namespace wavex::network::quic {
    class QuicConnection;
}

namespace wavex::protos::webtransport {
    // ─── Wire Constants ──────────────────────────────────────────────────────
    inline constexpr uint64_t kBidiStreamSignal = http::http3::WEBTRANSPORT_BIDI_SIGNAL;  ///< 0x41
    inline constexpr uint64_t kUniStreamType = static_cast<uint64_t>(http::http3::stream_type::WEBTRANSPORT_STREAM);
    inline constexpr uint64_t kCapsuleCloseSession = 0x2843;  ///< CLOSE_WEBTRANSPORT_SESSION
    inline constexpr uint64_t kCapsuleDrainSession = 0x78ae;  ///< DRAIN_WEBTRANSPORT_SESSION
    inline constexpr std::size_t kMaxCloseReasonBytes = 1024;
    inline constexpr std::string_view kProtocolToken = "webtransport";

    // ─── Errors ──────────────────────────────────────────────────────────────
    enum class error {
        session_closed = 1,  ///< the session ended (see session::close_code())
        stream_closed,       ///< the stream was closed or reset
        not_connected        ///< the QUIC connection is gone
    };

    [[nodiscard]] const std::error_category &error_category() noexcept;

    [[nodiscard]] std::error_code make_error_code(error e) noexcept;

    // ─── Capsules (RFC 9297 §3.2) ────────────────────────────────────────────
    namespace capsule {
        enum class parse_result { complete, incomplete, error };

        /// Decode one capsule from the front of `in`. `payload` views into `in`.
        [[nodiscard]] parse_result parse(std::string_view in, uint64_t &type, std::string_view &payload,
                                         std::size_t &consumed) noexcept;

        [[nodiscard]] std::string encode(uint64_t type, std::string_view payload);

        /// CLOSE_WEBTRANSPORT_SESSION: 32-bit application error code + UTF-8 reason (≤ 1024 bytes).
        [[nodiscard]] std::string encode_close_session(uint32_t code, std::string_view reason);

        [[nodiscard]] bool decode_close_session(std::string_view payload, uint32_t &code, std::string &reason);
    } // namespace capsule

    // ─── Options ─────────────────────────────────────────────────────────────
    struct options {
        // ─── 2. Member Variables ────────────────────────────────────────────
        std::size_t max_incoming_streams{256};    ///< queued, not yet accepted streams per direction
        std::size_t max_incoming_datagrams{512};  ///< queued, not yet received datagrams (excess is dropped)
    };

    class session;

    // ─── Stream ──────────────────────────────────────────────────────────────
    /**
     * @class stream
     * @brief A WebTransport stream (bidirectional or unidirectional) belonging to one session.
     *
     * Like any byte stream: a single reader, a single writer. `read_some` reports `asio::error::eof` once the
     * peer finished the stream. `finish()` sends FIN; `close()` abandons both directions.
     */
    class stream : public std::enable_shared_from_this<stream> {
    private:
        // ─── 2. Member Variables (minimum padding) ──────────────────────────
        std::shared_ptr<network::quic::QuicStream> quic_;
        std::string pending_;      ///< payload bytes read together with the stream header
        uint64_t session_id_{0};
        bool bidirectional_{true};
        bool incoming_{true};      ///< opened by the peer

    public:
        // ─── 3. Constructors & Destructor ───────────────────────────────────
        stream(std::shared_ptr<network::quic::QuicStream> quic, std::string pending, uint64_t session_id,
               bool bidirectional, bool incoming);

        ~stream();

        stream(const stream &) = delete;

        stream &operator=(const stream &) = delete;

        stream(stream &&) = delete;

        stream &operator=(stream &&) = delete;

        // ─── 4. Member Functions ────────────────────────────────────────────
        [[nodiscard]] uint64_t id() const noexcept;
        [[nodiscard]] uint64_t session_id() const noexcept { return session_id_; }
        [[nodiscard]] bool is_bidirectional() const noexcept { return bidirectional_; }
        [[nodiscard]] bool is_incoming() const noexcept { return incoming_; }
        [[nodiscard]] bool can_read() const noexcept { return bidirectional_ || incoming_; }
        [[nodiscard]] bool can_write() const noexcept { return bidirectional_ || !incoming_; }

        /// Read at least one byte; `{eof, 0}` once the peer finished the stream.
        [[nodiscard]] wavex::task<std::pair<std::error_code, std::size_t> > read_some(asio::mutable_buffer buffer);

        /// Read until the peer finishes the stream (or `max_bytes` would be exceeded → `message_size` error).
        [[nodiscard]] wavex::task<std::pair<std::error_code, std::string> > read_all(
            std::size_t max_bytes = 16 * 1024 * 1024);

        /// Write all of `data` (keep it alive until the awaitable completes).
        [[nodiscard]] wavex::task<std::error_code> write(std::string_view data);

        /// Send FIN: no more data in this direction.
        void finish() const noexcept;

        /// Abandon the stream in both directions.
        void close() noexcept;

        [[nodiscard]] const std::shared_ptr<network::quic::QuicStream> &native() const noexcept { return quic_; }
    };

    // ─── Session ─────────────────────────────────────────────────────────────
    /**
     * @class session
     * @brief One WebTransport session (draft-ietf-webtrans-http3).
     *
     * Incoming streams and datagrams are queued as they arrive (from the QUIC reactor thread) and handed out
     * by the `accept_*` / `receive_datagram` awaitables, which return empty once the session is closed.
     * Opening streams, sending datagrams and closing are thread-safe.
     */
    class session : public std::enable_shared_from_this<session> {
    public:
        // ─── 1. Nested Types ────────────────────────────────────────────────
        using stream_channel = asio::experimental::concurrent_channel<void(std::error_code, std::shared_ptr<stream>)>;
        using datagram_channel = asio::experimental::concurrent_channel<void(std::error_code, std::string)>;

    private:
        // ─── 2. Member Variables (minimum padding) ──────────────────────────
        std::shared_ptr<network::quic::QuicStream> connect_stream_;
        std::weak_ptr<network::quic::QuicConnection> conn_;
        std::weak_ptr<session_registry> registry_;
        network::AnyStream capsule_stream_;    ///< DATA-frame tunnel over the CONNECT stream
        asio::any_io_executor executor_;
        std::unique_ptr<stream_channel> incoming_bidi_;
        std::unique_ptr<stream_channel> incoming_uni_;
        std::unique_ptr<datagram_channel> datagrams_;
        mutable std::mutex mtx_;               ///< guards close_reason_ and streams_
        std::vector<std::weak_ptr<stream> > streams_;
        static constexpr std::size_t kMinSweepThreshold = 64;
        std::size_t streams_sweep_at_{kMinSweepThreshold}; ///< size at which streams_ is next swept for dead entries

        void track_stream(const std::shared_ptr<stream> &s);
        std::string close_reason_;
        std::string path_;
        std::string authority_;
        std::string origin_;
        uint64_t id_{0};
        std::atomic<uint32_t> close_code_{0};
        std::atomic<bool> closed_{false};
        std::atomic<bool> drain_requested_{false};

    public:
        // ─── 3. Constructors & Destructor ───────────────────────────────────
        session(uint64_t id, std::shared_ptr<network::quic::QuicStream> connect_stream,
                network::AnyStream capsule_stream, std::shared_ptr<network::quic::QuicConnection> conn,
                std::shared_ptr<session_registry> registry, const options &opts);

        ~session();

        session(const session &) = delete;

        session &operator=(const session &) = delete;

        session(session &&) = delete;

        session &operator=(session &&) = delete;

        // ─── 4. Member Functions ────────────────────────────────────────────
        /// The session ID: the stream ID of the CONNECT request.
        [[nodiscard]] uint64_t id() const noexcept { return id_; }

        /// Request target, authority and Origin of the CONNECT (set by accept()).
        [[nodiscard]] const std::string &path() const noexcept { return path_; }
        [[nodiscard]] const std::string &authority() const noexcept { return authority_; }
        [[nodiscard]] const std::string &origin() const noexcept { return origin_; }

        /// Next stream the peer opened, or nullptr once the session is closed.
        [[nodiscard]] wavex::task<std::shared_ptr<stream> > accept_bidirectional_stream();

        [[nodiscard]] wavex::task<std::shared_ptr<stream> > accept_unidirectional_stream();

        /// Open a server-initiated stream (nullptr if the session or connection is closed).
        [[nodiscard]] std::shared_ptr<stream> open_bidirectional_stream();

        [[nodiscard]] std::shared_ptr<stream> open_unidirectional_stream();

        /// Next datagram, or std::nullopt once the session is closed.
        [[nodiscard]] wavex::task<std::optional<std::string> > receive_datagram();

        /// Send an unreliable datagram (false if it cannot be sent: too large, not negotiated, closed).
        bool send_datagram(std::string_view payload) const;

        /// Largest datagram payload send_datagram() accepts right now.
        [[nodiscard]] std::size_t max_datagram_size() const noexcept;

        /// Terminate the session: CLOSE_WEBTRANSPORT_SESSION capsule, FIN on the CONNECT stream.
        void close(uint32_t code = 0, std::string_view reason = {});

        /// Ask the peer to wind the session down (DRAIN_WEBTRANSPORT_SESSION capsule).
        void drain() const;

        [[nodiscard]] bool is_closed() const noexcept { return closed_.load(std::memory_order_acquire); }
        [[nodiscard]] bool drain_requested() const noexcept { return drain_requested_.load(std::memory_order_acquire); }

        /// Application error code from the CLOSE capsule (0 when the session ended without one).
        [[nodiscard]] uint32_t close_code() const noexcept { return close_code_.load(std::memory_order_acquire); }

        [[nodiscard]] std::string close_reason() const;

        /// Streams the session still tracks for closing (live ones plus not-yet-swept dead entries). Diagnostics.
        [[nodiscard]] std::size_t tracked_stream_count() const;

        [[nodiscard]] asio::any_io_executor get_executor() const noexcept { return executor_; }

        // ─── Internal (registry / server plumbing) ──────────────────────────
        void set_request_info(std::string path, std::string authority, std::string origin);

        /// Hand an incoming stream to the application (called by the registry, any thread).
        void deliver_stream(std::shared_ptr<network::quic::QuicStream> quic, std::string pending, bool bidirectional);

        /// Hand an incoming datagram payload to the application (any thread).
        void deliver_datagram(std::string payload) const;

        /// Read capsules from the CONNECT stream until the session ends.
        [[nodiscard]] wavex::task<void> run_capsule_reader();

    private:
        /// Mark closed, wake all waiters, close the streams. `notify_peer` sends the CLOSE capsule + FIN.
        void terminate(uint32_t code, std::string_view reason, bool notify_peer);
    };

    // ─── Per-Connection Registry ─────────────────────────────────────────────
    /**
     * @class session_registry
     * @brief Maps session IDs to sessions for one QUIC connection and routes streams and datagrams.
     *
     * Streams that name a session which is not established yet (they may overtake the CONNECT response) are
     * buffered, up to kMaxPendingStreams per connection, and delivered when the session registers.
     */
    class session_registry : public std::enable_shared_from_this<session_registry> {
    public:
        // ─── 1. Nested Types ────────────────────────────────────────────────
        static constexpr std::size_t kMaxPendingStreams = 32;

        struct pending_stream {
            std::shared_ptr<network::quic::QuicStream> quic;
            std::string buffered;
            uint64_t session_id{0};
            bool bidirectional{true};
        };

    private:
        // ─── 2. Member Variables ────────────────────────────────────────────
        mutable std::mutex mtx_;
        std::unordered_map<uint64_t, std::weak_ptr<session> > sessions_;
        std::deque<pending_stream> pending_;
        std::weak_ptr<network::quic::QuicConnection> conn_;
        bool datagram_hook_installed_{false};

    public:
        // ─── 3. Constructors & Destructor ───────────────────────────────────
        session_registry() = default;

        ~session_registry() = default;

        session_registry(const session_registry &) = delete;

        session_registry &operator=(const session_registry &) = delete;

        // ─── 4. Member Functions ────────────────────────────────────────────
        /// Route the connection's DATAGRAM frames here (idempotent).
        void bind_connection(const std::shared_ptr<network::quic::QuicConnection> &conn);

        void add(const std::shared_ptr<session> &s);

        void remove(uint64_t session_id);

        [[nodiscard]] std::shared_ptr<session> find(uint64_t session_id) const;

        [[nodiscard]] std::size_t size() const;

        [[nodiscard]] std::size_t pending_count() const;

        void dispatch_stream(uint64_t session_id, std::shared_ptr<network::quic::QuicStream> quic,
                             std::string buffered, bool bidirectional);

        /// Parse an HTTP datagram (quarter stream ID + payload, RFC 9297 §2.1) and deliver it.
        void dispatch_datagram(std::string datagram) const;
    };

    /// The registry of the HTTP/3 connection context (created on first use).
    [[nodiscard]] std::shared_ptr<session_registry> registry_for(http::http3::connection_context &ctx);

    /// The HTTP/3 connection context of a QUIC connection (created on first use).
    [[nodiscard]] std::shared_ptr<http::http3::connection_context> http3_context_for(
        const std::shared_ptr<network::quic::QuicConnection> &conn);

    /**
     * @brief Classify a client-initiated bidirectional stream before it is treated as an HTTP/3 request.
     *
     * Reads the stream's first varint. If it is the WT_STREAM signal the stream is routed to its session and
     * true is returned. Otherwise the bytes are put back (QuicStream::unread) and false is returned: the caller
     * then serves the stream as an HTTP/3 request exactly as before.
     */
    [[nodiscard]] wavex::task<bool> dispatch_bidirectional_stream(std::shared_ptr<network::quic::QuicStream> s);

    // ─── Server Integration ──────────────────────────────────────────────────
    using handler_fn = std::function<wavex::task<void>(std::shared_ptr<session>)>;

    namespace detail {
        struct request_info {
            std::string path;
            std::string authority;
            std::string origin;
        };

        /// Runs a session once the 200 response is on the wire.
        [[nodiscard]] wavex::task<void> run_server_session(network::AnyStream connect_stream, std::string leftover,
                                                               options opts, request_info info, handler_fn handler);
    } // namespace detail

    /**
     * @brief Accept a WebTransport session request (HTTP/3 extended CONNECT, `:protocol = webtransport`).
     *
     * Answers `200` (adding `sec-webtransport-http3-draft: draft02` for draft-02 clients) and runs `handler`
     * with the session once the response is on the wire. When the handler returns the session is closed (code 0)
     * unless it already was. Anything else is answered 400 and false is returned.
     */
    template<typename Request, typename Response>
    bool accept(Request &req, Response &res, handler_fn handler, options opts = {}) {
        std::string_view proto;
        if constexpr (requires { req.connect_protocol(); }) proto = req.connect_protocol();
        if (req.version_major() != 3 || req.method_type() != http::method::CONNECT || proto != kProtocolToken ||
            !handler) {
            res.cancel_upgrade();
            res.status(400);
            res.send("WebTransport requires an HTTP/3 extended CONNECT with :protocol = webtransport");
            return false;
        }

        detail::request_info info;
        info.path = std::string(req.target());
        if constexpr (requires { req.raw().authority; }) info.authority = std::string(req.raw().authority);
        if (const auto origin = req.header("origin")) info.origin = std::string(*origin);

        res.status(200);
        if (req.header("sec-webtransport-http3-draft02")) {
            res.set("sec-webtransport-http3-draft", "draft02");
        }
        res.upgrade([handler = std::move(handler), opts, info = std::move(info)](
            network::AnyStream stream, std::string leftover) -> wavex::task<void> {
                co_await detail::run_server_session(std::move(stream), std::move(leftover), opts, info, handler);
            });
        res.send();
        return true;
    }
} // namespace wavex::protos::webtransport

template<>
struct std::is_error_code_enum<wavex::protos::webtransport::error> : std::true_type {
};

#endif // WAVEX_HAS_SSL
