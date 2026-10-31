// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * @file WebTransport.cpp
 * @brief WebTransport over HTTP/3: sessions, streams, datagrams, capsules and stream demultiplexing.
 */

#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL

#include <wavex/protos/webtransport/WebTransport.hpp>

#include <algorithm>
#if defined(__MINGW32__) || defined(__clang__) || defined(__GNUC__)
#include <cstring>
#endif
#include <limits>

#include <asio/as_tuple.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/write.hpp>

#include <wavex/Base/Logger.hpp>
#include <wavex/Network/QUIC/QuicConnection.hpp>
#include <wavex/Network/QUIC/QuicStream.hpp>
#include <wavex/Network/QUIC/VarInt.hpp>
#include <wavex/protos/http/http3tunnel.hpp>

namespace wavex::protos::webtransport {
    using network::quic::QuicConnection;
    using network::quic::QuicStream;
    using network::quic::VarInt;

    // ─── Errors ──────────────────────────────────────────────────────────────
    namespace {
        class webtransport_category final : public std::error_category {
        public:
            [[nodiscard]] const char *name() const noexcept override { return "wavex.webtransport"; }

            [[nodiscard]] std::string message(const int ev) const override {
                switch (static_cast<error>(ev)) {
                    case error::session_closed: return "WebTransport session closed";
                    case error::stream_closed: return "WebTransport stream closed";
                    case error::not_connected: return "QUIC connection is gone";
                }
                return "unknown WebTransport error";
            }
        };

        /// Largest prefix of `s` (≤ max bytes) that does not split a UTF-8 sequence.
        [[nodiscard]] std::string_view utf8_prefix(const std::string_view s, const std::size_t max) noexcept {
            if (s.size() <= max) return s;
            std::size_t cut = max;
            while (cut > 0 && (static_cast<unsigned char>(s[cut]) & 0xC0) == 0x80) --cut;
            return s.substr(0, cut);
        }

        /// Client-initiated bidirectional stream IDs are the only valid session IDs.
        [[nodiscard]] constexpr bool is_valid_session_id(const uint64_t id) noexcept {
            return (id & 0x03) == 0x00;
        }

        /// Read more bytes from a QUIC stream into `buf`. Returns false on EOF / error.
        wavex::task<bool> read_more(const std::shared_ptr<QuicStream> &s, std::string &buf) {
            char tmp[4096];
            auto [ec, n] = co_await s->async_read_some(asio::buffer(tmp), asio::as_tuple(asio::use_awaitable));
            if (n > 0) buf.append(tmp, n);
            co_return !ec && n > 0;
        }
    } // namespace

    const std::error_category &error_category() noexcept {
        static const webtransport_category category;
        return category;
    }

    std::error_code make_error_code(const error e) noexcept {
        return {static_cast<int>(e), error_category()};
    }

    // ─── Capsules ────────────────────────────────────────────────────────────
    namespace capsule {
        parse_result parse(const std::string_view in, uint64_t &type, std::string_view &payload,
                           std::size_t &consumed) noexcept {
            consumed = 0;
            std::size_t cursor = 0;
            uint64_t length = 0;
            if (!VarInt::decode(in, cursor, type)) return parse_result::incomplete;
            if (!VarInt::decode(in, cursor, length)) return parse_result::incomplete;
            if (length > in.size() - cursor) return parse_result::incomplete;
            payload = in.substr(cursor, static_cast<std::size_t>(length));
            consumed = cursor + static_cast<std::size_t>(length);
            return parse_result::complete;
        }

        std::string encode(const uint64_t type, const std::string_view payload) {
            std::string out;
            out.reserve(payload.size() + 16);
            VarInt::encode(type, out);
            VarInt::encode(payload.size(), out);
            out.append(payload);
            return out;
        }

        std::string encode_close_session(const uint32_t code, const std::string_view reason) {
            const auto r = utf8_prefix(reason, kMaxCloseReasonBytes);
            std::string payload;
            payload.reserve(4 + r.size());
            payload.push_back(static_cast<char>((code >> 24) & 0xFF));
            payload.push_back(static_cast<char>((code >> 16) & 0xFF));
            payload.push_back(static_cast<char>((code >> 8) & 0xFF));
            payload.push_back(static_cast<char>(code & 0xFF));
            payload.append(r);
            return encode(kCapsuleCloseSession, payload);
        }

        bool decode_close_session(const std::string_view payload, uint32_t &code, std::string &reason) {
            if (payload.size() < 4 || payload.size() - 4 > kMaxCloseReasonBytes) return false;
            code = (static_cast<uint32_t>(static_cast<uint8_t>(payload[0])) << 24) |
                   (static_cast<uint32_t>(static_cast<uint8_t>(payload[1])) << 16) |
                   (static_cast<uint32_t>(static_cast<uint8_t>(payload[2])) << 8) |
                   static_cast<uint32_t>(static_cast<uint8_t>(payload[3]));
            reason.assign(payload.substr(4));
            return true;
        }
    } // namespace capsule

    // ─── Stream ──────────────────────────────────────────────────────────────
    stream::stream(std::shared_ptr<QuicStream> quic, std::string pending, const uint64_t session_id,
                   const bool bidirectional, const bool incoming)
        : quic_(std::move(quic)),
          pending_(std::move(pending)),
          session_id_(session_id),
          bidirectional_(bidirectional),
          incoming_(incoming) {
    }

    stream::~stream() = default;

    uint64_t stream::id() const noexcept {
        return quic_ ? quic_->stream_id() : 0;
    }

    wavex::task<std::pair<std::error_code, std::size_t> > stream::read_some(const asio::mutable_buffer buffer) {
        auto self = shared_from_this();
        if (!can_read() || !quic_) {
            co_return std::pair{make_error_code(error::stream_closed), std::size_t{0}};
        }
        if (buffer.size() == 0) co_return std::pair{std::error_code{}, std::size_t{0}};
        if (!pending_.empty()) {
            const std::size_t n = (std::min)(buffer.size(), pending_.size());
            std::memcpy(buffer.data(), pending_.data(), n);
            pending_.erase(0, n);
            co_return std::pair{std::error_code{}, n};
        }
        for (;;) {
            auto [ec, n] = co_await quic_->async_read_some(buffer, asio::as_tuple(asio::use_awaitable));
            if (ec || n > 0) co_return std::pair{ec, n};
            if (quic_->is_fin_received() || !quic_->is_open()) {
                co_return std::pair{std::error_code(asio::error::eof), std::size_t{0}};
            }
        }
    }

    wavex::task<std::pair<std::error_code, std::string> > stream::read_all(const std::size_t max_bytes) {
        auto self = shared_from_this();
        std::string out;
        char buf[8192];
        for (;;) {
            auto [ec, n] = co_await read_some(asio::buffer(buf));
            if (n > 0) {
                if (out.size() + n > max_bytes) {
                    co_return std::pair{std::make_error_code(std::errc::message_size), std::move(out)};
                }
                out.append(buf, n);
            }
            if (ec == asio::error::eof) co_return std::pair{std::error_code{}, std::move(out)};
            if (ec) co_return std::pair{ec, std::move(out)};
        }
    }

    wavex::task<std::error_code> stream::write(const std::string_view data) {
        auto self = shared_from_this();
        if (!can_write() || !quic_) co_return make_error_code(error::stream_closed);
        auto [ec, n] = co_await asio::async_write(*quic_, asio::buffer(data), asio::as_tuple(asio::use_awaitable));
        (void) n;
        co_return ec;
    }

    void stream::finish() const noexcept {
        if (!quic_ || !can_write()) return;
        std::error_code ec;
        std::ignore = quic_->shutdown(asio::ip::tcp::socket::shutdown_send, ec);
    }

    void stream::close() noexcept {
        pending_.clear();
        // A peer-initiated unidirectional stream is receive-only: sending FIN on it would be a
        // STREAM_STATE_ERROR (RFC 9000 §19.8), so only streams we can write to are closed on the wire.
        if (quic_ && can_write()) quic_->close();
    }

    // ─── Session ─────────────────────────────────────────────────────────────
    session::session(const uint64_t id, std::shared_ptr<QuicStream> connect_stream, network::AnyStream capsule_stream,
                     // ReSharper disable once CppPassValueParameterByConstReference
                     std::shared_ptr<QuicConnection> conn,
                     // ReSharper disable once CppPassValueParameterByConstReference
                     std::shared_ptr<session_registry> registry,
                     const options &opts)
        : connect_stream_(std::move(connect_stream)),
          conn_(conn),
          registry_(registry),
          capsule_stream_(std::move(capsule_stream)),
          executor_(capsule_stream_.get_executor()),
          incoming_bidi_(std::make_unique<stream_channel>(executor_, opts.max_incoming_streams)),
          incoming_uni_(std::make_unique<stream_channel>(executor_, opts.max_incoming_streams)),
          datagrams_(std::make_unique<datagram_channel>(executor_, opts.max_incoming_datagrams)),
          id_(id) {
    }

    session::~session() {
        // Owned channels may still have queued streams; close them so nothing keeps waiting.
        incoming_bidi_->close();
        incoming_uni_->close();
        datagrams_->close();
    }

    void session::set_request_info(std::string path, std::string authority, std::string origin) {
        path_ = std::move(path);
        authority_ = std::move(authority);
        origin_ = std::move(origin);
    }

    std::string session::close_reason() const {
        std::lock_guard lock(mtx_);
        return close_reason_;
    }

    wavex::task<std::shared_ptr<stream> > session::accept_bidirectional_stream() {
        auto self = shared_from_this();
        auto [ec, s] = co_await incoming_bidi_->async_receive(asio::as_tuple(asio::use_awaitable));
        if (ec) co_return nullptr;
        co_return s;
    }

    wavex::task<std::shared_ptr<stream> > session::accept_unidirectional_stream() {
        auto self = shared_from_this();
        auto [ec, s] = co_await incoming_uni_->async_receive(asio::as_tuple(asio::use_awaitable));
        if (ec) co_return nullptr;
        co_return s;
    }

    wavex::task<std::optional<std::string> > session::receive_datagram() {
        auto self = shared_from_this();
        auto [ec, d] = co_await datagrams_->async_receive(asio::as_tuple(asio::use_awaitable));
        if (ec) co_return std::nullopt;
        co_return std::optional<std::string>(std::move(d));
    }

    std::shared_ptr<stream> session::open_bidirectional_stream() {
        if (is_closed()) return nullptr;
        const auto conn = conn_.lock();
        if (!conn) return nullptr;
        auto quic = conn->create_stream(true);
        std::string header;
        VarInt::encode(kBidiStreamSignal, header);
        VarInt::encode(id_, header);
        std::ignore = quic->write_outbound(header, false);
        auto s = std::make_shared<stream>(std::move(quic), std::string{}, id_, true, false);
        track_stream(s);
        return s;
    }

    std::shared_ptr<stream> session::open_unidirectional_stream() {
        if (is_closed()) return nullptr;
        const auto conn = conn_.lock();
        if (!conn) return nullptr;
        auto quic = conn->create_stream(false);
        std::string header;
        VarInt::encode(kUniStreamType, header);
        VarInt::encode(id_, header);
        std::ignore = quic->write_outbound(header, false);
        auto s = std::make_shared<stream>(std::move(quic), std::string{}, id_, false, false);
        track_stream(s);
        return s;
    }

    bool session::send_datagram(const std::string_view payload) const {
        if (is_closed()) return false;
        const auto conn = conn_.lock();
        if (!conn) return false;
        // RFC 9297 §2.1: Quarter Stream ID (the session's stream ID / 4) followed by the payload.
        std::string datagram;
        datagram.reserve(payload.size() + 8);
        VarInt::encode(id_ / 4, datagram);
        datagram.append(payload);
        return conn->send_datagram(datagram);
    }

    std::size_t session::max_datagram_size() const noexcept {
        const auto conn = conn_.lock();
        if (!conn) return 0;
        const std::size_t limit = conn->max_datagram_payload();
        const std::size_t prefix = VarInt::encoded_size(id_ / 4);
        return limit > prefix ? limit - prefix : 0;
    }

    void session::close(const uint32_t code, const std::string_view reason) {
        terminate(code, reason, true);
    }

    void session::drain() const {
        if (is_closed() || !connect_stream_) return;
        const std::string frame = http::http3::encode_tunnel_data_frame(capsule::encode(kCapsuleDrainSession, {}));
        std::ignore = connect_stream_->write_outbound(frame, false);
    }

    void session::terminate(const uint32_t code, const std::string_view reason, const bool notify_peer) {
        if (bool expected = false; !closed_.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
            return;
        }
        close_code_.store(code, std::memory_order_release);

        std::vector<std::weak_ptr<stream> > streams; {
            std::lock_guard lock(mtx_);
            close_reason_ = std::string(utf8_prefix(reason, kMaxCloseReasonBytes));
            streams.swap(streams_);
        }

        if (connect_stream_) {
            if (notify_peer) {
                // CLOSE_WEBTRANSPORT_SESSION in a DATA frame, then FIN (draft-ietf-webtrans-http3 §6).
                const std::string frame = http::http3::encode_tunnel_data_frame(
                    capsule::encode_close_session(code, reason));
                std::ignore = connect_stream_->write_outbound(frame, true);
            } else {
                // The peer ended the session: finish our side of the CONNECT stream as well.
                std::error_code ec;
                std::ignore = connect_stream_->shutdown(asio::ip::tcp::socket::shutdown_send, ec);
            }
        }

        incoming_bidi_->close();
        incoming_uni_->close();
        datagrams_->close();
        for (const auto &weak: streams) {
            if (const auto s = weak.lock()) s->close();
        }
        if (const auto reg = registry_.lock()) reg->remove(id_);
    }

    void session::track_stream(const std::shared_ptr<stream> &s) {
        std::lock_guard lock(mtx_);
        // Sweep dead entries only when the list has doubled since the last sweep: amortized O(1) per stream
        // (sweeping on every insert made accepting n streams O(n^2)), and the list, whose expired weak_ptrs keep
        // their stream's memory block alive, stays within twice the number of live streams.
        if (streams_.size() >= streams_sweep_at_) {
            std::erase_if(streams_, [](const std::weak_ptr<stream> &w) { return w.expired(); });
            streams_sweep_at_ = (std::max)(kMinSweepThreshold, streams_.size() * 2);
        }
        streams_.push_back(s);
    }

    std::size_t session::tracked_stream_count() const {
        std::lock_guard lock(mtx_);
        return streams_.size();
    }

    void session::deliver_stream(std::shared_ptr<QuicStream> quic, std::string pending, const bool bidirectional) {
        if (!quic) return;
        auto s = std::make_shared<stream>(quic, std::move(pending), id_, bidirectional, true);
        if (is_closed()) {
            s->close();
            return;
        }
        track_stream(s);
        auto &channel = bidirectional ? *incoming_bidi_ : *incoming_uni_;
        if (!channel.try_send(std::error_code{}, s)) {
            // Session closing, or the application stopped accepting: refuse the stream.
            s->close();
        }
    }

    void session::deliver_datagram(std::string payload) const {
        if (is_closed()) return;
        // Datagrams are unreliable: when the application falls behind, newer ones are dropped.
        std::ignore = datagrams_->try_send(std::error_code{}, std::move(payload));
    }

    wavex::task<void> session::run_capsule_reader() {
        auto self = shared_from_this();
        constexpr std::size_t kMaxBufferedCapsuleBytes = 1024 * 1024;
        std::string buf;
        char tmp[4096];
        for (;;) {
            for (;;) {
                uint64_t type = 0;
                std::string_view payload;
                std::size_t consumed = 0;
                if (capsule::parse(buf, type, payload, consumed) != capsule::parse_result::complete) break;
                if (type == kCapsuleCloseSession) {
                    uint32_t code = 0;
                    std::string reason;
                    if (!capsule::decode_close_session(payload, code, reason)) {
                        code = 0;
                        reason.clear();
                    }
                    terminate(code, reason, false);
                    co_return;
                }
                if (type == kCapsuleDrainSession) {
                    drain_requested_.store(true, std::memory_order_release);
                }
                // Unknown capsule types are ignored (RFC 9297 §3.2).
                buf.erase(0, consumed);
            }
            if (is_closed()) co_return;
            if (buf.size() > kMaxBufferedCapsuleBytes) {
                terminate(0, "capsule too large", true);
                co_return;
            }

            auto [ec, n] = co_await capsule_stream_.read_some(asio::buffer(tmp));
            if (n > 0) buf.append(tmp, n);
            if (ec || n == 0) {
                // FIN without a CLOSE capsule (or a reset) ends the session with code 0.
                terminate(0, {}, false);
                co_return;
            }
        }
    }

    // ─── Registry ────────────────────────────────────────────────────────────
    void session_registry::bind_connection(const std::shared_ptr<QuicConnection> &conn) {
        if (!conn) return;
        {
            std::lock_guard lock(mtx_);
            if (datagram_hook_installed_) return;
            datagram_hook_installed_ = true;
            conn_ = conn;
        }
        conn->set_datagram_callback([weak = weak_from_this()](std::string datagram) {
            if (const auto self = weak.lock()) self->dispatch_datagram(std::move(datagram));
        });
    }

    void session_registry::add(const std::shared_ptr<session> &s) {
        if (!s) return;
        std::vector<pending_stream> ready; {
            std::lock_guard lock(mtx_);
            sessions_[s->id()] = s;
            for (auto it = pending_.begin(); it != pending_.end();) {
                if (it->session_id == s->id()) {
                    ready.push_back(std::move(*it));
                    it = pending_.erase(it);
                } else {
                    ++it;
                }
            }
        }
        for (auto &p: ready) {
            s->deliver_stream(std::move(p.quic), std::move(p.buffered), p.bidirectional);
        }
    }

    void session_registry::remove(const uint64_t session_id) {
        std::vector<pending_stream> orphaned; {
            std::lock_guard lock(mtx_);
            sessions_.erase(session_id);
            for (auto it = pending_.begin(); it != pending_.end();) {
                if (it->session_id == session_id) {
                    orphaned.push_back(std::move(*it));
                    it = pending_.erase(it);
                } else {
                    ++it;
                }
            }
        }
        for (auto &p: orphaned) {
            if (p.quic && p.bidirectional) p.quic->close();
        }
    }

    std::shared_ptr<session> session_registry::find(const uint64_t session_id) const {
        std::lock_guard lock(mtx_);
        if (const auto it = sessions_.find(session_id); it != sessions_.end()) return it->second.lock();
        return nullptr;
    }

    std::size_t session_registry::size() const {
        std::lock_guard lock(mtx_);
        return sessions_.size();
    }

    std::size_t session_registry::pending_count() const {
        std::lock_guard lock(mtx_);
        return pending_.size();
    }

    void session_registry::dispatch_stream(const uint64_t session_id, std::shared_ptr<QuicStream> quic,
                                           std::string buffered, const bool bidirectional) {
        if (!quic) return;
        if (!is_valid_session_id(session_id)) {
            wavex::log::debug("[WebTransport] stream {} names invalid session {}", quic->stream_id(), session_id);
            if (bidirectional) quic->close();
            return;
        }
        std::shared_ptr<session> target;
        bool refused = false; {
            std::lock_guard lock(mtx_);
            if (const auto it = sessions_.find(session_id); it != sessions_.end()) target = it->second.lock();
            if (!target) {
                // The stream may have overtaken the CONNECT; keep it until the session registers.
                if (pending_.size() < kMaxPendingStreams) {
                    pending_.push_back(pending_stream{std::move(quic), std::move(buffered), session_id, bidirectional});
                    return;
                }
                refused = true;
            }
        }
        if (refused) {
            if (bidirectional) quic->close();
            return;
        }
        target->deliver_stream(std::move(quic), std::move(buffered), bidirectional);
    }

    void session_registry::dispatch_datagram(std::string datagram) const {
        std::size_t cursor = 0;
        uint64_t quarter_id = 0;
        if (!VarInt::decode(datagram, cursor, quarter_id)) return;
        if (quarter_id > (std::numeric_limits<uint64_t>::max)() / 4) return;
        const auto target = find(quarter_id * 4);
        if (!target) return; // no such session (yet): datagrams may be dropped
        datagram.erase(0, cursor);
        target->deliver_datagram(std::move(datagram));
    }

    std::shared_ptr<session_registry> registry_for(http::http3::connection_context &ctx) {
        std::lock_guard lock(ctx.extension_mtx);
        if (!ctx.webtransport) ctx.webtransport = std::make_shared<session_registry>();
        return ctx.webtransport;
    }

    std::shared_ptr<http::http3::connection_context> http3_context_for(const std::shared_ptr<QuicConnection> &conn) {
        if (!conn) return nullptr;
        // Several streams of one connection may get here at once; the connection creates the context exactly once
        // under its own lock (no process-wide mutex shared by unrelated connections).
        return std::static_pointer_cast<http::http3::connection_context>(conn->user_context_or_create(
            [] { return std::make_shared<http::http3::connection_context>(); }));
    }

    // ─── Stream Demultiplexing ───────────────────────────────────────────────
    wavex::task<bool> dispatch_bidirectional_stream(std::shared_ptr<QuicStream> s) {
        if (!s) co_return false;
        std::string peeked;
        uint64_t first = 0;
        std::size_t cursor = 0;
        while (!VarInt::decode(peeked, cursor, first)) {
            cursor = 0;
            if (!co_await read_more(s, peeked)) {
                // Let the request path see the bytes (and the EOF/error) exactly as they arrived.
                s->unread(peeked);
                co_return false;
            }
        }
        if (first != kBidiStreamSignal) {
            s->unread(peeked);
            co_return false;
        }

        uint64_t session_id = 0;
        std::size_t id_cursor = cursor;
        while (!VarInt::decode(peeked, id_cursor, session_id)) {
            id_cursor = cursor;
            if (!co_await read_more(s, peeked)) {
                s->close();
                co_return true;
            }
        }
        peeked.erase(0, id_cursor);

        const auto conn = s->connection();
        if (!conn) co_return true;
        const auto ctx = http3_context_for(conn);
        registry_for(*ctx)->dispatch_stream(session_id, std::move(s), std::move(peeked), true);
        co_return true;
    }

    wavex::task<void> dispatch_unidirectional_stream(std::shared_ptr<QuicStream> stream, std::string buffered,
                                                         std::shared_ptr<http::http3::connection_context> ctx) {
        if (!stream || !ctx) co_return;
        uint64_t session_id = 0;
        std::size_t cursor = 0;
        while (!VarInt::decode(buffered, cursor, session_id)) {
            cursor = 0;
            if (buffered.size() > 8 || !co_await read_more(stream, buffered)) co_return;
        }
        buffered.erase(0, cursor);
        registry_for(*ctx)->dispatch_stream(session_id, std::move(stream), std::move(buffered), false);
    }

    // ─── Server Session ──────────────────────────────────────────────────────
    wavex::task<void> detail::run_server_session(network::AnyStream connect_stream, std::string leftover,
                                                     options opts, request_info info, handler_fn handler) {
        const auto quic = connect_stream.native<QuicStream>();
        const auto conn = quic ? quic->connection() : nullptr;
        if (!quic || !conn) {
            wavex::log::warn("[WebTransport] session dropped: the CONNECT stream is not a live QUIC stream");
            co_return;
        }

        const auto ctx = http3_context_for(conn);
        const auto registry = registry_for(*ctx);
        registry->bind_connection(conn);

        auto capsules = http::http3::make_data_tunnel(std::move(connect_stream), std::move(leftover));
        auto sess = std::make_shared<session>(quic->stream_id(), quic, std::move(capsules), conn, registry, opts);
        sess->set_request_info(std::move(info.path), std::move(info.authority), std::move(info.origin));
        registry->add(sess);

        asio::co_spawn(sess->get_executor(), [sess]() -> wavex::task<void> {
            co_await sess->run_capsule_reader();
        }, asio::detached);

        try {
            co_await handler(sess);
        } catch (const std::exception &e) {
            wavex::log::error("[WebTransport] Unhandled exception in session handler: {}", e.what());
        } catch (...) {
            wavex::log::error("[WebTransport] Unknown exception in session handler");
        }
        sess->close(); // no-op if the session already ended
    }
} // namespace wavex::protos::webtransport

#endif // WAVEX_HAS_SSL
