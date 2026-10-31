// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * @file http2session.hpp
 * @brief Multiplexed HTTP/2 server connection (RFC 9113) with extended CONNECT tunnels (RFC 8441).
 *
 * The generic server loop serves one request at a time, which cannot express HTTP/2: streams interleave,
 * flow control is per stream, and a WebSocket tunnel (RFC 8441) stays open while the rest of the page keeps
 * loading on the same connection. `protocol_traits<http2codec>::serve_connection` therefore hands the
 * connection (after the client preface) to this session:
 *
 *  - one **reader** (the connection coroutine) parses frames, decodes HPACK in arrival order, tracks stream
 *    state and flow control, and starts a task per complete request;
 *  - one **task per stream** builds the request, runs it through the server's shared request pipeline
 *    (`Services::handle`, i.e. Server::process_request: routing, middlewares, errors, prepare_response) and
 *    sends the response, or, after a 2xx extended CONNECT with a takeover handler, runs the tunnel;
 *  - one **writer** drains a frame queue, so frames of different streams never interleave mid-frame.
 *
 * Everything runs on the connection's executor (its leased worker), so the session needs no locks and may
 * allocate request arenas from the connection's unsynchronized memory pool. Other threads reach it only
 * through a WebSocket's send queue, which re-dispatches onto that executor.
 *
 * `Services` is supplied by the server (Server::ConnectionServices) and provides:
 *   request_type / response_type, memory(), accepting(), idle_timeout(), max_request_size(), limits(),
 *   mark_idle(), mark_active(), handle(req, res, sink) -> wavex::task<bool>.
 */

#pragma once

#include <algorithm>
#include <chrono>
#if defined(__MINGW32__) || defined(__clang__) || defined(__GNUC__)
#include <cstdint>
#include <cstring>
#endif
#include <deque>
#include <expected>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <tuple>
#include <unordered_map>
#include <utility>
#include <vector>

#ifndef ASIO_HAS_CO_AWAIT
#define ASIO_HAS_CO_AWAIT 1
#endif
#include <asio/as_tuple.hpp>
#include <asio/buffer.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/steady_timer.hpp>
#include <asio/this_coro.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/write.hpp>

#include <wavex/Base/Logger.hpp>
#include <wavex/Base/Memory.hpp>
#include <wavex/Network/AnyStream.hpp>
#include <wavex/protos/ProtocolTraits.hpp>
#include <wavex/protos/http/http2codec.hpp>

namespace wavex::protos::http::http2 {
    // ─── Session Limits ──────────────────────────────────────────────────────
    struct session_limits {
        static constexpr uint32_t kMaxConcurrentStreams = 100;
        static constexpr uint32_t kInitialStreamWindow = 1u << 20;          ///< advertised per-stream receive window
        static constexpr uint32_t kConnectionWindow = 16u << 20;            ///< connection receive window
        static constexpr uint32_t kMaxFrameSize = 16384;                     ///< we accept the RFC default only
        static constexpr std::size_t kMaxHeaderBlock = 256 * 1024;          ///< HEADERS + CONTINUATION fragments
        static constexpr std::size_t kMaxOutboxBytes = 1u << 20;            ///< writer queue backpressure
        static constexpr int64_t kMaxWindow = 0x7FFFFFFF;
    };

    // ─── Non-template helpers (src/protos/http/http2session.cpp) ─────────────

    /// Server SETTINGS (with ENABLE_CONNECT_PROTOCOL) followed by the connection WINDOW_UPDATE.
    [[nodiscard]] std::string session_preamble();

    /**
     * @brief Rebuild a self-contained request (HEADERS [+ DATA]) for the codec parser from headers that the
     *        session already decoded in arrival order. The header block uses literals only, so parsing it does
     *        not touch any dynamic table.
     */
    [[nodiscard]] std::string build_request_wire(uint32_t stream_id,
                                                 const std::vector<std::pair<std::string, std::string> > &headers,
                                                 std::string_view body, bool end_stream);

    /// Encode one frame (9-octet header + payload).
    [[nodiscard]] std::string encode_frame(frame_type type, uint8_t flags, uint32_t stream_id, std::string_view payload);

    /// Split an oversized HEADERS frame payload into HEADERS + CONTINUATION frames (RFC 9113 §6.10).
    [[nodiscard]] std::string encode_header_frames(uint32_t stream_id, std::string_view block, bool end_stream,
                                                   uint32_t max_frame_size);

    /// Strip padding / priority fields from a HEADERS payload. Returns false when malformed.
    [[nodiscard]] bool headers_fragment(const frame_header &hdr, std::string_view payload, std::string_view &fragment);

    /// Strip padding from a DATA payload. Returns false when malformed.
    [[nodiscard]] bool data_payload(const frame_header &hdr, std::string_view payload, std::string_view &data);

    [[nodiscard]] uint32_t read_u32(std::string_view p) noexcept;

    /**
     * @class server_session
     * @brief One HTTP/2 connection after the client preface.
     */
    template<typename Stream, typename Services>
    class server_session : public std::enable_shared_from_this<server_session<Stream, Services> > {
    public:
        // ─── 1. Nested Types ────────────────────────────────────────────────
        using Request = Services::request_type;
        using Response = Services::response_type;
        using write_result = std::expected<void, std::error_code>;

        struct stream_state {
            // ─── 2. Member Variables (minimum padding) ──────────────────────
            std::unique_ptr<asio::steady_timer> event;  ///< wakes a tunnel reader (data, end, reset, cancel)
            std::vector<std::pair<std::string, std::string> > headers;
            std::string header_block;                   ///< fragments until END_HEADERS
            std::string body;                           ///< request body, buffered until END_STREAM
            std::string tunnel_in;                      ///< tunnel bytes not yet read
            int64_t send_window{65535};
            uint64_t recv_unacked{0};                   ///< consumed bytes not yet credited by WINDOW_UPDATE
            uint32_t id{0};
            bool end_stream_received{false};
            bool headers_done{false};
            bool dispatched{false};
            bool tunnel{false};
            bool reset{false};
            bool local_closed{false};
            bool read_cancelled{false};
            bool rejected{false};                       ///< answered early (e.g. 413); further DATA ignored
        };

    private:
        // ─── 2. Member Variables (minimum padding) ──────────────────────────
        std::shared_ptr<Stream> stream_;
        Services &services_;
        asio::any_io_executor executor_;
        std::unique_ptr<asio::steady_timer> progress_; ///< window/outbox/task changes; never re-armed
        std::unordered_map<uint32_t, std::shared_ptr<stream_state> > streams_;
        std::deque<std::string> outbox_;
        std::string rbuf_;
        hpack::dynamic_table decode_table_{};
        std::size_t rbuf_offset_{0};
        std::size_t outbox_bytes_{0};
        std::size_t active_tasks_{0};
        int64_t conn_send_window_{65535};
        int64_t peer_initial_window_{65535};
        uint64_t conn_recv_unacked_{0};
        uint32_t peer_max_frame_size_{16384};
        uint32_t last_peer_stream_id_{0};
        uint32_t continuation_sid_{0};
        bool continuation_end_stream_{false};
        bool writer_active_{false};
        bool dead_{false};
        bool goaway_sent_{false};
        bool goaway_received_{false};

    public:
        // ─── 3. Constructors & Destructor ───────────────────────────────────
        server_session(std::shared_ptr<Stream> stream, std::string buffered, Services &services)
            : stream_(std::move(stream)), services_(services), rbuf_(std::move(buffered)) {
        }

        ~server_session() = default;

        server_session(const server_session &) = delete;

        server_session &operator=(const server_session &) = delete;

        // ─── 4. Member Functions ────────────────────────────────────────────

        /// Serve the connection until it closes; returns only once every stream task has finished.
        wavex::task<void> run() {
            auto self = this->shared_from_this();
            executor_ = co_await asio::this_coro::executor;
            progress_ = std::make_unique<asio::steady_timer>(executor_, asio::steady_timer::time_point::max());

            enqueue(session_preamble());

            while (process_frames()) {
                if (dead_) break;

                if (!services_.accepting() && !goaway_sent_) send_goaway(error_code::NO_ERROR);
                if ((goaway_sent_ || goaway_received_) && streams_.empty()) break;

                if (streams_.empty()) services_.mark_idle();
                else services_.mark_active();

                if (!co_await read_more()) break;
            }

            co_await shutdown();
        }

    private:
        // ─── Writer ─────────────────────────────────────────────────────────
        void notify_progress() const {
            if (progress_) progress_->cancel();
        }

        void enqueue(std::string frame) {
            if (dead_ || frame.empty()) return;
            outbox_bytes_ += frame.size();
            outbox_.push_back(std::move(frame));
            if (!writer_active_) {
                writer_active_ = true;
                asio::co_spawn(executor_, [self = this->shared_from_this()]() -> wavex::task<void> {
                    co_await self->write_loop();
                }, asio::detached);
            }
        }

        wavex::task<void> write_loop() {
            constexpr std::size_t kBatchBytes = 64 * 1024;
            while (!outbox_.empty() && !dead_) {
                std::string batch = std::move(outbox_.front());
                outbox_.pop_front();
                while (!outbox_.empty() && batch.size() + outbox_.front().size() <= kBatchBytes) {
                    batch += outbox_.front();
                    outbox_.pop_front();
                }
                auto [ec, n] = co_await asio::async_write(*stream_, asio::buffer(batch),
                                                          asio::as_tuple(asio::use_awaitable));
                (void) n;
                outbox_bytes_ -= (std::min)(outbox_bytes_, batch.size());
                if (ec) {
                    mark_dead();
                    break;
                }
                notify_progress();
            }
            writer_active_ = false;
            notify_progress();
        }

        // ─── Waiting ────────────────────────────────────────────────────────

        /// Wait on `event` until `pred()` holds, the connection dies, or `deadline` passes.
        template<typename Pred>
        wavex::task<bool> wait_until(asio::steady_timer &event, Pred pred,
                                         const std::chrono::steady_clock::time_point deadline) {
            while (!pred()) {
                if (dead_ || std::chrono::steady_clock::now() >= deadline) co_return pred();
                asio::steady_timer timeout(executor_, deadline);
                timeout.async_wait([self = this->shared_from_this(), ev = &event](const std::error_code ec) {
                    if (!ec) ev->cancel();
                });
                co_await event.async_wait(asio::as_tuple(asio::use_awaitable));
                timeout.cancel();
            }
            co_return true;
        }

        void mark_dead() {
            if (dead_) return;
            dead_ = true;
            for (auto &[id, st]: streams_) {
                if (st->event) st->event->cancel();
            }
            notify_progress();
        }

        // ─── Reader ─────────────────────────────────────────────────────────
        wavex::task<bool> read_more() {
            // Compact the consumed prefix before growing the buffer.
            if (rbuf_offset_ > 0) {
                rbuf_.erase(0, rbuf_offset_);
                rbuf_offset_ = 0;
            }
            // An idle connection (no streams) closes after the keep-alive timeout.
            std::optional<asio::steady_timer> timer;
            auto timed_out = std::make_shared<bool>(false);
            if (streams_.empty()) {
                timer.emplace(executor_, services_.idle_timeout());
                timer->async_wait([self = this->shared_from_this(), timed_out](const std::error_code ec) {
                    // Never cancel the socket while a write is in flight: that would abort it too.
                    if (!ec && self->streams_.empty() && !self->writer_active_) {
                        *timed_out = true;
                        std::error_code ignored;
                        std::ignore = self->stream_->lowest_layer().cancel(ignored);
                    }
                });
            }
            const std::size_t prev = rbuf_.size();
            rbuf_.resize(prev + 16384);
            auto [ec, n] = co_await stream_->async_read_some(asio::buffer(rbuf_.data() + prev, 16384),
                                                             asio::as_tuple(asio::use_awaitable));
            if (timer) timer->cancel();
            rbuf_.resize(prev + n);
            if (*timed_out) {
                send_goaway(error_code::NO_ERROR);
                co_return false;
            }
            if (ec == asio::error::operation_aborted && !services_.accepting()) {
                // Graceful shutdown cancelled an idle read: say goodbye properly.
                send_goaway(error_code::NO_ERROR);
                co_return !streams_.empty();
            }
            if (ec || n == 0) {
                mark_dead();
                co_return false;
            }
            co_return true;
        }

        /// Handle every complete frame in the buffer. Returns false after a connection error.
        bool process_frames() {
            while (!dead_) {
                const std::string_view avail(rbuf_.data() + rbuf_offset_, rbuf_.size() - rbuf_offset_);
                if (avail.size() < frame_header::HEADER_SIZE) return true;
                frame_header hdr;
                if (!unpack_frame_header(avail, hdr)) return connection_error(error_code::PROTOCOL_ERROR);
                if (hdr.length > session_limits::kMaxFrameSize) {
                    return connection_error(error_code::FRAME_SIZE_ERROR);
                }
                if (avail.size() < frame_header::HEADER_SIZE + hdr.length) return true;
                const std::string_view payload = avail.substr(frame_header::HEADER_SIZE, hdr.length);
                const bool ok = handle_frame(hdr, payload);
                rbuf_offset_ += frame_header::HEADER_SIZE + hdr.length;
                if (!ok) return false;
            }
            return true;
        }

        bool connection_error(const error_code err) {
            wavex::log::debug("[HTTP/2] connection error {}", static_cast<uint32_t>(err));
            send_goaway(err);
            mark_dead_after_flush();
            return false;
        }

        void send_goaway(const error_code err) {
            if (goaway_sent_) return;
            goaway_sent_ = true;
            enqueue(encoder::serialize_goaway(last_peer_stream_id_, err));
        }

        void mark_dead_after_flush() {
            // The GOAWAY is queued; shutdown() waits for the writer before the transport is closed.
            for (auto &[id, st]: streams_) {
                st->reset = true;
                if (st->event) st->event->cancel();
            }
            notify_progress();
        }

        void reset_stream(stream_state &st, const error_code err) {
            if (!st.reset) enqueue(encoder::serialize_rst_stream(st.id, err));
            st.reset = true;
            if (st.event) st.event->cancel();
            notify_progress();
            if (!st.dispatched) streams_.erase(st.id);
        }

        bool handle_frame(const frame_header &hdr, const std::string_view payload) {
            if (continuation_sid_ != 0 &&
                (hdr.type != frame_type::CONTINUATION || hdr.stream_id != continuation_sid_)) {
                return connection_error(error_code::PROTOCOL_ERROR);
            }
            switch (hdr.type) {
                case frame_type::HEADERS: return on_headers(hdr, payload);
                case frame_type::CONTINUATION: return on_continuation(hdr, payload);
                case frame_type::DATA: return on_data(hdr, payload);
                case frame_type::SETTINGS: return on_settings(hdr, payload);
                case frame_type::WINDOW_UPDATE: return on_window_update(hdr, payload);
                case frame_type::PING:
                    if (hdr.stream_id != 0) return connection_error(error_code::PROTOCOL_ERROR);
                    if (payload.size() != 8) return connection_error(error_code::FRAME_SIZE_ERROR);
                    if (!hdr.has_flag(flags::ACK)) enqueue(encode_frame(frame_type::PING, flags::ACK, 0, payload));
                    return true;
                case frame_type::RST_STREAM:
                    if (hdr.stream_id == 0) return connection_error(error_code::PROTOCOL_ERROR);
                    if (payload.size() != 4) return connection_error(error_code::FRAME_SIZE_ERROR);
                    if (const auto it = streams_.find(hdr.stream_id); it != streams_.end()) {
                        auto st = it->second;
                        st->reset = true;
                        if (st->event) st->event->cancel();
                        notify_progress();
                        if (!st->dispatched) streams_.erase(it);
                    }
                    return true;
                case frame_type::GOAWAY:
                    goaway_received_ = true;
                    return true;
                case frame_type::PUSH_PROMISE:
                    return connection_error(error_code::PROTOCOL_ERROR); // clients never push
                case frame_type::PRIORITY:
                default:
                    return true; // priority signals and unknown extension frames are ignored (RFC 9113 §5.5)
            }
        }

        bool on_headers(const frame_header &hdr, const std::string_view payload) {
            const uint32_t sid = hdr.stream_id;
            if (sid == 0 || (sid & 1u) == 0) return connection_error(error_code::PROTOCOL_ERROR);
            std::string_view fragment;
            if (!headers_fragment(hdr, payload, fragment)) return connection_error(error_code::PROTOCOL_ERROR);

            std::shared_ptr<stream_state> st;
            if (const auto it = streams_.find(sid); it != streams_.end()) {
                st = it->second;
                // Trailers: only after the request headers, and they must end the stream (RFC 9113 §8.1).
                if (!st->headers_done || st->end_stream_received || !hdr.has_flag(flags::END_STREAM)) {
                    return connection_error(error_code::PROTOCOL_ERROR);
                }
                st->header_block.clear();
            } else {
                if (sid <= last_peer_stream_id_) return connection_error(error_code::STREAM_CLOSED);
                last_peer_stream_id_ = sid;
                st = std::make_shared<stream_state>();
                st->id = sid;
                st->send_window = peer_initial_window_;
                streams_.emplace(sid, st);
            }
            st->header_block.append(fragment);
            if (hdr.has_flag(flags::END_STREAM)) st->end_stream_received = true;
            if (!hdr.has_flag(flags::END_HEADERS)) {
                continuation_sid_ = sid;
                return true;
            }
            return finish_header_block(*st);
        }

        bool on_continuation(const frame_header &hdr, const std::string_view payload) {
            if (continuation_sid_ == 0 || hdr.stream_id != continuation_sid_) {
                return connection_error(error_code::PROTOCOL_ERROR);
            }
            const auto it = streams_.find(hdr.stream_id);
            if (it == streams_.end()) return connection_error(error_code::PROTOCOL_ERROR);
            const auto st = it->second; // keep it alive even if the stream is refused below
            st->header_block.append(payload);
            if (st->header_block.size() > session_limits::kMaxHeaderBlock) {
                return connection_error(error_code::ENHANCE_YOUR_CALM);
            }
            if (!hdr.has_flag(flags::END_HEADERS)) return true;
            continuation_sid_ = 0;
            return finish_header_block(*st);
        }

        /// Decode a complete header block (always, so the HPACK state stays in step), then act on it.
        bool finish_header_block(stream_state &st) {
            continuation_sid_ = 0;
            std::vector<std::pair<std::string, std::string> > decoded;
            const hpack::decoder dec(decode_table_, kDefaultMaxHeaderListSize);
            const bool decoded_ok = dec.decode_header_block(st.header_block, decoded);
            st.header_block.clear();
            st.header_block.shrink_to_fit();
            if (!decoded_ok && !dec.limit_exceeded()) return connection_error(error_code::COMPRESSION_ERROR);

            if (st.headers_done) { // trailers: decoded only to keep the table in step, then the request is complete
                if (!st.dispatched && !st.rejected) dispatch(st);
                return true;
            }
            st.headers_done = true;

            if (!decoded_ok) {
                // The list exceeded the cap mid-decode, so the dynamic table may now differ from the client's:
                // answer 431 on this stream and stop taking new streams on this connection.
                answer_error(st, wavex::protos::protocol_error::limits_exceeded);
                send_goaway(error_code::ENHANCE_YOUR_CALM);
                return true;
            }
            if (goaway_sent_ || streams_.size() > session_limits::kMaxConcurrentStreams) {
                reset_stream(st, error_code::REFUSED_STREAM);
                return true;
            }
            st.headers = std::move(decoded);

            bool is_connect = false;
            for (const auto &[n, v]: st.headers) {
                if (n == ":method") {
                    is_connect = (v == "CONNECT");
                    break;
                }
            }
            // A CONNECT opens a tunnel: it is handled as soon as its headers are in, not at END_STREAM.
            if (st.end_stream_received || is_connect) dispatch(st);
            return true;
        }

        bool on_data(const frame_header &hdr, const std::string_view payload) {
            if (hdr.stream_id == 0) return connection_error(error_code::PROTOCOL_ERROR);
            std::string_view data;
            if (!data_payload(hdr, payload, data)) return connection_error(error_code::PROTOCOL_ERROR);
            credit_connection(hdr.length); // the whole frame counts, padding included (RFC 9113 §6.9.1)

            const auto it = streams_.find(hdr.stream_id);
            if (it == streams_.end()) {
                if (hdr.stream_id > last_peer_stream_id_) return connection_error(error_code::PROTOCOL_ERROR);
                return true; // a stream we already finished: drop
            }
            auto st = it->second;
            if (!st->headers_done || st->end_stream_received) {
                return connection_error(error_code::STREAM_CLOSED);
            }
            if (st->reset || st->rejected) return true;

            if (st->tunnel || (st->dispatched && !st->end_stream_received)) {
                // Tunnel bytes: credited once the reader consumes them, which bounds what we buffer.
                st->tunnel_in.append(data);
                if (st->tunnel_in.size() > session_limits::kInitialStreamWindow) {
                    reset_stream(*st, error_code::FLOW_CONTROL_ERROR);
                    return true;
                }
                st->recv_unacked += hdr.length - data.size(); // padding is consumed immediately
            } else {
                st->body.append(data);
                credit_stream(*st, hdr.length);
                if (const auto cap = services_.max_request_size(); cap > 0 && st->body.size() > cap) {
                    st->rejected = true;
                    answer_error(*st, wavex::protos::protocol_error::payload_too_large);
                    return true;
                }
            }
            if (hdr.has_flag(flags::END_STREAM)) {
                st->end_stream_received = true;
                if (!st->dispatched) dispatch(*st);
            }
            if (st->event) st->event->cancel();
            return true;
        }

        bool on_settings(const frame_header &hdr, const std::string_view payload) {
            if (hdr.stream_id != 0) return connection_error(error_code::PROTOCOL_ERROR);
            if (hdr.has_flag(flags::ACK)) {
                return payload.empty() ? true : connection_error(error_code::FRAME_SIZE_ERROR);
            }
            if (payload.size() % 6 != 0) return connection_error(error_code::FRAME_SIZE_ERROR);
            for (std::size_t i = 0; i < payload.size(); i += 6) {
                const auto id = static_cast<uint16_t>((static_cast<uint8_t>(payload[i]) << 8) |
                                                      static_cast<uint8_t>(payload[i + 1]));
                const uint32_t value = read_u32(payload.substr(i + 2, 4));
                if (id == static_cast<uint16_t>(settings_parameter::INITIAL_WINDOW_SIZE)) {
                    if (value > session_limits::kMaxWindow) return connection_error(error_code::FLOW_CONTROL_ERROR);
                    const int64_t delta = static_cast<int64_t>(value) - peer_initial_window_;
                    peer_initial_window_ = value;
                    for (auto &[sid, st]: streams_) st->send_window += delta; // RFC 9113 §6.9.2
                } else if (id == static_cast<uint16_t>(settings_parameter::MAX_FRAME_SIZE)) {
                    if (value < 16384 || value > 16777215) return connection_error(error_code::PROTOCOL_ERROR);
                    peer_max_frame_size_ = value;
                } else if (id == static_cast<uint16_t>(settings_parameter::ENABLE_PUSH)) {
                    if (value > 1) return connection_error(error_code::PROTOCOL_ERROR);
                }
            }
            enqueue(encoder::serialize_settings_ack());
            notify_progress();
            return true;
        }

        bool on_window_update(const frame_header &hdr, const std::string_view payload) {
            if (payload.size() != 4) return connection_error(error_code::FRAME_SIZE_ERROR);
            const uint32_t inc = read_u32(payload) & 0x7FFFFFFF;
            if (hdr.stream_id == 0) {
                if (inc == 0) return connection_error(error_code::PROTOCOL_ERROR);
                conn_send_window_ += inc;
                if (conn_send_window_ > session_limits::kMaxWindow) {
                    return connection_error(error_code::FLOW_CONTROL_ERROR);
                }
            } else if (const auto it = streams_.find(hdr.stream_id); it != streams_.end()) {
                auto &st = *it->second;
                if (inc == 0) {
                    reset_stream(st, error_code::PROTOCOL_ERROR);
                    return true;
                }
                st.send_window += inc;
                if (st.send_window > session_limits::kMaxWindow) {
                    reset_stream(st, error_code::FLOW_CONTROL_ERROR);
                    return true;
                }
            }
            notify_progress();
            return true;
        }

        // ─── Receive Flow Control ───────────────────────────────────────────
        void credit_connection(const uint64_t n) {
            conn_recv_unacked_ += n;
            if (conn_recv_unacked_ >= session_limits::kConnectionWindow / 2) {
                enqueue(encoder::serialize_window_update(0, static_cast<uint32_t>(conn_recv_unacked_)));
                conn_recv_unacked_ = 0;
            }
        }

        void credit_stream(stream_state &st, const uint64_t n) {
            st.recv_unacked += n;
            if (!st.end_stream_received && !st.reset &&
                st.recv_unacked >= session_limits::kInitialStreamWindow / 2) {
                enqueue(encoder::serialize_window_update(st.id, static_cast<uint32_t>(st.recv_unacked)));
                st.recv_unacked = 0;
            }
        }

        // ─── Stream Tasks ───────────────────────────────────────────────────
        void dispatch(stream_state &st) {
            st.dispatched = true;
            ++active_tasks_;
            auto shared = streams_.at(st.id);
            asio::co_spawn(executor_, [self = this->shared_from_this(), shared]() -> wavex::task<void> {
                co_await self->run_stream(shared);
            }, asio::detached);
        }

        /// Send a kernel-style error response (400 / 413 / 431) on a stream from the reader.
        void answer_error(stream_state &st, const wavex::protos::protocol_error err) {
            if (st.dispatched) return;
            st.dispatched = true;
            st.rejected = true; // any further DATA on this stream is dropped
            ++active_tasks_;
            auto shared = streams_.at(st.id);
            asio::co_spawn(executor_, [self = this->shared_from_this(), shared, err]() -> wavex::task<void> {
                co_await self->run_error(shared, err);
            }, asio::detached);
        }

        void finish_task(const std::shared_ptr<stream_state> &st) {
            if (!st->end_stream_received && !st->reset) {
                // We are done but the client is still sending: stop it (RFC 9113 §8.1).
                enqueue(encoder::serialize_rst_stream(st->id, error_code::NO_ERROR));
                st->reset = true;
            }
            streams_.erase(st->id);
            if (active_tasks_ > 0) --active_tasks_;
            notify_progress();
        }

        wavex::task<void> run_error(std::shared_ptr<stream_state> st, const wavex::protos::protocol_error err) {
            auto self = this->shared_from_this();
            try {
                Response res(services_.memory());
                res.stream_id(st->id);
                res.set_version(2, 0);
                wavex::protos::detail::write_http_error(res, err);
                std::pmr::string wire(services_.memory());
                res.serialize_to(wire);
                std::ignore = co_await send_frames(st, std::string(wire), std::chrono::seconds(30));
            } catch (...) {
            }
            finish_task(st);
        }

        wavex::task<void> run_stream(std::shared_ptr<stream_state> st) {
            auto self = this->shared_from_this();
            try {
                co_await serve_stream(st);
            } catch (const std::exception &e) {
                wavex::log::error("[HTTP/2] stream {} failed: {}", st->id, e.what());
            } catch (...) {
            }
            finish_task(st);
        }

        wavex::task<void> serve_stream(const std::shared_ptr<stream_state> &st) {
            // Arena first, so the request and response (allocated from it) are destroyed before it.
            wavex::memory::RequestArena arena(services_.memory());
            Request req(arena.resource());
            Response res(arena.resource());
            res.stream_id(st->id);
            res.set_version(2, 0);

            {
                bool is_connect = false;
                for (const auto &[n, v]: st->headers) {
                    if (n == ":method") is_connect = (v == "CONNECT");
                }
                const std::string wire = build_request_wire(st->id, st->headers, st->body,
                                                            !is_connect || st->end_stream_received);
                st->body = std::string{};
                connection_context scratch; // literal-only block: no dynamic table involved
                const auto parsed = req.parse_stream(wire, scratch);
                if (parsed != parser::result::success) {
                    wavex::protos::detail::write_http_error(res, parsed == parser::result::headers_too_large
                                                      ? wavex::protos::protocol_error::limits_exceeded
                                                      : wavex::protos::protocol_error::bad_request);
                    co_await send_response(st, res, false);
                    co_return;
                }
            }
            req.stream_id(st->id);

            if (wavex::protos::detail::http_exceeds_limits(req, services_.limits())) {
                wavex::protos::detail::write_http_error(res, wavex::protos::protocol_error::limits_exceeded);
                co_await send_response(st, res, false);
                co_return;
            }

            auto weak = this->weak_from_this();
            co_await services_.handle(req, res,
                                      [weak, st](const std::string_view data, const std::chrono::milliseconds timeout)
                                  -> wavex::task<write_result> {
                                          // Copy before the first suspension: `data` is the caller's buffer.
                                          std::string bytes(data);
                                          auto s = weak.lock();
                                          if (!s) co_return std::unexpected(std::make_error_code(std::errc::broken_pipe));
                                          co_return co_await s->send_frames(st, std::move(bytes), timeout);
                                      });

            if (wavex::protos::detail::http_wants_takeover(req, res)) {
                // RFC 8441 §5: 2xx to an extended CONNECT; the stream now carries the tunnelled protocol.
                co_await send_response(st, res, true);
                if (st->reset || dead_) co_return;
                st->tunnel = true;
                st->event = std::make_unique<asio::steady_timer>(executor_, asio::steady_timer::time_point::max());
                if (auto takeover = res.take_upgrade()) {
                    co_await takeover(make_tunnel(st), std::string{});
                }
                if (!st->local_closed && !st->reset && !dead_) {
                    enqueue(encoder::serialize_data_frame(st->id, {}, true));
                    st->local_closed = true;
                }
                co_return;
            }

            if (!res.is_headers_sent()) {
                co_await send_response(st, res, false);
            } else if (!st->local_closed && !st->reset && !dead_) {
                // A streamed response that never ended its stream.
                enqueue(encoder::serialize_data_frame(st->id, {}, true));
                st->local_closed = true;
            }
        }

        wavex::task<void> send_response(const std::shared_ptr<stream_state> &st, Response &res,
                                            const bool keep_open) {
            std::pmr::string wire(services_.memory());
            res.serialize_to(wire);
            std::string bytes(wire);
            if (keep_open && bytes.size() > frame_header::HEADER_SIZE) {
                bytes[4] = static_cast<char>(static_cast<uint8_t>(bytes[4]) & ~flags::END_STREAM);
            }
            std::ignore = co_await send_frames(st, std::move(bytes), std::chrono::seconds(30));
        }

        // ─── Send Path (flow control, frame size, backpressure) ─────────────
        /**
         * @brief Queue frames produced for stream `st` (by the codec or a streaming response), honouring the
         *        peer's flow-control windows and maximum frame size. Frames are re-addressed to `st`.
         */
        wavex::task<write_result> send_frames(std::shared_ptr<stream_state> st, std::string bytes,
                                                  const std::chrono::milliseconds timeout) {
            auto self = this->shared_from_this();
            const auto deadline = std::chrono::steady_clock::now() +
                                  (timeout.count() > 0 ? timeout : std::chrono::milliseconds(30000));
            const auto failed = [this, &st] { return dead_ || st->reset; };
            std::size_t cursor = 0;
            while (cursor + frame_header::HEADER_SIZE <= bytes.size()) {
                frame_header hdr;
                if (!unpack_frame_header(std::string_view(bytes).substr(cursor), hdr)) break;
                const std::size_t total = frame_header::HEADER_SIZE + hdr.length;
                if (cursor + total > bytes.size()) break;
                const std::string_view payload(bytes.data() + cursor + frame_header::HEADER_SIZE, hdr.length);
                cursor += total;

                if (failed()) co_return std::unexpected(std::make_error_code(std::errc::connection_reset));
                if (!co_await wait_until(*progress_, [this, &failed] {
                    return failed() || outbox_bytes_ < session_limits::kMaxOutboxBytes;
                }, deadline)) {
                    co_return std::unexpected(std::make_error_code(std::errc::timed_out));
                }
                if (failed()) co_return std::unexpected(std::make_error_code(std::errc::connection_reset));

                const bool end_stream = hdr.has_flag(flags::END_STREAM);
                if (hdr.type == frame_type::DATA) {
                    std::size_t offset = 0;
                    do {
                        const std::size_t left = payload.size() - offset;
                        if (left > 0 && !co_await wait_until(*progress_, [this, &st, &failed] {
                            return failed() || (st->send_window > 0 && conn_send_window_ > 0);
                        }, deadline)) {
                            co_return std::unexpected(std::make_error_code(std::errc::timed_out));
                        }
                        if (failed()) co_return std::unexpected(std::make_error_code(std::errc::connection_reset));
                        const auto window = static_cast<std::size_t>((std::min)(st->send_window, conn_send_window_));
                        const std::size_t n = (std::min)({left, window, static_cast<std::size_t>(peer_max_frame_size_)});
                        const bool last = (offset + n == payload.size());
                        enqueue(encode_frame(frame_type::DATA, (last && end_stream) ? flags::END_STREAM : flags::NONE,
                                             st->id, payload.substr(offset, n)));
                        st->send_window -= static_cast<int64_t>(n);
                        conn_send_window_ -= static_cast<int64_t>(n);
                        offset += n;
                    } while (offset < payload.size());
                } else if (hdr.type == frame_type::HEADERS) {
                    enqueue(encode_header_frames(st->id, payload, end_stream, peer_max_frame_size_));
                } else {
                    enqueue(encode_frame(hdr.type, hdr.flags, st->id, payload));
                }
                if (end_stream) st->local_closed = true;
            }
            co_return write_result{};
        }

        // ─── Tunnel (extended CONNECT stream as a byte stream) ──────────────
        static wavex::task<network::AnyStream::read_result> tunnel_read(
            std::shared_ptr<server_session> self, std::shared_ptr<stream_state> st, const asio::mutable_buffer out) {
            for (;;) {
                if (!st->tunnel_in.empty()) {
                    const std::size_t n = (std::min)(out.size(), st->tunnel_in.size());
                    std::memcpy(out.data(), st->tunnel_in.data(), n);
                    st->tunnel_in.erase(0, n);
                    st->recv_unacked += n;
                    if (!st->end_stream_received && !st->reset &&
                        st->recv_unacked >= session_limits::kInitialStreamWindow / 4) {
                        self->enqueue(encoder::serialize_window_update(st->id, static_cast<uint32_t>(st->recv_unacked)));
                        st->recv_unacked = 0;
                    }
                    co_return network::AnyStream::read_result{std::error_code{}, n};
                }
                if (st->read_cancelled) {
                    st->read_cancelled = false;
                    co_return network::AnyStream::read_result{asio::error::operation_aborted, 0};
                }
                if (st->end_stream_received) co_return network::AnyStream::read_result{asio::error::eof, 0};
                if (st->reset || self->dead_) {
                    co_return network::AnyStream::read_result{asio::error::connection_reset, 0};
                }
                co_await st->event->async_wait(asio::as_tuple(asio::use_awaitable));
            }
        }

        static wavex::task<std::error_code> tunnel_write(std::shared_ptr<server_session> self,
                                                             std::shared_ptr<stream_state> st,
                                                             const asio::const_buffer in) {
            if (st->local_closed) co_return std::make_error_code(std::errc::broken_pipe);
            std::string frame = encoder::serialize_data_frame(
                st->id, std::string_view(static_cast<const char *>(in.data()), in.size()), false);
            auto r = co_await self->send_frames(st, std::move(frame), std::chrono::hours(24));
            co_return r ? std::error_code{} : r.error();
        }

        network::AnyStream make_tunnel(const std::shared_ptr<stream_state> &st) {
            auto ops = std::make_shared<network::AnyStream::operations>();
            ops->executor = executor_;
            std::weak_ptr<server_session> weak = this->shared_from_this();
            ops->read_some = [weak, st](const asio::mutable_buffer b) -> wavex::task<network::AnyStream::read_result> {
                auto self = weak.lock();
                if (!self) co_return network::AnyStream::read_result{asio::error::connection_reset, 0};
                co_return co_await tunnel_read(std::move(self), st, b);
            };
            ops->write = [weak, st](const asio::const_buffer b) -> wavex::task<std::error_code> {
                auto self = weak.lock();
                if (!self) co_return std::error_code(asio::error::connection_reset);
                co_return co_await tunnel_write(std::move(self), st, b);
            };
            ops->shutdown_send = [weak, st] {
                if (auto self = weak.lock(); self && !st->local_closed && !st->reset) {
                    self->enqueue(encoder::serialize_data_frame(st->id, {}, true));
                    st->local_closed = true;
                }
            };
            ops->cancel = [st] {
                st->read_cancelled = true;
                if (st->event) st->event->cancel();
            };
            ops->close = [weak, st] {
                if (auto self = weak.lock(); self && !st->reset) {
                    self->enqueue(encoder::serialize_rst_stream(st->id, error_code::CANCEL));
                    st->reset = true;
                    if (st->event) st->event->cancel();
                    self->notify_progress();
                }
            };
            return network::AnyStream(std::move(ops));
        }

        // ─── Shutdown ───────────────────────────────────────────────────────
        wavex::task<void> shutdown() {
            // Tell the stream tasks the connection is going away, then wait for them: they allocate from the
            // connection's memory pool, which must outlive them.
            if (!dead_) mark_dead_after_flush();
            const auto drain_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
            co_await wait_until(*progress_, [this] { return !writer_active_ || dead_; }, drain_deadline);
            mark_dead();
            while (active_tasks_ != 0) {
                co_await progress_->async_wait(asio::as_tuple(asio::use_awaitable));
            }
            streams_.clear();
        }
    };
} // namespace wavex::protos::http::http2
