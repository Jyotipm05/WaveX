/**
 * @file QuicStream.hpp
 * @brief Multiplexed virtual stream over a QUIC connection.
 *
 * Implements the AsyncStream concept for integration with WaveX Server.
 */

#pragma once

#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL

#if defined(min)
#undef min
#endif
#if defined(max)
#undef max
#endif

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include <asio/any_io_executor.hpp>
#include <asio/async_result.hpp>
#include <asio/buffer.hpp>
#include <asio/error.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/post.hpp>

#include <wavex/Network/QUIC/QuicConstants.hpp>
#include <wavex/Base/Logger.hpp>

namespace wavex::network::quic {

    class QuicConnection;

    struct StreamChunk {
        // ─── 2. Member Variables (SECOND - Ordered for Minimal Padding) ────
        uint64_t offset{0};
        std::string data{};

        // ─── 3. Constructors & Destructor (MIDDLE) ─────────────────────────
        StreamChunk() = default;
        StreamChunk(uint64_t off, std::string d)
            : offset(off), data(std::move(d)) {}
    };

    /**
     * @class QuicStream
     * @brief Multiplexed, full-duplex virtual stream over a QUIC connection.
     *
     * Adheres strictly to the AsyncStream concept:
     *   - async_read_some, async_write_some
     *   - lowest_layer(), next_layer(), shutdown(), close(), cancel()
     *   - Zero-allocation buffer piping into Server::handle_connection.
     */
    class QuicStream : public std::enable_shared_from_this<QuicStream> {
    public:
        // ─── 1. Nested Types & Definitions (TOP) ───────────────────────────
        using executor_type = asio::any_io_executor;
        using ReadCallback = std::function<void(std::error_code, std::size_t)>;

    private:
        // ─── 2. Member Variables (SECOND - Ordered for Minimal Padding) ────
        uint64_t stream_id_{0};
        uint64_t send_offset_{0};
        uint64_t recv_offset_{0};
        std::weak_ptr<QuicConnection> conn_{};
        asio::any_io_executor executor_{};
        mutable std::mutex mtx_{};
        std::deque<uint8_t> in_buffer_{};
        std::vector<StreamChunk> pending_inbound_{};
        std::optional<ReadCallback> pending_read_{};
        std::optional<uint64_t> final_size_{std::nullopt};
        bool is_open_{true};
        bool fin_received_{false};
        bool fin_sent_{false};
        bool final_size_error_{false};

    public:
        // ─── 3. Constructors & Destructor (MIDDLE) ─────────────────────────
        QuicStream(const std::shared_ptr<QuicConnection> &conn, uint64_t stream_id, asio::any_io_executor executor = {}) noexcept;
        ~QuicStream();
        QuicStream(const QuicStream &) = delete;
        QuicStream &operator=(const QuicStream &) = delete;
        QuicStream(QuicStream &&) = delete;
        QuicStream &operator=(QuicStream &&) = delete;

        // ─── 4. Member Functions & Friend Declarations (LAST) ──────────────
        [[nodiscard]] executor_type get_executor() const noexcept;
        void set_executor(executor_type ex) noexcept { executor_ = std::move(ex); }
        [[nodiscard]] uint64_t stream_id() const noexcept { return stream_id_; }
        [[nodiscard]] bool is_open() const noexcept;
        [[nodiscard]] bool is_fin_received() const noexcept;
        [[nodiscard]] bool is_fin_sent() const noexcept;
        [[nodiscard]] bool is_finished() const noexcept;
        void notify_finished_if_needed();

        // Stream concept methods
        [[nodiscard]] QuicStream &lowest_layer() noexcept { return *this; }
        [[nodiscard]] const QuicStream &lowest_layer() const noexcept { return *this; }
        [[nodiscard]] QuicStream &next_layer() noexcept { return *this; }
        [[nodiscard]] const QuicStream &next_layer() const noexcept { return *this; }

        std::error_code cancel(std::error_code &ec) noexcept;
        std::error_code shutdown(asio::ip::tcp::socket::shutdown_type type, std::error_code &ec) noexcept;
        std::error_code close(std::error_code &ec) noexcept;
        void close() noexcept;

        [[nodiscard]] std::size_t available(std::error_code &ec) const noexcept;
        std::size_t read_some(const asio::mutable_buffer &buffer, std::error_code &ec) noexcept;

        // Async read initiation
        template<typename MutableBufferSequence, typename Token>
        auto async_read_some(const MutableBufferSequence &buffers, Token &&token) {
            auto weak_self = weak_from_this();
            return asio::async_initiate<Token, void(std::error_code, std::size_t)>(
                [weak_self, buffers]<typename T0>(T0 handler) {
                    using HandlerType = std::decay_t<T0>;
                    auto shared_h = std::make_shared<HandlerType>(std::move(handler));
                    // DIAG: a completion handler must fire exactly once. If anything below
                    // fires it twice, the second call resumes an already-completed/destroyed
                    // coroutine, which looks like "random garbage" at the resume site - the
                    // exact symptom under investigation. This guard converts that into a loud,
                    // attributable log instead of a silent segfault.
                    auto fire_count = std::make_shared<std::atomic<int>>(0);
                    auto fire = [shared_h, fire_count](const char *site, std::error_code ec, std::size_t bytes) {
                        int prev = fire_count->fetch_add(1);
                        if (prev != 0) {
                            wavex::log::error(
                                "[QUIC][DIAG] async_read_some: shared_h invoked {} time(s) already! site={} ec={} bytes={} - SUPPRESSING to avoid resuming a dead coroutine",
                                prev + 1, site, ec.message(), bytes);
                            return;
                        }
                        (*shared_h)(ec, bytes);
                    };
                    auto self = weak_self.lock();
                    if (!self) {
                        auto executor = asio::get_associated_executor(*shared_h);
                        asio::post(executor, [fire] {
                            fire("no-self", asio::error::operation_aborted, 0);
                        });
                        return;
                    }
                    auto executor = asio::get_associated_executor(*shared_h, self->get_executor());

                    std::lock_guard lock(self->mtx_);
                    if (!self->is_open_ && self->in_buffer_.empty()) {
                        asio::post(executor, [fire] {
                            fire("not-open", asio::error::eof, 0);
                        });
                        return;
                    }

                    if (!self->in_buffer_.empty()) {
                        std::size_t dest_len = asio::buffer_size(buffers);
                        std::size_t to_copy = (std::min)(dest_len, self->in_buffer_.size());
                        std::size_t copied = 0;
                        for (auto b = asio::buffer_sequence_begin(buffers);
                             b != asio::buffer_sequence_end(buffers) && copied < to_copy; ++b) {
                            asio::mutable_buffer mb(*b);
                            std::size_t chunk = (std::min)(mb.size(), to_copy - copied);
                            auto *dest = static_cast<uint8_t*>(mb.data());
                            for (std::size_t i = 0; i < chunk; ++i) {
                                dest[i] = self->in_buffer_.front();
                                self->in_buffer_.pop_front();
                            }
                            copied += chunk;
                        }
                        asio::post(executor, [fire, copied] {
                            fire("fast-path", std::error_code{}, copied);
                        });
                        return;
                    }

                    if (self->fin_received_) {
                        asio::post(executor, [fire] {
                            fire("fin-received", asio::error::eof, 0);
                        });
                        return;
                    }

                    // Register pending read: wake callback posts to reader's executor where data is copied under lock
                    self->pending_read_ = [weak_self, buffers, fire, executor](std::error_code ec, std::size_t) {
                        asio::post(executor, [weak_self, buffers, fire, ec] {
                            auto s = weak_self.lock();
                            if (!s) {
                                fire("pending-no-self", asio::error::operation_aborted, 0);
                                return;
                            }
                            std::lock_guard lock(s->mtx_);
                            if (ec) {
                                fire("pending-ec", ec, 0);
                                return;
                            }
                            if (s->in_buffer_.empty()) {
                                fire("pending-empty", s->fin_received_ ? asio::error::eof : std::error_code{}, 0);
                                return;
                            }
                            std::size_t dest_len = asio::buffer_size(buffers);
                            std::size_t to_copy = (std::min)(dest_len, s->in_buffer_.size());
                            std::size_t copied = 0;
                            for (auto b = asio::buffer_sequence_begin(buffers);
                                 b != asio::buffer_sequence_end(buffers) && copied < to_copy; ++b) {
                                asio::mutable_buffer mb(*b);
                                std::size_t chunk = (std::min)(mb.size(), to_copy - copied);
                                auto *dest = static_cast<uint8_t*>(mb.data());
                                for (std::size_t i = 0; i < chunk; ++i) {
                                    dest[i] = s->in_buffer_.front();
                                    s->in_buffer_.pop_front();
                                }
                                copied += chunk;
                            }
                            fire("pending-success", std::error_code{}, copied);
                        });
                    };
                },
                token
            );
        }

        // Async write initiation
        template<typename ConstBufferSequence, typename Token>
        auto async_write_some(const ConstBufferSequence &buffers, Token &&token) {
            auto weak_self = weak_from_this();
            return asio::async_initiate<Token, void(std::error_code, std::size_t)>(
                [weak_self, buffers]<typename T0>(T0 handler) {
                    using HandlerType = std::decay_t<T0>;
                    auto shared_h = std::make_shared<HandlerType>(std::move(handler));
                    auto self = weak_self.lock();
                    if (!self) {
                        auto executor = asio::get_associated_executor(*shared_h);
                        asio::post(executor, [shared_h] {
                            (*shared_h)(asio::error::operation_aborted, 0);
                        });
                        return;
                    }
                    auto executor = asio::get_associated_executor(*shared_h, self->get_executor());

                    const std::size_t len = asio::buffer_size(buffers);
                    std::string payload;
                    payload.reserve(len);
                    for (auto b = asio::buffer_sequence_begin(buffers);
                         b != asio::buffer_sequence_end(buffers); ++b) {
                        asio::const_buffer cb(*b);
                        payload.append(static_cast<const char*>(cb.data()), cb.size());
                    }

                    std::error_code ec = self->write_outbound(payload, false);
                    asio::post(executor, [shared_h, ec, len] {
                        (*shared_h)(ec, ec ? 0 : len);
                    });
                },
                token
            );
        }

        // Internal plumbing
        void push_inbound(uint64_t offset, std::string_view data, bool fin);
        void push_inbound(std::string_view data, bool fin);
        std::error_code write_outbound(std::string_view data, bool fin);

        [[nodiscard]] bool has_final_size_error() const noexcept {
            std::lock_guard lock(mtx_);
            return final_size_error_;
        }
        [[nodiscard]] std::optional<uint64_t> final_size() const noexcept {
            std::lock_guard lock(mtx_);
            return final_size_;
        }
        [[nodiscard]] uint64_t recv_offset() const noexcept {
            std::lock_guard lock(mtx_);
            return recv_offset_;
        }
    };

} // namespace wavex::network::quic

#endif // WAVEX_HAS_SSL
