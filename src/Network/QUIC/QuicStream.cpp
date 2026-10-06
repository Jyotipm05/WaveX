#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL

#include <wavex/Network/QUIC/QuicStream.hpp>
#include <wavex/Network/QUIC/QuicConnection.hpp>

#if defined(min)
#undef min
#endif
#if defined(max)
#undef max
#endif

#include <algorithm>
#include <cstring>
#include <system_error>
#include <asio/system_executor.hpp>

namespace wavex::network::quic {

    QuicStream::QuicStream(const std::shared_ptr<QuicConnection> &conn, const uint64_t stream_id,
                           asio::any_io_executor executor) noexcept
        : stream_id_(stream_id), conn_(conn), executor_(std::move(executor)) {
    }

    QuicStream::~QuicStream() {
        close();
    }

    asio::any_io_executor QuicStream::get_executor() const noexcept {
        if (executor_) return executor_;
        if (auto c = conn_.lock()) {
            if (auto conn_ex = c->get_executor()) return conn_ex;
        }
        return asio::any_io_executor(asio::system_executor{});
    }

    bool QuicStream::is_open() const noexcept {
        std::lock_guard lock(mtx_);
        return is_open_;
    }

    bool QuicStream::is_fin_received() const noexcept {
        std::lock_guard lock(mtx_);
        return fin_received_;
    }

    bool QuicStream::is_fin_sent() const noexcept {
        std::lock_guard lock(mtx_);
        return fin_sent_;
    }

    bool QuicStream::is_finished() const noexcept {
        std::lock_guard lock(mtx_);
        return (fin_sent_ || !is_open_) && (fin_received_ || !is_open_);
    }

    void QuicStream::notify_finished_if_needed() {
        if (is_finished()) {
            if (auto c = conn_.lock()) {
                c->close_stream(stream_id_);
            }
        }
    }

    std::error_code QuicStream::cancel(std::error_code &ec) noexcept {
        ec.clear();
        std::lock_guard lock(mtx_);
        if (pending_read_) {
            auto cb = std::move(*pending_read_);
            pending_read_.reset();
            cb(asio::error::operation_aborted, 0);
        }
        return ec;
    }

    std::error_code QuicStream::shutdown(const asio::ip::tcp::socket::shutdown_type type,
                                         std::error_code &ec) noexcept {
        ec.clear();
        bool need_fin = false; {
            std::lock_guard lock(mtx_);
            if (type == asio::ip::tcp::socket::shutdown_send || type == asio::ip::tcp::socket::shutdown_both) {
                if (!fin_sent_) {
                    fin_sent_ = true;
                    need_fin = true;
                }
            }
            if (type == asio::ip::tcp::socket::shutdown_receive || type == asio::ip::tcp::socket::shutdown_both) {
                fin_received_ = true;
            }
        }
        if (need_fin) {
            if (auto conn = conn_.lock()) {
                conn->queue_stream_data(stream_id_, "", true);
            }
        }
        notify_finished_if_needed();
        return ec;
    }

    std::error_code QuicStream::close(std::error_code &ec) noexcept {
        ec.clear();
        close();
        return ec;
    }

    void QuicStream::close() noexcept {
        ReadCallback cb;
        bool need_fin = false; {
            std::lock_guard lock(mtx_);
            if (!is_open_) return;
            is_open_ = false;
            if (!fin_sent_) {
                fin_sent_ = true;
                need_fin = true;
            }
            if (pending_read_) {
                cb = std::move(*pending_read_);
                pending_read_.reset();
            }
        }
        if (need_fin) {
            if (auto conn = conn_.lock()) {
                conn->queue_stream_data(stream_id_, "", true);
            }
        }
        if (cb) {
            cb(asio::error::connection_reset, 0);
        }
        notify_finished_if_needed();
    }

    std::size_t QuicStream::available(std::error_code &ec) const noexcept {
        ec.clear();
        std::lock_guard lock(mtx_);
        return in_buffer_.size();
    }

    std::size_t QuicStream::read_some(const asio::mutable_buffer &buffer, std::error_code &ec) noexcept {
        ec.clear();
        std::lock_guard lock(mtx_);
        if (in_buffer_.empty()) {
            if (fin_received_ || !is_open_) {
                ec = asio::error::eof;
            }
            return 0;
        }

        const std::size_t to_read = (std::min)(buffer.size(), in_buffer_.size());
        auto *dest = static_cast<uint8_t *>(buffer.data());
        for (std::size_t i = 0; i < to_read; ++i) {
            dest[i] = in_buffer_.front();
            in_buffer_.pop_front();
        }
        return to_read;
    }

    void QuicStream::push_inbound(const std::string_view data, const bool fin) {
        push_inbound(recv_offset_, data, fin);
    }

    void QuicStream::push_inbound(uint64_t offset, std::string_view data, const bool fin) {
        ReadCallback cb;
        std::size_t available = 0;
        std::error_code ec;

        {
            std::lock_guard lock(mtx_);

            // 1. RFC 9000 §4.5 Final Size Validation
            if (fin) {
                const uint64_t expected_final = offset + data.size();
                if (final_size_.has_value()) {
                    if (*final_size_ != expected_final) {
                        final_size_error_ = true;
                        return;
                    }
                } else {
                    if (expected_final < recv_offset_) {
                        final_size_error_ = true;
                        return;
                    }
                    final_size_ = expected_final;
                }
            } else if (final_size_.has_value()) {
                if (offset + data.size() > *final_size_) {
                    final_size_error_ = true;
                    return;
                }
            }

            // 2. Check for duplicate or partially overlapping data against recv_offset_
            if (offset + data.size() <= recv_offset_) {
                // Entire chunk is behind recv_offset_
                if (final_size_.has_value() && recv_offset_ >= *final_size_) {
                    fin_received_ = true;
                    if (pending_read_ && in_buffer_.empty()) {
                        cb = std::move(*pending_read_);
                        pending_read_.reset();
                        ec = asio::error::eof;
                    }
                }
            } else {
                if (offset < recv_offset_) {
                    // Trim duplicate prefix
                    const std::size_t trim = static_cast<std::size_t>(recv_offset_ - offset);
                    data.remove_prefix(trim);
                    offset = recv_offset_;
                }

                auto append_bytes = [&](std::string_view chunk) {
                    if (chunk.empty()) return;
                    for (const char c : chunk) {
                        in_buffer_.push_back(static_cast<uint8_t>(c));
                    }
                    recv_offset_ += chunk.size();
                };

                if (offset == recv_offset_) {
                    append_bytes(data);

                    // Drain contiguous chunks from pending_inbound_
                    while (!pending_inbound_.empty()) {
                        auto &front = pending_inbound_.front();
                        if (front.offset > recv_offset_) {
                            break; // Gap encountered
                        }
                        if (front.offset + front.data.size() > recv_offset_) {
                            const std::size_t trim = static_cast<std::size_t>(recv_offset_ - front.offset);
                            std::string_view remaining = std::string_view(front.data).substr(trim);
                            append_bytes(remaining);
                        }
                        pending_inbound_.erase(pending_inbound_.begin());
                    }

                    if (final_size_.has_value() && recv_offset_ >= *final_size_) {
                        fin_received_ = true;
                    }

                    available = in_buffer_.size();
                    if (pending_read_ && (available > 0 || fin_received_)) {
                        cb = std::move(*pending_read_);
                        pending_read_.reset();
                        if (available == 0 && fin_received_) {
                            ec = asio::error::eof;
                        }
                    }
                } else {
                    // offset > recv_offset_: Out-of-order gap!
                    std::size_t current_pending = 0;
                    for (const auto &c : pending_inbound_) current_pending += c.data.size();
                    if (current_pending + data.size() <= 16 * 1024 * 1024) {
                        auto it = std::lower_bound(
                            pending_inbound_.begin(), pending_inbound_.end(), offset,
                            [](const StreamChunk &c, uint64_t off) {
                                return c.offset < off;
                            }
                        );
                        bool insert = true;
                        if (it != pending_inbound_.end() && it->offset == offset) {
                            if (it->data.size() >= data.size()) {
                                insert = false;
                            } else {
                                it->data = std::string(data);
                                insert = false;
                            }
                        }
                        if (insert) {
                            pending_inbound_.insert(it, StreamChunk(offset, std::string(data)));
                        }
                    }
                }
            }
        }

        if (cb) {
            cb(ec, available);
        }
        notify_finished_if_needed();
    }

    std::error_code QuicStream::write_outbound(const std::string_view data, const bool fin) {
        if (auto conn = conn_.lock()) {
            if (fin) {
                std::lock_guard lock(mtx_);
                fin_sent_ = true;
            }
            conn->queue_stream_data(stream_id_, data, fin);
            if (fin) {
                notify_finished_if_needed();
            }
            return {};
        }
        return asio::error::not_connected;
    }

} // namespace wavex::network::quic

#endif // WAVEX_HAS_SSL
