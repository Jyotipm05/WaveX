// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * @file AnyStream.hpp
 * @brief Transport seam: a type-erased, shared-ownership byte stream.
 *
 * Protocols that take over a connection after an HTTP exchange (WebSocket after `101 Switching Protocols`,
 * WebTransport / WebSocket after an HTTP/3 extended CONNECT) must not be templated on the transport the server
 * happened to accept on (plain TCP, TLS 1.3, a QUIC stream). `AnyStream` erases that type. It owns the
 * underlying stream through a `std::shared_ptr`, so copies of an `AnyStream` can be captured by value in
 * spawned coroutines without lifetime hazards (see asio-socket-lifecycle.md §2).
 *
 * Every operation is a free coroutine that copies the shared pointer into its own frame, never a capturing
 * coroutine lambda, so no coroutine frame ever points at a closure that may be destroyed first
 * (asio-socket-lifecycle.md §8).
 */

#pragma once

#if defined(__MINGW32__) || defined(__clang__) || defined(__GNUC__)
#include <cstddef>
#endif
#include <functional>
#include <memory>
#include <system_error>
#include <tuple>
#include <typeinfo>
#include <utility>

#ifndef ASIO_HAS_CO_AWAIT
#define ASIO_HAS_CO_AWAIT 1
#endif
#include <asio/any_io_executor.hpp>
#include <asio/as_tuple.hpp>
#include <asio/awaitable.hpp>
#include <asio/buffer.hpp>
#include <asio/error.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/write.hpp>

namespace wavex::network {
    /**
     * @class AnyStream
     * @brief Copyable handle to a type-erased asynchronous byte stream.
     *
     * Semantics follow Asio's AsyncStream: `read_some` returns as soon as at least one byte (or an error /
     * EOF) is available; `write` writes the whole buffer. `shutdown_send` half-closes the stream (TCP FIN or
     * QUIC STREAM FIN), `cancel` aborts outstanding operations and `close` tears the transport down.
     * All operations are no-ops (or return `asio::error::bad_descriptor`) on a default-constructed handle.
     */
    class AnyStream {
    public:
        // ─── 1. Nested Types & Definitions ───────────────────────────────────
        using read_result = std::pair<std::error_code, std::size_t>;
        using read_fn = std::function<asio::awaitable<read_result>(asio::mutable_buffer)>;
        using write_fn = std::function<asio::awaitable<std::error_code>(asio::const_buffer)>;

        /// The erased operations. Exposed so adapters (e.g. the HTTP/3 DATA-frame tunnel) can compose streams.
        struct operations {
            // ─── 2. Member Variables (minimum padding) ──────────────────────
            std::shared_ptr<void> native{};             ///< the wrapped stream object, if any
            const std::type_info *native_type{nullptr}; ///< dynamic type of `native`
            read_fn read_some{};
            write_fn write{};
            std::function<void()> shutdown_send{};
            std::function<void()> cancel{};
            std::function<void()> close{};
            asio::any_io_executor executor{};
        };

    private:
        // ─── 2. Member Variables ─────────────────────────────────────────────
        std::shared_ptr<operations> ops_{};

    public:
        // ─── 3. Constructors & Destructor ────────────────────────────────────
        AnyStream() = default;

        explicit AnyStream(std::shared_ptr<operations> ops) noexcept : ops_(std::move(ops)) {
        }

        ~AnyStream() = default;

        AnyStream(const AnyStream &) = default;

        AnyStream &operator=(const AnyStream &) = default;

        AnyStream(AnyStream &&) noexcept = default;

        AnyStream &operator=(AnyStream &&) noexcept = default;

        // ─── 4. Member Functions ─────────────────────────────────────────────

        /**
         * @brief Erase a concrete stream held by shared pointer.
         * @param stream   Any type modelling Asio's AsyncReadStream/AsyncWriteStream with `lowest_layer()`.
         * @param executor Executor the stream's I/O is serialized on. Defaults to the stream's own executor.
         *                 Pass the executor of the coroutine that owns the connection when the stream object
         *                 lives on a different reactor (e.g. IOCP sockets that stay on the master io_context).
         */
        template<typename Stream>
        static AnyStream wrap(std::shared_ptr<Stream> stream, asio::any_io_executor executor = {});

        [[nodiscard]] bool valid() const noexcept { return ops_ && ops_->read_some && ops_->write; }
        explicit operator bool() const noexcept { return valid(); }

        [[nodiscard]] asio::any_io_executor get_executor() const noexcept {
            return ops_ ? ops_->executor : asio::any_io_executor{};
        }

        [[nodiscard]] const std::shared_ptr<operations> &ops() const noexcept { return ops_; }

        /// Read at least one byte. `{eof, 0}` signals an orderly end of the peer's byte stream.
        [[nodiscard]] asio::awaitable<read_result> read_some(const asio::mutable_buffer buffer) const {
            if (!ops_ || !ops_->read_some) co_return read_result{asio::error::bad_descriptor, 0};
            co_return co_await ops_->read_some(buffer);
        }

        /// Write the whole buffer. The caller must keep the bytes alive until the awaitable completes.
        [[nodiscard]] asio::awaitable<std::error_code> write(const asio::const_buffer buffer) const {
            if (!ops_ || !ops_->write) co_return std::error_code(asio::error::bad_descriptor);
            co_return co_await ops_->write(buffer);
        }

        void shutdown_send() const {
            if (ops_ && ops_->shutdown_send) ops_->shutdown_send();
        }

        void cancel() const {
            if (ops_ && ops_->cancel) ops_->cancel();
        }

        void close() const {
            if (ops_ && ops_->close) ops_->close();
        }

        /// The wrapped object when its dynamic type is exactly `T`, otherwise nullptr.
        template<typename T>
        [[nodiscard]] std::shared_ptr<T> native() const noexcept {
            if (ops_ && ops_->native_type && *ops_->native_type == typeid(T)) {
                return std::static_pointer_cast<T>(ops_->native);
            }
            return nullptr;
        }
    };

    namespace detail {
        template<typename Stream>
        asio::awaitable<AnyStream::read_result> any_stream_read_some(std::shared_ptr<Stream> s,
                                                                     const asio::mutable_buffer buffer) {
            auto [ec, n] = co_await s->async_read_some(buffer, asio::as_tuple(asio::use_awaitable));
            co_return AnyStream::read_result{ec, n};
        }

        template<typename Stream>
        asio::awaitable<std::error_code> any_stream_write(std::shared_ptr<Stream> s, const asio::const_buffer buffer) {
            auto [ec, n] = co_await asio::async_write(*s, buffer, asio::as_tuple(asio::use_awaitable));
            (void) n;
            co_return ec;
        }
    } // namespace detail

    template<typename Stream>
    AnyStream AnyStream::wrap(std::shared_ptr<Stream> stream, asio::any_io_executor executor) {
        auto ops = std::make_shared<operations>();
        if (!stream) return AnyStream(std::move(ops));

        ops->executor = executor ? std::move(executor) : asio::any_io_executor(stream->get_executor());
        ops->native = stream;
        ops->native_type = &typeid(Stream);

        // `operations` co-owns the stream (through `native` and these closures), so the stream lives as long
        // as any AnyStream copy does. The read/write closures only forward to free coroutines that take their
        // own copy of the pointer; the coroutine frames never refer back to the closure objects.
        ops->read_some = [stream](const asio::mutable_buffer& b) {
            return detail::any_stream_read_some(stream, b);
        };
        ops->write = [stream](const asio::const_buffer& b) {
            return detail::any_stream_write(stream, b);
        };
        ops->shutdown_send = [stream] {
            if constexpr (std::error_code ec; requires { stream->lowest_layer().shutdown(asio::ip::tcp::socket::shutdown_send, ec); }) {
                std::ignore = stream->lowest_layer().shutdown(asio::ip::tcp::socket::shutdown_send, ec);
            }
        };
        ops->cancel = [stream] {
            std::error_code ec;
            std::ignore = stream->lowest_layer().cancel(ec);
        };
        ops->close = [stream] {
            std::error_code ec;
            std::ignore = stream->lowest_layer().cancel(ec);
            std::ignore = stream->lowest_layer().close(ec);
        };
        return AnyStream(std::move(ops));
    }
} // namespace wavex::network
