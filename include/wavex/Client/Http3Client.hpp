// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
/**
 * @file Http3Client.hpp
 * @brief HTTP/3 client (RFC 9114) over WaveX's own QUIC transport.
 *
 * One `Http3Client` is one QUIC connection to one origin. It opens the HTTP/3 control stream (SETTINGS) and the
 * two QPACK streams, then maps every request to its own bidirectional stream, so any number of requests can be in
 * flight at the same time on the same connection (`co_await` them from separate coroutines or use `when_all`
 * style fan-out). The QPACK dynamic table is not used (capacity 0), which keeps header blocks independent of
 * each other: no head-of-line blocking between requests.
 *
 * The host name is resolved with WaveX's native DNS resolver.
 *
 * @code
 * wavex::client::Http3Client c(co_await asio::this_coro::executor);
 * if (auto ec = co_await c.connect("example.com", 443); !ec) {
 *     auto res = co_await c.send(wavex::client::ClientRequest(wavex::client::method::GET, "https://example.com/"));
 *     if (res) std::cout << res->status_code() << "\n";
 * }
 * @endcode
 */
#pragma once

#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL

#include <wavex/Base/Executor.hpp>
#include <wavex/Base/Task.hpp>
#include <wavex/Client/HttpClient.hpp>

#include <chrono>
#include <cstdint>
#include <expected>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <system_error>
#include <vector>

namespace wavex::network::quic {
    class QuicClient;
    class QuicStream;
}

namespace wavex::client {
    namespace detail {
        struct Http3State;
    }

    /// HTTP/3 client errors (`std::error_code` with `http3_category()`).
    enum class http3_errc {
        not_connected = 1, ///< `connect()` was not called, failed, or the connection was lost / told to go away
        handshake_failed = 2, ///< QUIC/TLS handshake did not complete
        timeout = 3, ///< no complete response within `request_timeout`
        protocol_error = 4, ///< malformed HTTP/3 response
        response_too_large = 5,
        stream_reset = 6, ///< the server ended the stream before a complete response
    };

    [[nodiscard]] const std::error_category &http3_category() noexcept;

    [[nodiscard]] inline std::error_code make_error_code(const http3_errc e) noexcept {
        return {static_cast<int>(e), http3_category()};
    }

    struct Http3Options {
        bool verify_peer{false}; ///< verify the server certificate (see ClientOptions::verify_peer)
        std::chrono::milliseconds request_timeout{30000};
        std::size_t max_response_size{64u * 1024 * 1024}; ///< whole-response cap (headers + body)
    };

    class Http3Client {
    public:
        explicit Http3Client(const wavex::executor &ex, Http3Options options = {});

        Http3Client(const Http3Client &) = delete;
        Http3Client &operator=(const Http3Client &) = delete;
        ~Http3Client();

        /// Resolve `host`, run the QUIC handshake (ALPN "h3") and set up the control streams.
        [[nodiscard]] wavex::task<std::error_code> connect(std::string host, uint16_t port = 443);

        /// Send one request (an absolute `https://` URL) and wait for the complete response.
        [[nodiscard]] wavex::task<std::expected<ClientResponse, std::error_code> > send(const ClientRequest &req);

        /// Lower-level form used by `HttpClient`: the URL has already been split.
        [[nodiscard]] wavex::task<std::expected<ClientResponse, std::error_code> > exchange(
            const ClientRequest &req, std::string authority, std::string path_target,
            const BodySink *sink = nullptr, const HeadHook *head_hook = nullptr);

        /// Like `send`, but the body is delivered to `sink` as it arrives (see `BodySink`). The response carries
        /// status and headers; `body_error()` says whether the body arrived completely.
        [[nodiscard]] wavex::task<std::expected<ClientResponse, std::error_code> > send_streaming(
            const ClientRequest &req, BodySink sink);

        /// True while the connection is up and the server has not sent GOAWAY.
        [[nodiscard]] bool is_open() const noexcept;

        /// The server's SETTINGS_MAX_FIELD_SECTION_SIZE, or 0 if not (yet) received.
        [[nodiscard]] uint64_t peer_max_field_section_size() const noexcept;

        void close();

    private:
        wavex::executor ex_;
        Http3Options options_;
        std::unique_ptr<network::quic::QuicClient> quic_;
        std::shared_ptr<detail::Http3State> state_;
        std::vector<std::shared_ptr<network::quic::QuicStream> > local_uni_streams_;
    };


    /**
     * @class Http3Pool
     * @brief Keeps QUIC connections open between requests (opt-in via `ClientOptions::h3_pool`).
     *
     * One connection per (host, port, verify_peer) is shared by every request to that origin; HTTP/3 multiplexes
     * them as streams, so concurrent requests need no extra handshakes. A connection that has closed or received
     * GOAWAY is replaced on the next `acquire`. Use the pool from one io_context: a connection belongs to the
     * executor that created it, and a request from another executor opens a connection of its own.
     */
    class Http3Pool {
    public:
        Http3Pool() = default;
        Http3Pool(const Http3Pool &) = delete;
        Http3Pool &operator=(const Http3Pool &) = delete;

        /// An open connection to `host:port`. `force_new` discards the pooled one first.
        [[nodiscard]] wavex::task<std::expected<std::shared_ptr<Http3Client>, std::error_code> > acquire(
            wavex::executor ex, std::string host, uint16_t port, Http3Options options, bool force_new = false);

        /// Closes every pooled connection.
        void close_all();

        [[nodiscard]] std::size_t size() const;

    private:
        struct Entry {
            wavex::executor ex;
            std::shared_ptr<Http3Client> client;
        };

        mutable std::mutex mu_;
        std::map<std::string, Entry> entries_;
    };
} // namespace wavex::client

template<>
struct std::is_error_code_enum<wavex::client::http3_errc> : std::true_type {};

#endif // WAVEX_HAS_SSL
