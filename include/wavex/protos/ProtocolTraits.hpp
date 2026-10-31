// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
/**
 * @file ProtocolTraits.hpp
 * @brief Protocol session policy seam — encapsulates protocol-specific connection
 *        behavior (preface, persistence, response preparation, ALPN) decoupled from Server.
 *
 * Server<Codec, RouterType> speaks only to concepts and protocol_traits<Codec>, never
 * directly naming or coupling to specific codecs (http1codec, http2codec, or future protocols).
 */

#pragma once

#include <memory>
#include <string>
#include <string_view>
#ifndef ASIO_HAS_CO_AWAIT
#define ASIO_HAS_CO_AWAIT 1
#endif
#if defined(__MINGW32__) || defined(__clang__) || defined(__GNUC__)
#include <cstddef>
#endif
#if defined(__MINGW32__) && !defined(ASIO_HAS_PTHREADS)
#define ASIO_HAS_PTHREADS 1
#endif
#include <asio/awaitable.hpp>
#include <asio/as_tuple.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/buffer.hpp>
#include <asio/redirect_error.hpp>
#include <asio/this_coro.hpp>
#include <wavex/Network/AnyStream.hpp>

#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
#include <openssl/ssl.h>
#endif

namespace wavex::protos {
    /// Protocol-neutral reasons for which the server kernel must reject a request itself.
    enum class protocol_error {
        bad_request,         ///< the request could not be parsed
        payload_too_large,   ///< the request exceeded the configured size limit
        limits_exceeded,     ///< the request exceeded a structural limit (see request_limits)
        internal_error       ///< the handler threw
    };

    /// Structural limits the server hands to the protocol policy; what they count is up to the protocol.
    struct request_limits {
        std::size_t max_headers{0};
        std::size_t max_query_params{0};
    };

    namespace detail {
        /// Shared by the HTTP specializations: they differ only in framing, not in how errors are phrased.
        template<typename Response>
        void write_http_error(Response &res, const protocol_error e) {
            switch (e) {
                case protocol_error::bad_request: res.status(400).send("Bad Request"); break;
                case protocol_error::payload_too_large: res.status(413).send("Payload Too Large"); break;
                case protocol_error::limits_exceeded: res.status(431).send("Request Header Fields Too Large"); break;
                case protocol_error::internal_error:
                    res.status(500);
                    if constexpr (requires { res.set("Content-Type", "text/plain"); }) {
                        res.set("Content-Type", "text/plain");
                    }
                    res.send("Internal Server Error");
                    break;
            }
        }

        template<typename Request>
        bool http_exceeds_limits(const Request &req, const request_limits &lim) noexcept {
            return req.has_query_param_overflow() || req.query.size() > lim.max_query_params ||
                   req.header_count() > lim.max_headers;
        }

        template<typename Response>
        void http_default_status(Response &res, const bool route_found) {
            res.status(route_found ? 200 : 404);
        }

        template<typename Response>
        void http_write_not_found(Response &res, const std::string &body, const std::string &content_type) {
            res.status(404);
            if (!content_type.empty()) {
                res.set("Content-Type", content_type);
            }
            res.send(body);
        }

        /**
         * Shared by the HTTP/1.x and HTTP/3 specializations: whether the response hands the connection to a
         * takeover handler installed with `res.upgrade(...)`. Only a response that really agreed to switch
         * protocols qualifies — `101 Switching Protocols` on HTTP/1.1 (RFC 9110 §15.2.2), a 2xx answer to an
         * (extended) CONNECT on HTTP/3 (RFC 9220, WebTransport). A handler left on any other response is
         * ignored and the request finishes normally. Synchronous so that ordinary requests pay one branch.
         */
        template<typename Request, typename Response>
        bool http_wants_takeover(const Request &req, const Response &res) noexcept {
            if constexpr (requires { res.has_upgrade(); res.status_code(); req.version_major(); }) {
                if (!res.has_upgrade()) [[likely]] return false;
                const unsigned code = res.status_code();
                return req.version_major() >= 2 ? (code >= 200 && code < 300) : (code == 101);
            } else {
                return false;
            }
        }

        /// Run the takeover handler on the connection's own executor with the transport type-erased.
        template<typename Stream, typename Request, typename Response>
        asio::awaitable<void> http_take_over(std::shared_ptr<Stream> stream, Request &, Response &res,
                                             std::string unread) {
            auto takeover = res.take_upgrade();
            if (!takeover) co_return;
            auto executor = co_await asio::this_coro::executor;
            co_await takeover(wavex::network::AnyStream::wrap(std::move(stream), std::move(executor)),
                              std::move(unread));
        }
    } // namespace detail

    /**
     * @struct protocol_traits
     * @brief Primary template: conservative defaults for a simple,
     *        request-response-over-persistent-connection protocol.
     *
     * Customization points:
     *  - has_connection_preface / on_connection_start  (Protocol opening exchange, e.g. HTTP/2 PRI + SETTINGS)
     *  - keep_alive()                                   (Persistence decision per request)
     *  - prepare_response()                             (Protocol-specific response headers/state)
     *  - configure_alpn()                               (TLS ALPN selector registration)
     *  - classify_parse_error()                         (optional: parse failure -> protocol_error, default bad_request)
     *  - exceeds_limits() / write_error() / set_default_status() / write_not_found() / request_label()
     *                                                   (the kernel never touches response fields)
     *  - make_transport_listener()                      (optional: an extra listener, e.g. QUIC/UDP)
     *  - wants_takeover() / take_over()                 (optional: connection takeover after a protocol
     *                                                    switch, e.g. WebSocket / WebTransport)
     */
    template<typename Codec>
    struct protocol_traits {
        /// Connection-scoped session context (e.g. stateful compression tables)
        struct connection_context {
        };

        template<typename Stream>
        static auto &get_connection_context(Stream &, connection_context &fallback) noexcept {
            return fallback;
        }

        /// True if the protocol requires a connection-level opening exchange.
        static constexpr bool has_connection_preface = false;

        /// True if this protocol uses TCP transport.
        static constexpr bool has_tcp_transport = true;

        /// True if this protocol uses QUIC/UDP transport alongside TCP (e.g. HTTP/3).
        static constexpr bool has_quic_transport = false;

        /**
         * @brief Called once per connection after transport handshake, before the request loop.
         * @param stream     The connected stream (tcp::socket, ssl::stream, etc.).
         * @param stream_buf Receive buffer; implementations may pre-read into it.
         * @return true to continue, false to drop the connection.
         */
        template<typename Stream>
        static asio::awaitable<bool> on_connection_start([[maybe_unused]] Stream &stream, [[maybe_unused]] std::string &stream_buf) {
            co_return true;
        }

        /**
         * @brief Decide whether the connection stays open after this request.
         */
        template<typename Request>
        static bool keep_alive(const Request &req, const unsigned request_count, const unsigned max_requests) {
            return req.should_keep_alive() && (request_count < max_requests);
        }

        /**
         * @brief Hook to apply protocol-specific response state before dispatch.
         */
        template<typename Request, typename Response>
        static void prepare_response(const Request &, Response &, bool,
                                     unsigned, unsigned, unsigned short = 0) {
        }


        /// True if the request breaks a structural limit. Default: protocols without such limits never do.
        template<typename Request>
        static bool exceeds_limits(const Request &, const request_limits &) noexcept {
            return false;
        }

        /// Fill `res` for a kernel-level rejection. Default: leave it empty (protocol decides how to signal).
        template<typename Response>
        static void write_error(Response &, protocol_error) {
        }

        /// Called before dispatch with whether a route matched. Default: nothing to set.
        template<typename Response>
        static void set_default_status(Response &, bool) {
        }

        /// Fill `res` with the server-level "no route" reply (Server::set_not_found). Default: nothing.
        template<typename Response>
        static void write_not_found(Response &, const std::string &/*body*/, const std::string &/*media_type*/) {
        }

        /// Short text identifying the request in server log lines (e.g. its path). Default: empty.
        template<typename Request>
        static std::string_view request_label(const Request &) noexcept {
            return {};
        }

        /**
         * @brief Asked once the response is on the wire: does the connection now belong to another protocol?
         * Default: never.
         */
        template<typename Request, typename Response>
        static bool wants_takeover(const Request &, const Response &) noexcept {
            return false;
        }

        /**
         * @brief Hand the connection over (only called when wants_takeover() said yes). The server stops
         *        serving the connection afterwards and tears the transport down.
         * @param stream The connection's transport (shared ownership).
         * @param unread Bytes already received past the end of this request.
         */
        template<typename Stream, typename Request, typename Response>
        static asio::awaitable<void> take_over([[maybe_unused]] std::shared_ptr<Stream> stream, Request &, Response &,
                                               [[maybe_unused]]std::string unread) {
            co_return;
        }

#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
        /// Register the ALPN selection callback for this protocol (server-side).
        static void configure_alpn(SSL_CTX *) {
        }
#endif
    };
} // namespace wavex::protos

// ─── HTTP/1.x Specialization ─────────────────────────────────────────────────
#include <wavex/protos/http/http1codec.hpp>

template<>
struct wavex::protos::protocol_traits<wavex::protos::http::http1codec> {
    struct connection_context {
    };

    template<typename Stream>
    static auto &get_connection_context(Stream &, connection_context &fallback) noexcept {
        return fallback;
    }

    static constexpr bool has_connection_preface = false;
    static constexpr bool has_tcp_transport = true;
    static constexpr bool has_quic_transport = false;

    template<typename Request>
    static bool exceeds_limits(const Request &req, const request_limits &lim) noexcept {
        return detail::http_exceeds_limits(req, lim);
    }

    template<typename Response>
    static void write_error(Response &res, const protocol_error e) {
        detail::write_http_error(res, e);
    }

    template<typename Response>
    static void set_default_status(Response &res, const bool route_found) {
        detail::http_default_status(res, route_found);
    }

    template<typename Response>
    static void write_not_found(Response &res, const std::string &body, const std::string &media_type) {
        detail::http_write_not_found(res, body, media_type);
    }

    template<typename Request>
    static std::string_view request_label(const Request &req) noexcept {
        return req.path();
    }

    template<typename Stream>
    static asio::awaitable<bool> on_connection_start(Stream &, std::string &) {
        co_return true;
    }

    template<typename Request>
    static bool keep_alive(const Request &req, const unsigned request_count, const unsigned max_requests) {
        return req.should_keep_alive() && (request_count < max_requests);
    }

    /// RFC 6455 / RFC 9110 §7.8: after `101 Switching Protocols` the connection belongs to the new protocol.
    template<typename Request, typename Response>
    static bool wants_takeover(const Request &req, const Response &res) noexcept {
        return detail::http_wants_takeover(req, res);
    }

    template<typename Stream, typename Request, typename Response>
    static asio::awaitable<void> take_over(std::shared_ptr<Stream> stream, Request &req, Response &res,
                                           std::string unread) {
        return detail::http_take_over(std::move(stream), req, res, std::move(unread));
    }

    template<typename Request, typename Response>
    static void prepare_response(const Request &, Response &res, const bool keep,
                                 const unsigned timeout_sec, const unsigned remaining,
                                 const unsigned short alt_svc_port = 0) {
        if constexpr (requires { res.status_code(); }) {
            // A protocol switch carries its own `Connection: Upgrade`; keep-alive headers would contradict it.
            if (res.status_code() == 101) return;
        }
        if (keep) {
            res.set("Connection", "keep-alive");
            res.set("Keep-Alive",
                    "timeout=" + std::to_string(timeout_sec) + ", max=" + std::to_string(remaining));
        } else {
            res.set("Connection", "close");
        }
        if (alt_svc_port > 0 && !res.header("alt-svc")) {
            const auto port_str = std::to_string(alt_svc_port);
            res.set("alt-svc", "h3=\":" + port_str + "\"; ma=2592000,h3-29=\":" + port_str + "\"; ma=2592000");
        }
    }

#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
    static void configure_alpn(SSL_CTX *ctx) {
        SSL_CTX_set_alpn_select_cb(
            ctx,
            [](SSL *, const unsigned char **out, unsigned char *outLen,
               const unsigned char *in, const unsigned int inLen, void *) -> int {
                const unsigned char *p = in;
                while (p < in + inLen) {
                    const unsigned char len = *p++;
                    if (len == 8 && std::memcmp(p, "http/1.1", 8) == 0) {
                        *out = p;
                        *outLen = 8;
                        return SSL_TLSEXT_ERR_OK;
                    }
                    p += len;
                }
                return SSL_TLSEXT_ERR_NOACK;
            },
            nullptr);
    }
#endif
}; // namespace wavex::protos

// ─── HTTP/2 Specialization ───────────────────────────────────────────────────
#include <wavex/protos/http/http2codec.hpp>

namespace wavex::protos::http::http2 {
    // Defined in http2session.hpp (included at the end of this header).
    template<typename Stream, typename Services>
    class server_session;
}

template<>
struct wavex::protos::protocol_traits<wavex::protos::http::http2codec> {
    using connection_context = http::http2::connection_context;

    template<typename Stream>
    static auto &get_connection_context(Stream &, connection_context &fallback) noexcept {
        return fallback;
    }

    static constexpr bool has_connection_preface = true;
    static constexpr bool has_tcp_transport = true;
    static constexpr bool has_quic_transport = false;

    template<typename Request>
    static bool exceeds_limits(const Request &req, const request_limits &lim) noexcept {
        return detail::http_exceeds_limits(req, lim);
    }

    template<typename Response>
    static void write_error(Response &res, const protocol_error e) {
        detail::write_http_error(res, e);
    }

    /// Maps a failed parse to the error the client is told about (the kernel defaults to bad_request).
    template<typename Result>
    static protocol_error classify_parse_error(const Result r) noexcept {
        return r == wavex::protos::http::http2codec::result::headers_too_large ? protocol_error::limits_exceeded : protocol_error::bad_request;
    }

    template<typename Response>
    static void set_default_status(Response &res, const bool route_found) {
        detail::http_default_status(res, route_found);
    }

    template<typename Response>
    static void write_not_found(Response &res, const std::string &body, const std::string &media_type) {
        detail::http_write_not_found(res, body, media_type);
    }

    template<typename Request>
    static std::string_view request_label(const Request &req) noexcept {
        return req.path();
    }

    /**
         * @brief RFC 9113 §3.4: validate the client preface (24-byte PRI) and strip it from stream_buf, so the
         *        session only sees frames. The server's SETTINGS are sent by the session (serve_connection),
         *        which also acknowledges the client's SETTINGS when they arrive.
         */
    template<typename Stream>
    static asio::awaitable<bool> on_connection_start(Stream &stream, std::string &stream_buf) {
        namespace h2 = wavex::protos::http::http2;
        while (stream_buf.size() < h2::CONNECTION_PREFACE.size()) {
            char buf[4096];
            auto [ec, n] = co_await stream.async_read_some(
                asio::buffer(buf), asio::as_tuple(asio::use_awaitable));
            if (ec || n == 0) co_return false;
            stream_buf.append(buf, n);
        }
        if (!stream_buf.starts_with(h2::CONNECTION_PREFACE)) co_return false;
        stream_buf.erase(0, h2::CONNECTION_PREFACE.size());
        co_return true;
    }

    /**
     * @brief HTTP/2 drives its connection itself: streams are multiplexed, flow controlled and may stay open
     *        as tunnels (RFC 8441), which the one-request-at-a-time loop cannot express. The server hands the
     *        connection over after the preface; requests still go through the server's shared pipeline via
     *        `services.handle()`.
     */
    template<typename Stream, typename Services>
    static asio::awaitable<void> serve_connection(std::shared_ptr<Stream> stream, std::string buffered,
                                                  Services &services) {
        auto session = std::make_shared<http::http2::server_session<Stream, Services> >(
            std::move(stream), std::move(buffered), services);
        co_await session->run();
    }

    /// RFC 8441: a 2xx answer to an extended CONNECT turns the stream into a tunnel (used by the session).
    template<typename Request, typename Response>
    static bool wants_takeover(const Request &req, const Response &res) noexcept {
        return detail::http_wants_takeover(req, res);
    }

    /// HTTP/2 connections are always persistent and multiplexed (RFC 7540 §8.1.2.2).
    template<typename Request>
    static bool keep_alive(const Request &, unsigned, unsigned) {
        return true;
    }

    /// RFC 7540 §8.1.2.2 forbids Connection/Keep-Alive headers in HTTP/2.
    template<typename Request, typename Response>
    static void prepare_response(const Request &, Response &res, bool, unsigned, unsigned,
                                 const unsigned short alt_svc_port = 0) {
        if (alt_svc_port > 0 && !res.header("alt-svc")) {
            const auto port_str = std::to_string(alt_svc_port);
            res.set("alt-svc", "h3=\":" + port_str + "\"; ma=2592000,h3-29=\":" + port_str + "\"; ma=2592000");
        }
    }

#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
    static void configure_alpn(SSL_CTX *ctx) {
        SSL_CTX_set_alpn_select_cb(
            ctx,
            [](SSL *, const unsigned char **out, unsigned char *outLen,
               const unsigned char *in, const unsigned int inLen, void *) -> int {
                const unsigned char *p = in;
                const unsigned char *http11_start = nullptr;
                while (p < in + inLen) {
                    const unsigned char len = *p++;
                    if (len == 2 && p[0] == 'h' && p[1] == '2') {
                        *out = p;
                        *outLen = 2;
                        return SSL_TLSEXT_ERR_OK;
                    }
                    if (len == 8 && std::memcmp(p, "http/1.1", 8) == 0) {
                        http11_start = p;
                    }
                    p += len;
                }
                if (http11_start) {
                    *out = http11_start;
                    *outLen = 8;
                    return SSL_TLSEXT_ERR_OK;
                }
                return SSL_TLSEXT_ERR_ALERT_FATAL;
            },
            nullptr);
    }
#endif
}; // namespace wavex::protos

// ─── HTTP/3 Specialization ───────────────────────────────────────────────────
#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
#include <wavex/protos/http/http3codec.hpp>
#include <wavex/Network/QUIC/QuicListener.hpp>

template<>
struct wavex::protos::protocol_traits<wavex::protos::http::http3codec> {
    using connection_context = http::http3::connection_context;

    // RFC 9114: HTTP/3 does not define a connection preface on request streams.
    static constexpr bool has_connection_preface = false;

    // RFC 9114: HTTP/3 is defined exclusively over QUIC (UDP) and has no TCP framing.
    static constexpr bool has_tcp_transport = false;

    // HTTP/3 requires a QUIC/UDP listener alongside the TCP/TLS listener.
    static constexpr bool has_quic_transport = true;

    /// The generic server advertises Alt-Svc on its own port when this is set (see Server::run).
    static constexpr bool advertises_alt_svc_by_default = true;

    template<typename Request>
    static bool exceeds_limits(const Request &req, const request_limits &lim) noexcept {
        return detail::http_exceeds_limits(req, lim);
    }

    template<typename Response>
    static void write_error(Response &res, const protocol_error e) {
        detail::write_http_error(res, e);
    }

    template<typename Response>
    static void set_default_status(Response &res, const bool route_found) {
        detail::http_default_status(res, route_found);
    }

    template<typename Response>
    static void write_not_found(Response &res, const std::string &body, const std::string &media_type) {
        detail::http_write_not_found(res, body, media_type);
    }

    template<typename Request>
    static std::string_view request_label(const Request &req) noexcept {
        return req.path();
    }

    /// The QUIC/UDP listener for this protocol. The generic server only sees a TransportListener.
    template<typename Host>
    static std::unique_ptr<wavex::network::TransportListener> make_transport_listener(Host &host) {
        return std::make_unique<wavex::network::quic::QuicTransportListener<Host> >(host);
    }

    template<typename Stream>
    static auto &get_connection_context(Stream &stream, connection_context &fallback) {
        if constexpr (requires { stream->connection(); }) {
            if (auto conn = stream->connection()) {
                auto ctx = std::static_pointer_cast<connection_context>(conn->user_context());
                if (!ctx) {
                    ctx = std::make_shared<connection_context>();
                    conn->set_user_context(ctx);
                }
                return *ctx;
            }
        } else if constexpr (requires { stream.connection(); }) {
            if (auto conn = stream.connection()) {
                auto ctx = std::static_pointer_cast<connection_context>(conn->user_context());
                if (!ctx) {
                    ctx = std::make_shared<connection_context>();
                    conn->set_user_context(ctx);
                }
                return *ctx;
            }
        }
        return fallback;
    }

    template<typename Stream>
    static asio::awaitable<bool> on_connection_start(Stream &, std::string &) {
        co_return true;
    }

    /// RFC 9220 / WebTransport: a 2xx answer to an extended CONNECT turns the request stream into a tunnel.
    template<typename Request, typename Response>
    static bool wants_takeover(const Request &req, const Response &res) noexcept {
        return detail::http_wants_takeover(req, res);
    }

    template<typename Stream, typename Request, typename Response>
    static asio::awaitable<void> take_over(std::shared_ptr<Stream> stream, Request &req, Response &res,
                                           std::string unread) {
        return detail::http_take_over(std::move(stream), req, res, std::move(unread));
    }

    template<typename Request>
    static bool keep_alive(const Request &req, unsigned, unsigned) {
        if constexpr (requires { req.version_major(); }) {
            if (req.version_major() == 3) {
                return false; // In HTTP/3, each QUIC stream carries exactly one request/response
            }
        }
        if constexpr (requires { req.should_keep_alive(); }) {
            return req.should_keep_alive();
        }
        return true;
    }

    template<typename Request, typename Response>
    static void prepare_response(const Request &req, Response &res, bool keep_alive, unsigned timeout_sec,
                                 unsigned max_req,
                                 unsigned short = 0) {
        if constexpr (requires { req.version_major(); }) {
            if (req.version_major() == 1) {
                res.set_keep_alive(keep_alive, timeout_sec, max_req);
                return;
            }
        }
        // RFC 9114 forbids Connection and Keep-Alive headers in native HTTP/3
    }

    static void configure_alpn(SSL_CTX *ctx) {
        SSL_CTX_set_alpn_select_cb(
            ctx,
            [](SSL *, const unsigned char **out, unsigned char *outLen,
               const unsigned char *in, const unsigned int inLen, void *) -> int {
                const unsigned char *p = in;
                const unsigned char *h2_start = nullptr;
                const unsigned char *http11_start = nullptr;

                while (p < in + inLen) {
                    const unsigned char len = *p++;
                    if ((len == 2 && p[0] == 'h' && p[1] == '3') ||
                        (len == 5 && std::memcmp(p, "h3-29", 5) == 0)) {
                        *out = p;
                        *outLen = len;
                        return SSL_TLSEXT_ERR_OK;
                    }
                    if (len == 2 && p[0] == 'h' && p[1] == '2') {
                        h2_start = p;
                    }
                    if (len == 8 && std::memcmp(p, "http/1.1", 8) == 0) {
                        http11_start = p;
                    }
                    p += len;
                }

                if (h2_start) {
                    *out = h2_start;
                    *outLen = 2;
                    return SSL_TLSEXT_ERR_OK;
                }
                if (http11_start) {
                    *out = http11_start;
                    *outLen = 8;
                    return SSL_TLSEXT_ERR_OK;
                }

                return SSL_TLSEXT_ERR_NOACK;
            },
            nullptr);
    }
}; // namespace wavex::protos
#endif // WAVEX_HAS_SSL

// The HTTP/2 session uses the helpers above; it is defined after them (see the forward declaration).
#include <wavex/protos/http/http2session.hpp>
