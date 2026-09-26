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

#include <string>
#include <string_view>
#ifndef ASIO_HAS_CO_AWAIT
#define ASIO_HAS_CO_AWAIT 1
#endif
#if defined(__MINGW32__) && !defined(ASIO_HAS_PTHREADS)
#define ASIO_HAS_PTHREADS 1
#endif
#include <asio/awaitable.hpp>
#include <asio/as_tuple.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/write.hpp>
#include <asio/buffer.hpp>
#include <asio/redirect_error.hpp>

#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
#include <openssl/ssl.h>
#endif

namespace wavex::protos {
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
     */
    template<typename Codec>
    struct protocol_traits {
        /// Connection-scoped session context (e.g. stateful compression tables)
        struct connection_context {
        };

        /// True if the protocol requires a connection-level opening exchange.
        static constexpr bool has_connection_preface = false;

        /// True if this protocol uses QUIC/UDP transport alongside TCP (e.g. HTTP/3).
        static constexpr bool has_quic_transport = false;

        /**
         * @brief Called once per connection after transport handshake, before the request loop.
         * @param stream     The connected stream (tcp::socket, ssl::stream, etc.).
         * @param stream_buf Receive buffer; implementations may pre-read into it.
         * @return true to continue, false to drop the connection.
         */
        template<typename Stream>
        static asio::awaitable<bool> on_connection_start(Stream &stream, std::string &stream_buf) {
            co_return true;
        }

        /**
         * @brief Decide whether the connection stays open after this request.
         */
        template<typename Request>
        static bool keep_alive(const Request &req, unsigned request_count, unsigned max_requests) {
            return req.should_keep_alive() && (request_count < max_requests);
        }

        /**
         * @brief Hook to apply protocol-specific response state before dispatch.
         */
        template<typename Request, typename Response>
        static void prepare_response(const Request &, Response &, bool,
                                     unsigned, unsigned) {
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

namespace wavex::protos {
    template<>
    struct protocol_traits<http::http1codec> {
        struct connection_context {
        };

        static constexpr bool has_connection_preface = false;
        static constexpr bool has_quic_transport = false;

        template<typename Stream>
        static asio::awaitable<bool> on_connection_start(Stream &, std::string &) {
            co_return true;
        }

        template<typename Request>
        static bool keep_alive(const Request &req, unsigned request_count, unsigned max_requests) {
            return req.should_keep_alive() && (request_count < max_requests);
        }

        template<typename Request, typename Response>
        static void prepare_response(const Request &, Response &res, bool keep,
                                     unsigned timeout_sec, unsigned remaining) {
            if (keep) {
                res.set("Connection", "keep-alive");
                res.set("Keep-Alive",
                        "timeout=" + std::to_string(timeout_sec) + ", max=" + std::to_string(remaining));
            } else {
                res.set("Connection", "close");
            }
        }

#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
        static void configure_alpn(SSL_CTX *ctx) {
            SSL_CTX_set_alpn_select_cb(
                ctx,
                [](SSL *, const unsigned char **out, unsigned char *outLen,
                   const unsigned char *in, unsigned int inLen, void *) -> int {
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
    };
} // namespace wavex::protos

// ─── HTTP/2 Specialization ───────────────────────────────────────────────────
#include <wavex/protos/http/http2codec.hpp>

namespace wavex::protos {
    template<>
    struct protocol_traits<http::http2codec> {
        using connection_context = http::http2::connection_context;

        static constexpr bool has_connection_preface = true;
        static constexpr bool has_quic_transport = false;

        /**
         * @brief RFC 7540 §3.5: validate client preface (24-byte PRI), reply with
         *        server SETTINGS + SETTINGS ACK, and strip the preface from stream_buf
         *        so the frame parser only receives raw frames.
         */
        template<typename Stream>
        static asio::awaitable<bool> on_connection_start(Stream &stream, std::string &stream_buf) {
            namespace h2 = wavex::protos::http::http2;
            while (stream_buf.size() < h2::CONNECTION_PREFACE.size() + 9) {
                char buf[4096];
                auto [ec, n] = co_await stream.async_read_some(
                    asio::buffer(buf), asio::as_tuple(asio::use_awaitable));
                if (ec || n == 0) co_return false;
                stream_buf.append(buf, n);
            }
            if (!stream_buf.starts_with(h2::CONNECTION_PREFACE)) co_return false;

            const std::string server_settings = h2::encoder::serialize_settings({});
            const std::string settings_ack = h2::encoder::serialize_settings_ack();
            std::string preface_response;
            preface_response.reserve(server_settings.size() + settings_ack.size());
            preface_response += server_settings;
            preface_response += settings_ack;

            asio::error_code write_ec;
            co_await asio::async_write(
                stream, asio::buffer(preface_response),
                asio::redirect_error(asio::use_awaitable, write_ec));
            if (write_ec) co_return false;

            stream_buf.erase(0, h2::CONNECTION_PREFACE.size());
            co_return true;
        }

        /// HTTP/2 connections are always persistent and multiplexed (RFC 7540 §8.1.2.2).
        template<typename Request>
        static bool keep_alive(const Request &, unsigned, unsigned) {
            return true;
        }

        /// RFC 7540 §8.1.2.2 forbids Connection/Keep-Alive headers in HTTP/2.
        template<typename Request, typename Response>
        static void prepare_response(const Request &, Response &, bool, unsigned, unsigned) {
        }

#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
        static void configure_alpn(SSL_CTX *ctx) {
            SSL_CTX_set_alpn_select_cb(
                ctx,
                [](SSL *, const unsigned char **out, unsigned char *outLen,
                   const unsigned char *in, unsigned int inLen, void *) -> int {
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
    };

} // namespace wavex::protos

// ─── HTTP/3 Specialization ───────────────────────────────────────────────────
#include <wavex/protos/http/http3codec.hpp>

namespace wavex::protos {
    template<>
    struct protocol_traits<http::http3codec> {
        using connection_context = http::http3::connection_context;

        // RFC 9114: HTTP/3 does not define a connection preface on request streams.
        static constexpr bool has_connection_preface = false;

        // HTTP/3 requires a QUIC/UDP listener alongside the TCP/TLS listener.
        static constexpr bool has_quic_transport = true;

        template<typename Stream>
        static asio::awaitable<bool> on_connection_start(Stream &, std::string &) {
            co_return true;
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
        static void prepare_response(const Request &req, Response &res, bool keep_alive, unsigned timeout_sec, unsigned max_req) {
            if constexpr (requires { req.version_major(); }) {
                if (req.version_major() == 1) {
                    res.set_keep_alive(keep_alive, timeout_sec, max_req);
                    // Alt-Svc injection is handled by Server::handle_connection using the
                    // actual runtime port_ — never hardcoded here.
                    return;
                }
            }
            // RFC 9114 forbids Connection and Keep-Alive headers in native HTTP/3
        }

#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
        static void configure_alpn(SSL_CTX *ctx) {
            SSL_CTX_set_alpn_select_cb(
                ctx,
                [](SSL *, const unsigned char **out, unsigned char *outLen,
                   const unsigned char *in, unsigned int inLen, void *) -> int {
                    const unsigned char *p = in;
                    const unsigned char *http11_start = nullptr;
                    while (p < in + inLen) {
                        const unsigned char len = *p++;
                        if (len == 2 && p[0] == 'h' && p[1] == '3') {
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
                    return SSL_TLSEXT_ERR_OK;
                },
                nullptr);
        }
#endif
    };
} // namespace wavex::protos  // HTTP/3 specialization

