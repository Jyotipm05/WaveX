// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
/**
 * @file HttpClient.cpp
 * @brief Implementation of HttpClient methods for 3rd-party HTTP service calls.
 */

#include <coroutine>
#include <utility>
#include <wavex/Client/HttpClient.hpp>
#include <asio/write.hpp>
#include <asio/connect.hpp>
#include <asio/redirect_error.hpp>

#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
#include <asio/ssl.hpp>
#endif

namespace wavex::client {
    asio::awaitable<Http1Response> HttpClient::send(Http1Request req) {
        Http1Response res;

        std::string raw_target(req.target());
        url::Url parsed_url = url::Url::parse(raw_target);

        if (parsed_url.host.empty()) {
            res.status(400).send("Invalid target URL: missing host");
            co_return std::move(res);
        }

        std::string host = parsed_url.host;
        uint16_t port = parsed_url.effective_port();
        std::string port_str = std::to_string(port);

        // Path and query for the HTTP request line
        std::string path_target = parsed_url.path.empty() ? "/" : parsed_url.path;
        if (!parsed_url.query.empty()) {
            path_target += "?";
            path_target += parsed_url.query;
        }
        req.target(path_target);

        // Ensure Host header is set
        if (!req.header("Host")) {
            std::string host_header = host;
            if (port != 80 && port != 443) {
                host_header += ":" + port_str;
            }
            req.set_header("Host", host_header);
        }

        // Ensure User-Agent header is set
        if (!req.header("User-Agent")) {
            req.set_header("User-Agent", "WaveX-Client/0.1.0");
        }

        // Default Connection header
        if (!req.header("Connection")) {
            req.set_header("Connection", "close");
        }

        auto executor = co_await asio::this_coro::executor;
        asio::ip::tcp::resolver resolver(executor);

#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
        if (parsed_url.scheme == "https") {
            try {
                asio::ssl::context ssl_ctx(asio::ssl::context::tlsv13_client);
                ssl_ctx.set_verify_mode(asio::ssl::verify_none);

                asio::ssl::stream<asio::ip::tcp::socket> ssl_socket(executor, ssl_ctx);
                if (!SSL_set_tlsext_host_name(ssl_socket.native_handle(), host.c_str())) {
                    res.status(500).send("Internal Error: Failed to set TLS SNI hostname");
                    co_return std::move(res);
                }

                auto endpoints = co_await resolver.async_resolve(host, port_str, asio::use_awaitable);
                co_await asio::async_connect(ssl_socket.lowest_layer(), endpoints, asio::use_awaitable);
                co_await ssl_socket.async_handshake(asio::ssl::stream_base::client, asio::use_awaitable);

                std::string wire = req.serialize();
                co_await asio::async_write(ssl_socket, asio::buffer(wire), asio::use_awaitable);

                std::string response_buffer;
                char buf[4096];
                asio::error_code ec;

                while (true) {
                    std::size_t bytes = co_await ssl_socket.async_read_some(
                        asio::buffer(buf), asio::redirect_error(asio::use_awaitable, ec));
                    if (ec || bytes == 0) break;
                    response_buffer.append(buf, bytes);
                }

                if (!res.parse(response_buffer)) {
                    res.status(502).send("Bad Gateway: Invalid response format from upstream HTTPS server");
                }

                asio::error_code ignore_ec;
                co_await ssl_socket.async_shutdown(asio::redirect_error(asio::use_awaitable, ignore_ec));
                ssl_socket.lowest_layer().close(ignore_ec);
            } catch (const std::exception &ex) {
                res.status(502).send(std::string("Bad Gateway: ") + ex.what());
            }
            co_return std::move(res);
        }
#else
        if (parsed_url.scheme == "https") {
            res.status(500).send("HTTPS request failed: WaveX was built without TLS support (WAVEX_HAS_SSL=0)");
            co_return std::move(res);
        }
#endif

        asio::ip::tcp::socket socket(executor);

        try {
            auto endpoints = co_await resolver.async_resolve(host, port_str, asio::use_awaitable);
            co_await asio::async_connect(socket, endpoints, asio::use_awaitable);

            std::string wire = req.serialize();
            co_await asio::async_write(socket, asio::buffer(wire), asio::use_awaitable);

            std::string response_buffer;
            char buf[4096];
            asio::error_code ec;

            while (true) {
                std::size_t bytes = co_await socket.async_read_some(
                    asio::buffer(buf), asio::redirect_error(asio::use_awaitable, ec));
                if (ec || bytes == 0) break;
                response_buffer.append(buf, bytes);
            }

            if (!res.parse(response_buffer)) {
                res.status(502).send("Bad Gateway: Invalid response format from upstream server");
            }
        } catch (const std::exception &ex) {
            res.status(502).send(std::string("Bad Gateway: ") + ex.what());
        }

        asio::error_code ignore_ec;
        std::ignore = socket.shutdown(asio::ip::tcp::socket::shutdown_both, ignore_ec);
        std::ignore = socket.close(ignore_ec);

        co_return std::move(res);
    }

    asio::awaitable<Http1Response> HttpClient::get(const std::string_view url) {
        return request(method::GET, url);
    }

    asio::awaitable<Http1Response> HttpClient::post(const std::string_view url, const nlohmann::json &json_body) {
        return request(method::POST, url, json_body.dump(), {{"Content-Type", "application/json"}});
    }

    asio::awaitable<Http1Response> HttpClient::request(
        const method m,
        const std::string_view url,
        const std::string_view body,
        const std::vector<std::pair<std::string, std::string> > &headers) {
        Http1Request req(m, url);
        for (const auto &[k, v]: headers) {
            req.set_header(k, v);
        }
        if (!body.empty()) {
            req.set_body(body);
        }
        return send(std::move(req));
    }
} // namespace wavex::client
