// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
/**
 * @file HttpClient.cpp
 * @brief Implementation of HttpClient methods for HTTP/1.1 & HTTP/2, plain TCP & TLS 1.3,
 *        domainless IPv4/IPv6 client endpoints, and query parameter handling.
 */

#include <coroutine>
#include <utility>
#include <vector>
#include <string>
#include <string_view>
#include <charconv>
#include <algorithm>
#include <cctype>

#include <wavex/Client/HttpClient.hpp>
#include <wavex/protos/http/http2codec.hpp>
#include <asio/write.hpp>
#include <asio/connect.hpp>
#include <asio/redirect_error.hpp>
#include <asio/ip/address.hpp>

#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
#include <asio/ssl.hpp>
#include <openssl/ssl.h>
#endif

namespace wavex::client {
    namespace {
        bool detail_case_equal(const std::string_view a, const std::string_view b) noexcept {
            if (a.size() != b.size()) return false;
            for (size_t i = 0; i < a.size(); ++i) {
                if (std::tolower(static_cast<unsigned char>(a[i])) !=
                    std::tolower(static_cast<unsigned char>(b[i]))) {
                    return false;
                }
            }
            return true;
        }

        template<typename Stream>
        asio::awaitable<ClientResponse> execute_http1_exchange(
            Stream &stream,
            const std::string &host_header,
            const ClientRequest &req,
            const std::string &path_target) {

            ClientResponse res;
            res.http_version(HttpVersion::Http1_1);

            // Build wire request
            std::string wire;
            wire.reserve(256 + req.body().size());
            wire += protos::http::to_string(req.method());
            wire += " ";
            wire += path_target;
            wire += " HTTP/1.1\r\n";

            bool has_host = false;
            bool has_user_agent = false;
            bool has_conn = false;
            bool has_content_length = false;

            for (const auto &[k, v]: req.headers()) {
                wire += k + ": " + v + "\r\n";
                if (detail_case_equal(k, "Host")) has_host = true;
                if (detail_case_equal(k, "User-Agent")) has_user_agent = true;
                if (detail_case_equal(k, "Connection")) has_conn = true;
                if (detail_case_equal(k, "Content-Length")) has_content_length = true;
            }

            if (!has_host) {
                wire += "Host: " + host_header + "\r\n";
            }
            if (!has_user_agent) {
                wire += "User-Agent: WaveX-Client/0.1.0\r\n";
            }
            if (!has_conn) {
                wire += "Connection: close\r\n";
            }
            if (!req.body().empty() && !has_content_length) {
                wire += "Content-Length: " + std::to_string(req.body().size()) + "\r\n";
            }
            wire += "\r\n";
            if (!req.body().empty()) {
                wire += req.body();
            }

            asio::error_code write_ec;
            co_await asio::async_write(
                stream, asio::buffer(wire),
                asio::redirect_error(asio::use_awaitable, write_ec));
            if (write_ec) {
                res.status_code(502);
                res.status_text("Bad Gateway");
                res.body("Failed to send HTTP/1.1 request: " + write_ec.message());
                co_return res;
            }

            std::string response_buffer;
            char buf[4096];
            asio::error_code read_ec;

            while (true) {
                std::size_t bytes = co_await stream.async_read_some(
                    asio::buffer(buf), asio::redirect_error(asio::use_awaitable, read_ec));
                if (bytes > 0) {
                    response_buffer.append(buf, bytes);
                }
                if (read_ec) break;
            }

            protos::http::http1codec::response parsed_h1;
            std::size_t consumed = 0;
            if (protos::http::http1codec::parser::parse_response(response_buffer, parsed_h1, consumed) !=
                protos::http::http1codec::parser::result::success) {
                res.status_code(502);
                res.status_text("Bad Gateway");
                res.body("Invalid response format from upstream HTTP server");
                co_return res;
            }

            res.status_code(parsed_h1.status_code);
            res.status_text(parsed_h1.status_text);
            res.set_raw_response(response_buffer); // Preserve full wire bytes

            if (const auto te = parsed_h1.get_header("Transfer-Encoding");
                te && te->find("chunked") != std::string_view::npos) {
                res.body(protos::http::http1codec::decoder::dechunk(parsed_h1.body));
            } else {
                res.body(parsed_h1.body);
            }

            for (const auto &[k, v]: parsed_h1.headers) {
                res.header(k, v);
            }

            co_return res;
        }

        template<typename Stream>
        asio::awaitable<ClientResponse> execute_http2_exchange(
            Stream &stream,
            const std::string &scheme,
            const std::string &host_header,
            const ClientRequest &req,
            const std::string &path_target) {

            namespace h2 = protos::http::http2;

            ClientResponse res;
            res.http_version(HttpVersion::Http2);

            // 1. Connection Preface + initial SETTINGS frame
            std::string initial_wire;
            initial_wire.reserve(h2::CONNECTION_PREFACE.size() + 32);
            initial_wire += h2::CONNECTION_PREFACE;
            initial_wire += h2::encoder::serialize_settings({});

            // 2. Build HEADERS frame for stream 1
            std::vector<std::pair<std::string, std::string> > filtered_headers;
            bool has_user_agent = false;
            for (const auto &[k, v]: req.headers()) {
                if (detail_case_equal(k, "Connection") ||
                    detail_case_equal(k, "Keep-Alive") ||
                    detail_case_equal(k, "Transfer-Encoding") ||
                    detail_case_equal(k, "Upgrade") ||
                    detail_case_equal(k, "Host")) {
                    continue;
                }
                if (detail_case_equal(k, "User-Agent")) has_user_agent = true;

                std::string lower_k = k;
                std::ranges::transform(lower_k, lower_k.begin(),
                                       [](const unsigned char c) { return std::tolower(c); });
                filtered_headers.emplace_back(std::move(lower_k), v);
            }
            if (!has_user_agent) {
                filtered_headers.emplace_back("user-agent", "WaveX-Client/0.1.0");
            }

            std::vector<protos::http::header> h2_headers;
            h2_headers.reserve(filtered_headers.size());
            for (const auto &[k, v]: filtered_headers) {
                h2_headers.emplace_back(k, v);
            }

            const std::string header_block = h2::hpack::encoder::encode_request_headers(
                req.method(), path_target, scheme, host_header, h2_headers);

            h2::frame_header h_hdr;
            h_hdr.length = static_cast<uint32_t>(header_block.size());
            h_hdr.type = h2::frame_type::HEADERS;
            h_hdr.flags = h2::flags::END_HEADERS;
            if (req.body().empty()) {
                h_hdr.flags |= h2::flags::END_STREAM;
            }
            h_hdr.stream_id = 1;

            std::array<uint8_t, h2::frame_header::HEADER_SIZE> h_bytes{};
            h2::pack_frame_header(h_hdr, h_bytes);

            initial_wire.append(reinterpret_cast<const char *>(h_bytes.data()), h_bytes.size());
            initial_wire.append(header_block);

            // 3. Append DATA frame(s) if body present
            if (!req.body().empty()) {
                std::size_t offset = 0;
                while (offset < req.body().size()) {
                    constexpr uint32_t MAX_FRAME_SIZE = 16384;
                    const auto chunk_len = static_cast<uint32_t>(
                        std::min<std::size_t>(req.body().size() - offset, MAX_FRAME_SIZE));
                    const bool is_last = (offset + chunk_len == req.body().size());

                    h2::frame_header d_hdr;
                    d_hdr.length = chunk_len;
                    d_hdr.type = h2::frame_type::DATA;
                    d_hdr.flags = is_last ? h2::flags::END_STREAM : h2::flags::NONE;
                    d_hdr.stream_id = 1;

                    std::array<uint8_t, h2::frame_header::HEADER_SIZE> d_bytes{};
                    h2::pack_frame_header(d_hdr, d_bytes);

                    initial_wire.append(reinterpret_cast<const char *>(d_bytes.data()), d_bytes.size());
                    initial_wire.append(req.body().substr(offset, chunk_len));

                    offset += chunk_len;
                }
            }

            asio::error_code write_ec;
            co_await asio::async_write(
                stream, asio::buffer(initial_wire),
                asio::redirect_error(asio::use_awaitable, write_ec));
            if (write_ec) {
                res.status_code(502);
                res.status_text("Bad Gateway");
                res.body("Failed to send HTTP/2 request: " + write_ec.message());
                co_return res;
            }

            // 4. Response reception loop
            std::string recv_buf;
            char read_buf[4096];
            asio::error_code read_ec;

            h2::hpack::dynamic_table dt;
            h2::hpack::decoder dec(dt);

            bool headers_received = false;
            bool response_finished = false;
            std::string body_accumulator;

            while (!response_finished) {
                std::size_t bytes = co_await stream.async_read_some(
                    asio::buffer(read_buf), asio::redirect_error(asio::use_awaitable, read_ec));
                if (bytes > 0) {
                    recv_buf.append(read_buf, bytes);
                }

                while (recv_buf.size() >= h2::frame_header::HEADER_SIZE) {
                    h2::frame_header hdr;
                    const std::string_view hdr_view(recv_buf.data(), h2::frame_header::HEADER_SIZE);
                    h2::unpack_frame_header(hdr_view, hdr);

                    if (recv_buf.size() < h2::frame_header::HEADER_SIZE + hdr.length) {
                        break; // Wait for full frame
                    }

                    const std::string_view payload(recv_buf.data() + h2::frame_header::HEADER_SIZE, hdr.length);

                    if (hdr.type == h2::frame_type::SETTINGS) {
                        if (!hdr.has_flag(h2::flags::ACK)) {
                            const std::string ack = h2::encoder::serialize_settings_ack();
                            asio::error_code ack_ec;
                            co_await asio::async_write(
                                stream, asio::buffer(ack),
                                asio::redirect_error(asio::use_awaitable, ack_ec));
                        }
                    } else if (hdr.type == h2::frame_type::PING) {
                        if (!hdr.has_flag(h2::flags::ACK) && payload.size() == 8) {
                            uint64_t opaque = 0;
                            for (int i = 0; i < 8; ++i) {
                                opaque = (opaque << 8) | static_cast<uint8_t>(payload[i]);
                            }
                            const std::string ping_ack = h2::encoder::serialize_ping(opaque, true);
                            asio::error_code p_ec;
                            co_await asio::async_write(
                                stream, asio::buffer(ping_ack),
                                asio::redirect_error(asio::use_awaitable, p_ec));
                        }
                    } else if (hdr.type == h2::frame_type::HEADERS && hdr.stream_id == 1) {
                        std::size_t pad_len = 0;
                        std::size_t header_cursor = 0;

                        if (hdr.has_flag(h2::flags::PADDED)) {
                            if (!payload.empty()) {
                                pad_len = static_cast<uint8_t>(payload[0]);
                                header_cursor += 1;
                            }
                        }
                        if (hdr.has_flag(h2::flags::PRIORITY)) {
                            header_cursor += 5;
                        }

                        if (payload.size() >= header_cursor + pad_len) {
                            const std::string_view h_block = payload.substr(
                                header_cursor, payload.size() - header_cursor - pad_len);
                            std::vector<std::pair<std::string, std::string> > decoded_headers;
                            if (dec.decode_header_block(h_block, decoded_headers)) {
                                headers_received = true;
                                for (const auto &[n, v]: decoded_headers) {
                                    if (n == ":status") {
                                        unsigned int parsed_code = 200;
                                        std::from_chars(v.data(), v.data() + v.size(), parsed_code);
                                        res.status_code(parsed_code);
                                        res.status_text(protos::http::http2codec::status_text_for(parsed_code));
                                    } else {
                                        res.header(n, v);
                                    }
                                }
                            }
                        }

                        if (hdr.has_flag(h2::flags::END_STREAM)) {
                            response_finished = true;
                        }
                    } else if (hdr.type == h2::frame_type::DATA && hdr.stream_id == 1) {
                        std::size_t pad_len = 0;
                        std::size_t data_offset = 0;
                        if (hdr.has_flag(h2::flags::PADDED) && !payload.empty()) {
                            pad_len = static_cast<uint8_t>(payload[0]);
                            data_offset += 1;
                        }
                        if (payload.size() >= data_offset + pad_len) {
                            body_accumulator.append(
                                payload.substr(data_offset, payload.size() - data_offset - pad_len));
                        }
                        if (hdr.has_flag(h2::flags::END_STREAM)) {
                            response_finished = true;
                        }
                    } else if (hdr.type == h2::frame_type::RST_STREAM && hdr.stream_id == 1) {
                        response_finished = true;
                    } else if (hdr.type == h2::frame_type::GOAWAY) {
                        response_finished = true;
                    }

                    recv_buf.erase(0, h2::frame_header::HEADER_SIZE + hdr.length);
                    if (response_finished) break;
                }

                if (read_ec) break;
            }

            // Send graceful GOAWAY
            const std::string goaway = h2::encoder::serialize_goaway(0, h2::error_code::NO_ERROR, "");
            asio::error_code g_ec;
            co_await asio::async_write(
                stream, asio::buffer(goaway),
                asio::redirect_error(asio::use_awaitable, g_ec));

            if (!headers_received && res.status_code() == 0) {
                res.status_code(502);
                res.status_text("Bad Gateway");
                res.body("HTTP/2 response incomplete or connection reset by peer");
                co_return res;
            }

            res.body(body_accumulator);
            co_return res;
        }
    } // anonymous namespace

    asio::awaitable<ClientResponse> HttpClient::send(const ClientRequest &req, const ClientOptions &options) {
        ClientResponse res;

        // 1. Target URL parsing
        const std::string raw_target = req.target();
        const url::Url parsed_url = url::Url::parse(raw_target);

        if (parsed_url.host.empty()) {
            res.status_code(400);
            res.status_text("Bad Request");
            res.body("Invalid target URL: missing host");
            co_return res;
        }

        const std::string host = parsed_url.host;
        const uint16_t port = parsed_url.effective_port();
        const std::string port_str = std::to_string(port);

        // 2. Query String Construction
        std::string full_query = parsed_url.query;
        for (const auto &[k, v]: req.queries()) {
            if (!full_query.empty()) full_query += "&";
            full_query += uri::encode(k) + "=" + uri::encode(v);
        }

        // 3. Path & Target for Request Line / :path
        std::string path_target = parsed_url.path.empty() ? "/" : parsed_url.path;
        if (!full_query.empty()) {
            path_target += "?" + full_query;
        }

        // 4. Domainless IP Host formatting (RFC 3986 §3.2.2)
        asio::error_code ip_ec;
        const auto ip_addr = asio::ip::make_address(host, ip_ec);
        const bool is_ip_literal = !ip_ec;

        std::string host_header = (is_ip_literal && ip_addr.is_v6()) ? ("[" + host + "]") : host;
        if ((parsed_url.scheme == "http" && port != 80) || (parsed_url.scheme == "https" && port != 443)) {
            host_header += ":" + port_str;
        }

        const bool is_tls = (parsed_url.scheme == "https");

        auto executor = co_await asio::this_coro::executor;
        asio::ip::tcp::resolver resolver(executor);

        asio::error_code resolve_ec;
        auto endpoints = co_await resolver.async_resolve(
            host, port_str, asio::redirect_error(asio::use_awaitable, resolve_ec));
        if (resolve_ec) {
            res.status_code(502);
            res.status_text("Bad Gateway");
            res.body("Host resolution failed: " + resolve_ec.message());
            co_return res;
        }

#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
        if (is_tls) {
            try {
                asio::ssl::context ssl_ctx(asio::ssl::context::tlsv13_client);
                if (options.verify_peer) {
                    ssl_ctx.set_verify_mode(asio::ssl::verify_peer);
                    if (!options.ca_file.empty()) {
                        ssl_ctx.load_verify_file(options.ca_file);
                    } else {
                        ssl_ctx.set_default_verify_paths();
                    }
                } else {
                    ssl_ctx.set_verify_mode(asio::ssl::verify_none);
                }

                if (!options.cert_file.empty()) {
                    ssl_ctx.use_certificate_chain_file(options.cert_file);
                }
                if (!options.key_file.empty()) {
                    ssl_ctx.use_private_key_file(options.key_file, asio::ssl::context::pem);
                }

                asio::ssl::stream<asio::ip::tcp::socket> ssl_socket(executor, ssl_ctx);

                // Set SNI only if host is NOT an IP literal (RFC 6066 §3)
                if (!is_ip_literal) {
                    SSL_set_tlsext_host_name(ssl_socket.native_handle(), host.c_str());
                }

                // Configure ALPN advertisement
                unsigned char alpn_protos[32];
                unsigned int alpn_len = 0;
                if (options.version == HttpVersion::Http2) {
                    alpn_protos[0] = 2; alpn_protos[1] = 'h'; alpn_protos[2] = '2';
                    alpn_len = 3;
                } else if (options.version == HttpVersion::Http1_1) {
                    alpn_protos[0] = 8;
                    std::memcpy(&alpn_protos[1], "http/1.1", 8);
                    alpn_len = 9;
                } else { // Auto
                    alpn_protos[0] = 2; alpn_protos[1] = 'h'; alpn_protos[2] = '2';
                    alpn_protos[3] = 8;
                    std::memcpy(&alpn_protos[4], "http/1.1", 8);
                    alpn_len = 12;
                }
                SSL_set_alpn_protos(ssl_socket.native_handle(), alpn_protos, alpn_len);

                asio::error_code conn_ec;
                co_await asio::async_connect(
                    ssl_socket.lowest_layer(), endpoints,
                    asio::redirect_error(asio::use_awaitable, conn_ec));
                if (conn_ec) {
                    res.status_code(502);
                    res.status_text("Bad Gateway");
                    res.body("TCP connect failed: " + conn_ec.message());
                    co_return res;
                }

                asio::error_code hs_ec;
                co_await ssl_socket.async_handshake(
                    asio::ssl::stream_base::client,
                    asio::redirect_error(asio::use_awaitable, hs_ec));
                if (hs_ec) {
                    res.status_code(502);
                    res.status_text("Bad Gateway");
                    res.body("TLS handshake failed: " + hs_ec.message());
                    co_return res;
                }

                const unsigned char *alpn_sel = nullptr;
                unsigned int alpn_sel_len = 0;
                SSL_get0_alpn_selected(ssl_socket.native_handle(), &alpn_sel, &alpn_sel_len);
                bool use_h2 = false;
                if (alpn_sel && alpn_sel_len == 2 && std::memcmp(alpn_sel, "h2", 2) == 0) {
                    use_h2 = true;
                } else if (options.version == HttpVersion::Http2) {
                    use_h2 = true;
                }

                if (use_h2) {
                    res = co_await execute_http2_exchange(
                        ssl_socket, "https", host_header, req, path_target);
                } else {
                    res = co_await execute_http1_exchange(
                        ssl_socket, host_header, req, path_target);
                }

                asio::error_code close_ec;
                co_await ssl_socket.async_shutdown(asio::redirect_error(asio::use_awaitable, close_ec));
                ssl_socket.lowest_layer().close(close_ec);
            } catch (const std::exception &ex) {
                res.status_code(502);
                res.status_text("Bad Gateway");
                res.body(std::string("HTTPS error: ") + ex.what());
            }
            co_return res;
        }
#else
        if (is_tls) {
            res.status_code(500);
            res.status_text("Internal Server Error");
            res.body("HTTPS request failed: WaveX was built without TLS support (WAVEX_HAS_SSL=0)");
            co_return res;
        }
#endif

        asio::ip::tcp::socket socket(executor);
        try {
            asio::error_code conn_ec;
            co_await asio::async_connect(
                socket, endpoints, asio::redirect_error(asio::use_awaitable, conn_ec));
            if (conn_ec) {
                res.status_code(502);
                res.status_text("Bad Gateway");
                res.body("TCP connect failed: " + conn_ec.message());
                co_return res;
            }

            if (options.version == HttpVersion::Http2) {
                res = co_await execute_http2_exchange(
                    socket, "http", host_header, req, path_target);
            } else {
                res = co_await execute_http1_exchange(
                    socket, host_header, req, path_target);
            }

            asio::error_code close_ec;
            std::ignore = socket.shutdown(asio::ip::tcp::socket::shutdown_both, close_ec);
            std::ignore = socket.close(close_ec);
        } catch (const std::exception &ex) {
            res.status_code(502);
            res.status_text("Bad Gateway");
            res.body(std::string("HTTP error: ") + ex.what());
        }

        co_return res;
    }
} // namespace wavex::client
