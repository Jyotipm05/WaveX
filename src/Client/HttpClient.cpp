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

#include <utility>
#include <vector>
#include <string>
#include <string_view>
#include <charconv>
#include <algorithm>

#include <wavex/Client/HttpClient.hpp>
#include <wavex/Network/Dns/Resolver.hpp>
#include <wavex/Client/Http3Client.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/experimental/channel.hpp>
#include <wavex/protos/http/http2codec.hpp>
#include <wavex/Utils/BinaryFile.hpp>
#include <wavex/Utils/FsUtils.hpp>
#include <wavex/Utils/Compression.hpp>
#include <wavex/Base/MimeTypes.hpp>
#include <asio/write.hpp>
#include <asio/connect.hpp>
#include <asio/redirect_error.hpp>
#include <asio/ip/address.hpp>
#include <chrono>
#include <mutex>
#include <unordered_map>

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

        /// Read an HTTP/1.x response incrementally and hand the body to `sink` (framing is the codec's job).
        template<typename Stream>
        wavex::task<ClientResponse> read_http1_streaming(Stream &stream, const bool head_request,
                                                         const BodySink &sink, const HeadHook *head_hook,
                                                         ClientResponse res) {
            using protos::http::http1codec;
            http1codec::response_stream_parser parser(head_request);
            char buf[16384];
            std::string_view pending;
            bool eof = false;
            for (;;) {
                auto ev = parser.next(pending);
                using kind = http1codec::response_stream_parser::event_kind;
                if (ev.kind == kind::need_more) {
                    if (eof) {
                        if (!parser.finish()) {
                            if (!parser.head_received()) {
                                res.status_code(502);
                                res.status_text("Bad Gateway");
                                res.body("Invalid response format from upstream HTTP server");
                            } else {
                                res.body_error(std::make_error_code(std::errc::connection_reset));
                            }
                        }
                        co_return res;
                    }
                    asio::error_code read_ec;
                    const std::size_t n = co_await stream.async_read_some(
                        asio::buffer(buf), asio::redirect_error(asio::use_awaitable, read_ec));
                    pending = std::string_view(buf, n);
                    if (read_ec) eof = true; // eof or reset; whatever arrived with it is still parsed
                    continue;
                }
                if (ev.kind == kind::head) {
                    res.status_code(parser.status_code());
                    res.status_text(parser.status_text());
                    for (const auto &[k, v]: parser.headers()) res.header(k, v);
                    if (head_hook && *head_hook) co_await (*head_hook)(res);
                    continue;
                }
                if (ev.kind == kind::body) {
                    if (!co_await sink(ev.data)) {
                        res.body_error(std::make_error_code(std::errc::operation_canceled));
                        co_return res;
                    }
                    continue;
                }
                if (ev.kind == kind::error) {
                    if (!parser.head_received()) {
                        res.status_code(502);
                        res.status_text("Bad Gateway");
                        res.body("Invalid response format from upstream HTTP server");
                    } else {
                        res.body_error(std::make_error_code(std::errc::protocol_error));
                    }
                    co_return res;
                }
                co_return res; // done
            }
        }

        template<typename Stream>
        wavex::task<ClientResponse> execute_http1_exchange(
            Stream &stream,
            const std::string &host_header,
            const ClientRequest &req,
            const std::string &path_target,
            const BodySink *sink = nullptr,
            const HeadHook *head_hook = nullptr) {
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

            if (sink) {
                co_return co_await read_http1_streaming(stream, req.method() == method::HEAD, *sink, head_hook, std::move(res));
            }

            std::string response_buffer;
            char buf[4096];
            asio::error_code read_ec;
            protos::http::http1codec::response parsed_h1;
            std::size_t consumed = 0;
            bool response_complete = false;

            while (true) {
                std::size_t bytes = co_await stream.async_read_some(
                    asio::buffer(buf), asio::redirect_error(asio::use_awaitable, read_ec));
                if (bytes > 0) {
                    response_buffer.append(buf, bytes);
                }

                if (!response_buffer.empty()) {
                    parsed_h1 = {};
                    consumed = 0;
                    if (protos::http::http1codec::parser::parse_response(
                            response_buffer, parsed_h1, consumed) ==
                        protos::http::http1codec::parser::result::success) {
                        response_complete = true;
                        break;
                    }
                }

                if (read_ec) break;
            }

            if (!response_complete) {
                consumed = 0;
                if (protos::http::http1codec::parser::parse_response(response_buffer, parsed_h1, consumed) !=
                    protos::http::http1codec::parser::result::success) {
                    res.status_code(502);
                    res.status_text("Bad Gateway");
                    res.body("Invalid response format from upstream HTTP server");
                    co_return res;
                }
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
        wavex::task<ClientResponse> execute_http2_exchange(
            Stream &stream,
            const std::string &scheme,
            const std::string &host_header,
            const ClientRequest &req,
            const std::string &path_target,
            const BodySink *sink = nullptr,
            const HeadHook *head_hook = nullptr) {
            namespace h2 = protos::http::http2;

            ClientResponse res;
            res.http_version(HttpVersion::Http2);

            // 1. Connection Preface + initial SETTINGS frame
            std::string initial_wire;
            initial_wire.reserve(h2::CONNECTION_PREFACE.size() + 32);
            initial_wire += h2::CONNECTION_PREFACE;
            // Open the receive windows fully: this client reads whole responses and never sends
            // WINDOW_UPDATE, so a server honouring flow control would otherwise stall after 64 KiB.
            initial_wire += h2::encoder::serialize_settings({{h2::settings_parameter::INITIAL_WINDOW_SIZE, 0x7FFFFFFF}});
            initial_wire += h2::encoder::serialize_window_update(0, 0x7FFFFFFF - 65535);

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
            bool sink_aborted = false;
            bool head_sent = false;
            bool end_stream_seen = false;
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
                            if (std::vector<std::pair<std::string, std::string> > decoded_headers; dec.
                                decode_header_block(h_block, decoded_headers)) {
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
                                if (head_hook && *head_hook && sink && !head_sent) {
                                    head_sent = true;
                                    co_await (*head_hook)(res);
                                }
                            }
                        }

                        if (hdr.has_flag(h2::flags::END_STREAM)) {
                            response_finished = true;
                            end_stream_seen = true;
                        }
                    } else if (hdr.type == h2::frame_type::DATA && hdr.stream_id == 1) {
                        std::size_t pad_len = 0;
                        std::size_t data_offset = 0;
                        if (hdr.has_flag(h2::flags::PADDED) && !payload.empty()) {
                            pad_len = static_cast<uint8_t>(payload[0]);
                            data_offset += 1;
                        }
                        if (payload.size() >= data_offset + pad_len) {
                            const auto piece = payload.substr(data_offset, payload.size() - data_offset - pad_len);
                            if (sink) {
                                if (!piece.empty() && !co_await (*sink)(piece)) {
                                    res.body_error(std::make_error_code(std::errc::operation_canceled));
                                    sink_aborted = true;
                                    response_finished = true;
                                }
                            } else {
                                body_accumulator.append(piece);
                            }
                        }
                        if (hdr.has_flag(h2::flags::END_STREAM)) {
                            response_finished = true;
                            end_stream_seen = true;
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

            if (sink && !sink_aborted && !end_stream_seen) {
                res.body_error(std::make_error_code(std::errc::connection_reset)); // RST_STREAM/GOAWAY/EOF mid-body
            }
            res.body(body_accumulator);
            co_return res;
        }
    } // anonymous namespace

#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
    namespace {
        /// Origins known to speak HTTP/3 (from Alt-Svc headers or DNS HTTPS records) and origins where HTTP/3 failed.
        class AltSvcCache {
        public:
            struct Hit {
                uint16_t port;
            };

            static AltSvcCache &instance() {
                static AltSvcCache c;
                return c;
            }

            std::optional<Hit> lookup(const std::string &origin) {
                std::scoped_lock lk(mu_);
                const auto it = map_.find(origin);
                if (it == map_.end()) return std::nullopt;
                const auto now = std::chrono::steady_clock::now();
                if (it->second.expires <= now) {
                    map_.erase(it);
                    return std::nullopt;
                }
                if (it->second.failed_until > now) return std::nullopt;
                return Hit{it->second.port};
            }

            void learn(const std::string &origin, const uint16_t port, const std::chrono::seconds ttl) {
                std::scoped_lock lk(mu_);
                auto &e = map_[origin];
                e.port = port;
                e.expires = std::chrono::steady_clock::now() + ttl;
            }

            void forget(const std::string &origin) {
                std::scoped_lock lk(mu_);
                map_.erase(origin);
            }

            void mark_failed(const std::string &origin, const uint16_t port) {
                std::scoped_lock lk(mu_);
                auto &e = map_[origin];
                e.port = port;
                const auto now = std::chrono::steady_clock::now();
                e.expires = now + std::chrono::minutes(10);
                e.failed_until = now + std::chrono::minutes(5); // do not pay a handshake timeout on every request
            }

            bool known(const std::string &origin) {
                std::scoped_lock lk(mu_);
                const auto it = map_.find(origin);
                return it != map_.end() && it->second.expires > std::chrono::steady_clock::now();
            }

        private:
            struct Entry {
                uint16_t port{443};
                std::chrono::steady_clock::time_point expires{};
                std::chrono::steady_clock::time_point failed_until{};
            };

            std::mutex mu_;
            std::unordered_map<std::string, Entry> map_;
        };

        /// Parse an `Alt-Svc` header (RFC 7838): `h3=":443"; ma=86400, h3-29=":443"`, or `clear`.
        void learn_alt_svc(const std::string &origin, const std::string_view value) {
            auto &cache = AltSvcCache::instance();
            if (detail_case_equal(value, "clear")) {
                cache.forget(origin);
                return;
            }
            std::size_t pos = 0;
            while (pos < value.size()) {
                auto end = value.find(',', pos);
                if (end == std::string_view::npos) end = value.size();
                const auto item = value.substr(pos, end - pos);
                pos = end + 1;

                const auto eq = item.find('=');
                if (eq == std::string_view::npos) continue;
                auto proto = item.substr(0, eq);
                while (!proto.empty() && proto.front() == ' ') proto.remove_prefix(1);
                if (proto != "h3") continue;

                const auto q1 = item.find('"', eq);
                const auto q2 = q1 == std::string_view::npos ? q1 : item.find('"', q1 + 1);
                if (q2 == std::string_view::npos) continue;
                const auto authority = item.substr(q1 + 1, q2 - q1 - 1);
                const auto colon = authority.rfind(':');
                if (colon == std::string_view::npos || colon != 0) continue; // same host only (":port")

                unsigned port = 0;
                const auto ps = authority.substr(colon + 1);
                if (std::from_chars(ps.data(), ps.data() + ps.size(), port).ec != std::errc{} || port == 0 ||
                    port > 65535) {
                    continue;
                }
                unsigned long long ma = 86400;
                if (const auto m = item.find("ma="); m != std::string_view::npos) {
                    const auto ms = item.substr(m + 3);
                    unsigned long long v = 0;
                    if (std::from_chars(ms.data(), ms.data() + ms.size(), v).ec == std::errc{}) ma = v;
                }
                if (ma == 0) {
                    cache.forget(origin);
                } else {
                    cache.learn(origin, static_cast<uint16_t>(port),
                                std::chrono::seconds(std::min<unsigned long long>(ma, 7ull * 86400)));
                }
                return;
            }
        }

        /// Does `host` advertise HTTP/3? Alt-Svc cache first, then a DNS HTTPS record (RFC 9460).
        wavex::task<std::optional<uint16_t> > discover_h3(const std::string host, const uint16_t port) {
            auto &cache = AltSvcCache::instance();
            const std::string origin = host + ":" + std::to_string(port);
            if (const auto hit = cache.lookup(origin)) co_return hit->port;
            if (cache.known(origin)) co_return std::nullopt; // marked failed recently
            asio::error_code ip_ec;
            asio::ip::make_address(host, ip_ec);
            if (!ip_ec) co_return std::nullopt;

            auto records = co_await dns::resolver::shared()->resolve_https(host);
            if (records) {
                for (const auto &svc: *records) {
                    if (!svc.target.empty() && !dns::names_equal(svc.target, host)) continue; // same host only
                    if (std::ranges::find(svc.alpn, "h3") == svc.alpn.end()) continue;
                    const uint16_t p = svc.port.value_or(port);
                    cache.learn(origin, p, std::chrono::minutes(5));
                    co_return p;
                }
            }
            co_return std::nullopt;
        }
    } // anonymous namespace
#endif

    wavex::task<ClientResponse> HttpClient::send(const ClientRequest &req, const ClientOptions &options) {
        co_return co_await send_impl(req, options, nullptr, nullptr);
    }

    wavex::task<ClientResponse> HttpClient::send_streaming(const ClientRequest &req, const ClientOptions &options,
                                                           BodySink sink) {
        co_return co_await send_impl(req, options, &sink, nullptr);
    }

    // ─── Pull-style body reader ──────────────────────────────────────────────
    //
    // A pump coroutine runs `send_impl` with a sink that hands every chunk over a zero-buffer channel, so the
    // network is read only as fast as `read_chunk()` is called (same backpressure as the callback API).

    struct ResponseReader::State {
        struct Msg {
            enum class kind : std::uint8_t { head, chunk, end } k{kind::end};
            ClientResponse res{};
            std::string data{};
        };

        explicit State(const asio::any_io_executor &ex) : ch(ex, 0) {}

        asio::experimental::channel<void(asio::error_code, Msg)> ch;
        ClientResponse head{};
        std::error_code err{};
        bool finished{false};
        bool head_sent{false};
    };

    wavex::task<void> HttpClient::pump_response(std::shared_ptr<ResponseReader::State> st, ClientRequest req,
                                                ClientOptions options) {
        {
            using Msg = ResponseReader::State::Msg;
            const BodySink sink = [st](std::string_view chunk) -> wavex::task<bool> {
                const auto [ec] = co_await st->ch.async_send(
                    asio::error_code{}, Msg{Msg::kind::chunk, {}, std::string(chunk)},
                    asio::as_tuple(asio::use_awaitable));
                co_return !ec;
            };
            const HeadHook on_head = [st](const ClientResponse &head) -> wavex::task<void> {
                st->head_sent = true;
                co_await st->ch.async_send(asio::error_code{}, Msg{Msg::kind::head, head, {}},
                                           asio::as_tuple(asio::use_awaitable));
            };
            ClientResponse final_res;
            try {
                final_res = co_await send_impl(req, options, &sink, &on_head);
            } catch (const std::exception &) {
                final_res.status_code(502);
                final_res.status_text("Bad Gateway");
                final_res.body_error(std::make_error_code(std::errc::connection_aborted));
            }
            co_await st->ch.async_send(asio::error_code{}, Msg{Msg::kind::end, std::move(final_res), {}},
                                       asio::as_tuple(asio::use_awaitable));
        }
    }

    wavex::task<ResponseReader> HttpClient::open(const ClientRequest &req, const ClientOptions &options) {
        using Msg = ResponseReader::State::Msg;
        const auto ex = co_await asio::this_coro::executor;
        auto st = std::make_shared<ResponseReader::State>(ex);
        asio::co_spawn(ex, pump_response(st, req, options), asio::detached);

        auto [ec, first] = co_await st->ch.async_receive(asio::as_tuple(asio::use_awaitable));
        if (ec) {
            st->head.status_code(502);
            st->head.status_text("Bad Gateway");
            st->finished = true;
            st->err = ec;
        } else {
            st->head = std::move(first.res);
            if (first.k == Msg::kind::end) {
                st->finished = true;
                st->err = st->head.body_error();
            }
        }
        co_return ResponseReader(std::move(st));
    }

    const ClientResponse &ResponseReader::response() const noexcept {
        static const ClientResponse empty;
        return st_ ? st_->head : empty;
    }

    wavex::task<std::optional<std::string> > ResponseReader::read_chunk() {
        using Msg = State::Msg;
        if (!st_ || st_->finished) co_return std::nullopt;
        auto st = st_; // keeps the state alive if the reader is destroyed while suspended
        auto [ec, m] = co_await st->ch.async_receive(asio::as_tuple(asio::use_awaitable));
        if (ec) {
            st->finished = true;
            if (!st->err) st->err = std::make_error_code(std::errc::operation_canceled);
            co_return std::nullopt;
        }
        if (m.k == Msg::kind::chunk) co_return std::move(m.data);
        st->finished = true;
        st->err = m.res.body_error();
        co_return std::nullopt;
    }

    std::error_code ResponseReader::body_error() const noexcept { return st_ ? st_->err : std::error_code{}; }

    void ResponseReader::close() noexcept {
        if (!st_) return;
        st_->finished = true;
        st_->ch.close();
        st_.reset();
    }

    wavex::task<ClientResponse> HttpClient::send_impl(const ClientRequest &req, const ClientOptions &options,
                                                      const BodySink *sink, const HeadHook *head_hook) {
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

#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
        if (is_tls && (options.version == HttpVersion::Http3 ||
                       (options.version == HttpVersion::Auto && options.h3_discovery))) {
            const bool forced = options.version == HttpVersion::Http3;
            std::optional<uint16_t> h3_port;
            if (forced) h3_port = port;
            else h3_port = co_await discover_h3(host, port);

            if (h3_port) {
                Http3Options h3opt;
                h3opt.verify_peer = options.verify_peer;
                h3opt.request_timeout = options.timeout;
                const auto h3_executor = co_await asio::this_coro::executor;
                std::expected<ClientResponse, std::error_code> h3res =
                        std::unexpected(make_error_code(http3_errc::not_connected));
                if (options.h3_pool) {
                    // Pooled: the QUIC connection outlives this request. A reused connection that turns out to be
                    // dead (idle timeout, GOAWAY) is replaced once and the request is retried.
                    for (int attempt = 0; attempt < 2; ++attempt) {
                        auto conn = co_await options.h3_pool->acquire(h3_executor, host, *h3_port, h3opt, attempt > 0);
                        if (!conn) {
                            h3res = std::unexpected(conn.error());
                            break;
                        }
                        h3res = co_await (*conn)->exchange(req, host_header, path_target, sink, head_hook);
                        if (h3res || h3res.error() != make_error_code(http3_errc::not_connected)) break;
                    }
                } else {
                    Http3Client h3(h3_executor, h3opt);
                    if (const auto cec = co_await h3.connect(host, *h3_port); !cec) {
                        h3res = co_await h3.exchange(req, host_header, path_target, sink, head_hook);
                    } else {
                        h3res = std::unexpected(cec);
                    }
                    h3.close();
                }
                if (h3res) {
                    if (options.h3_discovery) {
                        if (const auto alt = h3res->header("alt-svc"); alt && !alt->empty()) {
                            learn_alt_svc(host + ":" + std::to_string(port), *alt);
                        }
                    }
                    co_return std::move(*h3res);
                }
                if (forced) {
                    res.status_code(502);
                    res.status_text("Bad Gateway");
                    res.body("HTTP/3 request failed: " + h3res.error().message());
                    co_return res;
                }
                AltSvcCache::instance().mark_failed(host + ":" + std::to_string(port), *h3_port);
            }
        }
#else
        if (options.version == HttpVersion::Http3) {
            res.status_code(500);
            res.status_text("Internal Server Error");
            res.body("HTTP/3 request failed: WaveX was built without TLS/QUIC support (WAVEX_HAS_SSL=0)");
            co_return res;
        }
#endif

        auto executor = co_await asio::this_coro::executor;
        asio::ip::tcp::resolver::results_type endpoints;

        if (is_ip_literal) {
            endpoints = asio::ip::tcp::resolver::results_type::create(
                asio::ip::tcp::endpoint(ip_addr, port), host, port_str);
        } else {
            asio::error_code resolve_ec;
            bool resolved = false;
            if (options.dns != DnsMode::System) {
                if (auto native = co_await dns::resolver::shared()->resolve(host)) {
                    std::vector<asio::ip::tcp::endpoint> eps;
                    eps.reserve(native->list.size());
                    for (const auto &a: native->list) eps.emplace_back(a, port);
                    endpoints = asio::ip::tcp::resolver::results_type::create(eps.begin(), eps.end(), host, port_str);
                    resolved = true;
                } else {
                    resolve_ec = native.error();
                    const bool definitive = native.error() == dns::errc::name_not_found ||
                                            native.error() == dns::errc::no_data ||
                                            native.error() == dns::errc::invalid_name;
                    if (options.dns == DnsMode::Native || definitive) {
                        res.status_code(502);
                        res.status_text("Bad Gateway");
                        res.body("Host resolution failed: " + resolve_ec.message());
                        co_return res;
                    }
                }
            }
            if (!resolved) {
                asio::ip::tcp::resolver resolver(executor);
                endpoints = co_await resolver.async_resolve(
                    host, port_str, asio::redirect_error(asio::use_awaitable, resolve_ec));
                if (resolve_ec) {
                    res.status_code(502);
                    res.status_text("Bad Gateway");
                    res.body("Host resolution failed: " + resolve_ec.message());
                    co_return res;
                }
            }
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
                    alpn_protos[0] = 2;
                    alpn_protos[1] = 'h';
                    alpn_protos[2] = '2';
                    alpn_len = 3;
                } else if (options.version == HttpVersion::Http1_1) {
                    alpn_protos[0] = 8;
                    std::memcpy(&alpn_protos[1], "http/1.1", 8);
                    alpn_len = 9;
                } else {
                    // Auto
                    alpn_protos[0] = 2;
                    alpn_protos[1] = 'h';
                    alpn_protos[2] = '2';
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
                asio::error_code nd_ec;
                ssl_socket.lowest_layer().set_option(asio::ip::tcp::no_delay(true), nd_ec);

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
                        ssl_socket, "https", host_header, req, path_target, sink, head_hook);
                } else {
                    res = co_await execute_http1_exchange(
                        ssl_socket, host_header, req, path_target, sink, head_hook);
                }

#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
                if (options.h3_discovery && options.version == HttpVersion::Auto) {
                    if (const auto alt = res.header("alt-svc"); alt && !alt->empty()) {
                        learn_alt_svc(host + ":" + std::to_string(port), *alt);
                    }
                }
#endif

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
            asio::error_code nd_ec;
            socket.set_option(asio::ip::tcp::no_delay(true), nd_ec);

            if (options.version == HttpVersion::Http2) {
                res = co_await execute_http2_exchange(
                    socket, "http", host_header, req, path_target, sink, head_hook);
            } else {
                res = co_await execute_http1_exchange(
                    socket, host_header, req, path_target, sink, head_hook);
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

    // ── ClientRequest Methods ───────────────────────────────────────────────

    ClientRequest &ClientRequest::set_header(const std::string_view key, const std::string_view value) {
        for (auto &[k, v]: headers_) {
            if (detail_case_equal(k, key)) {
                v = std::string(value);
                return *this;
            }
        }
        headers_.emplace_back(std::string(key), std::string(value));
        return *this;
    }

    std::optional<std::string_view> ClientRequest::header(const std::string_view key) const noexcept {
        for (const auto &[k, v]: headers_) {
            if (detail_case_equal(k, key)) return v;
        }
        return std::nullopt;
    }

    ClientRequest &ClientRequest::set_body(const std::string_view body, const std::string_view content_type) {
        body_ = std::string(body);
        if (!content_type.empty()) {
            set_header("Content-Type", content_type);
        }
        return *this;
    }

    ClientRequest &ClientRequest::json(const nlohmann::json &j) {
        body_ = j.dump();
        set_header("Content-Type", "application/json");
        return *this;
    }

    ClientRequest &ClientRequest::multipart(const utils::MultipartFormData &form) {
        body_ = form.compose();
        set_header("Content-Type", form.content_type_header());
        return *this;
    }

    ClientRequest &ClientRequest::add_field(const std::string_view name, const std::string_view value) {
        multipart_builder_.add_field(name, value);
        return multipart(multipart_builder_);
    }

    ClientRequest &ClientRequest::add_file(const std::string_view name,
                                           const std::string_view filename,
                                           const std::string_view data,
                                           const std::string_view content_type) {
        std::string ct(content_type);
        if (ct.empty()) {
            ct = std::string(base::mime_type_from_path(filename));
        }
        multipart_builder_.add_file(name, filename, data, ct);
        return multipart(multipart_builder_);
    }

    ClientRequest &ClientRequest::add_file_from_path(const std::string_view name,
                                                     const std::string &filepath,
                                                     const std::string_view content_type) {
        if (const auto res = wavex::utils::BinaryFile::read_all(filepath)) {
            const std::string &content = *res;
            const std::string filename = wavex::utils::fs_utils::filename(filepath);
            std::string ct(content_type);
            if (ct.empty()) {
                ct = std::string(base::mime_type_from_path(filepath));
            }
            multipart_builder_.add_file(name, filename, content, ct);
            multipart(multipart_builder_);
        }
        return *this;
    }

    ClientRequest &ClientRequest::file_body(const std::string &filepath,
                                            const std::string_view content_type) {
        if (auto res = wavex::utils::BinaryFile::read_all(filepath)) {
            body_ = std::move(*res);
            std::string ct(content_type);
            if (ct.empty()) {
                ct = std::string(base::mime_type_from_path(filepath));
            }
            set_header("Content-Type", ct);
        }
        return *this;
    }

    ClientRequest &ClientRequest::compress(const utils::CompressionFormat format) {
        if (auto compressed = utils::Compressor::compress(body_, format); compressed.has_value()) {
            body_ = std::move(*compressed);
            set_header("Content-Encoding",
                       format == utils::CompressionFormat::Gzip ? "gzip" : "deflate");
        }
        return *this;
    }

    // ── ClientResponse Methods ──────────────────────────────────────────────

    nlohmann::json ClientResponse::json() const {
        return nlohmann::json::parse(body_);
    }

    std::optional<std::string> ClientResponse::decompressed_body(
        const utils::CompressionFormat format) const {
        auto decompress_helper = [](const std::string_view d,
                                    const utils::CompressionFormat fmt) -> std::optional<std::string> {
            if (auto res = utils::Compressor::decompress(d, fmt)) return *res;
            return std::nullopt;
        };
        if (const auto enc = header("Content-Encoding"); enc.has_value()) {
            if (enc->find("gzip") != std::string_view::npos) {
                return decompress_helper(body_, utils::CompressionFormat::Gzip);
            }
            if (enc->find("deflate") != std::string_view::npos) {
                return decompress_helper(body_, utils::CompressionFormat::Deflate);
            }
        }
        return decompress_helper(body_, format);
    }

    bool ClientResponse::save_to_file(const std::string &dest_path) const {
        return wavex::utils::BinaryFile::write_all(dest_path, body_);
    }
} // namespace wavex::client
