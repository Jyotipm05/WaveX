// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
/**
 * @file Http3Client.cpp
 * @brief HTTP/3 client over the in-tree QUIC transport.
 */

#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL

#include <wavex/Client/Http3Client.hpp>

#include <wavex/Base/Uri.hpp>
#include <wavex/Base/Url.hpp>
#include <wavex/Network/Dns/Resolver.hpp>
#include <wavex/Network/QUIC/QuicClient.hpp>
#include <wavex/Network/QUIC/VarInt.hpp>
#include <wavex/protos/http/http3codec.hpp>

#include <asio/as_tuple.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/experimental/awaitable_operators.hpp>
#include <asio/steady_timer.hpp>
#include <asio/this_coro.hpp>
#include <asio/use_awaitable.hpp>

#include <algorithm>
#include <cctype>

namespace wavex::client {
    namespace h3 = protos::http::http3;
    using network::quic::QuicClient;
    using network::quic::QuicStream;
    using network::quic::VarInt;

    namespace detail {
        struct Http3State {
            std::atomic<bool> goaway{false};
            std::atomic<uint64_t> peer_max_field_section_size{0};
        };
    } // namespace detail

    namespace {
        class http3_category_impl final : public std::error_category {
        public:
            [[nodiscard]] const char *name() const noexcept override { return "wavex.http3"; }

            [[nodiscard]] std::string message(const int c) const override {
                switch (static_cast<http3_errc>(c)) {
                    case http3_errc::not_connected: return "HTTP/3 connection is not open";
                    case http3_errc::handshake_failed: return "QUIC handshake failed";
                    case http3_errc::timeout: return "HTTP/3 request timed out";
                    case http3_errc::protocol_error: return "malformed HTTP/3 response";
                    case http3_errc::response_too_large: return "HTTP/3 response too large";
                    case http3_errc::stream_reset: return "HTTP/3 stream ended before a complete response";
                }
                return "unknown HTTP/3 error";
            }
        };

        bool ieq(const std::string_view a, const std::string_view b) noexcept {
            return a.size() == b.size() && std::ranges::equal(a, b, [](const char x, const char y) {
                return std::tolower(static_cast<unsigned char>(x)) == std::tolower(static_cast<unsigned char>(y));
            });
        }

        std::string lower(std::string s) {
            for (auto &c: s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            return s;
        }

        /// Parse the payload of a SETTINGS frame (pairs of varints).
        void apply_settings(const std::string_view payload, detail::Http3State &st) {
            std::size_t cur = 0;
            while (cur < payload.size()) {
                uint64_t id{}, value{};
                if (!VarInt::decode(payload, cur, id) || !VarInt::decode(payload, cur, value)) return;
                if (id == static_cast<uint64_t>(h3::settings_parameter::MAX_FIELD_SECTION_SIZE)) {
                    st.peer_max_field_section_size.store(value, std::memory_order_release);
                }
            }
        }

        /// Reads a server-initiated unidirectional stream: interprets the control stream, discards the rest.
        wavex::task<void> read_peer_uni(std::shared_ptr<QuicStream> stream, std::shared_ptr<detail::Http3State> st) {
            constexpr std::size_t kMaxBuffered = 1u << 20;
            std::string buf;
            char tmp[2048];
            bool have_type = false;
            uint64_t type = 0;
            while (stream->is_open()) {
                auto [ec, n] = co_await stream->async_read_some(asio::buffer(tmp), asio::as_tuple(asio::use_awaitable));
                if (ec || n == 0) break;
                if (have_type && type != static_cast<uint64_t>(h3::stream_type::CONTROL)) continue; // QPACK etc.
                buf.append(tmp, n);
                if (!have_type) {
                    std::size_t cur = 0;
                    if (!VarInt::decode(buf, cur, type)) continue;
                    have_type = true;
                    buf.erase(0, cur);
                    if (type != static_cast<uint64_t>(h3::stream_type::CONTROL)) {
                        buf.clear();
                        continue;
                    }
                }
                for (;;) {
                    h3::frame_header hdr;
                    std::string_view payload;
                    std::size_t used = 0;
                    if (h3::parser::parse_frame(buf, hdr, payload, used) != h3::parser::result::success) break;
                    if (hdr.type == static_cast<uint64_t>(h3::frame_type::SETTINGS)) {
                        apply_settings(payload, *st);
                    } else if (hdr.type == static_cast<uint64_t>(h3::frame_type::GOAWAY)) {
                        st->goaway.store(true, std::memory_order_release);
                    }
                    buf.erase(0, used);
                }
                if (buf.size() > kMaxBuffered) break;
            }
            co_return;
        }

        struct read_result {
            std::error_code ec;
            std::string data;
        };

        wavex::task<read_result> read_all(std::shared_ptr<QuicStream> stream, const std::size_t limit) {
            read_result out;
            char tmp[16384];
            for (;;) {
                auto [ec, n] = co_await stream->async_read_some(asio::buffer(tmp), asio::as_tuple(asio::use_awaitable));
                if (n > 0) out.data.append(tmp, n);
                if (out.data.size() > limit) {
                    out.ec = make_error_code(http3_errc::response_too_large);
                    break;
                }
                if (ec) {
                    if (ec != asio::error::eof) out.ec = ec;
                    break;
                }
            }
            co_return out;
        }
    } // namespace

    const std::error_category &http3_category() noexcept {
        static const http3_category_impl c;
        return c;
    }

    Http3Client::Http3Client(const wavex::executor &ex, const Http3Options options)
        : ex_(ex), options_(options), state_(std::make_shared<detail::Http3State>()) {
    }

    Http3Client::~Http3Client() { close(); }

    void Http3Client::close() {
        if (quic_) quic_->close();
        local_uni_streams_.clear();
    }

    bool Http3Client::is_open() const noexcept {
        return quic_ && quic_->is_connected() && !state_->goaway.load(std::memory_order_acquire);
    }

    uint64_t Http3Client::peer_max_field_section_size() const noexcept {
        return state_->peer_max_field_section_size.load(std::memory_order_acquire);
    }

    wavex::task<std::error_code> Http3Client::connect(std::string host, const uint16_t port) {
        close();
        state_ = std::make_shared<detail::Http3State>();

        auto resolved = co_await dns::resolver::shared()->resolve(host);
        if (!resolved) co_return resolved.error();

        // Try the first few addresses in order (IPv6 and IPv4 interleaved); each attempt has its own timeout.
        const std::size_t attempts = std::min<std::size_t>(resolved->list.size(), 3);
        for (std::size_t i = 0; i < attempts; ++i) {
            auto client = std::make_unique<QuicClient>(ex_);
            client->set_verify_peer(options_.verify_peer);
            client->set_peer_uni_stream_handler([st = state_, ex = ex_](std::shared_ptr<QuicStream> s) {
                asio::co_spawn(ex, read_peer_uni(std::move(s), st), asio::detached);
            });
            if (!co_await client->connect(host, resolved->list[i], port)) {
                client->close();
                continue;
            }
            quic_ = std::move(client);

            // Control stream with SETTINGS, plus the (unused, capacity 0) QPACK encoder and decoder streams.
            const auto open_uni = [this](const h3::stream_type type, const std::string &body) {
                if (auto s = quic_->create_stream(false)) {
                    std::string w;
                    VarInt::encode(static_cast<uint64_t>(type), w);
                    w += body;
                    s->write_outbound(w, false);
                    local_uni_streams_.push_back(std::move(s));
                }
            };
            open_uni(h3::stream_type::CONTROL,
                     h3::encoder::serialize_settings({
                         {h3::settings_parameter::QPACK_MAX_TABLE_CAPACITY, 0},
                         {h3::settings_parameter::QPACK_BLOCKED_STREAMS, 0},
                     }));
            open_uni(h3::stream_type::QPACK_ENCODER, {});
            open_uni(h3::stream_type::QPACK_DECODER, {});
            co_return std::error_code{};
        }
        co_return make_error_code(http3_errc::handshake_failed);
    }

    wavex::task<std::expected<ClientResponse, std::error_code> > Http3Client::exchange(
        const ClientRequest &req, std::string authority, std::string path_target) {
        using namespace asio::experimental::awaitable_operators;
        if (!is_open()) co_return std::unexpected(make_error_code(http3_errc::not_connected));
        auto stream = quic_->create_stream(true);
        if (!stream) co_return std::unexpected(make_error_code(http3_errc::not_connected));

        // Request header block: lowercase names, hop-by-hop headers dropped (RFC 9114 §4.2).
        std::vector<std::pair<std::string, std::string> > fields;
        bool has_ua = false, has_len = false;
        for (const auto &[k, v]: req.headers()) {
            if (ieq(k, "connection") || ieq(k, "keep-alive") || ieq(k, "transfer-encoding") || ieq(k, "upgrade") ||
                ieq(k, "host") || ieq(k, "proxy-connection") || ieq(k, "te")) {
                continue;
            }
            has_ua |= ieq(k, "user-agent");
            has_len |= ieq(k, "content-length");
            fields.emplace_back(lower(k), v);
        }
        if (!has_ua) fields.emplace_back("user-agent", "WaveX-Client/0.1.0");
        if (!has_len && !req.body().empty()) fields.emplace_back("content-length", std::to_string(req.body().size()));

        std::vector<protos::http::header> views;
        views.reserve(fields.size());
        for (const auto &[k, v]: fields) views.emplace_back(k, v);

        const std::string block = h3::qpack::encoder::encode_request_headers(req.method(), path_target, "https",
                                                                             authority, views);
        std::string wire = h3::encoder::encode_frame(h3::frame_type::HEADERS, block);
        if (!req.body().empty()) wire += h3::encoder::encode_data_frame(req.body());
        if (const auto ec = stream->write_outbound(wire, true)) co_return std::unexpected(ec);

        asio::steady_timer timer(ex_, options_.request_timeout);
        auto raced = co_await (read_all(stream, options_.max_response_size) ||
                               timer.async_wait(asio::as_tuple(asio::use_awaitable)));
        if (raced.index() == 1) {
            stream->close();
            co_return std::unexpected(make_error_code(http3_errc::timeout));
        }
        auto &rr = std::get<0>(raced);
        if (rr.ec) co_return std::unexpected(rr.ec == asio::error::operation_aborted ||
                                             rr.ec == asio::error::connection_reset
                                                 ? make_error_code(http3_errc::stream_reset)
                                                 : rr.ec);

        h3::response res;
        h3::qpack::dynamic_table dt;
        std::size_t consumed = 0;
        if (h3::parser::parse_response(rr.data, res, consumed, dt) != h3::parser::result::success) {
            co_return std::unexpected(make_error_code(rr.data.empty() ? http3_errc::stream_reset
                                                                      : http3_errc::protocol_error));
        }

        ClientResponse out;
        out.http_version(HttpVersion::Http3);
        out.status_code(res.status_code);
        out.status_text(res.status_text);
        for (const auto &h: res.headers) out.header(h.name, h.value);
        out.body(res.body);
        stream->close();
        co_return out;
    }

    wavex::task<std::expected<ClientResponse, std::error_code> > Http3Client::send(const ClientRequest &req) {
        const auto parsed = url::Url::parse(req.target());
        if (parsed.host.empty()) co_return std::unexpected(std::make_error_code(std::errc::invalid_argument));

        std::string query = parsed.query;
        for (const auto &[k, v]: req.queries()) {
            if (!query.empty()) query += '&';
            query += uri::encode(k) + '=' + uri::encode(v);
        }
        std::string path = parsed.path.empty() ? "/" : parsed.path;
        if (!query.empty()) path += '?' + query;

        asio::error_code ip_ec;
        const auto ip = asio::ip::make_address(parsed.host, ip_ec);
        std::string authority = (!ip_ec && ip.is_v6()) ? "[" + parsed.host + "]" : parsed.host;
        const auto port = parsed.effective_port();
        if (port != 443) authority += ':' + std::to_string(port);
        co_return co_await exchange(req, std::move(authority), std::move(path));
    }

} // namespace wavex::client

#endif // WAVEX_HAS_SSL
