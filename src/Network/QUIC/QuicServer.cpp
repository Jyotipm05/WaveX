#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL

#include <ranges>
#include <wavex/Network/QUIC/QuicServer.hpp>
#include <wavex/Base/Logger.hpp>

#if defined(min)
#undef min
#endif
#if defined(max)
#undef max
#endif

#include <asio/as_tuple.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/post.hpp>
#include <filesystem>
#include <fstream>
#include <future>

namespace wavex::network::quic {

    QuicServer::QuicServer(const wavex::executor &ex, const uint16_t port)
        : ex_(ex), socket_(ex) {
        asio::error_code ec;
        socket_.open(asio::ip::udp::v4(), ec);
        socket_.set_option(asio::socket_base::reuse_address(true), ec);
        socket_.bind(asio::ip::udp::endpoint(asio::ip::udp::v4(), port), ec);
    }

    QuicServer::QuicServer(const wavex::executor &ex, const std::string_view host, const uint16_t port)
        : ex_(ex), socket_(ex) {
        asio::error_code ec;
        const auto addr = asio::ip::make_address(host, ec);
        if (!ec) {
            socket_.open(addr.is_v6() ? asio::ip::udp::v6() : asio::ip::udp::v4(), ec);
            socket_.set_option(asio::socket_base::reuse_address(true), ec);
            socket_.bind(asio::ip::udp::endpoint(addr, port), ec);
        }
    }

    QuicServer::~QuicServer() {
        stop();
        if (shared_ssl_ctx_) {
            SSL_CTX_free(shared_ssl_ctx_);
            shared_ssl_ctx_ = nullptr;
        }
    }

    void QuicServer::start() {
        if (!socket_.is_open() || stopped_.load()) return;
        if (!shared_ssl_ctx_ && !tls_cert_file_.empty() && !tls_key_file_.empty()) {
            init_shared_ssl_ctx();
        }
        running_.store(true);
        do_receive();
    }

    void QuicServer::stop() {
        if (stopped_.exchange(true)) return;
        running_.store(false);

        {
            std::lock_guard sock_lock(sock_mtx_);
            asio::error_code ec;
            socket_.close(ec); // cancels pending async_receive_from first
        }

        // Teardown MUST happen on the io thread, after all in-flight
        // handle_datagram/flush_outbound calls have finished, and posted
        // callbacks must not touch a dying server.
        std::unordered_map<ConnectionId, std::shared_ptr<QuicConnection>> conns;
        {
            std::lock_guard lock(mtx_);
            conns.swap(connections_);
        }
        if (conns.empty() || wavex::running_in_this_thread(ex_) || wavex::context_stopped(ex_)) {
            for (auto &conn: conns | std::views::values) {
                if (conn) conn->close();
            }
            return;
        }

        // conns/drained are posted by shared_ptr, not by reference: fut.wait_for()
        // below only waits UP TO 500ms and its result is discarded, so stop() can
        // return before the posted task ever runs (e.g. if the io thread is busy
        // draining a burst of in-flight packets). If the lambda captured conns/
        // drained by reference, that would leave it holding dangling references
        // into this function's stack frame the moment stop() returns on timeout -
        // a use-after-free whenever the task finally does run.
        auto conns_ptr = std::make_shared<std::unordered_map<ConnectionId, std::shared_ptr<QuicConnection>>>(
            std::move(conns));
        auto drained = std::make_shared<std::promise<void>>();
        const auto fut = drained->get_future();
        asio::post(ex_, [conns_ptr, drained] {
            for (auto &conn: *conns_ptr | std::views::values) {
                if (conn) conn->close();
            }
            drained->set_value();
        });
        fut.wait_for(std::chrono::milliseconds(500));
    }

    void QuicServer::do_receive() {
        std::lock_guard sock_lock(sock_mtx_);
        if (!running_.load() || stopped_.load()) return;

        socket_.async_receive_from(
            asio::buffer(recv_buf_), sender_endpoint_,
            [this](const std::error_code ec, const std::size_t bytes_recvd) {
                // Only abort the receive loop on intentional cancellation (shutdown).
                // Transient UDP errors (e.g. ECONNRESET on Windows) must not halt the loop.
                if (ec == asio::error::operation_aborted || stopped_.load() || !running_.load()) return;
                if (ec || bytes_recvd == 0) {
                    do_receive();
                    return;
                }

                wavex::log::debug("[QuicServer] Received {} bytes from {}",
                                  bytes_recvd, sender_endpoint_.address().to_string());

                const std::string_view datagram(reinterpret_cast<const char *>(recv_buf_.data()), bytes_recvd);
                PacketHeader hdr;
                std::size_t hdr_len = 0;
                const bool is_long = !datagram.empty() && (static_cast<uint8_t>(datagram[0]) & 0x80) != 0;

                bool unpacked = false;
                if (is_long) {
                    unpacked = unpack_packet_header(datagram, hdr, hdr_len);
                } else {
                    // Short headers always carry a server-chosen CID, and all of those have
                    // server_cid_len_ bytes, so no per-packet scan over the connection table is needed
                    // (that scan was O(connections) work an attacker could trigger with any short packet).
                    unpacked = unpack_packet_header(datagram, hdr, hdr_len, server_cid_len_);
                }

                if (!unpacked) {
                    wavex::log::warn("[QUIC] [server] Failed to unpack packet header from {} bytes UDP datagram", bytes_recvd);
                } else {

                    // RFC 9000 §6.1/§14.1: only answer unknown versions for datagrams large enough to be a
                    // client Initial, so Version Negotiation cannot be used for reflection/amplification.
                    if (hdr.is_long && hdr.version != QUIC_VERSION_1 && hdr.version != 0 &&
                        bytes_recvd < kMinInitialDatagramSize) {
                        do_receive();
                        return;
                    }
                    if (hdr.is_long && hdr.version != QUIC_VERSION_1 && hdr.version != 0) {
                        // RFC 9000 §6: Version Negotiation packet
                        std::string vn_packet;
                        vn_packet.push_back(static_cast<char>(0x80 | 0x40));
                        vn_packet.push_back(0);
                        vn_packet.push_back(0);
                        vn_packet.push_back(0);
                        vn_packet.push_back(0); // Version 0
                        vn_packet.push_back(static_cast<char>(hdr.scid.length()));
                        vn_packet.append(reinterpret_cast<const char *>(hdr.scid.data()), hdr.scid.length());
                        vn_packet.push_back(static_cast<char>(hdr.dcid.length()));
                        vn_packet.append(reinterpret_cast<const char *>(hdr.dcid.data()), hdr.dcid.length());
                        // Supported version: QUIC_VERSION_1 (0x00000001)
                        vn_packet.push_back(0);
                        vn_packet.push_back(0);
                        vn_packet.push_back(0);
                        vn_packet.push_back(1);

                        auto buf = std::make_shared<std::string>(std::move(vn_packet));
                        {
                            std::lock_guard sock_lock(sock_mtx_);
                            socket_.async_send_to(asio::buffer(*buf), sender_endpoint_, [buf](auto, auto) {
                            });
                        }
                        do_receive();
                        return;
                    }

                    std::shared_ptr<QuicConnection> conn; {
                        std::lock_guard lock(mtx_);
                        // Route by DCID only. The table is keyed by server-chosen CIDs and the client's original
                        // DCID; a client-chosen SCID must never select (or overwrite) another connection.
                        auto it = connections_.find(hdr.dcid);
                        if (it != connections_.end()) {
                            conn = it->second;
                        } else if (hdr.is_long && hdr.type == PacketType::Initial &&
                                   bytes_recvd < kMinInitialDatagramSize) {
                            // RFC 9000 §14.1: a server MUST discard Initial packets carried in datagrams
                            // smaller than 1200 bytes (anti-amplification).
                            wavex::log::debug("[QUIC] [server] Dropping undersized Initial datagram ({} bytes)",
                                              bytes_recvd);
                        } else if (hdr.is_long && hdr.type == PacketType::Initial) {
                            // New incoming connection (Initial)
                            const ConnectionId server_cid = ConnectionId::random(server_cid_len_);
                            conn = std::make_shared<QuicConnection>(server_cid, hdr.scid, sender_endpoint_, true,
                                                                    ex_, hdr.dcid);
                            conn->set_max_field_section_size(max_field_section_size_);

                            conn->set_outbound_callback([this, weak_conn = std::weak_ptr<QuicConnection>(conn)] {
                                if (stopped_.load() || !running_.load()) return;
                                if (wavex::running_in_this_thread(ex_)) {
                                    if (const auto c = weak_conn.lock()) {
                                        flush_outbound(c);
                                    }
                                } else {
                                    asio::post(ex_, [this, weak_conn] {
                                        if (stopped_.load() || !running_.load()) return;
                                        if (const auto c = weak_conn.lock()) {
                                            flush_outbound(c);
                                        }
                                    });
                                }
                            });

                            conn->set_closed_callback([this, server_cid, owner = conn.get()](
                                const ConnectionId &scid, const ConnectionId &, const ConnectionId &orig_dcid) {
                                asio::post(ex_, [this, server_cid, scid, orig_dcid, owner] {
                                    if (stopped_.load()) return;
                                    std::lock_guard lock(mtx_);
                                    // Only erase entries that still point at this connection: a key may have
                                    // been re-used by a newer connection in the meantime.
                                    auto erase_owned = [&](const ConnectionId &key) {
                                        if (key.empty()) return;
                                        if (const auto it = connections_.find(key);
                                            it != connections_.end() && it->second.get() == owner) {
                                            connections_.erase(it);
                                        }
                                    };
                                    erase_owned(server_cid);
                                    erase_owned(scid);
                                    erase_owned(orig_dcid);
                                    wavex::log::info("[QUIC] [server] Removed closed connection (remaining={})", connections_.size());
                                });
                            });

                            if (shared_ssl_ctx_) {
                                conn->set_shared_ssl_ctx(shared_ssl_ctx_);
                            } else if (!tls_cert_file_.empty() && !tls_key_file_.empty()) {
                                conn->set_tls_credentials(tls_cert_file_, tls_key_file_);
                            }
                            if (!conn->init_tls_handshake_engine()) {
                                wavex::log::error("[QUIC] Failed to init_tls_handshake_engine for new incoming connection!");
                            }
                            connections_[server_cid] = conn;
                            connections_.try_emplace(hdr.dcid, conn);

                            if (stream_handler_ || uni_stream_handler_) {
                                conn->set_stream_created_callback([this](std::shared_ptr<QuicStream> stream) {
                                    if (!stream) return;
                                    const uint64_t sid = stream->stream_id();
                                    // Client-initiated unidirectional stream (sid & 0x03 == 2) per RFC 9114 §6.2
                                    if ((sid & 0x03) == 0x02) {
                                         UniStreamHandler uni_handler;
                                        {
                                            std::lock_guard lock(mtx_);
                                            uni_handler = uni_stream_handler_;
                                        }
                                        if (uni_handler) {
                                            // NOTE: must pass the callable itself (not uni_handler(stream)) so
                                            // co_spawn owns a copy for the coroutine's lifetime. Calling
                                            // uni_handler(stream) here only creates the (lazily-suspended)
                                            // awaitable frame, whose implicit closure pointer would dangle the
                                            // moment the local `uni_handler` variable goes out of scope below -
                                            // a use-after-free on first resume.
                                            asio::co_spawn(ex_, [uni_handler, stream]() -> wavex::task<void> {
                                                co_await uni_handler(stream);
                                            }, asio::detached);
                                        } else {
                                            asio::co_spawn(ex_, [stream]() -> wavex::task<void> {
                                                char buf[1024];
                                                while (stream->is_open()) {
                                                    auto [ec, n] = co_await stream->async_read_some(
                                                        asio::buffer(buf), asio::as_tuple(asio::use_awaitable));
                                                    if (ec || n == 0) break;
                                                }
                                                co_return;
                                            }, asio::detached);
                                        }
                                        return;
                                    }
                                    // Only client-initiated bidirectional streams (sid & 0x03 == 0) carry HTTP requests
                                    if ((sid & 0x03) == 0x00) {
                                        StreamHandler handler;
                                        {
                                            std::lock_guard lock(mtx_);
                                            handler = stream_handler_;
                                        }
                                        if (handler) {
                                            // See NOTE above (uni_handler case): pass the callable itself, not
                                            // handler(stream), so co_spawn owns a copy for the coroutine's full
                                            // lifetime instead of dangling once the local `handler` goes out of
                                            // scope. This was the root cause of the async_read_some fast-path
                                            // segfault: the coroutine's captured reference to the handler's own
                                            // closure (e.g. server_received_msg in test_quic.cpp) was already a
                                            // dangling pointer by the time the completion handler resumed it.
                                            asio::co_spawn(ex_, [handler, stream]() -> wavex::task<void> {
                                                co_await handler(stream);
                                            }, asio::detached);
                                        }
                                    }
                                });
                            }
                        }
                    }

                    if (conn) {
                        conn->handle_datagram(datagram);
                        flush_outbound(conn);
                    } else {
                        wavex::log::warn("[QUIC] [server] No connection found for DCID={} (type={})",
                                         hdr.dcid.to_string(), static_cast<int>(hdr.type));
                    }
                }

                do_receive();
            }
        );
    }

    void QuicServer::flush_outbound(const std::shared_ptr<QuicConnection> &conn) {
        if (stopped_.load()) return;
        for (auto datagrams = conn->poll_outgoing_datagrams(); auto &dgram: datagrams) {
            if (dgram.empty()) continue;
            auto buf = std::make_shared<std::string>(std::move(dgram));
            std::lock_guard sock_lock(sock_mtx_);
            if (!socket_.is_open()) return;
            socket_.async_send_to(
                asio::buffer(*buf), conn->peer_endpoint(),
                [buf](const std::error_code ec, std::size_t) {
                    if (ec && ec != asio::error::operation_aborted) {
                        wavex::log::error("[QUIC] async_send_to failed: {}", ec.message());
                    }
                }
            );
        }
    }

    void QuicServer::set_tls_credentials(std::string cert_file, std::string key_file) {
        std::error_code ec;
        if (!std::filesystem::exists(cert_file, ec)) {
            wavex::log::error("[QuicServer] TLS certificate file not found: '{}'", cert_file);
            throw std::runtime_error("QuicServer::set_tls_credentials: Certificate file not found: '" + cert_file + "'");
        }
        if (!std::filesystem::exists(key_file, ec)) {
            wavex::log::error("[QuicServer] TLS private key file not found: '{}'", key_file);
            throw std::runtime_error("QuicServer::set_tls_credentials: Private key file not found: '" + key_file + "'");
        }
        std::lock_guard lock(mtx_);
        tls_cert_file_ = std::move(cert_file);
        tls_key_file_ = std::move(key_file);
        init_shared_ssl_ctx();
    }

    void QuicServer::init_shared_ssl_ctx() {
        if (shared_ssl_ctx_) {
            SSL_CTX_free(shared_ssl_ctx_);
            shared_ssl_ctx_ = nullptr;
        }
        if (tls_cert_file_.empty() || tls_key_file_.empty()) return;

        shared_ssl_ctx_ = SSL_CTX_new(TLS_server_method());
        if (!shared_ssl_ctx_) {
            wavex::log::error("[QuicServer] SSL_CTX_new failed for shared server context");
            return;
        }

        SSL_CTX_set_min_proto_version(shared_ssl_ctx_, TLS1_3_VERSION);
        SSL_CTX_set_max_proto_version(shared_ssl_ctx_, TLS1_3_VERSION);
        SSL_CTX_set_ciphersuites(shared_ssl_ctx_, "TLS_AES_128_GCM_SHA256");

        if ([[maybe_unused]] const char *keylog_path = std::getenv("SSLKEYLOGFILE")) {
            SSL_CTX_set_keylog_callback(
                shared_ssl_ctx_,
                [](const SSL *, const char *line) {
                    if (const char *path = std::getenv("SSLKEYLOGFILE")) {
                        if (std::ofstream ofs(path, std::ios::app); ofs.is_open()) {
                            ofs << line << "\n";
                        }
                    }
                });
        }

        if (SSL_CTX_use_certificate_file(shared_ssl_ctx_, tls_cert_file_.c_str(), SSL_FILETYPE_PEM) != 1) {
            wavex::log::error("[QuicServer] SSL_CTX_use_certificate_file failed for '{}'", tls_cert_file_);
            SSL_CTX_free(shared_ssl_ctx_);
            shared_ssl_ctx_ = nullptr;
            throw std::runtime_error("QuicServer: SSL_CTX_use_certificate_file failed for '" + tls_cert_file_ + "'");
        }
        if (SSL_CTX_use_PrivateKey_file(shared_ssl_ctx_, tls_key_file_.c_str(), SSL_FILETYPE_PEM) != 1) {
            wavex::log::error("[QuicServer] SSL_CTX_use_PrivateKey_file failed for '{}'", tls_key_file_);
            SSL_CTX_free(shared_ssl_ctx_);
            shared_ssl_ctx_ = nullptr;
            throw std::runtime_error("QuicServer: SSL_CTX_use_PrivateKey_file failed for '" + tls_key_file_ + "'");
        }

        SSL_CTX_set_alpn_select_cb(
            shared_ssl_ctx_,
            [](SSL *, const unsigned char **out, unsigned char *outlen,
               const unsigned char *in, const unsigned int inlen, void *) -> int {
                unsigned int i = 0;
                while (i < inlen) {
                    const unsigned char proto_len = in[i++];
                    if (i + proto_len > inlen) break;
                    if (const std::string_view proto(reinterpret_cast<const char *>(in + i), proto_len); proto == "h3" || proto == "h3-29") {
                        *out = in + i;
                        *outlen = proto_len;
                        return SSL_TLSEXT_ERR_OK;
                    }
                    i += proto_len;
                }
                return SSL_TLSEXT_ERR_NOACK;
            },
            nullptr);

        wavex::log::info("[QuicServer] Initialized shared server SSL_CTX with cert '{}' and key '{}'",
                         tls_cert_file_, tls_key_file_);
    }

} // namespace wavex::network::quic

#endif // WAVEX_HAS_SSL
