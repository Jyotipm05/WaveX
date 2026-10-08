#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL

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
#include <future>

namespace wavex::network::quic {

    QuicServer::QuicServer(asio::io_context &io, const uint16_t port)
        : io_(io), socket_(io) {
        asio::error_code ec;
        socket_.open(asio::ip::udp::v4(), ec);
        socket_.set_option(asio::socket_base::reuse_address(true), ec);
        socket_.bind(asio::ip::udp::endpoint(asio::ip::udp::v4(), port), ec);
    }

    QuicServer::QuicServer(asio::io_context &io, const std::string_view host, const uint16_t port)
        : io_(io), socket_(io) {
        asio::error_code ec;
        auto addr = asio::ip::make_address(host, ec);
        if (!ec) {
            socket_.open(addr.is_v6() ? asio::ip::udp::v6() : asio::ip::udp::v4(), ec);
            socket_.set_option(asio::socket_base::reuse_address(true), ec);
            socket_.bind(asio::ip::udp::endpoint(addr, port), ec);
        }
    }

    QuicServer::~QuicServer() {
        stop();
    }

    void QuicServer::start() {
        if (!socket_.is_open() || stopped_.load()) return;
        running_.store(true);
        do_receive();
    }

    void QuicServer::stop() {
        if (stopped_.exchange(true)) return;
        running_.store(false);

        asio::error_code ec;
        socket_.close(ec); // cancels pending async_receive_from first

        // Teardown MUST happen on the io thread, after all in-flight
        // handle_datagram/flush_outbound calls have finished, and posted
        // callbacks must not touch a dying server.
        std::unordered_map<ConnectionId, std::shared_ptr<QuicConnection>> conns;
        {
            std::lock_guard lock(mtx_);
            conns.swap(connections_);
        }
        if (conns.empty() || io_.get_executor().running_in_this_thread() || io_.stopped()) {
            for (auto &[cid, conn] : conns) {
                if (conn) conn->close();
            }
            return;
        }

        std::promise<void> drained;
        auto fut = drained.get_future();
        asio::post(io_, [&conns, &drained] {
            for (auto &[cid, conn] : conns) {
                if (conn) conn->close();
            }
            drained.set_value();
        });
        fut.wait_for(std::chrono::milliseconds(500));
    }

    void QuicServer::do_receive() {
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

                wavex::log::info("[QuicServer] Received {} bytes from {}",
                                 bytes_recvd, sender_endpoint_.address().to_string());

                const std::string_view datagram(reinterpret_cast<const char *>(recv_buf_.data()), bytes_recvd);
                PacketHeader hdr;
                std::size_t hdr_len = 0;

                if (!unpack_packet_header(datagram, hdr, hdr_len)) {
                    wavex::log::warn("[QUIC] [server] Failed to unpack packet header from {} bytes UDP datagram", bytes_recvd);
                } else {

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
                        socket_.async_send_to(asio::buffer(*buf), sender_endpoint_, [buf](auto, auto) {
                        });
                        do_receive();
                        return;
                    }

                    std::shared_ptr<QuicConnection> conn; {
                        std::lock_guard lock(mtx_);
                        auto it = connections_.find(hdr.dcid);
                        if (it == connections_.end() && !hdr.scid.empty()) {
                            it = connections_.find(hdr.scid);
                        }
                        if (it != connections_.end()) {
                            conn = it->second;
                        } else if (hdr.is_long && hdr.type == PacketType::Initial) {
                            // New incoming connection (Initial)
                            const ConnectionId server_cid = ConnectionId::random(8);
                            conn = std::make_shared<QuicConnection>(server_cid, hdr.scid, sender_endpoint_, true,
                                                                    io_.get_executor(), hdr.dcid);

                            conn->set_outbound_callback([this, weak_conn = std::weak_ptr<QuicConnection>(conn)] {
                                if (stopped_.load() || !running_.load()) return;
                                if (io_.get_executor().running_in_this_thread()) {
                                    if (auto c = weak_conn.lock()) {
                                        flush_outbound(c);
                                    }
                                } else {
                                    asio::post(io_, [this, weak_conn] {
                                        if (stopped_.load() || !running_.load()) return;
                                        if (auto c = weak_conn.lock()) {
                                            flush_outbound(c);
                                        }
                                    });
                                }
                            });

                            conn->set_closed_callback([this, server_cid](const ConnectionId &scid, const ConnectionId &peer_cid, const ConnectionId &orig_dcid) {
                                asio::post(io_, [this, server_cid, scid, peer_cid, orig_dcid] {
                                    if (stopped_.load()) return;
                                    std::lock_guard lock(mtx_);
                                    connections_.erase(server_cid);
                                    connections_.erase(scid);
                                    if (!orig_dcid.empty()) connections_.erase(orig_dcid);
                                    if (!peer_cid.empty()) connections_.erase(peer_cid);
                                    wavex::log::info("[QUIC] [server] Removed closed connection (remaining={})", connections_.size());
                                });
                            });

                            std::string cert = tls_cert_file_;
                            std::string key = tls_key_file_;
                            if (!cert.empty() && !key.empty()) {
                                conn->set_tls_credentials(std::move(cert), std::move(key));
                                if (!conn->init_tls_handshake_engine()) {
                                    wavex::log::error("[QUIC] Failed to init_tls_handshake_engine for new incoming connection!");
                                }
                            } else {
                                wavex::log::warn("[QUIC] New incoming connection without TLS credentials: cert='{}' key='{}'", cert, key);
                            }
                            connections_[server_cid] = conn;
                            connections_[hdr.dcid] = conn;
                            if (!hdr.scid.empty()) connections_[hdr.scid] = conn;

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
                                            asio::co_spawn(io_, uni_handler(stream), asio::detached);
                                        } else {
                                            asio::co_spawn(io_, [stream]() -> asio::awaitable<void> {
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
                                            asio::co_spawn(io_, handler(stream), asio::detached);
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
        if (stopped_.load() || !socket_.is_open()) return;
        auto datagrams = conn->poll_outgoing_datagrams();
        for (auto &dgram: datagrams) {
            auto buf = std::make_shared<std::string>(std::move(dgram));
            socket_.async_send_to(
                asio::buffer(*buf), conn->peer_endpoint(),
                [buf](std::error_code ec, std::size_t) {
                    if (ec && ec != asio::error::operation_aborted) {
                        wavex::log::error("[QUIC] async_send_to failed: {}", ec.message());
                    }
                }
            );
        }
    }

} // namespace wavex::network::quic

#endif // WAVEX_HAS_SSL
