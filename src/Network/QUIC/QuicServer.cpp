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
        if (!socket_.is_open()) return;
        running_ = true;
        do_receive();
    }

    void QuicServer::stop() {
        running_ = false;
        asio::error_code ec;
        socket_.close(ec);
        std::lock_guard lock(mtx_);
        for (auto &[cid, conn] : connections_) {
            if (conn) {
                conn->close();
            }
        }
        connections_.clear();
    }

    void QuicServer::do_receive() {
        if (!running_) return;

        socket_.async_receive_from(
            asio::buffer(recv_buf_), sender_endpoint_,
            [this](const std::error_code ec, const std::size_t bytes_recvd) {
                // Only abort the receive loop on intentional cancellation (shutdown).
                // Transient UDP errors (e.g. ECONNRESET on Windows) must not halt the loop.
                if (ec == asio::error::operation_aborted) return;
                if (ec || bytes_recvd == 0) {
                    do_receive();
                    return;
                }

                wavex::log::info("[QUIC] [server] Received UDP datagram ({} bytes) from {}:{}",
                                 bytes_recvd, sender_endpoint_.address().to_string(), sender_endpoint_.port());

                const std::string_view datagram(reinterpret_cast<const char *>(recv_buf_.data()), bytes_recvd);
                PacketHeader hdr;
                std::size_t hdr_len = 0;

                if (!unpack_packet_header(datagram, hdr, hdr_len)) {
                    wavex::log::warn("[QUIC] [server] Failed to unpack packet header from {} bytes UDP datagram", bytes_recvd);
                } else {
                    wavex::log::info("[QUIC] [server] Datagram header unpacked: is_long={} type={} dcid={} scid={}",
                                     hdr.is_long, static_cast<int>(hdr.type), hdr.dcid.to_string(), hdr.scid.to_string());

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
                        if (it != connections_.end()) {
                            conn = it->second;
                        } else if (hdr.is_long && hdr.type == PacketType::Initial) {
                            // New incoming connection (Initial)
                            const ConnectionId server_cid = ConnectionId::random(8);
                            conn = std::make_shared<QuicConnection>(server_cid, hdr.scid, sender_endpoint_, true,
                                                                    io_.get_executor(), hdr.dcid);
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

                            conn->set_closed_callback([this](const ConnectionId &scid, const ConnectionId &peer_cid, const ConnectionId &orig_dcid) {
                                asio::post(io_, [this, scid, peer_cid, orig_dcid] {
                                    std::lock_guard lock(mtx_);
                                    connections_.erase(scid);
                                    if (!orig_dcid.empty()) connections_.erase(orig_dcid);
                                    if (!peer_cid.empty()) connections_.erase(peer_cid);
                                    wavex::log::info("[QUIC] [server] Removed closed connection (remaining={})", connections_.size());
                                });
                            });

                            conn->set_outbound_callback([this, weak_conn = std::weak_ptr<QuicConnection>(conn)] {
                                asio::post(io_, [this, weak_conn] {
                                    if (auto c = weak_conn.lock()) {
                                        flush_outbound(c);
                                    }
                                });
                            });

                            if (stream_handler_) {
                                conn->set_stream_created_callback([this](std::shared_ptr<QuicStream> stream) {
                                    if (!stream) return;
                                    const uint64_t sid = stream->stream_id();
                                    // Client-initiated unidirectional stream (sid & 0x03 == 2) per RFC 9114 §6.2
                                    if ((sid & 0x03) == 0x02) {
                                        asio::co_spawn(io_, [stream]() -> asio::awaitable<void> {
                                            char buf[1024];
                                            while (stream->is_open()) {
                                                auto [ec, n] = co_await stream->async_read_some(
                                                    asio::buffer(buf), asio::as_tuple(asio::use_awaitable));
                                                if (ec || n == 0) break;
                                            }
                                            co_return;
                                        }, asio::detached);
                                        return;
                                    }
                                    // Only client-initiated bidirectional streams (sid & 0x03 == 0) carry HTTP requests
                                    if ((sid & 0x03) == 0x00 && stream_handler_) {
                                        asio::co_spawn(io_, stream_handler_(stream), asio::detached);
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
        auto datagrams = conn->poll_outgoing_datagrams();
        if (!datagrams.empty()) {
            wavex::log::info("[QUIC] flush_outbound: sending {} datagram(s) via UDP to {}", datagrams.size(), conn->peer_endpoint().port());
        }
        for (auto &dgram: datagrams) {
            auto buf = std::make_shared<std::string>(std::move(dgram));
            socket_.async_send_to(
                asio::buffer(*buf), conn->peer_endpoint(),
                [buf](std::error_code ec, std::size_t) {
                    if (ec) {
                        wavex::log::error("[QUIC] async_send_to failed: {}", ec.message());
                    }
                }
            );
        }
    }

} // namespace wavex::network::quic

#endif // WAVEX_HAS_SSL
