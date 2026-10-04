#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL

#include <wavex/Network/QUIC/QuicClient.hpp>
#include <wavex/Network/QUIC/QuicCrypto.hpp>

#if defined(min)
#undef min
#endif
#if defined(max)
#undef max
#endif

#include <asio/use_awaitable.hpp>
#include <memory>
#include <string>
#include <utility>

namespace wavex::network::quic {

    QuicClient::QuicClient(asio::io_context &io)
        : io_(io), socket_(io) {
        asio::error_code ec;
        socket_.open(asio::ip::udp::v4(), ec);
        socket_.bind(asio::ip::udp::endpoint(asio::ip::udp::v4(), 0), ec);
    }

    QuicClient::~QuicClient() {
        close();
    }

    asio::awaitable<bool> QuicClient::connect(const std::string_view host, const uint16_t port) {
        asio::error_code ec;
        auto addr = asio::ip::make_address(host, ec);
        if (ec) co_return false;

        server_endpoint_ = asio::ip::udp::endpoint(addr, port);
        const ConnectionId client_cid = ConnectionId::random(8);
        const ConnectionId initial_peer_cid = ConnectionId::random(8);

        connection_ = std::make_shared<QuicConnection>(client_cid, initial_peer_cid, server_endpoint_, false,
                                                       io_.get_executor(), initial_peer_cid);
        connection_->set_outbound_callback([this] {
            flush_outbound();
        });

        // Send Initial Ping packet to initiate connection
        PacketHeader hdr;
        hdr.is_long = true;
        hdr.type = PacketType::Initial;
        hdr.version = QUIC_VERSION_1;
        hdr.dcid = initial_peer_cid;
        hdr.scid = client_cid;
        hdr.packet_number = 0;

        PingFrame pf;
        std::string payload;
        serialize_frame(pf, payload);

        std::string packet;
        ProtectionKeys client_keys, server_keys;
        CryptoSuite::derive_initial_secrets(initial_peer_cid, client_keys, server_keys);
        CryptoSuite::protect_packet(client_keys, hdr, payload, packet);

        co_await socket_.async_send_to(asio::buffer(packet), server_endpoint_, asio::use_awaitable);

        do_receive();
        connected_ = true;
        co_return true;
    }

    std::shared_ptr<QuicStream> QuicClient::create_stream(const bool bidirectional) {
        if (!connection_) return nullptr;
        auto stream = connection_->create_stream(bidirectional);
        flush_outbound();
        return stream;
    }

    void QuicClient::close() {
        if (connection_) {
            connection_->close();
            flush_outbound();
        }
        asio::error_code ec;
        socket_.close(ec);
    }

    void QuicClient::do_receive() {
        socket_.async_receive_from(
            asio::buffer(recv_buf_), server_endpoint_,
            [this](const std::error_code ec, const std::size_t bytes_recvd) {
                if (ec || bytes_recvd == 0) return;
                const std::string_view datagram(reinterpret_cast<const char *>(recv_buf_.data()), bytes_recvd);
                if (connection_) {
                    connection_->handle_datagram(datagram);
                    flush_outbound();
                }
                do_receive();
            }
        );
    }

    void QuicClient::flush_outbound() {
        if (!connection_) return;
        auto datagrams = connection_->poll_outgoing_datagrams();
        for (auto &dgram: datagrams) {
            auto buf = std::make_shared<std::string>(std::move(dgram));
            socket_.async_send_to(
                asio::buffer(*buf), server_endpoint_,
                [buf](std::error_code, std::size_t) {
                }
            );
        }
    }

} // namespace wavex::network::quic

#endif // WAVEX_HAS_SSL

