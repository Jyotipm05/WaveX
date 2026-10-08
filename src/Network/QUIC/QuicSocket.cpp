#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL

#include <wavex/Network/QUIC/QuicSocket.hpp>
#include <wavex/Network/QUIC/QuicCrypto.hpp>
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
#include <asio/use_awaitable.hpp>

#include <algorithm>
#include <cstring>
#include <future>
#include <memory>
#include <string>
#include <system_error>
#include <vector>

namespace wavex::network::quic {

    // ─── 10. Client Outbound Driver ────────────────────────────────────────────

    class ClientOutboundDriver : public basic_quic_socket::OutboundDriver,
                                 public std::enable_shared_from_this<ClientOutboundDriver> {
    public:
        asio::any_io_executor executor_{};
        asio::ip::udp::socket udp_socket_;
        std::weak_ptr<QuicConnection> conn_{};
        basic_quic_socket::endpoint_type server_endpoint_{};
        basic_quic_socket::endpoint_type sender_endpoint_{};
        std::array<uint8_t, 65536> recv_buf_{};
        bool running_{true};

        explicit ClientOutboundDriver(const asio::any_io_executor &ex)
            : executor_(ex), udp_socket_(ex) {
        }

        ~ClientOutboundDriver() override {
            ClientOutboundDriver::close_driver();
        }

        void send_datagram(std::string dgram, const basic_quic_socket::endpoint_type &dest) override {
            if (!udp_socket_.is_open() || !running_) return;
            auto buf = std::make_shared<std::string>(std::move(dgram));
            udp_socket_.async_send_to(
                asio::buffer(*buf), dest,
                [buf](std::error_code, std::size_t) {
                }
            );
        }

        void close_driver() override {
            if (!running_) return;
            running_ = false;
            asio::error_code ec;
            if (udp_socket_.is_open()) {
                udp_socket_.close(ec);
            }
        }

        void start_receive() {
            if (!running_ || !udp_socket_.is_open()) return;
            auto weak_self = std::weak_ptr<ClientOutboundDriver>(shared_from_this());
            udp_socket_.async_receive_from(
                asio::buffer(recv_buf_), sender_endpoint_,
                [this, weak_self](const std::error_code ec, const std::size_t bytes_recvd) {
                    auto self = weak_self.lock();
                    if (!self || ec == asio::error::operation_aborted || !running_) return;
                    if (!ec && bytes_recvd > 0) {
                        if (auto c = conn_.lock()) {
                            const std::string_view dgram(reinterpret_cast<const char *>(recv_buf_.data()), bytes_recvd);
                            c->handle_datagram(dgram);
                            flush_outbound();
                        }
                    }
                    self->start_receive();
                }
            );
        }

        void flush_outbound() {
            if (auto c = conn_.lock()) {
                auto dgrams = c->poll_outgoing_datagrams();
                for (auto &d: dgrams) {
                    send_datagram(std::move(d), server_endpoint_);
                }
            }
        }
    };

    // ─── 11. basic_quic_socket Implementation ──────────────────────────────────

    basic_quic_socket::basic_quic_socket(const executor_type &ex)
        : stream_(nullptr), conn_(nullptr), outbound_driver_(nullptr),
          executor_(ex), remote_endpoint_{}, local_endpoint_{},
          is_open_(false), is_connected_(false) {
    }

    basic_quic_socket::basic_quic_socket(asio::io_context &io)
        : basic_quic_socket(io.get_executor()) {
    }

    basic_quic_socket::basic_quic_socket(const executor_type &ex, const endpoint_type &ep)
        : basic_quic_socket(ex) {
        open(quic_protocol(ep.protocol().family()));
    }

    basic_quic_socket::basic_quic_socket(asio::io_context &io, const endpoint_type &ep)
        : basic_quic_socket(io.get_executor(), ep) {
    }

    basic_quic_socket::~basic_quic_socket() {
        std::error_code ec;
        close(ec);
    }

    basic_quic_socket::basic_quic_socket(basic_quic_socket &&other) noexcept
        : stream_(std::move(other.stream_)),
          conn_(std::move(other.conn_)),
          outbound_driver_(std::move(other.outbound_driver_)),
          executor_(std::move(other.executor_)),
          remote_endpoint_(std::move(other.remote_endpoint_)),
          local_endpoint_(std::move(other.local_endpoint_)),
          is_open_(other.is_open_),
          is_connected_(other.is_connected_) {
        other.is_open_ = false;
        other.is_connected_ = false;
    }

    basic_quic_socket &basic_quic_socket::operator=(basic_quic_socket &&other) noexcept {
        if (this != &other) {
            std::error_code ec;
            close(ec);
            stream_ = std::move(other.stream_);
            conn_ = std::move(other.conn_);
            outbound_driver_ = std::move(other.outbound_driver_);
            executor_ = std::move(other.executor_);
            remote_endpoint_ = std::move(other.remote_endpoint_);
            local_endpoint_ = std::move(other.local_endpoint_);
            is_open_ = other.is_open_;
            is_connected_ = other.is_connected_;
            other.is_open_ = false;
            other.is_connected_ = false;
        }
        return *this;
    }

    uint64_t basic_quic_socket::stream_id() const noexcept {
        return stream_ ? stream_->stream_id() : 0;
    }

    basic_quic_socket::endpoint_type basic_quic_socket::remote_endpoint() const {
        if (!is_connected_) throw std::system_error(asio::error::not_connected);
        return remote_endpoint_;
    }

    basic_quic_socket::endpoint_type basic_quic_socket::remote_endpoint(std::error_code &ec) const noexcept {
        if (!is_connected_) {
            ec = asio::error::not_connected;
            return {};
        }
        ec.clear();
        return remote_endpoint_;
    }

    basic_quic_socket::endpoint_type basic_quic_socket::local_endpoint() const {
        return local_endpoint_;
    }

    basic_quic_socket::endpoint_type basic_quic_socket::local_endpoint(std::error_code &ec) const noexcept {
        ec.clear();
        return local_endpoint_;
    }

    void basic_quic_socket::open(const protocol_type &proto) {
        std::error_code ec;
        open(proto, ec);
        if (ec) throw std::system_error(ec);
    }

    void basic_quic_socket::open(const protocol_type &, std::error_code &ec) noexcept {
        ec.clear();
        is_open_ = true;
    }

    void basic_quic_socket::close() {
        std::error_code ec;
        close(ec);
        if (ec) throw std::system_error(ec);
    }

    void basic_quic_socket::close(std::error_code &ec) noexcept {
        ec.clear();
        if (stream_) {
            stream_->close(ec);
            stream_.reset();
        }
        if (outbound_driver_ && conn_) {
            auto pkts = conn_->poll_outgoing_datagrams();
            for (auto &pkt: pkts) {
                outbound_driver_->send_datagram(std::move(pkt), remote_endpoint_);
            }
        }
        outbound_driver_.reset();
        conn_.reset();
        is_open_ = false;
        is_connected_ = false;
    }

    void basic_quic_socket::cancel() {
        std::error_code ec;
        cancel(ec);
        if (ec) throw std::system_error(ec);
    }

    void basic_quic_socket::cancel(std::error_code &ec) const noexcept {
        ec.clear();
        if (stream_) {
            stream_->cancel(ec);
        }
    }

    void basic_quic_socket::shutdown(asio::ip::tcp::socket::shutdown_type what, std::error_code &ec) const noexcept {
        if (stream_) {
            stream_->shutdown(what, ec);
        } else {
            ec = asio::error::not_connected;
        }
    }

    void basic_quic_socket::connect(const endpoint_type &peer_ep) {
        std::error_code ec;
        connect(peer_ep, ec);
        if (ec) throw std::system_error(ec);
    }

    void basic_quic_socket::connect(const endpoint_type &peer_ep, std::error_code &ec) noexcept {
        auto driver = std::make_shared<ClientOutboundDriver>(executor_);
        driver->udp_socket_.open(peer_ep.protocol(), ec);
        if (ec) return;
        driver->udp_socket_.bind(endpoint_type(peer_ep.protocol(), 0), ec);
        if (ec) return;

        driver->server_endpoint_ = peer_ep;
        remote_endpoint_ = peer_ep;
        local_endpoint_ = driver->udp_socket_.local_endpoint(ec);
        if (ec) return;

        const ConnectionId client_cid = ConnectionId::random(8);
        const ConnectionId initial_peer_cid = ConnectionId::random(8);

        conn_ = std::make_shared<QuicConnection>(
            client_cid, initial_peer_cid, peer_ep, false, executor_, initial_peer_cid
        );
        driver->conn_ = conn_;

        conn_->set_outbound_callback([w = std::weak_ptr<ClientOutboundDriver>(driver)] {
            if (auto d = w.lock()) {
                d->flush_outbound();
            }
        });

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

        driver->udp_socket_.send_to(asio::buffer(packet), peer_ep, 0, ec);
        if (ec) return;

        driver->start_receive();
        outbound_driver_ = driver;
        stream_ = conn_->create_stream(true);
        is_open_ = true;
        is_connected_ = true;
    }

    void basic_quic_socket::async_connect_impl(const endpoint_type &peer_ep,
                                               std::function<void(std::error_code)> handler) {
        auto driver = std::make_shared<ClientOutboundDriver>(executor_);
        asio::error_code ec;
        driver->udp_socket_.open(peer_ep.protocol(), ec);
        if (ec) {
            handler(ec);
            return;
        }
        driver->udp_socket_.bind(endpoint_type(peer_ep.protocol(), 0), ec);
        if (ec) {
            handler(ec);
            return;
        }

        driver->server_endpoint_ = peer_ep;
        remote_endpoint_ = peer_ep;
        local_endpoint_ = driver->udp_socket_.local_endpoint(ec);

        const ConnectionId client_cid = ConnectionId::random(8);
        const ConnectionId initial_peer_cid = ConnectionId::random(8);

        conn_ = std::make_shared<QuicConnection>(
            client_cid, initial_peer_cid, peer_ep, false, executor_, initial_peer_cid
        );
        driver->conn_ = conn_;

        conn_->set_outbound_callback([w = std::weak_ptr<ClientOutboundDriver>(driver)] {
            if (auto d = w.lock()) {
                d->flush_outbound();
            }
        });

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

        auto pkt_buf = std::make_shared<std::string>(std::move(packet));
        driver->udp_socket_.async_send_to(
            asio::buffer(*pkt_buf), peer_ep,
            [this, driver, pkt_buf, h = std::move(handler)](std::error_code send_ec, std::size_t) mutable {
                if (send_ec) {
                    h(send_ec);
                    return;
                }
                driver->start_receive();
                outbound_driver_ = driver;
                stream_ = conn_->create_stream(true);
                is_open_ = true;
                is_connected_ = true;
                h(std::error_code{});
            }
        );
    }

    basic_quic_socket basic_quic_socket::open_stream(const bool bidirectional) const {
        if (!conn_ || !is_connected_) {
            throw std::system_error(asio::error::not_connected);
        }
        basic_quic_socket new_sock(executor_);
        auto new_stream = conn_->create_stream(bidirectional);
        new_sock.assign_stream(new_stream, conn_, outbound_driver_, remote_endpoint_, local_endpoint_);
        conn_->queue_stream_data(new_stream->stream_id(), "", false);
        return new_sock;
    }

    void basic_quic_socket::assign_stream(
        std::shared_ptr<QuicStream> stream,
        std::shared_ptr<QuicConnection> conn,
        std::shared_ptr<OutboundDriver> driver,
        endpoint_type remote_ep,
        endpoint_type local_ep) {
        stream_ = std::move(stream);
        conn_ = std::move(conn);
        outbound_driver_ = std::move(driver);
        remote_endpoint_ = remote_ep;
        local_endpoint_ = local_ep;
        is_open_ = (stream_ != nullptr);
        is_connected_ = (stream_ != nullptr);
    }

    // ─── 12. basic_quic_acceptor::AcceptorDriver ───────────────────────────────

    class basic_quic_acceptor::AcceptorDriver : public basic_quic_socket::OutboundDriver {
    public:
        asio::ip::udp::socket &socket_;
        bool active_{true};

        explicit AcceptorDriver(asio::ip::udp::socket &sock) : socket_(sock) {
        }

        ~AcceptorDriver() override = default;

        void send_datagram(std::string dgram, const basic_quic_socket::endpoint_type &dest) override {
            if (!active_ || !socket_.is_open()) return;
            auto buf = std::make_shared<std::string>(std::move(dgram));
            socket_.async_send_to(
                asio::buffer(*buf), dest,
                [buf](std::error_code, std::size_t) {
                }
            );
        }

        void close_driver() override {
            active_ = false;
        }
    };

    // ─── 13. basic_quic_acceptor Implementation ────────────────────────────────

    basic_quic_acceptor::basic_quic_acceptor(const executor_type &ex)
        : executor_(ex), mtx_{}, udp_socket_(ex),
          driver_(nullptr),
          sender_endpoint_{}, connections_{}, accept_queue_{}, pending_accepts_{},
          tls_cert_file_{}, tls_key_file_{}, recv_buf_{},
          is_listening_(false), is_open_(false) {
        driver_ = std::make_shared<AcceptorDriver>(udp_socket_);
    }

    basic_quic_acceptor::basic_quic_acceptor(asio::io_context &io)
        : basic_quic_acceptor(io.get_executor()) {
    }

    basic_quic_acceptor::basic_quic_acceptor(const executor_type &ex, const endpoint_type &ep, const bool reuse_addr)
        : basic_quic_acceptor(ex) {
        asio::error_code ec;
        open(quic_protocol(ep.protocol().family()), ec);
        if (reuse_addr) {
            udp_socket_.set_option(asio::socket_base::reuse_address(true), ec);
        }
        bind(ep, ec);
        listen();
    }

    basic_quic_acceptor::basic_quic_acceptor(asio::io_context &io, const endpoint_type &ep, const bool reuse_addr)
        : basic_quic_acceptor(io.get_executor(), ep, reuse_addr) {
    }

    basic_quic_acceptor::basic_quic_acceptor(asio::io_context &io, const endpoint_type &ep, std::string cert_file,
                                             std::string key_file)
        : basic_quic_acceptor(io.get_executor(), ep, true) {
        set_tls_credentials(std::move(cert_file), std::move(key_file));
    }

    basic_quic_acceptor::~basic_quic_acceptor() {
        std::error_code ec;
        close(ec);
    }

    basic_quic_acceptor::basic_quic_acceptor(basic_quic_acceptor &&other) noexcept
        : executor_(std::move(other.executor_)),
          mtx_{},
          udp_socket_(std::move(other.udp_socket_)),
          driver_(std::move(other.driver_)),
          sender_endpoint_(std::move(other.sender_endpoint_)),
          connections_(std::move(other.connections_)),
          accept_queue_(std::move(other.accept_queue_)),
          pending_accepts_(std::move(other.pending_accepts_)),
          tls_cert_file_(std::move(other.tls_cert_file_)),
          tls_key_file_(std::move(other.tls_key_file_)),
          recv_buf_(other.recv_buf_),
          is_listening_(other.is_listening_),
          is_open_(other.is_open_) {
        other.is_listening_ = false;
        other.is_open_ = false;
    }

    basic_quic_acceptor &basic_quic_acceptor::operator=(basic_quic_acceptor &&other) noexcept {
        if (this != &other) {
            std::error_code ec;
            close(ec);
            executor_ = std::move(other.executor_);
            udp_socket_ = std::move(other.udp_socket_);
            driver_ = std::move(other.driver_);
            sender_endpoint_ = std::move(other.sender_endpoint_);
            connections_ = std::move(other.connections_);
            accept_queue_ = std::move(other.accept_queue_);
            pending_accepts_ = std::move(other.pending_accepts_);
            tls_cert_file_ = std::move(other.tls_cert_file_);
            tls_key_file_ = std::move(other.tls_key_file_);
            recv_buf_ = other.recv_buf_;
            is_listening_ = other.is_listening_;
            is_open_ = other.is_open_;
            other.is_listening_ = false;
            other.is_open_ = false;
        }
        return *this;
    }

    void basic_quic_acceptor::open(const protocol_type &proto) {
        std::error_code ec;
        open(proto, ec);
        if (ec) throw std::system_error(ec);
    }

    void basic_quic_acceptor::open(const protocol_type &proto, std::error_code &ec) noexcept {
        udp_socket_.open(proto.family() == PF_INET6 ? asio::ip::udp::v6() : asio::ip::udp::v4(), ec);
        if (!ec) is_open_ = true;
    }

    void basic_quic_acceptor::bind(const endpoint_type &ep) {
        std::error_code ec;
        bind(ep, ec);
        if (ec) throw std::system_error(ec);
    }

    void basic_quic_acceptor::bind(const endpoint_type &ep, std::error_code &ec) noexcept {
        if (!udp_socket_.is_open()) {
            open(quic_protocol(ep.protocol().family()), ec);
            if (ec) return;
        }
        udp_socket_.bind(ep, ec);
        if (!ec) is_open_ = true;
    }

    void basic_quic_acceptor::listen(int /*backlog*/) {
        std::error_code ec;
        listen(0, ec);
        if (ec) throw std::system_error(ec);
    }

    void basic_quic_acceptor::listen(int /*backlog*/, std::error_code &ec) noexcept {
        ec.clear();
        if (!is_listening_) {
            is_listening_ = true;
            do_receive();
        }
    }

    void basic_quic_acceptor::close() {
        std::error_code ec;
        close(ec);
        if (ec) throw std::system_error(ec);
    }

    void basic_quic_acceptor::close(std::error_code &ec) noexcept {
        is_listening_ = false;
        is_open_ = false;
        cancel(ec);
        if (udp_socket_.is_open()) {
            udp_socket_.close(ec);
        }
        std::unordered_map<ConnectionId, std::shared_ptr<QuicConnection>> conns;
        {
            std::lock_guard lock(mtx_);
            conns = std::move(connections_);
            connections_.clear();
            accept_queue_.clear();
        }
        for (auto &[cid, c] : conns) {
            if (c) c->close();
        }
    }

    void basic_quic_acceptor::cancel() {
        std::error_code ec;
        cancel(ec);
        if (ec) throw std::system_error(ec);
    }

    void basic_quic_acceptor::cancel(std::error_code &ec) noexcept {
        ec.clear();
        if (udp_socket_.is_open()) {
            udp_socket_.cancel(ec);
        }
        std::deque<AcceptHandlerFn> pending; {
            std::lock_guard lock(mtx_);
            pending = std::move(pending_accepts_);
            pending_accepts_.clear();
        }
        for (auto &h: pending) {
            h(asio::error::operation_aborted, AcceptedStreamInfo{});
        }
    }

    basic_quic_acceptor::endpoint_type basic_quic_acceptor::local_endpoint() const {
        std::error_code ec;
        auto ep = local_endpoint(ec);
        if (ec) throw std::system_error(ec);
        return ep;
    }

    basic_quic_acceptor::endpoint_type basic_quic_acceptor::local_endpoint(std::error_code &ec) const noexcept {
        auto ep = udp_socket_.local_endpoint(ec);
        if (!ec && ep.address().is_unspecified()) {
            ep.address(asio::ip::address_v4::loopback());
        }
        return ep;
    }

    void basic_quic_acceptor::set_tls_credentials(std::string cert_file, std::string key_file) {
        std::lock_guard lock(mtx_);
        tls_cert_file_ = std::move(cert_file);
        tls_key_file_ = std::move(key_file);
    }

    std::shared_ptr<basic_quic_socket::OutboundDriver> basic_quic_acceptor::driver() const noexcept {
        return driver_;
    }

    void basic_quic_acceptor::accept(basic_quic_socket &peer_socket) {
        std::error_code ec;
        accept(peer_socket, ec);
        if (ec) throw std::system_error(ec);
    }

    void basic_quic_acceptor::accept(basic_quic_socket &peer_socket, std::error_code &ec) noexcept {
        ec.clear();
        std::unique_lock lock(mtx_);
        if (!accept_queue_.empty()) {
            auto info = std::move(accept_queue_.front());
            accept_queue_.pop_front();
            lock.unlock();
            peer_socket.assign_stream(info.stream, info.conn, driver(), info.peer_ep, local_endpoint());
            return;
        }

        std::promise<AcceptedStreamInfo> prom;
        auto fut = prom.get_future();
        pending_accepts_.push_back([&prom, &ec](std::error_code err, const AcceptedStreamInfo &info) {
            if (err) ec = err;
            prom.set_value(info);
        });
        lock.unlock();

        auto info = fut.get();
        if (!ec) {
            peer_socket.assign_stream(info.stream, info.conn, driver(), info.peer_ep, local_endpoint());
        }
    }

    void basic_quic_acceptor::async_accept_impl(AcceptHandlerFn handler) {
        std::lock_guard lock(mtx_);
        if (!accept_queue_.empty()) {
            auto info = std::move(accept_queue_.front());
            accept_queue_.pop_front();
            handler(std::error_code{}, std::move(info));
            return;
        }
        pending_accepts_.push_back(std::move(handler));
    }

    void basic_quic_acceptor::do_receive() {
        if (!is_listening_ || !udp_socket_.is_open()) return;

        udp_socket_.async_receive_from(
            asio::buffer(recv_buf_), sender_endpoint_,
            [this](const std::error_code ec, const std::size_t bytes_recvd) {
                if (ec == asio::error::operation_aborted || !is_listening_) return;
                if (ec || bytes_recvd == 0) {
                    do_receive();
                    return;
                }

                const std::string_view datagram(reinterpret_cast<const char *>(recv_buf_.data()), bytes_recvd);
                PacketHeader hdr;
                std::size_t hdr_len = 0;

                if (!unpack_packet_header(datagram, hdr, hdr_len)) {
                    wavex::log::warn("[QUIC] [acceptor] Failed to unpack packet header from {} bytes UDP datagram", bytes_recvd);
                } else {

                    if (hdr.is_long && hdr.version != QUIC_VERSION_1 && hdr.version != 0) {
                        std::string vn_packet;
                        vn_packet.push_back(static_cast<char>(0x80 | 0x40));
                        vn_packet.push_back(0);
                        vn_packet.push_back(0);
                        vn_packet.push_back(0);
                        vn_packet.push_back(0);
                        vn_packet.push_back(static_cast<char>(hdr.scid.length()));
                        vn_packet.append(reinterpret_cast<const char *>(hdr.scid.data()), hdr.scid.length());
                        vn_packet.push_back(static_cast<char>(hdr.dcid.length()));
                        vn_packet.append(reinterpret_cast<const char *>(hdr.dcid.data()), hdr.dcid.length());
                        vn_packet.push_back(0);
                        vn_packet.push_back(0);
                        vn_packet.push_back(0);
                        vn_packet.push_back(1);

                        auto buf = std::make_shared<std::string>(std::move(vn_packet));
                        udp_socket_.async_send_to(asio::buffer(*buf), sender_endpoint_, [buf](auto, auto) {
                        });
                        do_receive();
                        return;
                    }

                    std::shared_ptr<QuicConnection> conn;
                    bool is_new = false; {
                        std::lock_guard lock(mtx_);
                        auto it = connections_.find(hdr.dcid);
                        if (it != connections_.end()) {
                            conn = it->second;
                        } else if (hdr.is_long && hdr.type == PacketType::Initial) {
                            is_new = true;
                            const ConnectionId server_cid = ConnectionId::random(8);
                            conn = std::make_shared<QuicConnection>(
                                server_cid, hdr.scid, sender_endpoint_, true, executor_, hdr.dcid
                            );
                            if (!tls_cert_file_.empty() && !tls_key_file_.empty()) {
                                conn->set_tls_credentials(tls_cert_file_, tls_key_file_);
                                if (!conn->init_tls_handshake_engine()) {
                                    wavex::log::error("[QUIC] [acceptor] Failed to init_tls_handshake_engine!");
                                }
                            } else {
                                wavex::log::warn("[QUIC] [acceptor] New incoming connection without TLS credentials: cert='{}' key='{}'", tls_cert_file_, tls_key_file_);
                            }
                            connections_[server_cid] = conn;
                            connections_[hdr.dcid] = conn;

                            conn->set_closed_callback([this](const ConnectionId &scid, const ConnectionId &peer_cid, const ConnectionId &orig_dcid) {
                                asio::post(executor_, [this, scid, peer_cid, orig_dcid] {
                                    std::lock_guard lock(mtx_);
                                    connections_.erase(scid);
                                    if (!orig_dcid.empty()) connections_.erase(orig_dcid);
                                    if (!peer_cid.empty()) connections_.erase(peer_cid);
                                    std::erase_if(accept_queue_, [&](const AcceptedStreamInfo &info) {
                                        return !info.conn || info.conn->local_cid() == scid || info.conn->state() == ConnectionState::Closed;
                                    });
                                });
                            });

                            conn->set_outbound_callback([this, weak_conn = std::weak_ptr<QuicConnection>(conn)] {
                                asio::post(executor_, [this, weak_conn] {
                                    if (auto c = weak_conn.lock()) {
                                        flush_outbound(c);
                                    }
                                });
                            });

                            conn->set_stream_created_callback(
                                [this, weak_conn = std::weak_ptr<QuicConnection>(conn), sender_ep = sender_endpoint_](std::shared_ptr<QuicStream> stream) {
                                    if (!stream) return;
                                    const uint64_t sid = stream->stream_id();
                                    // Client-initiated unidirectional stream (sid & 0x03 == 2)
                                    if ((sid & 0x03) == 0x02) {
                                        asio::co_spawn(executor_, [stream]() -> asio::awaitable<void> {
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
                                    // Client-initiated bidirectional stream (sid & 0x03 == 0)
                                    if ((sid & 0x03) == 0x00) {
                                        if (auto c = weak_conn.lock()) {
                                            on_stream_ready(std::move(stream), c, sender_ep);
                                        }
                                    }
                                });
                        }
                    }

                    if (conn) {
                        conn->handle_datagram(datagram);
                        flush_outbound(conn);
                    } else {
                        wavex::log::warn("[QUIC] [acceptor] No connection found for DCID={} (type={})",
                                         hdr.dcid.to_string(), static_cast<int>(hdr.type));
                    }
                }

                do_receive();
            }
        );
    }

    void basic_quic_acceptor::flush_outbound(const std::shared_ptr<QuicConnection> &conn) {
        auto datagrams = conn->poll_outgoing_datagrams();
        for (auto &dgram: datagrams) {
            auto buf = std::make_shared<std::string>(std::move(dgram));
            udp_socket_.async_send_to(
                asio::buffer(*buf), conn->peer_endpoint(),
                [buf](std::error_code, std::size_t) {
                }
            );
        }
    }

    void basic_quic_acceptor::on_stream_ready(
        std::shared_ptr<QuicStream> stream,
        std::shared_ptr<QuicConnection> conn,
        endpoint_type peer_ep) {
        AcceptHandlerFn handler; {
            std::lock_guard lock(mtx_);
            if (!pending_accepts_.empty()) {
                handler = std::move(pending_accepts_.front());
                pending_accepts_.pop_front();
            } else {
                constexpr std::size_t kMaxAcceptQueueSize = 256;
                if (accept_queue_.size() < kMaxAcceptQueueSize) {
                    accept_queue_.push_back(AcceptedStreamInfo{std::move(stream), std::move(conn), peer_ep});
                } else {
                    wavex::log::warn("[QUIC] [acceptor] accept_queue_ limit reached ({}), dropping unaccepted stream", kMaxAcceptQueueSize);
                }
                return;
            }
        }
        if (handler) {
            handler(std::error_code{}, AcceptedStreamInfo{std::move(stream), std::move(conn), peer_ep});
        }
    }
} // namespace wavex::network::quic

#endif // WAVEX_HAS_SSL

