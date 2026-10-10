/**
 * @file QuicSocket.hpp
 * @brief Asio-compatible socket and acceptor abstractions over QUIC transport.
 */

#pragma once

#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL

#if defined(min)
#undef min
#endif
#if defined(max)
#undef max
#endif

#include <array>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <system_error>
#include <unordered_map>
#include <utility>

#include <asio/any_io_executor.hpp>
#include <asio/async_result.hpp>
#include <asio/buffer.hpp>
#include <asio/error.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/ip/udp.hpp>
#include <asio/post.hpp>
#include <asio/socket_base.hpp>

#include <wavex/Network/QUIC/ConnectionId.hpp>
#include <wavex/Network/QUIC/QuicConnection.hpp>
#include <wavex/Network/QUIC/QuicStream.hpp>

namespace wavex::network::quic {
    /**
     * @class quic_protocol
     * @brief Protocol traits tag mimicking asio::ip::tcp / asio::ip::udp.
     */
    class quic_protocol {
    public:
        // ─── 1. Nested Types & Definitions (TOP) ───────────────────────────
        using endpoint = asio::ip::udp::endpoint;
        using resolver = asio::ip::udp::resolver;

    private:
        // ─── 2. Member Variables (SECOND - Ordered for Minimal Padding) ────
        int family_{PF_INET};

    public:
        // ─── 3. Constructors & Destructor (MIDDLE) ─────────────────────────
        constexpr explicit quic_protocol(const int family = PF_INET) noexcept : family_(family) {
        }

        ~quic_protocol() = default;

        constexpr quic_protocol(const quic_protocol &) noexcept = default;

        constexpr quic_protocol &operator=(const quic_protocol &) noexcept = default;

        constexpr quic_protocol(quic_protocol &&) noexcept = default;

        constexpr quic_protocol &operator=(quic_protocol &&) noexcept = default;

        // ─── 4. Member Functions & Friend Declarations (LAST) ──────────────
        [[nodiscard]] static auto type() noexcept -> int { return SOCK_DGRAM; }
        [[nodiscard]] static auto protocol() noexcept -> int { return IPPROTO_UDP; }
        [[nodiscard]] auto family() const noexcept -> int { return family_; }

        [[nodiscard]] operator asio::ip::udp() const noexcept {
            return family_ == PF_INET6 ? asio::ip::udp::v6() : asio::ip::udp::v4();
        }

        [[nodiscard]] static auto v4() noexcept -> quic_protocol { return quic_protocol(PF_INET); }
        [[nodiscard]] static auto v6() noexcept -> quic_protocol { return quic_protocol(PF_INET6); }

        friend constexpr auto operator==(const quic_protocol &p1, const quic_protocol &p2) noexcept -> bool {
            return p1.family_ == p2.family_;
        }

        friend constexpr auto operator!=(const quic_protocol &p1, const quic_protocol &p2) noexcept -> bool {
            return !(p1 == p2);
        }
    };

    [[nodiscard]] inline auto v4() noexcept -> quic_protocol { return quic_protocol::v4(); }
    [[nodiscard]] inline auto v6() noexcept -> quic_protocol { return quic_protocol::v6(); }

    /**
     * @class basic_quic_socket
     * @brief Stream socket mimicking asio::ip::tcp::socket over a QUIC stream.
     */
    class basic_quic_socket {
    public:
        // ─── 1. Nested Types & Definitions (TOP) ───────────────────────────
        using executor_type = asio::any_io_executor;
        using lowest_layer_type = basic_quic_socket;
        using protocol_type = quic_protocol;
        using endpoint_type = quic_protocol::endpoint;

        struct OutboundDriver {
            virtual ~OutboundDriver() = default;

            virtual void send_datagram(std::string dgram, const endpoint_type &dest) = 0;

            virtual void close_driver() = 0;
        };

    private:
        // ─── 2. Member Variables (SECOND - Ordered for Minimal Padding) ────
        std::shared_ptr<QuicStream> stream_{};
        std::shared_ptr<QuicConnection> conn_{};
        std::shared_ptr<OutboundDriver> outbound_driver_{};
        asio::any_io_executor executor_{};
        endpoint_type remote_endpoint_{};
        endpoint_type local_endpoint_{};
        bool is_open_{false};
        bool is_connected_{false};

    public:
        // ─── 3. Constructors & Destructor (MIDDLE) ─────────────────────────
        explicit basic_quic_socket(const executor_type &ex);

        explicit basic_quic_socket(asio::io_context &io);

        basic_quic_socket(const executor_type &ex, const endpoint_type &ep);

        basic_quic_socket(asio::io_context &io, const endpoint_type &ep);

        ~basic_quic_socket();

        basic_quic_socket(const basic_quic_socket &) = delete;

        basic_quic_socket &operator=(const basic_quic_socket &) = delete;

        basic_quic_socket(basic_quic_socket &&) noexcept;

        basic_quic_socket &operator=(basic_quic_socket &&) noexcept;

        // ─── 4. Member Functions & Friend Declarations (LAST) ──────────────
        [[nodiscard]] auto get_executor() const noexcept -> executor_type { return executor_; }
        [[nodiscard]] lowest_layer_type &lowest_layer() noexcept { return *this; }
        [[nodiscard]] const lowest_layer_type &lowest_layer() const noexcept { return *this; }

        [[nodiscard]] bool is_open() const noexcept { return is_open_; }

        [[nodiscard]] uint64_t stream_id() const noexcept;

        [[nodiscard]] endpoint_type remote_endpoint() const;

        [[nodiscard]] endpoint_type remote_endpoint(std::error_code &ec) const noexcept;

        [[nodiscard]] endpoint_type local_endpoint() const;

        [[nodiscard]] endpoint_type local_endpoint(std::error_code &ec) const noexcept;

        void open(const protocol_type &proto = quic_protocol::v4());

        void open(const protocol_type &proto, std::error_code &ec) noexcept;

        void close();

        void close(std::error_code &ec) noexcept;

        void cancel();

        void cancel(std::error_code &ec) const noexcept;

        void shutdown(asio::ip::tcp::socket::shutdown_type what, std::error_code &ec) const noexcept;

        void connect(const endpoint_type &peer_ep);

        void connect(const endpoint_type &peer_ep, std::error_code &ec) noexcept;

        template<typename ConnectToken = asio::default_completion_token_t<executor_type> >
        auto async_connect(const endpoint_type &peer_ep, ConnectToken &&token = ConnectToken{}) {
            return asio::async_initiate<ConnectToken, void(std::error_code)>(
                [this, peer_ep]<typename T0>(T0 handler) {
                    using HandlerType = std::decay_t<T0>;
                    auto shared_h = std::make_shared<HandlerType>(std::move(handler));
                    auto ex = asio::get_associated_executor(*shared_h, this->get_executor());
                    this->async_connect_impl(peer_ep, [shared_h, ex](std::error_code ec) {
                        asio::post(ex, [shared_h, ec]() mutable {
                            (*shared_h)(ec);
                        });
                    });
                },
                token
            );
        }

        template<typename MutableBufferSequence>
        std::size_t read_some(const MutableBufferSequence &buffers, std::error_code &ec) noexcept {
            if (!stream_) {
                ec = asio::error::not_connected;
                return 0;
            }
            auto first = asio::buffer_sequence_begin(buffers);
            if (first == asio::buffer_sequence_end(buffers)) {
                ec.clear();
                return 0;
            }
            return stream_->read_some(*first, ec);
        }

        template<typename MutableBufferSequence, typename ReadToken = asio::default_completion_token_t<executor_type> >
        auto async_read_some(const MutableBufferSequence &buffers, ReadToken &&token = ReadToken{}) {
            if (!stream_) {
                return asio::async_initiate<ReadToken, void(std::error_code, std::size_t)>(
                    [this](auto handler) {
                        auto ex = asio::get_associated_executor(handler, this->get_executor());
                        asio::post(ex, [h = std::move(handler)]() mutable {
                            h(asio::error::not_connected, 0);
                        });
                    },
                    token
                );
            }
            return stream_->async_read_some(buffers, std::forward<ReadToken>(token));
        }

        template<typename ConstBufferSequence>
        std::size_t write_some(const ConstBufferSequence &buffers, std::error_code &ec) noexcept {
            if (!stream_) {
                ec = asio::error::not_connected;
                return 0;
            }
            const std::size_t len = asio::buffer_size(buffers);
            std::string payload;
            payload.reserve(len);
            for (auto b = asio::buffer_sequence_begin(buffers); b != asio::buffer_sequence_end(buffers); ++b) {
                asio::const_buffer cb(*b);
                payload.append(static_cast<const char *>(cb.data()), cb.size());
            }
            ec = stream_->write_outbound(payload, false);
            return ec ? 0 : len;
        }

        template<typename ConstBufferSequence, typename WriteToken = asio::default_completion_token_t<executor_type> >
        auto async_write_some(const ConstBufferSequence &buffers, WriteToken &&token = WriteToken{}) {
            if (!stream_) {
                return asio::async_initiate<WriteToken, void(std::error_code, std::size_t)>(
                    [this](auto handler) {
                        auto ex = asio::get_associated_executor(handler, this->get_executor());
                        asio::post(ex, [h = std::move(handler)]() mutable {
                            h(asio::error::not_connected, 0);
                        });
                    },
                    token
                );
            }
            return stream_->async_write_some(buffers, std::forward<WriteToken>(token));
        }

        [[nodiscard]] basic_quic_socket open_stream(bool bidirectional = true) const;

        void assign_stream(
            std::shared_ptr<QuicStream> stream,
            std::shared_ptr<QuicConnection> conn,
            std::shared_ptr<OutboundDriver> driver,
            endpoint_type remote_ep,
            endpoint_type local_ep);

        [[nodiscard]] std::shared_ptr<QuicStream> stream() const noexcept { return stream_; }
        [[nodiscard]] std::shared_ptr<QuicConnection> connection() const noexcept { return conn_; }

    private:
        void async_connect_impl(const endpoint_type &peer_ep, std::function<void(std::error_code)> handler);
    };

    /**
     * @class basic_quic_acceptor
     * @brief Acceptor mimicking asio::ip::tcp::acceptor, listening on a UDP port for QUIC streams.
     */
    class basic_quic_acceptor {
    public:
        // ─── 1. Nested Types & Definitions (TOP) ───────────────────────────
        using executor_type = asio::any_io_executor;
        using protocol_type = quic_protocol;
        using endpoint_type = quic_protocol::endpoint;

        struct AcceptedStreamInfo {
            std::shared_ptr<QuicStream> stream{};
            std::shared_ptr<QuicConnection> conn{};
            endpoint_type peer_ep{};
        };

        using AcceptHandlerFn = std::function<void(std::error_code, const AcceptedStreamInfo &)>;

        class AcceptorDriver;

    private:
        // ─── 2. Member Variables (SECOND - Ordered for Minimal Padding) ────
        asio::any_io_executor executor_{};
        mutable std::mutex mtx_{};
        asio::ip::udp::socket udp_socket_;
        std::shared_ptr<AcceptorDriver> driver_{};
        endpoint_type sender_endpoint_{};
        std::unordered_map<ConnectionId, std::shared_ptr<QuicConnection> > connections_{};
        std::deque<AcceptedStreamInfo> accept_queue_{};
        std::deque<AcceptHandlerFn> pending_accepts_{};
        std::string tls_cert_file_{};
        std::string tls_key_file_{};
        std::array<uint8_t, 65536> recv_buf_{};
        bool is_listening_{false};
        bool is_open_{false};

    public:
        // ─── 3. Constructors & Destructor (MIDDLE) ─────────────────────────
        explicit basic_quic_acceptor(const executor_type &ex);

        explicit basic_quic_acceptor(asio::io_context &io);

        basic_quic_acceptor(const executor_type &ex, const endpoint_type &ep, bool reuse_addr = true);

        basic_quic_acceptor(asio::io_context &io, const endpoint_type &ep, bool reuse_addr = true);

        basic_quic_acceptor(asio::io_context &io, const endpoint_type &ep, std::string cert_file, std::string key_file);

        ~basic_quic_acceptor();

        basic_quic_acceptor(const basic_quic_acceptor &) = delete;

        basic_quic_acceptor &operator=(const basic_quic_acceptor &) = delete;

        basic_quic_acceptor(basic_quic_acceptor &&) noexcept;

        basic_quic_acceptor &operator=(basic_quic_acceptor &&) noexcept;

        // ─── 4. Member Functions & Friend Declarations (LAST) ──────────────
        [[nodiscard]] executor_type get_executor() const noexcept { return executor_; }

        void open(const protocol_type &proto = quic_protocol::v4());

        void open(const protocol_type &proto, std::error_code &ec) noexcept;

        void bind(const endpoint_type &ep);

        void bind(const endpoint_type &ep, std::error_code &ec) noexcept;

        void listen(int backlog = asio::socket_base::max_listen_connections);

        void listen(int backlog, std::error_code &ec) noexcept;

        void close();

        void close(std::error_code &ec) noexcept;

        void cancel();

        void cancel(std::error_code &ec) noexcept;

        [[nodiscard]] bool is_open() const noexcept { return is_open_ && udp_socket_.is_open(); }

        [[nodiscard]] endpoint_type local_endpoint() const;

        [[nodiscard]] endpoint_type local_endpoint(std::error_code &ec) const noexcept;

        void set_tls_credentials(std::string cert_file, std::string key_file);

        void accept(basic_quic_socket &peer_socket);

        void accept(basic_quic_socket &peer_socket, std::error_code &ec) noexcept;

        template<typename AcceptToken = asio::default_completion_token_t<executor_type> >
        auto async_accept(basic_quic_socket &peer_socket, AcceptToken &&token = AcceptToken{}) {
            return asio::async_initiate<AcceptToken, void(std::error_code)>(
                [this, &peer_socket]<typename T0>(T0 handler) {
                    using HandlerType = std::decay_t<T0>;
                    auto shared_h = std::make_shared<HandlerType>(std::move(handler));
                    auto ex = asio::get_associated_executor(*shared_h, this->get_executor());
                    this->async_accept_impl(
                        [&peer_socket, shared_h, ex, this](std::error_code ec, const AcceptedStreamInfo &info) {
                            if (!ec) {
                                peer_socket.assign_stream(
                                    info.stream, info.conn, this->driver(),
                                    info.peer_ep, this->local_endpoint()
                                );
                            }
                            asio::post(ex, [shared_h, ec]() mutable {
                                (*shared_h)(ec);
                            });
                        }
                    );
                },
                token
            );
        }

        template<typename AcceptToken = asio::default_completion_token_t<executor_type> >
        auto async_accept(AcceptToken &&token = AcceptToken{}) {
            return asio::async_initiate<AcceptToken, void(std::error_code, basic_quic_socket)>(
                [this]<typename T0>(T0 handler) {
                    using HandlerType = std::decay_t<T0>;
                    auto shared_h = std::make_shared<HandlerType>(std::move(handler));
                    auto ex = asio::get_associated_executor(*shared_h, this->get_executor());
                    this->async_accept_impl(
                        [shared_h, ex, this](std::error_code ec, const AcceptedStreamInfo &info) mutable {
                            basic_quic_socket sock(this->get_executor());
                            if (!ec) {
                                sock.assign_stream(
                                    info.stream, info.conn, this->driver(),
                                    info.peer_ep, this->local_endpoint()
                                );
                            }
                            asio::post(ex, [shared_h, ec, s = std::move(sock)]() mutable {
                                (*shared_h)(ec, std::move(s));
                            });
                        }
                    );
                },
                token
            );
        }

        [[nodiscard]] std::shared_ptr<basic_quic_socket::OutboundDriver> driver() const noexcept;

    private:
        void do_receive();

        void async_accept_impl(AcceptHandlerFn handler);

        void flush_outbound(const std::shared_ptr<QuicConnection> &conn);

        void on_stream_ready(std::shared_ptr<QuicStream> stream, std::shared_ptr<QuicConnection> conn,
                             endpoint_type peer_ep);
    };

    // ─── 12. Type Aliases (Asio TCP/UDP Convention) ─────────────────────────────

    using protocol = quic_protocol;
    using socket = basic_quic_socket;
    using acceptor = basic_quic_acceptor;
    using endpoint = quic_protocol::endpoint;
    using resolver = quic_protocol::resolver;
} // namespace wavex::network::quic

#endif // WAVEX_HAS_SSL
