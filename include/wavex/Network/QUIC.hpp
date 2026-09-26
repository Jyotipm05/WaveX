// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * @file QUIC.hpp
 * @brief High-performance, RFC 9000 & RFC 9001 compliant QUIC transport implementation for WaveX.
 *
 * Implements:
 *  - RFC 9000: QUIC Core Transport, Connection IDs, Variable-Length Integers, Packet Framing,
 *              Flow Control, Stream Multiplexing, and Loss Detection / Recovery.
 *  - RFC 9001: Using TLS to Secure QUIC, Initial Secrets, Key Derivation, Packet & Header Protection.
 *  - Full AsyncStream Concept compatibility: QuicStream can be plugged directly into WaveX's
 *    Server::handle_connection and client subsystems without changes or overhead.
 */

#pragma once

#ifndef ASIO_HAS_CO_AWAIT
#define ASIO_HAS_CO_AWAIT 1
#endif

#include <array>
#include <cstdint>
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>
#include <deque>
#include <memory>
#include <variant>
#include <optional>
#include <functional>
#include <unordered_map>
#include <mutex>
#include <expected>
#include <system_error>

#include <asio/io_context.hpp>
#include <asio/ip/udp.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/awaitable.hpp>
#include <asio/async_result.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/buffer.hpp>
#include <asio/steady_timer.hpp>
#include <asio/post.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>

#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/core_dispatch.h>
#else
#error "WaveX QUIC transport requires OpenSSL (WAVEX_HAS_SSL=1). Please build with SSL support enabled."
#endif

namespace wavex::network::quic {

    // ─── 1. Constants and Basic Enums ──────────────────────────────────────────

    inline constexpr uint32_t QUIC_VERSION_1 = 0x00000001;
    inline constexpr uint32_t QUIC_VERSION_NEGOTIATION = 0x00000000;
    inline constexpr std::size_t MAX_CONNECTION_ID_LEN = 20;
    inline constexpr std::size_t DEFAULT_MAX_PACKET_SIZE = 1280;

    enum class PacketType : uint8_t {
        Initial = 0x00,
        ZeroRTT = 0x01,
        Handshake = 0x02,
        Retry = 0x03,
        OneRTT = 0x04,
        VersionNegotiation = 0x05
    };

    enum class TransportError : uint64_t {
        NoError = 0x00,
        InternalError = 0x01,
        ConnectionRefused = 0x02,
        FlowControlError = 0x03,
        StreamLimitError = 0x04,
        StreamStateError = 0x05,
        FinalSizeError = 0x06,
        FrameEncodingError = 0x07,
        TransportParameterError = 0x08,
        ConnectionIdLimitError = 0x09,
        ProtocolViolation = 0x0a,
        InvalidToken = 0x0b,
        ApplicationError = 0x0c,
        CryptoBufferExceeded = 0x0d,
        KeyUpdateError = 0xe,
        AeadLimitReached = 0x0f,
        NoViablePath = 0x10
    };

    enum class FrameType : uint64_t {
        Padding = 0x00,
        Ping = 0x01,
        Ack = 0x02,
        AckEcn = 0x03,
        ResetStream = 0x04,
        StopSending = 0x05,
        Crypto = 0x06,
        NewToken = 0x07,
        Stream = 0x08,
        StreamOff = 0x0c,
        StreamLen = 0x0a,
        StreamOffLen = 0x0e,
        StreamFin = 0x09,
        StreamOffFin = 0x0d,
        StreamLenFin = 0x0b,
        StreamOffLenFin = 0x0f,
        MaxData = 0x10,
        MaxStreamData = 0x11,
        MaxStreamsBidi = 0x12,
        MaxStreamsUni = 0x13,
        DataBlocked = 0x14,
        StreamDataBlocked = 0x15,
        StreamsBlockedBidi = 0x16,
        StreamsBlockedUni = 0x17,
        NewConnectionId = 0x18,
        RetireConnectionId = 0x19,
        PathChallenge = 0x1a,
        PathResponse = 0x1b,
        ConnectionCloseQuic = 0x1c,
        ConnectionCloseApp = 0x1d,
        HandshakeDone = 0x1e
    };

    // ─── 2. RFC 9000 Variable-Length Integer (VarInt) ──────────────────────────

    struct VarInt {
        // ─── 4. Member Functions (LAST) ────────────────────────────────────
        [[nodiscard]] static std::size_t encoded_size(uint64_t val) noexcept;
        static void encode(uint64_t val, std::string &out);
        static std::size_t encode(uint64_t val, uint8_t *out, std::size_t max_len) noexcept;
        static bool decode(std::string_view buf, std::size_t &cursor, uint64_t &val) noexcept;
    };

    // ─── 3. Connection ID ──────────────────────────────────────────────────────

    struct ConnectionId {
        // ─── 2. Member Variables (SECOND - Ordered for Minimal Padding) ────
        std::array<uint8_t, MAX_CONNECTION_ID_LEN> data_{};
        uint8_t length_{0};

        // ─── 3. Constructors & Destructor (MIDDLE) ─────────────────────────
        constexpr ConnectionId() noexcept = default;
        ConnectionId(const uint8_t *src, std::size_t len) noexcept;
        explicit ConnectionId(std::string_view sv) noexcept;
        ~ConnectionId() = default;
        ConnectionId(const ConnectionId &) = default;
        ConnectionId &operator=(const ConnectionId &) = default;
        ConnectionId(ConnectionId &&) noexcept = default;
        ConnectionId &operator=(ConnectionId &&) noexcept = default;

        // ─── 4. Member Functions & Friend Declarations (LAST) ──────────────
        [[nodiscard]] uint8_t length() const noexcept { return length_; }
        [[nodiscard]] const uint8_t *data() const noexcept { return data_.data(); }
        [[nodiscard]] uint8_t *data() noexcept { return data_.data(); }
        [[nodiscard]] bool empty() const noexcept { return length_ == 0; }
        [[nodiscard]] std::string to_string() const;
        [[nodiscard]] std::string_view as_string_view() const noexcept {
            return {reinterpret_cast<const char*>(data_.data()), length_};
        }

        static ConnectionId from_hex(std::string_view hex);
        static ConnectionId random(std::size_t len = 8);

        bool operator==(const ConnectionId &other) const noexcept;
        bool operator!=(const ConnectionId &other) const noexcept { return !(*this == other); }
    };

} // namespace wavex::network::quic

namespace std {
    template<>
    struct hash<wavex::network::quic::ConnectionId> {
        std::size_t operator()(const wavex::network::quic::ConnectionId &cid) const noexcept;
    };
} // namespace std

namespace wavex::network::quic {

    // ─── 4. RFC 9000 Frame Structures ──────────────────────────────────────────

    struct PaddingFrame {
        uint32_t length{1};
    };

    struct PingFrame {};

    struct AckRange {
        uint64_t gap{0};
        uint64_t ack_range_len{0};
    };

    struct AckFrame {
        // ─── 2. Member Variables (SECOND - Ordered for Minimal Padding) ────
        std::vector<AckRange> ranges{};
        uint64_t largest_acknowledged{0};
        uint64_t ack_delay{0};
        bool ecn{false};
    };

    struct ResetStreamFrame {
        uint64_t stream_id{0};
        uint64_t error_code{0};
        uint64_t final_size{0};
    };

    struct StopSendingFrame {
        uint64_t stream_id{0};
        uint64_t error_code{0};
    };

    struct CryptoFrame {
        uint64_t offset{0};
        std::string data{};
    };

    struct NewTokenFrame {
        std::string token{};
    };

    struct StreamFrame {
        // ─── 2. Member Variables (SECOND - Ordered for Minimal Padding) ────
        std::string data{};
        uint64_t stream_id{0};
        uint64_t offset{0};
        bool fin{false};
        bool has_offset{false};
        bool has_length{true};
    };

    struct MaxDataFrame {
        uint64_t max_data{0};
    };

    struct MaxStreamDataFrame {
        uint64_t stream_id{0};
        uint64_t max_stream_data{0};
    };

    struct MaxStreamsFrame {
        uint64_t max_streams{0};
        bool bidirectional{true};
    };

    struct DataBlockedFrame {
        uint64_t data_limit{0};
    };

    struct StreamDataBlockedFrame {
        uint64_t stream_id{0};
        uint64_t stream_data_limit{0};
    };

    struct StreamsBlockedFrame {
        uint64_t stream_limit{0};
        bool bidirectional{true};
    };

    struct ConnectionCloseFrame {
        // ─── 2. Member Variables (SECOND - Ordered for Minimal Padding) ────
        std::string reason_phrase{};
        uint64_t error_code{0};
        uint64_t frame_type{0};
        bool is_application{false};
    };

    struct HandshakeDoneFrame {};

    using Frame = std::variant<
        PaddingFrame,
        PingFrame,
        AckFrame,
        ResetStreamFrame,
        StopSendingFrame,
        CryptoFrame,
        NewTokenFrame,
        StreamFrame,
        MaxDataFrame,
        MaxStreamDataFrame,
        MaxStreamsFrame,
        DataBlockedFrame,
        StreamDataBlockedFrame,
        StreamsBlockedFrame,
        ConnectionCloseFrame,
        HandshakeDoneFrame
    >;

    void serialize_frame(const Frame &frame, std::string &out);
    bool parse_frames(std::string_view payload, std::vector<Frame> &out_frames);

    // ─── 5. RFC 9000 & 9001 Packet Structure & Crypto ──────────────────────────

    struct PacketHeader {
        // ─── 2. Member Variables (SECOND - Ordered for Minimal Padding) ────
        std::string token{};
        uint64_t length{0};
        uint64_t packet_number{0};
        uint32_t version{QUIC_VERSION_1};
        uint32_t pn_offset{0};
        ConnectionId dcid{};
        ConnectionId scid{};
        PacketType type{PacketType::OneRTT};
        uint8_t flags{0};
        uint8_t packet_number_len{4};
        bool is_long{false};
    };

    struct ProtectionKeys {
        // ─── 2. Member Variables (SECOND - Ordered for Minimal Padding) ────
        std::array<uint8_t, 32> secret{};
        std::array<uint8_t, 16> key{};
        std::array<uint8_t, 12> iv{};
        std::array<uint8_t, 16> hp{};
        bool valid{false};
    };

    struct CryptoSuite {
        static bool derive_initial_secrets(
            const ConnectionId &client_dcid,
            ProtectionKeys &client_keys,
            ProtectionKeys &server_keys) noexcept;

        static bool expand_quic_keys(
            const uint8_t *secret, std::size_t secret_len,
            ProtectionKeys &keys) noexcept;

        static bool protect_packet(
            const ProtectionKeys &keys,
            PacketHeader &hdr,
            std::string_view plaintext,
            std::string &ciphertext_out) noexcept;

        static bool unprotect_packet(
            const ProtectionKeys &keys,
            PacketHeader &hdr,
            std::string_view packet_bytes,
            std::string &plaintext_out,
            uint64_t largest_pn = 0,
            std::size_t expected_dcid_len = 8) noexcept;
    };

    void pack_packet_header(const PacketHeader &hdr, std::string &out);
    bool unpack_packet_header(std::string_view raw, PacketHeader &hdr, std::size_t &hdr_len, std::size_t expected_dcid_len = 8) noexcept;

    // ─── 6. QuicStream (Meets WaveX AsyncStream Concept) ───────────────────────

    class QuicConnection;

    /**
     * @class QuicStream
     * @brief Multiplexed, full-duplex virtual stream over a QUIC connection.
     *
     * Adheres strictly to the AsyncStream concept:
     *   - async_read_some, async_write_some
     *   - lowest_layer(), next_layer(), shutdown(), close(), cancel()
     *   - Zero-allocation buffer piping into Server::handle_connection.
     */
    class QuicStream : public std::enable_shared_from_this<QuicStream> {
    public:
        // ─── 1. Nested Types & Definitions (TOP) ───────────────────────────
        using executor_type = asio::any_io_executor;
        using ReadCallback = std::function<void(std::error_code, std::size_t)>;

    private:
        // ─── 2. Member Variables (SECOND - Ordered for Minimal Padding) ────
        std::weak_ptr<QuicConnection> conn_{};
        asio::any_io_executor executor_{};
        mutable std::mutex mtx_{};
        std::deque<uint8_t> in_buffer_{};
        std::optional<ReadCallback> pending_read_{};
        void* pending_buf_{nullptr};
        std::size_t pending_buf_size_{0};
        uint64_t stream_id_{0};
        uint64_t send_offset_{0};
        uint64_t recv_offset_{0};
        bool is_open_{true};
        bool fin_received_{false};
        bool fin_sent_{false};

    public:
        // ─── 3. Constructors & Destructor (MIDDLE) ─────────────────────────
        QuicStream(std::shared_ptr<QuicConnection> conn, uint64_t stream_id, asio::any_io_executor executor = {}) noexcept;
        ~QuicStream();
        QuicStream(const QuicStream &) = delete;
        QuicStream &operator=(const QuicStream &) = delete;
        QuicStream(QuicStream &&) noexcept = default;
        QuicStream &operator=(QuicStream &&) noexcept = default;

        // ─── 4. Member Functions & Friend Declarations (LAST) ──────────────
        [[nodiscard]] executor_type get_executor() const noexcept;
        void set_executor(executor_type ex) noexcept { executor_ = std::move(ex); }
        [[nodiscard]] uint64_t stream_id() const noexcept { return stream_id_; }
        [[nodiscard]] bool is_open() const noexcept;
        [[nodiscard]] bool is_fin_received() const noexcept;
        [[nodiscard]] bool is_fin_sent() const noexcept;

        // Stream concept methods
        [[nodiscard]] QuicStream &lowest_layer() noexcept { return *this; }
        [[nodiscard]] const QuicStream &lowest_layer() const noexcept { return *this; }
        [[nodiscard]] QuicStream &next_layer() noexcept { return *this; }
        [[nodiscard]] const QuicStream &next_layer() const noexcept { return *this; }

        std::error_code cancel(std::error_code &ec) noexcept;
        std::error_code shutdown(asio::ip::tcp::socket::shutdown_type type, std::error_code &ec) noexcept;
        std::error_code close(std::error_code &ec) noexcept;
        void close() noexcept;

        [[nodiscard]] std::size_t available(std::error_code &ec) const noexcept;
        std::size_t read_some(const asio::mutable_buffer &buffer, std::error_code &ec) noexcept;

        // Async read initiation
        template<typename MutableBufferSequence, typename Token>
        auto async_read_some(const MutableBufferSequence &buffers, Token &&token) {
            auto weak_self = weak_from_this();
            return asio::async_initiate<Token, void(std::error_code, std::size_t)>(
                [weak_self, buffers](auto handler) {
                    using HandlerType = std::decay_t<decltype(handler)>;
                    auto shared_h = std::make_shared<HandlerType>(std::move(handler));
                    auto self = weak_self.lock();
                    if (!self) {
                        auto executor = asio::get_associated_executor(*shared_h);
                        asio::post(executor, [shared_h] {
                            (*shared_h)(asio::error::operation_aborted, 0);
                        });
                        return;
                    }
                    auto executor = asio::get_associated_executor(*shared_h, self->get_executor());

                    std::lock_guard lock(self->mtx_);
                    if (!self->is_open_ && self->in_buffer_.empty()) {
                        asio::post(executor, [shared_h] {
                            (*shared_h)(asio::error::eof, 0);
                        });
                        return;
                    }

                    if (!self->in_buffer_.empty()) {
                        std::size_t dest_len = asio::buffer_size(buffers);
                        std::size_t to_copy = std::min(dest_len, self->in_buffer_.size());
                        std::size_t copied = 0;
                        for (auto b = asio::buffer_sequence_begin(buffers);
                             b != asio::buffer_sequence_end(buffers) && copied < to_copy; ++b) {
                            asio::mutable_buffer mb(*b);
                            std::size_t chunk = std::min(mb.size(), to_copy - copied);
                            auto *dest = static_cast<uint8_t*>(mb.data());
                            for (std::size_t i = 0; i < chunk; ++i) {
                                dest[i] = self->in_buffer_.front();
                                self->in_buffer_.pop_front();
                            }
                            copied += chunk;
                        }
                        asio::post(executor, [shared_h, copied] {
                            (*shared_h)(std::error_code{}, copied);
                        });
                        return;
                    }

                    if (self->fin_received_) {
                        asio::post(executor, [shared_h] {
                            (*shared_h)(asio::error::eof, 0);
                        });
                        return;
                    }

                    // Register pending read
                    auto first_buf = *asio::buffer_sequence_begin(buffers);
                    self->pending_buf_ = first_buf.data();
                    self->pending_buf_size_ = first_buf.size();
                    self->pending_read_ = [shared_h, executor](std::error_code ec, std::size_t bytes) {
                        asio::post(executor, [shared_h, ec, bytes] {
                            (*shared_h)(ec, bytes);
                        });
                    };
                },
                token
            );
        }

        // Async write initiation
        template<typename ConstBufferSequence, typename Token>
        auto async_write_some(const ConstBufferSequence &buffers, Token &&token) {
            auto weak_self = weak_from_this();
            return asio::async_initiate<Token, void(std::error_code, std::size_t)>(
                [weak_self, buffers](auto handler) {
                    using HandlerType = std::decay_t<decltype(handler)>;
                    auto shared_h = std::make_shared<HandlerType>(std::move(handler));
                    auto self = weak_self.lock();
                    if (!self) {
                        auto executor = asio::get_associated_executor(*shared_h);
                        asio::post(executor, [shared_h] {
                            (*shared_h)(asio::error::operation_aborted, 0);
                        });
                        return;
                    }
                    auto executor = asio::get_associated_executor(*shared_h, self->get_executor());

                    const std::size_t len = asio::buffer_size(buffers);
                    std::string payload;
                    payload.reserve(len);
                    for (auto b = asio::buffer_sequence_begin(buffers);
                         b != asio::buffer_sequence_end(buffers); ++b) {
                        asio::const_buffer cb(*b);
                        payload.append(static_cast<const char*>(cb.data()), cb.size());
                    }

                    std::error_code ec = self->write_outbound(payload, false);
                    asio::post(executor, [shared_h, ec, len] {
                        (*shared_h)(ec, ec ? 0 : len);
                    });
                },
                token
            );
        }

        // Internal plumbing
        void push_inbound(std::string_view data, bool fin);
        std::error_code write_outbound(std::string_view data, bool fin);
    };

    // ─── 7. QuicConnection ─────────────────────────────────────────────────────

    enum class ConnectionState : uint8_t {
        Initial,
        Handshaking,
        Connected,
        Draining,
        Closed
    };

    /**
     * @class QuicConnection
     * @brief State machine for a single QUIC connection between two endpoints.
     */
    class QuicConnection : public std::enable_shared_from_this<QuicConnection> {
    public:
        // ─── 1. Nested Types & Definitions (TOP) ───────────────────────────
        using StreamCreatedCallback = std::function<void(std::shared_ptr<QuicStream>)>;
        using OutboundCallback = std::function<void()>;

        struct TlsCtx {
            // ─── 2. Member Variables ────
#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
            SSL *ssl{nullptr};
            SSL_CTX *ctx{nullptr};
            std::deque<std::string> recv_crypto_queue{};
            std::deque<std::string> send_crypto_queue{};
            uint32_t current_write_level{0};
            uint32_t current_read_level{0};
            bool initialized{false};
#else
            bool initialized{false};
#endif

            // ─── 3. Constructors & Destructor ────
            TlsCtx() = default;
            ~TlsCtx();
            TlsCtx(const TlsCtx &) = delete;
            TlsCtx &operator=(const TlsCtx &) = delete;
            TlsCtx(TlsCtx &&) noexcept = default;
            TlsCtx &operator=(TlsCtx &&) noexcept = default;
        };

    private:
        // ─── 2. Member Variables (SECOND - Ordered for Minimal Padding) ────
        std::unique_ptr<TlsCtx> tls_{};
        mutable std::mutex mtx_{};
        asio::ip::udp::endpoint peer_endpoint_{};
        std::unordered_map<uint64_t, std::shared_ptr<QuicStream>> streams_{};
        std::deque<std::string> pending_outbound_datagrams_{};
        std::deque<std::shared_ptr<QuicStream>> accepted_streams_{};
        std::optional<std::function<void(std::shared_ptr<QuicStream>)>> stream_acceptor_{};
        StreamCreatedCallback on_stream_created_{};
        OutboundCallback on_outbound_{};
        asio::any_io_executor executor_{};
        std::string tls_cert_file_{};
        std::string tls_key_file_{};
        ProtectionKeys initial_keys_peer_{};
        ProtectionKeys initial_keys_local_{};
        ProtectionKeys handshake_keys_peer_{};
        ProtectionKeys handshake_keys_local_{};
        ProtectionKeys one_rtt_keys_peer_{};
        ProtectionKeys one_rtt_keys_local_{};
        ProtectionKeys one_rtt_keys_{};
        uint64_t max_data_{1024 * 1024}; // 1 MB
        uint64_t max_stream_data_{256 * 1024}; // 256 KB
        uint64_t data_sent_{0};
        uint64_t data_received_{0};
        uint64_t next_bidi_stream_id_{0};
        uint64_t next_uni_stream_id_{0};
        uint64_t next_packet_number_{0};
        uint64_t largest_received_pn_{0};
        uint64_t largest_received_initial_pn_{0};
        uint64_t largest_received_handshake_pn_{0};
        uint64_t crypto_send_offset_initial_{0};
        uint64_t crypto_send_offset_handshake_{0};
        uint64_t crypto_send_offset_app_{0};
        uint32_t version_{QUIC_VERSION_1};
        uint32_t current_write_level_{0};
        uint32_t current_read_level_{0};
        ConnectionId local_cid_{};
        ConnectionId peer_cid_{};
        ConnectionId original_dcid_{};
        ConnectionState state_{ConnectionState::Initial};
        bool is_server_{true};
        bool handshake_done_{false};
        bool has_received_initial_{false};
        bool has_received_handshake_{false};
        bool settings_received_{false};

    public:
        // ─── 3. Constructors & Destructor (MIDDLE) ─────────────────────────
        QuicConnection(
            ConnectionId local_cid,
            ConnectionId peer_cid,
            asio::ip::udp::endpoint peer_ep,
            bool is_server = true,
            asio::any_io_executor executor = {},
            ConnectionId initial_dcid = {}) noexcept;
        ~QuicConnection();

        // ─── 4. Member Functions & Friend Declarations (LAST) ──────────────
        [[nodiscard]] asio::any_io_executor get_executor() const noexcept { return executor_; }
        void set_executor(asio::any_io_executor ex) noexcept { executor_ = std::move(ex); }
        [[nodiscard]] const ConnectionId &local_cid() const noexcept { return local_cid_; }
        [[nodiscard]] const ConnectionId &peer_cid() const noexcept { return peer_cid_; }
        [[nodiscard]] const asio::ip::udp::endpoint &peer_endpoint() const noexcept { return peer_endpoint_; }
        [[nodiscard]] ConnectionState state() const noexcept { return state_; }
        [[nodiscard]] bool is_connected() const noexcept { return state_ == ConnectionState::Connected; }

        void set_stream_created_callback(StreamCreatedCallback cb) {
            std::lock_guard lock(mtx_);
            on_stream_created_ = std::move(cb);
        }

        void set_outbound_callback(OutboundCallback cb) {
            std::lock_guard lock(mtx_);
            on_outbound_ = std::move(cb);
        }

        void set_tls_credentials(std::string cert_file, std::string key_file) {
            std::lock_guard lock(mtx_);
            tls_cert_file_ = std::move(cert_file);
            tls_key_file_ = std::move(key_file);
        }

        bool init_tls_handshake_engine();

        // Inbound packet handling
        void handle_datagram(std::string_view datagram);

        // Stream management
        std::shared_ptr<QuicStream> create_stream(bool bidirectional = true);
        std::shared_ptr<QuicStream> get_or_create_stream(uint64_t stream_id);
        void close_stream(uint64_t stream_id);

        // Accept a new stream asynchronously
        asio::awaitable<std::shared_ptr<QuicStream>> accept_stream();

        // Send stream payload
        void queue_stream_data(uint64_t stream_id, std::string_view data, bool fin);

        // Drain outbound UDP datagrams
        std::vector<std::string> poll_outgoing_datagrams();

        void close(TransportError err = TransportError::NoError, std::string_view reason = "");

        // Internal TLS engine plumbing
        void queue_crypto_frame(std::string_view data);
        int on_tls_crypto_recv(const unsigned char **buf, size_t *bytes_read);
        int on_tls_crypto_release(size_t bytes_read);
        int on_tls_secret(uint32_t prot_level, int direction, const unsigned char *secret, size_t secret_len);
        int on_tls_transport_params(const unsigned char *params, size_t params_len);

    private:
        void send_ack(uint64_t pn, PacketType type);
        void process_frames(const std::vector<Frame> &frames, uint64_t pn);
        void send_initial_handshake_response();
        void run_tls_engine();
        [[nodiscard]] std::string build_quic_transport_params() const;
    };

    // ─── 8. QuicServer and QuicClient ──────────────────────────────────────────

    /**
     * @class QuicServer
     * @brief Asynchronous UDP server hosting QUIC connections and dispatching streams.
     */
    class QuicServer {
    public:
        // ─── 1. Nested Types & Definitions (TOP) ───────────────────────────
        using StreamHandler = std::function<asio::awaitable<void>(std::shared_ptr<QuicStream>)>;

    private:
        // ─── 2. Member Variables (SECOND - Ordered for Minimal Padding) ────
        asio::io_context &io_;
        asio::ip::udp::socket socket_;
        asio::ip::udp::endpoint sender_endpoint_{};
        std::unordered_map<ConnectionId, std::shared_ptr<QuicConnection>> connections_{};
        mutable std::mutex mtx_{};
        std::array<uint8_t, 65536> recv_buf_{};
        StreamHandler stream_handler_{};
        std::string tls_cert_file_{};
        std::string tls_key_file_{};
        bool running_{false};

    public:
        // ─── 3. Constructors & Destructor (MIDDLE) ─────────────────────────
        QuicServer(asio::io_context &io, uint16_t port);
        QuicServer(asio::io_context &io, std::string_view host, uint16_t port);
        ~QuicServer();

        // ─── 4. Member Functions & Friend Declarations (LAST) ──────────────
        void set_stream_handler(StreamHandler handler) {
            std::lock_guard lock(mtx_);
            stream_handler_ = std::move(handler);
        }

        void set_tls_credentials(std::string cert_file, std::string key_file) {
            std::lock_guard lock(mtx_);
            tls_cert_file_ = std::move(cert_file);
            tls_key_file_ = std::move(key_file);
        }

        void start();
        void stop();

        [[nodiscard]] uint16_t local_port() const noexcept {
            asio::error_code ec;
            auto ep = socket_.local_endpoint(ec);
            return ec ? 0 : ep.port();
        }

    private:
        void do_receive();
        void flush_outbound(const std::shared_ptr<QuicConnection> &conn);
    };

    /**
     * @class QuicClient
     * @brief Asynchronous QUIC client establishing connections over UDP.
     */
    class QuicClient {
    private:
        // ─── 2. Member Variables (SECOND - Ordered for Minimal Padding) ────
        asio::io_context &io_;
        asio::ip::udp::socket socket_;
        asio::ip::udp::endpoint server_endpoint_{};
        std::shared_ptr<QuicConnection> connection_{};
        mutable std::mutex mtx_{};
        std::array<uint8_t, 65536> recv_buf_{};
        bool connected_{false};

    public:
        // ─── 3. Constructors & Destructor (MIDDLE) ─────────────────────────
        explicit QuicClient(asio::io_context &io);
        ~QuicClient();

        // ─── 4. Member Functions & Friend Declarations (LAST) ──────────────
        asio::awaitable<bool> connect(std::string_view host, uint16_t port);
        std::shared_ptr<QuicStream> create_stream(bool bidirectional = true);
        void close();

    private:
        void do_receive();
        void flush_outbound();
    };

} // namespace wavex::network::quic
