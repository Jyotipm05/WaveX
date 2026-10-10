/**
 * @file QuicConnection.hpp
 * @brief QUIC connection state machine and stream multiplexer.
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
#include <chrono>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include <asio/any_io_executor.hpp>
#include <asio/awaitable.hpp>
#include <asio/ip/udp.hpp>
#include <asio/steady_timer.hpp>

#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
#include <openssl/ssl.h>
#endif

#include <wavex/Network/QUIC/QuicConstants.hpp>
#include <wavex/Network/QUIC/ConnectionId.hpp>
#include <wavex/Network/QUIC/QuicFrames.hpp>
#include <wavex/Network/QUIC/QuicCrypto.hpp>
#include <wavex/Network/QUIC/CongestionControl.hpp>
#include <wavex/Network/QUIC/QuicStream.hpp>

namespace wavex::network::quic {
    /**
     * @class QuicConnection
     * @brief State machine for a single QUIC connection between two endpoints.
     */
    class QuicConnection : public std::enable_shared_from_this<QuicConnection> {
    public:
        // ─── 1. Nested Types & Definitions (TOP) ───────────────────────────
        using StreamCreatedCallback = std::function<void(std::shared_ptr<QuicStream>)>;
        using OutboundCallback = std::function<void()>;
        using ClosedCallback = std::function<void(const ConnectionId &local_cid, const ConnectionId &peer_cid,
                                                  const ConnectionId &orig_dcid)>;
        using ConnectedCallback = std::function<void()>;

        struct CryptoStreamReassembler {
            // ─── 1. Nested Types & Constants ───
            inline static constexpr std::size_t kMaxCryptoBufferSize = 65536;

            // ─── 2. Member Variables (SECOND - Ordered for Minimal Padding) ────
            std::map<uint64_t, std::string> pending{};
            std::string ready{};
            uint64_t next_offset{0};
            std::size_t ready_consumed{0};
            std::size_t pending_bytes{0};

            // ─── 3. Constructors & Destructor (MIDDLE) ─────────────────────────
            CryptoStreamReassembler() = default;

            ~CryptoStreamReassembler() = default;

            CryptoStreamReassembler(const CryptoStreamReassembler &) = default;

            auto operator=(const CryptoStreamReassembler &) -> CryptoStreamReassembler & = default;

            CryptoStreamReassembler(CryptoStreamReassembler &&) noexcept = default;

            auto operator=(CryptoStreamReassembler &&) noexcept -> CryptoStreamReassembler & = default;

            // ─── 4. Member Functions (LAST) ────────────────────────────────────
            [[nodiscard]] auto insert(uint64_t offset, std::string_view data) -> bool;

            [[nodiscard]] auto available() const noexcept -> std::string_view;

            void consume(std::size_t bytes);

            [[nodiscard]] auto has_available() const noexcept -> bool;
        };

        struct ReceivedPacketTracker {
            // ─── 2. Member Variables (SECOND - Ordered for Minimal Padding) ────
            std::vector<std::pair<uint64_t, uint64_t> > intervals{};
            uint64_t largest_pn{0};
            bool has_packets{false};
            bool ack_eliciting_pending{false};

            // ─── 3. Constructors & Destructor (MIDDLE) ─────────────────────────
            ReceivedPacketTracker() = default;

            ~ReceivedPacketTracker() = default;

            ReceivedPacketTracker(const ReceivedPacketTracker &) = default;

            auto operator=(const ReceivedPacketTracker &) -> ReceivedPacketTracker & = default;

            ReceivedPacketTracker(ReceivedPacketTracker &&) noexcept = default;

            auto operator=(ReceivedPacketTracker &&) noexcept -> ReceivedPacketTracker & = default;

            // ─── 4. Member Functions (LAST) ────────────────────────────────────
            void add_packet(uint64_t pn, bool ack_eliciting = true);

            [[nodiscard]] auto build_ack_frame(uint64_t ack_delay = 0) const -> AckFrame;

            void mark_ack_sent() noexcept { ack_eliciting_pending = false; }
            [[nodiscard]] auto needs_ack() const noexcept -> bool { return has_packets && ack_eliciting_pending; }

            void reset() noexcept {
                intervals.clear();
                largest_pn = 0;
                has_packets = false;
                ack_eliciting_pending = false;
            }
        };

        struct TlsCtx {
            // ─── 2. Member Variables ────
#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
            SSL *ssl{nullptr};
            SSL_CTX *ctx{nullptr};
            uint32_t current_write_level{0};
            uint32_t current_read_level{0};
            bool initialized{false};
            bool owns_ctx{true};
#else
            bool initialized{false};
#endif

            // ─── 3. Constructors & Destructor ────
            TlsCtx() = default;

            ~TlsCtx();

            TlsCtx(const TlsCtx &) = delete;

            auto operator=(const TlsCtx &) -> TlsCtx & = delete;

            TlsCtx(TlsCtx &&other) noexcept;

            auto operator=(TlsCtx &&other) noexcept -> TlsCtx &;
        };

    private:
        // ─── 2. Member Variables (SECOND - Ordered for Minimal Padding) ────
        std::unique_ptr<TlsCtx> tls_{};
        SSL_CTX *shared_ssl_ctx_{nullptr};
        std::unique_ptr<asio::steady_timer> loss_detection_timer_{};
        std::unique_ptr<asio::steady_timer> idle_timer_{};
        mutable std::recursive_mutex mtx_{};
        asio::ip::udp::endpoint peer_endpoint_{};
        std::unordered_map<uint64_t, std::shared_ptr<QuicStream> > streams_{};
        std::unordered_map<uint64_t, uint64_t> stream_send_offsets_{};
        std::unordered_map<uint64_t, uint64_t> stream_data_sent_{};
        std::unordered_map<uint64_t, std::string> stream_send_queues_{};
        std::unordered_map<uint64_t, bool> stream_send_fin_{};
        std::deque<std::string> pending_outbound_datagrams_{};
        std::deque<std::string> buffered_handshake_packets_{};
        std::deque<std::string> buffered_one_rtt_packets_{};
        std::deque<std::shared_ptr<QuicStream> > accepted_streams_{};
        std::optional<std::function<void(std::shared_ptr<QuicStream>)> > stream_acceptor_{};
        StreamCreatedCallback on_stream_created_{};
        OutboundCallback on_outbound_{};
        ClosedCallback on_closed_{};
        ConnectedCallback on_connected_{};
        asio::any_io_executor executor_{};
        std::string tls_cert_file_{};
        std::string tls_key_file_{};
        std::string sni_hostname_{};
        std::string local_transport_params_{};
        ProtectionKeys initial_keys_peer_{};
        ProtectionKeys initial_keys_local_{};
        ProtectionKeys handshake_keys_peer_{};
        ProtectionKeys handshake_keys_local_{};
        ProtectionKeys one_rtt_keys_peer_{};
        ProtectionKeys one_rtt_keys_local_{};
        ProtectionKeys one_rtt_keys_{};
        CongestionController congestion_controller_{};
        std::array<CryptoStreamReassembler, 4> crypto_reassemblers_{};
        std::array<ReceivedPacketTracker, 3> ack_trackers_{};
        std::array<std::vector<SentPacket>, 3> sent_packets_{};
        std::array<uint64_t, 3> next_packet_number_{0, 0, 0};
        std::array<uint64_t, 3> largest_acked_packet_{0, 0, 0};
        std::chrono::steady_clock::time_point loss_time_{};
        std::chrono::milliseconds idle_timeout_{30000};
        uint64_t max_data_{1024 * 1024}; // 1 MB
        uint64_t max_stream_data_{256 * 1024}; // 256 KB
        uint64_t data_sent_{0};
        uint64_t data_received_{0};
        uint64_t cumulative_bytes_received_{0};
        uint64_t cumulative_bytes_sent_{0};
        uint64_t next_bidi_stream_id_{0};
        uint64_t next_uni_stream_id_{0};
        uint64_t max_peer_bidi_streams_{100};
        uint64_t max_peer_uni_streams_{100};
        uint64_t crypto_send_offset_initial_{0};
        uint64_t crypto_send_offset_handshake_{0};
        uint64_t crypto_send_offset_app_{0};
        uint32_t version_{QUIC_VERSION_1};
        uint32_t current_write_level_{0};
        uint32_t current_read_level_{0};
        uint32_t last_read_crypto_level_{0};
        uint32_t pto_count_{0};
        ConnectionId local_cid_{};
        ConnectionId peer_cid_{};
        ConnectionId original_dcid_{};
        ConnectionState state_{ConnectionState::Initial};
        std::array<bool, 3> has_largest_acked_{false, false, false};
        bool is_server_{true};
        bool peer_address_validated_{false};
        bool handshake_done_{false};
        bool has_received_initial_{false};
        bool has_received_handshake_{false};
        bool settings_received_{false};
        bool draining_buffered_packets_{false};
        bool http3_session_initialized_{false};
        bool handshake_done_sent_{false};

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
        [[nodiscard]] auto get_executor() const noexcept -> asio::any_io_executor { return executor_; }
        void set_executor(asio::any_io_executor ex) noexcept { executor_ = std::move(ex); }
        [[nodiscard]] auto local_cid() const noexcept -> const ConnectionId & { return local_cid_; }
        [[nodiscard]] auto peer_cid() const noexcept -> const ConnectionId & { return peer_cid_; }
        [[nodiscard]] auto peer_endpoint() const noexcept -> const asio::ip::udp::endpoint & { return peer_endpoint_; }
        [[nodiscard]] auto state() const noexcept -> ConnectionState { return state_; }
        [[nodiscard]] auto is_connected() const noexcept -> bool { return state_ == ConnectionState::Connected; }

        [[nodiscard]] auto congestion_controller() const noexcept -> const CongestionController & {
            return congestion_controller_;
        }

        [[nodiscard]] auto congestion_controller() noexcept -> CongestionController & { return congestion_controller_; }

        void set_stream_created_callback(StreamCreatedCallback cb) {
            std::scoped_lock lock(mtx_);
            on_stream_created_ = std::move(cb);
        }

        void set_outbound_callback(OutboundCallback cb) {
            std::scoped_lock lock(mtx_);
            on_outbound_ = std::move(cb);
        }

        void set_closed_callback(ClosedCallback cb) {
            std::scoped_lock lock(mtx_);
            on_closed_ = std::move(cb);
        }

        void set_connected_callback(ConnectedCallback cb) {
            std::scoped_lock lock(mtx_);
            on_connected_ = std::move(cb);
            if (state_ == ConnectionState::Connected && on_connected_) {
                on_connected_();
            }
        }

        void set_sni_hostname(std::string sni) {
            std::scoped_lock lock(mtx_);
            sni_hostname_ = std::move(sni);
        }

        void set_idle_timeout(std::chrono::milliseconds timeout) noexcept {
            std::scoped_lock lock(mtx_);
            idle_timeout_ = timeout;
        }

        [[nodiscard]] auto stream_count() const noexcept -> std::size_t {
            std::scoped_lock lock(mtx_);
            return streams_.size();
        }

        [[nodiscard]] auto can_send() const noexcept -> bool {
            std::scoped_lock lock(mtx_);
            return congestion_controller_.can_send() && (data_sent_ < max_data_);
        }

        [[nodiscard]] auto is_peer_address_validated() const noexcept -> bool {
            std::scoped_lock lock(mtx_);
            return peer_address_validated_;
        }

        [[nodiscard]] auto max_data() const noexcept -> uint64_t {
            std::scoped_lock lock(mtx_);
            return max_data_;
        }

        [[nodiscard]] auto max_stream_data() const noexcept -> uint64_t {
            std::scoped_lock lock(mtx_);
            return max_stream_data_;
        }

        [[nodiscard]] auto data_sent() const noexcept -> uint64_t {
            std::scoped_lock lock(mtx_);
            return data_sent_;
        }

        void set_max_peer_streams(uint64_t max_bidi, uint64_t max_uni) noexcept {
            std::scoped_lock lock(mtx_);
            max_peer_bidi_streams_ = max_bidi;
            max_peer_uni_streams_ = max_uni;
        }

        void refresh_idle_timer();

        void set_tls_credentials(std::string cert_file, std::string key_file) {
            std::scoped_lock lock(mtx_);
            tls_cert_file_ = std::move(cert_file);
            tls_key_file_ = std::move(key_file);
        }

        void set_shared_ssl_ctx(SSL_CTX *shared_ctx) noexcept {
            std::scoped_lock lock(mtx_);
            shared_ssl_ctx_ = shared_ctx;
        }

        [[nodiscard]] auto current_write_level() const noexcept -> uint32_t { return current_write_level_; }
        [[nodiscard]] auto current_read_level() const noexcept -> uint32_t { return current_read_level_; }

        auto reassembler_for_level(uint32_t level) noexcept -> CryptoStreamReassembler &;

        auto reassembler_for_pkt_type(PacketType type) noexcept -> CryptoStreamReassembler &;

        auto init_tls_handshake_engine() -> bool;

        void run_tls_engine();

        // Inbound packet handling
        void handle_datagram(std::string_view datagram);

        // Stream management
        auto create_stream(bool bidirectional = true) -> std::shared_ptr<QuicStream>;

        auto get_or_create_stream(uint64_t stream_id) -> std::shared_ptr<QuicStream>;

        void close_stream(uint64_t stream_id);

        // Accept a new stream asynchronously
        auto accept_stream() -> asio::awaitable<std::shared_ptr<QuicStream> >;

        // Send stream payload
        void queue_stream_data(uint64_t stream_id, std::string_view data, bool fin);

        // RFC 9114 HTTP/3 Control & QPACK Stream Helpers
        auto open_unidirectional_stream() -> uint64_t;

        void write_stream(uint64_t stream_id, std::string_view data, bool fin = false);

        void write_stream(uint64_t stream_id, const std::vector<uint8_t> &data, bool fin = false);

        void initialize_http3_session();

        [[nodiscard]] auto is_http3_session_initialized() const noexcept -> bool { return http3_session_initialized_; }

        // Drain outbound UDP datagrams
        auto poll_outgoing_datagrams() -> std::vector<std::string>;

        void close(TransportError err = TransportError::NoError, std::string_view reason = "");

        // Internal TLS engine plumbing
        void queue_crypto_frame(std::string_view data);

        auto on_tls_crypto_recv(const unsigned char **buf, size_t *bytes_read) -> int;

        auto on_tls_crypto_release(size_t bytes_read) -> int;

        auto on_tls_secret(uint32_t prot_level, int direction, const unsigned char *secret, size_t secret_len) -> int;

        static auto on_tls_transport_params(const unsigned char *params, size_t params_len) -> int;

        static constexpr auto space_index(const PacketType type) noexcept -> std::size_t {
            switch (type) {
                case PacketType::Initial: return 0;
                case PacketType::Handshake: return 1;
                case PacketType::ZeroRTT:
                case PacketType::OneRTT:
                default: return 2;
            }
        }

        [[nodiscard]] auto ack_tracker_for_pkt_type(const PacketType type) noexcept -> ReceivedPacketTracker & {
            return ack_trackers_[space_index(type)];
        }

        [[nodiscard]] auto ack_tracker_for_pkt_type(
            const PacketType type) const noexcept -> const ReceivedPacketTracker & {
            return ack_trackers_[space_index(type)];
        }

        [[nodiscard]] auto allocate_next_pn(const PacketType type) noexcept -> uint64_t {
            return next_packet_number_[space_index(type)]++;
        }

        [[nodiscard]] auto sent_packets(std::size_t space) const noexcept -> const std::vector<SentPacket> & {
            return sent_packets_[space];
        }

        [[nodiscard]] auto pto_count() const noexcept -> uint32_t { return pto_count_; }

    private:
        void send_ack(uint64_t pn, PacketType type);

        void send_ack_for_space(PacketType type);

        void track_sent_packet(PacketType type, uint64_t pn, std::size_t bytes, std::vector<Frame> frames);

        void on_ack_received(PacketType pkt_type, const AckFrame &ack);

        void detect_lost_packets(std::size_t space, uint64_t largest_acked);

        void arm_loss_detection_timer();

        void on_loss_detection_timeout();

        void retransmit_frame(const Frame &frame, PacketType pkt_type);

        void process_frames(const std::vector<Frame> &frames, uint64_t pn, PacketType pkt_type,
                            std::vector<std::shared_ptr<QuicStream> > &new_streams);

        void send_initial_handshake_response();

        void send_handshake_done();

        void flush_stream_send_queues();

        void drain_buffered_packets();

        [[nodiscard]] auto build_quic_transport_params() const -> std::string;
    };
} // namespace wavex::network::quic

#endif // WAVEX_HAS_SSL
