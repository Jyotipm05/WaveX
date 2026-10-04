#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL

#include <wavex/Network/QUIC/QuicConnection.hpp>
#include <wavex/Base/Logger.hpp>

#if defined(min)
#undef min
#endif
#if defined(max)
#undef max
#endif

#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/as_tuple.hpp>
#include <asio/redirect_error.hpp>
#include <asio/post.hpp>
#include <future>

#include <algorithm>
#include <cstring>
#include <filesystem>
#include <random>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <cassert>

namespace wavex::network::quic {

    // ─── 7. QuicConnection Implementation ──────────────────────────────────────

#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
    QuicConnection::TlsCtx::~TlsCtx() {
        if (ssl) {
            SSL_free(ssl);
            ssl = nullptr;
        }
        if (ctx) {
            SSL_CTX_free(ctx);
            ctx = nullptr;
        }
    }

    extern "C" {
    static int quic_tls_crypto_send(
        SSL * /*s*/, const unsigned char *buf, size_t buf_len,
        size_t *consumed, void *arg) {
        if (!arg || !buf || buf_len == 0) return 0;
        auto *conn = static_cast<QuicConnection *>(arg);
        wavex::log::info("[QUIC] crypto_send_fn: {} bytes at write_level={}", buf_len, conn->current_write_level());
        conn->queue_crypto_frame(std::string_view(reinterpret_cast<const char *>(buf), buf_len));
        if (consumed) *consumed = buf_len;
        return 1;
    }

    static int quic_tls_crypto_recv_rcd(
        SSL * /*s*/, const unsigned char **buf, size_t *bytes_read,
        void *arg) {
        if (!arg || !buf || !bytes_read) return 0;
        auto *conn = static_cast<QuicConnection *>(arg);
        const int res = conn->on_tls_crypto_recv(buf, bytes_read);
        if (*bytes_read > 0) {
            wavex::log::info("[QUIC] crypto_recv_rcd: supplied {} bytes to TLS engine", *bytes_read);
        }
        return res;
    }

    static int quic_tls_crypto_release_rcd(
        SSL * /*s*/, size_t bytes_read, void *arg) {
        if (!arg) return 0;
        auto *conn = static_cast<QuicConnection *>(arg);
        wavex::log::info("[QUIC] crypto_release_rcd: released {} bytes", bytes_read);
        return conn->on_tls_crypto_release(bytes_read);
    }

    static int quic_tls_yield_secret(
        SSL * /*s*/, uint32_t prot_level, int direction,
        const unsigned char *secret, size_t secret_len, void *arg) {
        if (!arg || !secret) return 0;
        auto *conn = static_cast<QuicConnection *>(arg);
        wavex::log::info("[QUIC] yield_secret: prot_level={} direction={} (0=read,1=write) len={}",
                         prot_level, direction, secret_len);
        return conn->on_tls_secret(prot_level, direction, secret, secret_len);
    }

    static int quic_tls_got_transport_params(
        SSL * /*s*/, const unsigned char *params, size_t params_len,
        void *arg) {
        if (!arg) return 0;
        auto *conn = static_cast<QuicConnection *>(arg);
        wavex::log::info("[QUIC] got_transport_params: len={}", params_len);
        return conn->on_tls_transport_params(params, params_len);
    }

    static int quic_tls_alert(
        SSL * /*s*/, unsigned char alert_code, void * /*arg*/) {
        wavex::log::warn("[QUIC] tls_alert: alert_code={}", alert_code);
        return 1;
    }
    } // extern "C"
#else
    QuicConnection::TlsCtx::~TlsCtx() = default;
#endif

    void QuicConnection::CryptoStreamReassembler::insert(const uint64_t offset, const std::string_view data) {
        if (data.empty()) return;
        if (offset + data.size() <= next_offset) return;
        pending.emplace(offset, std::string(data));
        while (!pending.empty()) {
            const auto it = pending.begin();
            if (it->first > next_offset) break;
            const uint64_t end = it->first + it->second.size();
            if (end > next_offset) {
                const std::size_t overlap = static_cast<std::size_t>(next_offset - it->first);
                ready.append(it->second.data() + overlap, it->second.size() - overlap);
                next_offset = end;
            }
            pending.erase(it);
        }
    }

    std::string_view QuicConnection::CryptoStreamReassembler::available() const noexcept {
        if (ready_consumed >= ready.size()) return {};
        return std::string_view(ready.data() + ready_consumed, ready.size() - ready_consumed);
    }

    void QuicConnection::CryptoStreamReassembler::consume(const std::size_t bytes) {
        ready_consumed += bytes;
        if (ready_consumed >= ready.size()) {
            ready.clear();
            ready_consumed = 0;
        } else if (ready_consumed > 65536) {
            ready.erase(0, ready_consumed);
            ready_consumed = 0;
        }
    }

    bool QuicConnection::CryptoStreamReassembler::has_available() const noexcept {
        return ready_consumed < ready.size();
    }

    void QuicConnection::ReceivedPacketTracker::add_packet(const uint64_t pn, const bool ack_eliciting) {
        has_packets = true;
        if (ack_eliciting) {
            ack_eliciting_pending = true;
        }

        if (intervals.empty()) {
            intervals.push_back({pn, pn});
            largest_pn = pn;
            return;
        }

        largest_pn = (std::max)(largest_pn, pn);

        auto it = intervals.begin();
        while (it != intervals.end() && it->second < pn) {
            ++it;
        }

        if (it != intervals.end()) {
            if (it->first <= pn && pn <= it->second) {
                return;
            }
            if (pn + 1 == it->first) {
                it->first = pn;
                if (it != intervals.begin()) {
                    auto prev = std::prev(it);
                    if (prev->second + 1 == it->first) {
                        prev->second = it->second;
                        intervals.erase(it);
                    }
                }
                return;
            }
        }

        if (it != intervals.begin()) {
            auto prev = std::prev(it);
            if (prev->second + 1 == pn) {
                prev->second = pn;
                if (it != intervals.end() && prev->second + 1 == it->first) {
                    prev->second = it->second;
                    intervals.erase(it);
                }
                return;
            }
        }

        intervals.insert(it, {pn, pn});

        if (intervals.size() > 64) {
            intervals.erase(intervals.begin());
        }
    }

    AckFrame QuicConnection::ReceivedPacketTracker::build_ack_frame(const uint64_t ack_delay) const {
        AckFrame ack;
        if (intervals.empty()) {
            ack.largest_acknowledged = largest_pn;
            ack.ack_delay = ack_delay;
            ack.ranges.push_back(AckRange{0, 0});
            return ack;
        }

        ack.largest_acknowledged = intervals.back().second;
        ack.ack_delay = ack_delay;

        const uint64_t first_ack_range = intervals.back().second - intervals.back().first;
        ack.ranges.push_back(AckRange{0, first_ack_range});

        if (intervals.size() > 1) {
            for (std::size_t i = intervals.size() - 1; i > 0; --i) {
                const auto &curr = intervals[i - 1];
                const auto &prev = intervals[i];
                const uint64_t gap = (prev.first > curr.second + 2) ? (prev.first - curr.second - 2) : 0;
                const uint64_t range_len = curr.second - curr.first;
                ack.ranges.push_back(AckRange{gap, range_len});
            }
        }

        return ack;
    }

    QuicConnection::CryptoStreamReassembler &QuicConnection::reassembler_for_level(uint32_t level) noexcept {
        if (level >= crypto_reassemblers_.size()) level = 0;
        return crypto_reassemblers_[level];
    }

    QuicConnection::CryptoStreamReassembler &QuicConnection::reassembler_for_pkt_type(const PacketType type) noexcept {
        switch (type) {
            case PacketType::Initial: return crypto_reassemblers_[0];
            case PacketType::ZeroRTT: return crypto_reassemblers_[1];
            case PacketType::Handshake: return crypto_reassemblers_[2];
            case PacketType::OneRTT:
            default: return crypto_reassemblers_[3];
        }
    }

    QuicConnection::~QuicConnection() {
        if (loss_detection_timer_) {
            asio::error_code ec;
            loss_detection_timer_->cancel(ec);
        }
    }

    QuicConnection::QuicConnection(
        ConnectionId local_cid,
        ConnectionId peer_cid,
        asio::ip::udp::endpoint peer_ep,
        const bool is_server,
        asio::any_io_executor executor,
        ConnectionId initial_dcid) noexcept
        : peer_endpoint_(std::move(peer_ep)),
          executor_(std::move(executor)),
          local_cid_(std::move(local_cid)),
          peer_cid_(std::move(peer_cid)),
          original_dcid_(std::move(initial_dcid)),
          is_server_(is_server) {
        const ConnectionId &secret_cid = (!original_dcid_.empty()) ? original_dcid_ : peer_cid_;
        if (is_server_) {
            CryptoSuite::derive_initial_secrets(secret_cid, initial_keys_peer_, initial_keys_local_);
        } else {
            CryptoSuite::derive_initial_secrets(secret_cid, initial_keys_local_, initial_keys_peer_);
        }
    }

    bool QuicConnection::init_tls_handshake_engine() {
#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
        if (tls_ && tls_->initialized) return true;
        if (!tls_) tls_ = std::make_unique<TlsCtx>();

        tls_->ctx = SSL_CTX_new(is_server_ ? TLS_server_method() : TLS_client_method());
        if (!tls_->ctx) {
            wavex::log::error("[QUIC] init_tls_handshake_engine: SSL_CTX_new failed");
            return false;
        }

        SSL_CTX_set_min_proto_version(tls_->ctx, TLS1_3_VERSION);
        SSL_CTX_set_max_proto_version(tls_->ctx, TLS1_3_VERSION);

        // Standard TLS 1.3 cipher suite preferred for QUIC
        SSL_CTX_set_ciphersuites(tls_->ctx, "TLS_AES_128_GCM_SHA256");

        // Ground-truth tooling: support SSLKEYLOGFILE for Wireshark / diagnostic interop
        if (const char *keylog_path = std::getenv("SSLKEYLOGFILE")) {
            SSL_CTX_set_keylog_callback(
                tls_->ctx,
                [](const SSL *, const char *line) {
                    if (const char *path = std::getenv("SSLKEYLOGFILE")) {
                        if (std::ofstream ofs(path, std::ios::app); ofs.is_open()) {
                            ofs << line << "\n";
                        }
                    }
                });
        }

        if (is_server_) {
            if (!tls_cert_file_.empty() && !tls_key_file_.empty()) {
                std::string cert_file = tls_cert_file_;
                std::string key_file = tls_key_file_;
                std::error_code ec;
                if (!std::filesystem::exists(cert_file, ec)) {
#ifdef PROJECT_DIR
                    std::string alt = std::string(PROJECT_DIR) + "/" + cert_file;
                    if (std::filesystem::exists(alt, ec)) cert_file = alt;
#endif
                    if (!std::filesystem::exists(cert_file, ec) && std::filesystem::exists("../" + tls_cert_file_, ec)) {
                        cert_file = "../" + tls_cert_file_;
                    }
                }
                if (!std::filesystem::exists(key_file, ec)) {
#ifdef PROJECT_DIR
                    std::string alt = std::string(PROJECT_DIR) + "/" + key_file;
                    if (std::filesystem::exists(alt, ec)) key_file = alt;
#endif
                    if (!std::filesystem::exists(key_file, ec) && std::filesystem::exists("../" + tls_key_file_, ec)) {
                        key_file = "../" + tls_key_file_;
                    }
                }

                if (SSL_CTX_use_certificate_file(tls_->ctx, cert_file.c_str(), SSL_FILETYPE_PEM) != 1) {
                    wavex::log::error("[QUIC] init_tls_handshake_engine: SSL_CTX_use_certificate_file failed for '{}'", cert_file);
                    return false;
                }
                if (SSL_CTX_use_PrivateKey_file(tls_->ctx, key_file.c_str(), SSL_FILETYPE_PEM) != 1) {
                    wavex::log::error("[QUIC] init_tls_handshake_engine: SSL_CTX_use_PrivateKey_file failed for '{}'", key_file);
                    return false;
                }
                wavex::log::info("[QUIC] init_tls_handshake_engine: loaded cert '{}' and key '{}'", cert_file, key_file);
            } else {
                wavex::log::warn("[QUIC] init_tls_handshake_engine: is_server=true but cert ('{}') or key ('{}') is empty!",
                                 tls_cert_file_, tls_key_file_);
            }

            // ALPN selection callback for server (mandated by RFC 9001 §8.1)
            SSL_CTX_set_alpn_select_cb(
                tls_->ctx,
                [](SSL * /*ssl*/,
                   const unsigned char **out,
                   unsigned char *outlen,
                   const unsigned char *in,
                   unsigned int inlen,
                   void * /*arg*/) -> int {
                    unsigned int i = 0;
                    while (i < inlen) {
                        const unsigned char proto_len = in[i++];
                        if (i + proto_len > inlen) break;
                        const std::string_view proto(reinterpret_cast<const char *>(in + i), proto_len);
                        if (proto == "h3" || proto == "h3-29") {
                            *out = in + i;
                            *outlen = proto_len;
                            return SSL_TLSEXT_ERR_OK;
                        }
                        i += proto_len;
                    }
                    return SSL_TLSEXT_ERR_NOACK;
                },
                nullptr);
        }

        tls_->ssl = SSL_new(tls_->ctx);
        if (!tls_->ssl) {
            wavex::log::error("[QUIC] init_tls_handshake_engine: SSL_new failed");
            return false;
        }

        if (is_server_) {
            SSL_set_accept_state(tls_->ssl);
        } else {
            SSL_set_connect_state(tls_->ssl);
            static const unsigned char kAlpnProtos[] = "\x02h3\x05h3-29";
            SSL_set_alpn_protos(tls_->ssl, kAlpnProtos, sizeof(kAlpnProtos) - 1);
        }

        static const OSSL_DISPATCH kDispatchTable[] = {
            {
                OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_SEND,
                reinterpret_cast<void(*)()>(quic_tls_crypto_send)
            },
            {
                OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_RECV_RCD,
                reinterpret_cast<void(*)()>(quic_tls_crypto_recv_rcd)
            },
            {
                OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_RELEASE_RCD,
                reinterpret_cast<void(*)()>(quic_tls_crypto_release_rcd)
            },
            {
                OSSL_FUNC_SSL_QUIC_TLS_YIELD_SECRET,
                reinterpret_cast<void(*)()>(quic_tls_yield_secret)
            },
            {
                OSSL_FUNC_SSL_QUIC_TLS_GOT_TRANSPORT_PARAMS,
                reinterpret_cast<void(*)()>(quic_tls_got_transport_params)
            },
            {
                OSSL_FUNC_SSL_QUIC_TLS_ALERT,
                reinterpret_cast<void(*)()>(quic_tls_alert)
            },
            OSSL_DISPATCH_END
        };

        if (SSL_set_quic_tls_cbs(tls_->ssl, kDispatchTable, this) != 1) {
            wavex::log::error("[QUIC] init_tls_handshake_engine: SSL_set_quic_tls_cbs failed");
            return false;
        }

        local_transport_params_ = build_quic_transport_params();
        if (SSL_set_quic_tls_transport_params(
                tls_->ssl,
                reinterpret_cast<const unsigned char *>(local_transport_params_.data()),
                local_transport_params_.size()) != 1) {
            wavex::log::error("[QUIC] init_tls_handshake_engine: SSL_set_quic_tls_transport_params failed");
            return false;
        }

        tls_->initialized = true;
        wavex::log::info("[QUIC] init_tls_handshake_engine: TLS engine initialized successfully (is_server={})", is_server_);
        if (!is_server_) {
            run_tls_engine();
        }
        return true;
#else
        return false;
#endif
    }

    std::string QuicConnection::build_quic_transport_params() const {
        std::string out;
        auto add_varint_param = [&out](uint64_t id, uint64_t val) {
            VarInt::encode(id, out);
            const std::size_t val_len = VarInt::encoded_size(val);
            VarInt::encode(val_len, out);
            VarInt::encode(val, out);
        };

        const ConnectionId &orig_cid = (!original_dcid_.empty()) ? original_dcid_ : local_cid_;
        if (!orig_cid.empty()) {
            VarInt::encode(0x00, out); // original_destination_connection_id
            VarInt::encode(orig_cid.length(), out);
            out.append(reinterpret_cast<const char *>(orig_cid.data()), orig_cid.length());
        }

        if (!local_cid_.empty()) {
            VarInt::encode(0x0f, out); // initial_source_connection_id (RFC 9000 §18.2)
            VarInt::encode(local_cid_.length(), out);
            out.append(reinterpret_cast<const char *>(local_cid_.data()), local_cid_.length());
        }

        add_varint_param(0x01, 30000); // max_idle_timeout (30s)
        add_varint_param(0x04, max_data_); // initial_max_data (1MB)
        add_varint_param(0x05, max_stream_data_); // initial_max_stream_data_bidi_local (256KB)
        add_varint_param(0x06, max_stream_data_); // initial_max_stream_data_bidi_remote (256KB)
        add_varint_param(0x07, max_stream_data_); // initial_max_stream_data_uni (256KB)
        add_varint_param(0x08, 100); // initial_max_streams_bidi
        add_varint_param(0x09, 100); // initial_max_streams_uni
        add_varint_param(0x0e, 2); // active_connection_id_limit (RFC 9000 §18.2)

        return out;
    }

    int QuicConnection::on_tls_crypto_recv(const unsigned char **buf, size_t *bytes_read) {
#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
        static constexpr unsigned char kEmptyBuf[1] = {0};
        auto &r = reassembler_for_level(current_read_level_);
        last_read_crypto_level_ = current_read_level_;

        if (!r.has_available()) {
            *buf = kEmptyBuf;
            *bytes_read = 0;
            return 1;
        }

        const auto avail = r.available();
        *buf = reinterpret_cast<const unsigned char *>(avail.data());
        *bytes_read = avail.size();
        return 1;
#else
        static const unsigned char kEmptyBuf[1] = {0};
        *buf = kEmptyBuf;
        *bytes_read = 0;
        return 1;
#endif
    }

    int QuicConnection::on_tls_crypto_release(const size_t bytes_read) {
#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
        auto &r = reassembler_for_level(last_read_crypto_level_);
        r.consume(bytes_read);
        return 1;
#else
        (void) bytes_read;
        return 1;
#endif
    }

    int QuicConnection::on_tls_secret(
        uint32_t prot_level, int direction,
        const unsigned char *secret, size_t secret_len) {
#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
        wavex::log::info("[QUIC] on_tls_secret: prot_level={} direction={} (0=read, 1=write) secret_len={}",
                         prot_level, direction, secret_len);
        ProtectionKeys keys;
        if (!CryptoSuite::expand_quic_keys(secret, secret_len, keys)) {
            wavex::log::error("[QUIC] on_tls_secret: expand_quic_keys failed for level={}", prot_level);
            return 0;
        }

        if (direction == 1) {
            // 1 = write (local/sender)
            current_write_level_ = prot_level;
            if (prot_level == 2) {
                // OSSL_RECORD_PROTECTION_LEVEL_HANDSHAKE
                handshake_keys_local_ = keys;
                wavex::log::info("[QUIC] on_tls_secret: handshake_keys_local_ expanded and marked valid");
            } else if (prot_level == 3) {
                // OSSL_RECORD_PROTECTION_LEVEL_APPLICATION
                one_rtt_keys_local_ = keys;
                one_rtt_keys_ = keys;
                wavex::log::info("[QUIC] on_tls_secret: one_rtt_keys_local_ expanded and marked valid");
            }
        } else {
            // 0 = read (peer/receiver)
            current_read_level_ = prot_level;
            if (prot_level == 2) {
                // OSSL_RECORD_PROTECTION_LEVEL_HANDSHAKE
                handshake_keys_peer_ = keys;
                wavex::log::info("[QUIC] on_tls_secret: handshake_keys_peer_ expanded and marked valid! Draining buffered packets...");
                drain_buffered_packets();
            } else if (prot_level == 3) {
                // OSSL_RECORD_PROTECTION_LEVEL_APPLICATION
                one_rtt_keys_peer_ = keys;
                wavex::log::info("[QUIC] on_tls_secret: one_rtt_keys_peer_ expanded and marked valid! Draining buffered packets...");
                drain_buffered_packets();
            }
        }
        return 1;
#else
        (void) prot_level;
        (void) direction;
        (void) secret;
        (void) secret_len;
        return 1;
#endif
    }

    int QuicConnection::on_tls_transport_params(
        const unsigned char * /*params*/, size_t /*params_len*/) {
        return 1;
    }

    void QuicConnection::queue_crypto_frame(std::string_view data) {
        std::size_t offset = 0;

        while (offset < data.size() || data.empty()) {
            constexpr std::size_t kMaxChunk = 1150;
            std::size_t chunk_len = (std::min)(data.size() - offset, kMaxChunk);
            std::string_view chunk = data.substr(offset, chunk_len);

            CryptoFrame cf;
            std::string payload;

            PacketHeader hdr;
            hdr.is_long = true;
            hdr.version = version_;
            hdr.dcid = peer_cid_;
            hdr.scid = local_cid_;

            const ProtectionKeys *keys = nullptr;

            if (current_write_level_ == 0) {
                // OSSL_RECORD_PROTECTION_LEVEL_NONE (Initial)
                hdr.type = PacketType::Initial;
                hdr.packet_number = allocate_next_pn(PacketType::Initial);
                cf.offset = crypto_send_offset_initial_;
                crypto_send_offset_initial_ += chunk.size();
                cf.data = std::string(chunk);

                if (ack_trackers_[0].has_packets) {
                    AckFrame ack = ack_trackers_[0].build_ack_frame();
                    serialize_frame(ack, payload);
                    ack_trackers_[0].mark_ack_sent();
                }
                serialize_frame(cf, payload);

                // Server ack-eliciting Initial packets MUST be expanded to at least 1200 bytes (RFC 9000 §14.1)
                const std::size_t est_overhead =
                        1 + 4 + (1 + hdr.dcid.length()) + (1 + hdr.scid.length()) + 1 + 2 + 4 + 16;
                if (payload.size() + est_overhead < 1200) {
                    payload.resize(1200 - est_overhead, '\0');
                }

                keys = &initial_keys_local_;
            } else if (current_write_level_ == 2) {
                // OSSL_RECORD_PROTECTION_LEVEL_HANDSHAKE
                hdr.type = PacketType::Handshake;
                hdr.packet_number = allocate_next_pn(PacketType::Handshake);
                cf.offset = crypto_send_offset_handshake_;
                crypto_send_offset_handshake_ += chunk.size();
                cf.data = std::string(chunk);

                if (ack_trackers_[1].has_packets) {
                    AckFrame ack = ack_trackers_[1].build_ack_frame();
                    serialize_frame(ack, payload);
                    ack_trackers_[1].mark_ack_sent();
                }
                serialize_frame(cf, payload);
                keys = handshake_keys_local_.valid ? &handshake_keys_local_ : nullptr;
            } else {
                // OSSL_RECORD_PROTECTION_LEVEL_APPLICATION (1-RTT)
                hdr.is_long = false;
                hdr.type = PacketType::OneRTT;
                hdr.packet_number = allocate_next_pn(PacketType::OneRTT);
                cf.offset = crypto_send_offset_app_;
                crypto_send_offset_app_ += chunk.size();
                cf.data = std::string(chunk);
                if (ack_trackers_[2].has_packets && ack_trackers_[2].needs_ack()) {
                    AckFrame ack = ack_trackers_[2].build_ack_frame();
                    serialize_frame(ack, payload);
                    ack_trackers_[2].mark_ack_sent();
                }
                serialize_frame(cf, payload);
                keys = one_rtt_keys_local_.valid ? &one_rtt_keys_local_ : (!tls_ || !tls_->initialized ? &initial_keys_local_ : nullptr);
            }

            std::string packet;
            if (!keys || !keys->valid) {
                wavex::log::error("[QUIC] queue_crypto_frame: No valid keys for write_level={}! Dropping crypto packet.",
                                  current_write_level_);
            } else if (!CryptoSuite::protect_packet(*keys, hdr, payload, packet)) {
                wavex::log::error("[QUIC] queue_crypto_frame: CryptoSuite::protect_packet failed for write_level={}!",
                                  current_write_level_);
            } else {
                wavex::log::info("[QUIC] queue_crypto_frame: successfully protected packet ({} bytes, type={:02x}, pn={}), enqueuing to pending_outbound_datagrams_ (total={})",
                                 packet.size(), static_cast<uint8_t>(hdr.type), hdr.packet_number, pending_outbound_datagrams_.size() + 1);
                track_sent_packet(hdr.type, hdr.packet_number, packet.size(), {cf});
                pending_outbound_datagrams_.push_back(std::move(packet));
            }

            offset += chunk_len;
            if (data.empty()) break;
        }

        if (on_outbound_) on_outbound_();
    }

    void QuicConnection::run_tls_engine() {
#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
        if (!tls_ || !tls_->ssl || !tls_->initialized) {
            wavex::log::warn("[QUIC] run_tls_engine: TLS engine not initialized! tls_={} initialized={}",
                             (tls_ != nullptr), (tls_ ? tls_->initialized : false));
            return;
        }

        const int ret = SSL_do_handshake(tls_->ssl);
        if (ret != 1) {
            const int err = SSL_get_error(tls_->ssl, ret);
            wavex::log::error("[QUIC] SSL_do_handshake rc={} SSL_get_error={}", ret, err);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                if (on_outbound_) on_outbound_();
                return;
            }
            // Fatal TLS error
            state_ = ConnectionState::Closed;
            return;
        }

        // ret == 1: Handshake completed successfully
        wavex::log::info("[QUIC] SSL_do_handshake succeeded (rc=1)! Handshake complete.");
        handshake_done_ = true;
        state_ = ConnectionState::Connected;
        drain_buffered_packets();

        if (is_server_) {
            // Send HANDSHAKE_DONE in a 1-RTT short packet (RFC 9000 §19.20)
            PacketHeader one_rtt_hdr;
            one_rtt_hdr.is_long = false;
            one_rtt_hdr.type = PacketType::OneRTT;
            one_rtt_hdr.dcid = peer_cid_;
            one_rtt_hdr.packet_number = allocate_next_pn(PacketType::OneRTT);

            HandshakeDoneFrame hdf;
            std::string one_rtt_payload;
            serialize_frame(hdf, one_rtt_payload);

            const auto &keys = one_rtt_keys_local_.valid ? one_rtt_keys_local_ : initial_keys_local_;
            std::string one_rtt_packet;
            if (CryptoSuite::protect_packet(keys, one_rtt_hdr, one_rtt_payload, one_rtt_packet)) {
                track_sent_packet(PacketType::OneRTT, one_rtt_hdr.packet_number, one_rtt_packet.size(), {hdf});
                pending_outbound_datagrams_.push_back(std::move(one_rtt_packet));
            }

            if (!http3_session_initialized_) {
                initialize_http3_session();
            }
        }

        if (on_outbound_) on_outbound_();
#endif
    }

    void QuicConnection::send_ack_for_space(const PacketType type) {
        const std::size_t s = space_index(type);
        auto &tracker = ack_trackers_[s];
        if (!tracker.has_packets) return;

        PacketHeader hdr;
        const ProtectionKeys *keys = nullptr;
        if (type == PacketType::OneRTT) {
            hdr.is_long = false;
            hdr.type = PacketType::OneRTT;
            hdr.dcid = peer_cid_;
            hdr.packet_number = allocate_next_pn(PacketType::OneRTT);
            keys = one_rtt_keys_local_.valid
                       ? &one_rtt_keys_local_
                       : (one_rtt_keys_.valid ? &one_rtt_keys_ : &initial_keys_local_);
        } else if (type == PacketType::Handshake) {
            hdr.is_long = true;
            hdr.type = PacketType::Handshake;
            hdr.version = version_;
            hdr.dcid = peer_cid_;
            hdr.scid = local_cid_;
            hdr.packet_number = allocate_next_pn(PacketType::Handshake);
            keys = handshake_keys_local_.valid ? &handshake_keys_local_ : nullptr;
        } else {
            hdr.is_long = true;
            hdr.type = PacketType::Initial;
            hdr.version = version_;
            hdr.dcid = peer_cid_;
            hdr.scid = local_cid_;
            hdr.packet_number = allocate_next_pn(PacketType::Initial);
            keys = &initial_keys_local_;
        }
        if (!keys || !keys->valid) return;

        AckFrame ack = tracker.build_ack_frame();
        tracker.mark_ack_sent();

        std::string payload;
        serialize_frame(ack, payload);

        std::string packet;
        if (CryptoSuite::protect_packet(*keys, hdr, payload, packet)) {
            wavex::log::info("[QUIC] send_ack_for_space: Sent coalesced ACK (space={}, pn={}, largest_ack={}, ranges={})",
                             s, hdr.packet_number, ack.largest_acknowledged, ack.ranges.size());
            pending_outbound_datagrams_.push_back(std::move(packet));
        }
        if (on_outbound_) on_outbound_();
    }

    void QuicConnection::send_ack(const uint64_t pn, const PacketType type) {
        const std::size_t s = space_index(type);
        ack_trackers_[s].add_packet(pn, true);
        send_ack_for_space(type);
    }

    void QuicConnection::track_sent_packet(const PacketType type, const uint64_t pn, const std::size_t bytes, std::vector<Frame> frames) {
        const std::size_t s = space_index(type);
        const bool ack_eliciting = !frames.empty();
        sent_packets_[s].emplace_back(pn, bytes, type, std::move(frames), std::chrono::steady_clock::now());
        congestion_controller_.on_packet_sent(bytes, true);
        if (ack_eliciting) {
            arm_loss_detection_timer();
        }
    }

    void QuicConnection::on_ack_received(const PacketType pkt_type, const AckFrame &ack) {
        const std::size_t s = space_index(pkt_type);
        auto &pkts = sent_packets_[s];
        if (pkts.empty()) return;

        // Decode all acknowledged ranges
        std::vector<std::pair<uint64_t, uint64_t>> acked_ranges;
        uint64_t largest = ack.largest_acknowledged;
        uint64_t first_range_len = ack.ranges.empty() ? 0 : ack.ranges[0].ack_range_len;
        uint64_t smallest = (largest >= first_range_len) ? (largest - first_range_len) : 0;
        acked_ranges.emplace_back(smallest, largest);

        for (std::size_t i = 1; i < ack.ranges.size(); ++i) {
            if (smallest < ack.ranges[i].gap + 2) break;
            largest = smallest - ack.ranges[i].gap - 2;
            uint64_t len = ack.ranges[i].ack_range_len;
            smallest = (largest >= len) ? (largest - len) : 0;
            acked_ranges.emplace_back(smallest, largest);
        }

        auto is_acked = [&](const uint64_t pn) noexcept {
            for (const auto &[min_pn, max_pn] : acked_ranges) {
                if (pn >= min_pn && pn <= max_pn) return true;
            }
            return false;
        };

        bool newly_acked_any = false;
        const auto now = std::chrono::steady_clock::now();
        std::vector<SentPacket> remaining;
        remaining.reserve(pkts.size());

        for (auto &pkt : pkts) {
            if (is_acked(pkt.packet_number)) {
                newly_acked_any = true;
                congestion_controller_.on_packet_acked(pkt.bytes_sent);
                if (pkt.packet_number == ack.largest_acknowledged) {
                    const auto rtt_sample = std::chrono::duration_cast<std::chrono::microseconds>(now - pkt.time_sent);
                    congestion_controller_.update_rtt(rtt_sample, std::chrono::microseconds(ack.ack_delay * 1000));
                }
            } else {
                remaining.push_back(std::move(pkt));
            }
        }

        pkts = std::move(remaining);

        if (newly_acked_any) {
            pto_count_ = 0;
            if (!has_largest_acked_[s] || ack.largest_acknowledged > largest_acked_packet_[s]) {
                largest_acked_packet_[s] = ack.largest_acknowledged;
                has_largest_acked_[s] = true;
            }
            detect_lost_packets(s, ack.largest_acknowledged);
            arm_loss_detection_timer();
        }
    }

    void QuicConnection::detect_lost_packets(const std::size_t space, const uint64_t largest_acked) {
        if (space >= sent_packets_.size()) return;
        auto &pkts = sent_packets_[space];
        if (pkts.empty()) return;

        const auto &rtt_stats = congestion_controller_.rtt_stats();
        const auto now = std::chrono::steady_clock::now();
        const auto max_rtt = (std::max)(rtt_stats.smoothed_rtt, rtt_stats.latest_rtt);
        const auto time_threshold = (max_rtt * 9) / 8;

        std::vector<SentPacket> remaining;
        remaining.reserve(pkts.size());

        for (auto &pkt : pkts) {
            if (pkt.packet_number > largest_acked) {
                remaining.push_back(std::move(pkt));
                continue;
            }

            const bool packet_loss = (largest_acked >= pkt.packet_number + CongestionController::kPacketThreshold);
            const bool time_loss = (now >= pkt.time_sent + time_threshold);

            if (packet_loss || time_loss) {
                wavex::log::info("[QUIC] Declaring packet lost: space={}, pn={}, bytes={}, packet_loss={}, time_loss={}",
                                 space, pkt.packet_number, pkt.bytes_sent, packet_loss, time_loss);
                congestion_controller_.on_congestion_event(pkt.time_sent, now);
                for (const auto &f : pkt.retransmittable_frames) {
                    retransmit_frame(f, pkt.packet_type);
                }
            } else {
                remaining.push_back(std::move(pkt));
            }
        }

        pkts = std::move(remaining);
    }

    void QuicConnection::arm_loss_detection_timer() {
        if (!executor_) return;
        if (state_ == ConnectionState::Closed) return;

        bool has_in_flight = false;
        auto earliest_sent = std::chrono::steady_clock::time_point::max();

        for (std::size_t s = 0; s < 3; ++s) {
            for (const auto &pkt : sent_packets_[s]) {
                if (pkt.ack_eliciting && !pkt.retransmittable_frames.empty()) {
                    has_in_flight = true;
                    if (pkt.time_sent < earliest_sent) {
                        earliest_sent = pkt.time_sent;
                    }
                }
            }
        }

        if (!has_in_flight) {
            if (loss_detection_timer_) {
                asio::error_code ec;
                loss_detection_timer_->cancel(ec);
            }
            return;
        }

        if (!loss_detection_timer_) {
            loss_detection_timer_ = std::make_unique<asio::steady_timer>(executor_);
        }

        const auto &rtt_stats = congestion_controller_.rtt_stats();
        const auto rttvar_4 = (std::max)(rtt_stats.rttvar * 4, std::chrono::microseconds(1000));
        const auto pto_base = rtt_stats.smoothed_rtt + rttvar_4;
        const uint32_t shift = (std::min)(pto_count_, 10u);
        const auto pto_duration = pto_base * (1ULL << shift);

        auto timeout_point = earliest_sent + pto_duration;
        const auto now = std::chrono::steady_clock::now();
        if (timeout_point < now) {
            timeout_point = now;
        }

        asio::error_code ec;
        loss_detection_timer_->expires_at(timeout_point, ec);
        auto weak_self = weak_from_this();
        loss_detection_timer_->async_wait([weak_self](const asio::error_code &timer_ec) {
            if (timer_ec) return;
            if (auto self = weak_self.lock()) {
                self->on_loss_detection_timeout();
            }
        });
    }

    void QuicConnection::on_loss_detection_timeout() {
        std::lock_guard lock(mtx_);
        if (state_ == ConnectionState::Closed) return;

        bool retransmitted = false;
        for (std::size_t s = 0; s < 3; ++s) {
            auto &pkts = sent_packets_[s];
            if (pkts.empty()) continue;

            for (auto &pkt : pkts) {
                if (!pkt.retransmittable_frames.empty()) {
                    wavex::log::info("[QUIC] PTO timeout fired (pto_count={}): retransmitting {} frames from space={}, pn={}",
                                     pto_count_, pkt.retransmittable_frames.size(), s, pkt.packet_number);
                    for (const auto &f : pkt.retransmittable_frames) {
                        retransmit_frame(f, pkt.packet_type);
                    }
                    pkt.retransmittable_frames.clear();
                    retransmitted = true;
                    break;
                }
            }
            if (retransmitted) break;
        }

        pto_count_++;
        arm_loss_detection_timer();

        if (on_outbound_) on_outbound_();
    }

    void QuicConnection::retransmit_frame(const Frame &frame, const PacketType pkt_type) {
        std::visit([this, pkt_type]<typename T0>(const T0 &f) {
            using T = std::decay_t<T0>;
            if constexpr (std::is_same_v<T, CryptoFrame>) {
                CryptoFrame cf = f;
                std::string payload;
                serialize_frame(cf, payload);

                PacketHeader hdr;
                const ProtectionKeys *keys = nullptr;
                if (pkt_type == PacketType::Initial) {
                    hdr.is_long = true;
                    hdr.type = PacketType::Initial;
                    hdr.version = version_;
                    hdr.dcid = peer_cid_;
                    hdr.scid = local_cid_;
                    hdr.packet_number = allocate_next_pn(PacketType::Initial);
                    keys = &initial_keys_local_;
                    const std::size_t est_overhead = 1 + 4 + (1 + hdr.dcid.length()) + (1 + hdr.scid.length()) + 1 + 2 + 4 + 16;
                    if (payload.size() + est_overhead < 1200) {
                        payload.resize(1200 - est_overhead, '\0');
                    }
                } else if (pkt_type == PacketType::Handshake) {
                    hdr.is_long = true;
                    hdr.type = PacketType::Handshake;
                    hdr.version = version_;
                    hdr.dcid = peer_cid_;
                    hdr.scid = local_cid_;
                    hdr.packet_number = allocate_next_pn(PacketType::Handshake);
                    keys = handshake_keys_local_.valid ? &handshake_keys_local_ : nullptr;
                } else {
                    hdr.is_long = false;
                    hdr.type = PacketType::OneRTT;
                    hdr.dcid = peer_cid_;
                    hdr.packet_number = allocate_next_pn(PacketType::OneRTT);
                    keys = one_rtt_keys_local_.valid ? &one_rtt_keys_local_ : &initial_keys_local_;
                }

                if (keys && keys->valid) {
                    std::string packet;
                    if (CryptoSuite::protect_packet(*keys, hdr, payload, packet)) {
                        wavex::log::info("[QUIC] retransmit_frame: resending CRYPTO frame (space={}, new_pn={}, bytes={})",
                                         space_index(hdr.type), hdr.packet_number, packet.size());
                        track_sent_packet(hdr.type, hdr.packet_number, packet.size(), {cf});
                        pending_outbound_datagrams_.push_back(std::move(packet));
                    }
                }
            } else if constexpr (std::is_same_v<T, StreamFrame>) {
                StreamFrame sf = f;
                auto it = streams_.find(sf.stream_id);
                if (it == streams_.end() || !it->second->is_open()) {
                    return;
                }

                std::string payload;
                serialize_frame(sf, payload);

                PacketHeader hdr;
                hdr.is_long = false;
                hdr.type = PacketType::OneRTT;
                hdr.dcid = peer_cid_;
                hdr.packet_number = allocate_next_pn(PacketType::OneRTT);

                std::string packet;
                const auto &keys = (one_rtt_keys_local_.valid)
                                       ? one_rtt_keys_local_
                                       : (one_rtt_keys_.valid ? one_rtt_keys_ : initial_keys_local_);
                if (CryptoSuite::protect_packet(keys, hdr, payload, packet)) {
                    wavex::log::info("[QUIC] retransmit_frame: resending STREAM frame (sid={}, offset={}, size={}, new_pn={})",
                                     sf.stream_id, sf.offset, sf.data.size(), hdr.packet_number);
                    track_sent_packet(PacketType::OneRTT, hdr.packet_number, packet.size(), {sf});
                    pending_outbound_datagrams_.push_back(std::move(packet));
                }
            } else if constexpr (std::is_same_v<T, HandshakeDoneFrame>) {
                PacketHeader hdr;
                hdr.is_long = false;
                hdr.type = PacketType::OneRTT;
                hdr.dcid = peer_cid_;
                hdr.packet_number = allocate_next_pn(PacketType::OneRTT);

                HandshakeDoneFrame hdf = f;
                std::string payload;
                serialize_frame(hdf, payload);

                const auto &keys = one_rtt_keys_local_.valid ? one_rtt_keys_local_ : initial_keys_local_;
                std::string packet;
                if (CryptoSuite::protect_packet(keys, hdr, payload, packet)) {
                    wavex::log::info("[QUIC] retransmit_frame: resending HANDSHAKE_DONE frame (new_pn={})", hdr.packet_number);
                    track_sent_packet(PacketType::OneRTT, hdr.packet_number, packet.size(), {hdf});
                    pending_outbound_datagrams_.push_back(std::move(packet));
                }
            }
        }, frame);
    }

    void QuicConnection::drain_buffered_packets() {
        if (draining_buffered_packets_) return;
        draining_buffered_packets_ = true;

        bool progress = true;
        while (progress) {
            progress = false;

            if (handshake_keys_peer_.valid && !buffered_handshake_packets_.empty()) {
                auto pkt = std::move(buffered_handshake_packets_.front());
                buffered_handshake_packets_.pop_front();
                wavex::log::info("[QUIC] Draining buffered Handshake packet ({} bytes, remaining in queue={})",
                                 pkt.size(), buffered_handshake_packets_.size());
                handle_datagram(pkt);
                progress = true;
                continue;
            }

            if (one_rtt_keys_peer_.valid && !buffered_one_rtt_packets_.empty()) {
                auto pkt = std::move(buffered_one_rtt_packets_.front());
                buffered_one_rtt_packets_.pop_front();
                wavex::log::info("[QUIC] Draining buffered 1-RTT packet ({} bytes, remaining in queue={})",
                                 pkt.size(), buffered_one_rtt_packets_.size());
                handle_datagram(pkt);
                progress = true;
                continue;
            }
        }

        draining_buffered_packets_ = false;
    }

    void QuicConnection::handle_datagram(const std::string_view datagram) {
        std::vector<std::shared_ptr<QuicStream> > created_streams;
        OutboundCallback outbound_cb;
        StreamCreatedCallback stream_created_cb; {
            std::lock_guard lock(mtx_);
            std::string_view remaining = datagram;

            while (!remaining.empty()) {
                PacketHeader hdr;
                std::size_t hdr_len = 0;
                if (!unpack_packet_header(remaining, hdr, hdr_len, local_cid_.length())) {
                    wavex::log::warn("[QUIC] handle_datagram: failed to unpack packet header from remaining {} bytes", remaining.size());
                    break;
                }

                std::size_t packet_size = remaining.size();
                if (hdr.is_long && hdr.length > 0) {
                    const std::size_t expected_size = hdr.pn_offset + static_cast<std::size_t>(hdr.length);
                    if (expected_size <= remaining.size()) {
                        packet_size = expected_size;
                    }
                }

                const std::string_view packet_bytes = remaining.substr(0, packet_size);
                remaining.remove_prefix(packet_size);

                wavex::log::info("[QUIC] handle_datagram: processing packet ({} bytes, is_long={}, type={}, dcid={})",
                                 packet_bytes.size(), hdr.is_long, static_cast<int>(hdr.type), hdr.dcid.to_string());

                const ProtectionKeys *keys = nullptr;
                if (hdr.is_long) {
                    if (hdr.type == PacketType::Initial) {
                        keys = &initial_keys_peer_;
                    } else if (hdr.type == PacketType::Handshake) {
                        if (!handshake_keys_peer_.valid) {
                            if (buffered_handshake_packets_.size() < 16) {
                                buffered_handshake_packets_.emplace_back(packet_bytes);
                                wavex::log::info("[QUIC] Buffering Handshake packet ({} bytes) - handshake_keys_peer not yet valid (queue_size={})",
                                                 packet_bytes.size(), buffered_handshake_packets_.size());
                            } else {
                                wavex::log::warn("[QUIC] Dropping Handshake packet ({} bytes) - buffer limit reached", packet_bytes.size());
                            }
                            continue;
                        }
                        keys = &handshake_keys_peer_;
                    }
                } else {
                    if (!one_rtt_keys_peer_.valid) {
                        if (!tls_ || !tls_->initialized) {
                            // Non-TLS or mock test fallback
                            keys = one_rtt_keys_.valid ? &one_rtt_keys_ : &initial_keys_peer_;
                        } else {
                            if (buffered_one_rtt_packets_.size() < 16) {
                                buffered_one_rtt_packets_.emplace_back(packet_bytes);
                                wavex::log::info("[QUIC] Buffering 1-RTT packet ({} bytes) - one_rtt_keys_peer not yet valid (queue_size={})",
                                                 packet_bytes.size(), buffered_one_rtt_packets_.size());
                            } else {
                                wavex::log::warn("[QUIC] Dropping 1-RTT packet ({} bytes) - buffer limit reached", packet_bytes.size());
                            }
                            continue;
                        }
                    } else {
                        keys = &one_rtt_keys_peer_;
                    }
                }

                // Drop packet if we don't have the right keys for this level yet
                if (!keys || !keys->valid) {
                    wavex::log::warn("[QUIC] handle_datagram: no valid keys for packet type={}! Dropping packet.", static_cast<int>(hdr.type));
                    continue;
                }

                const std::size_t space_idx = space_index(hdr.type);
                const uint64_t largest_pn_in_space = ack_trackers_[space_idx].largest_pn;

                std::string plaintext;
                if (!CryptoSuite::unprotect_packet(*keys, hdr, packet_bytes, plaintext, largest_pn_in_space,
                                                   local_cid_.length())) {
                    wavex::log::warn("[QUIC] handle_datagram: unprotect_packet failed for packet type={} ({} bytes)!",
                                     static_cast<int>(hdr.type), packet_bytes.size());
                    continue;
                }

                wavex::log::info("[QUIC] handle_datagram: packet decrypted! type={} pn={} plaintext_len={}",
                                 static_cast<int>(hdr.type), hdr.packet_number, plaintext.size());

                if (plaintext.size() == 224) {
                    std::string hex;
                    for (unsigned char c : plaintext) hex += std::format("{:02x} ", c);
                    wavex::log::info("[QUIC] pn={} plaintext hex dump: {}", hdr.packet_number, hex);
                }

                if (hdr.is_long) {
                    if (hdr.type == PacketType::Initial) {
                        has_received_initial_ = true;
                    } else if (hdr.type == PacketType::Handshake) {
                        has_received_handshake_ = true;
                    }
                }

                std::vector<Frame> frames;
                if (parse_frames(plaintext, frames)) {
                    wavex::log::info("[QUIC] parse_frames succeeded: {} frames extracted", frames.size());
                    bool is_ack_eliciting = false;
                    bool has_crypto_frame = false;
                    for (const auto &f: frames) {
                        if (!std::holds_alternative<AckFrame>(f) &&
                            !std::holds_alternative<PaddingFrame>(f) &&
                            !std::holds_alternative<ConnectionCloseFrame>(f)) {
                            is_ack_eliciting = true;
                        }

                        if (const auto *cf = std::get_if<CryptoFrame>(&f)) {
                            wavex::log::info("[QUIC] Received CryptoFrame: {} bytes at offset {} (pkt_type={})",
                                             cf->data.size(), cf->offset, static_cast<int>(hdr.type));
#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
                            if (tls_ && tls_->initialized) {
                                auto &reassembler = reassembler_for_pkt_type(hdr.type);
                                reassembler.insert(cf->offset, cf->data);
                                wavex::log::info("[QUIC] Crypto reassembler for pkt_type={}: ready={} unconsumed={} next_offset={} pending_fragments={}",
                                                 static_cast<int>(hdr.type),
                                                 reassembler.ready.size(),
                                                 reassembler.ready.size() - reassembler.ready_consumed,
                                                 reassembler.next_offset,
                                                 reassembler.pending.size());
                                has_crypto_frame = true;
                            } else {
                                wavex::log::warn("[QUIC] Received CryptoFrame ({} bytes) but TLS engine not initialized! tls_={} initialized={}",
                                                 cf->data.size(), (tls_ != nullptr), (tls_ ? tls_->initialized : false));
                            }
#endif
                        }
                    }

                    // Record packet into tracker ONCE per packet
                    ack_trackers_[space_idx].add_packet(hdr.packet_number, is_ack_eliciting);

                    if (has_crypto_frame) {
                        wavex::log::info("[QUIC] invoking run_tls_engine() due to incoming CRYPTO frame");
                        run_tls_engine();
                    }

                    // Pass the packet type so process_frames can handle frames
                    process_frames(frames, hdr.packet_number, hdr.type, created_streams);
                } else {
                    std::string hex;
                    for (unsigned char c : plaintext) hex += std::format("{:02x} ", c);
                    wavex::log::warn("[QUIC] parse_frames failed for packet pn={} (plaintext_len={}) hex: {}",
                                     hdr.packet_number, plaintext.size(), hex);
                }
            }

            // Coalesced ACK dispatch for any space that still has pending ack-eliciting packets
            if (ack_trackers_[0].needs_ack()) {
                send_ack_for_space(PacketType::Initial);
            }
            if (ack_trackers_[1].needs_ack()) {
                send_ack_for_space(PacketType::Handshake);
            }
            if (ack_trackers_[2].needs_ack()) {
                send_ack_for_space(PacketType::OneRTT);
            }

            if (is_server_ && state_ == ConnectionState::Initial) {
                // For mock or non-TLS connections (e.g. unit tests without certs), auto-complete handshake
                if (!tls_ || !tls_->initialized) {
                    wavex::log::info("[QUIC] Non-TLS or uninitialized fallback: calling send_initial_handshake_response()");
                    send_initial_handshake_response();
                    state_ = ConnectionState::Connected;
                }
            }

            drain_buffered_packets();

            outbound_cb = on_outbound_;
            stream_created_cb = on_stream_created_;
        }

        if (stream_created_cb) {
            for (const auto &s: created_streams) {
                stream_created_cb(s);
            }
        }
        if (outbound_cb) outbound_cb();
    }

    void QuicConnection::process_frames(const std::vector<Frame> &frames, const uint64_t pn, const PacketType pkt_type,
                                        std::vector<std::shared_ptr<QuicStream> > &new_streams) {
        for (const auto &f: frames) {
            std::visit([this, pn, pkt_type, &new_streams]<typename T0>(const T0 &frame) {
                using T = std::decay_t<T0>;
                if constexpr (std::is_same_v<T, PingFrame>) {
                    // PING frames are ack-eliciting; coalesced ACK is handled at packet/datagram level
                } else if constexpr (std::is_same_v<T, AckFrame>) {
                    on_ack_received(pkt_type, frame);
                } else if constexpr (std::is_same_v<T, StreamFrame>) {
                    // STREAM frames are ack-eliciting; coalesced ACK is handled at packet/datagram level
                    auto it = streams_.find(frame.stream_id);
                    if (it == streams_.end()) {
                        auto stream = std::make_shared<QuicStream>(shared_from_this(), frame.stream_id, executor_);
                        streams_[frame.stream_id] = stream;
                        accepted_streams_.push_back(stream);
                        if (stream_acceptor_) {
                            auto cb = std::move(*stream_acceptor_);
                            stream_acceptor_.reset();
                            cb(stream);
                        }
                        new_streams.push_back(stream);
                        it = streams_.find(frame.stream_id);
                    }
                    it->second->push_inbound(frame.offset, frame.data, frame.fin);
                    if (it->second->has_final_size_error()) {
                        wavex::log::error("[QUIC] Stream {} FINAL_SIZE_ERROR: final size mismatch with peer", frame.stream_id);
                    }
                } else if constexpr (std::is_same_v<T, MaxDataFrame>) {
                    if (frame.max_data > max_data_) {
                        max_data_ = frame.max_data;
                    }
                } else if constexpr (std::is_same_v<T, MaxStreamDataFrame>) {
                    if (frame.max_stream_data > max_stream_data_) {
                        max_stream_data_ = frame.max_stream_data;
                    }
                } else if constexpr (std::is_same_v<T, ResetStreamFrame>) {
                    auto it = streams_.find(frame.stream_id);
                    if (it != streams_.end()) {
                        it->second->close();
                    }
                } else if constexpr (std::is_same_v<T, StopSendingFrame>) {
                    auto it = streams_.find(frame.stream_id);
                    if (it != streams_.end()) {
                        it->second->close();
                    }
                } else if constexpr (std::is_same_v<T, ConnectionCloseFrame>) {
                    wavex::log::error(
                        "[QUIC] Received CONNECTION_CLOSE from peer: is_application={} error_code=0x{:x} ({}) frame_type=0x{:x} reason=\"{}\" (pkt_type={} pn={})",
                        frame.is_application, frame.error_code, frame.error_code,
                        frame.frame_type, frame.reason_phrase,
                        static_cast<int>(pkt_type), pn);
                    state_ = ConnectionState::Closed;
                }
            }, f);
        }
    }

    void QuicConnection::send_initial_handshake_response() {
        // Build Initial Server Packet with Ack only (RFC 9000 §19.20 forbids HANDSHAKE_DONE in Initial packet)
        PacketHeader hdr;
        hdr.is_long = true;
        hdr.type = PacketType::Initial;
        hdr.version = version_;
        hdr.dcid = peer_cid_;
        hdr.scid = local_cid_;
        hdr.packet_number = allocate_next_pn(PacketType::Initial);

        AckFrame ack = ack_trackers_[0].has_packets ? ack_trackers_[0].build_ack_frame() : AckFrame{};
        ack_trackers_[0].mark_ack_sent();

        std::string payload;
        serialize_frame(ack, payload);

        std::string packet;
        const auto &keys = initial_keys_local_;
        if (CryptoSuite::protect_packet(keys, hdr, payload, packet)) {
            pending_outbound_datagrams_.push_back(std::move(packet));
        }

        // Send HANDSHAKE_DONE in a 1-RTT packet (RFC 9000 §19.20)
        PacketHeader one_rtt_hdr;
        one_rtt_hdr.is_long = false;
        one_rtt_hdr.type = PacketType::OneRTT;
        one_rtt_hdr.dcid = peer_cid_;
        one_rtt_hdr.packet_number = allocate_next_pn(PacketType::OneRTT);

        HandshakeDoneFrame hdf;
        std::string one_rtt_payload;
        serialize_frame(hdf, one_rtt_payload);

        const auto &one_rtt_keys = (one_rtt_keys_local_.valid)
                                       ? one_rtt_keys_local_
                                       : (one_rtt_keys_.valid ? one_rtt_keys_ : initial_keys_local_);
        std::string one_rtt_packet;
        if (CryptoSuite::protect_packet(one_rtt_keys, one_rtt_hdr, one_rtt_payload, one_rtt_packet)) {
            track_sent_packet(PacketType::OneRTT, one_rtt_hdr.packet_number, one_rtt_packet.size(), {hdf});
            pending_outbound_datagrams_.push_back(std::move(one_rtt_packet));
        }
    }

    std::shared_ptr<QuicStream> QuicConnection::create_stream(const bool bidirectional) {
        std::lock_guard lock(mtx_);
        uint64_t sid = 0;
        if (bidirectional) {
            sid = (next_bidi_stream_id_++) << 2;
            if (is_server_) sid |= 0x01;
        } else {
            sid = (next_uni_stream_id_++) << 2 | 0x02;
            if (is_server_) sid |= 0x01;
        }

        auto stream = std::make_shared<QuicStream>(shared_from_this(), sid, executor_);
        streams_[sid] = stream;
        return stream;
    }

    std::shared_ptr<QuicStream> QuicConnection::get_or_create_stream(const uint64_t stream_id) {
        std::lock_guard lock(mtx_);
        auto it = streams_.find(stream_id);
        if (it != streams_.end()) return it->second;

        auto stream = std::make_shared<QuicStream>(shared_from_this(), stream_id, executor_);
        streams_[stream_id] = stream;
        return stream;
    }

    void QuicConnection::close_stream(const uint64_t stream_id) {
        std::lock_guard lock(mtx_);
        auto it = streams_.find(stream_id);
        if (it != streams_.end()) {
            it->second->close();
            streams_.erase(it);
        }
    }

    asio::awaitable<std::shared_ptr<QuicStream> > QuicConnection::accept_stream() {
        std::unique_lock lock(mtx_);
        if (!accepted_streams_.empty()) {
            auto stream = accepted_streams_.front();
            accepted_streams_.pop_front();
            co_return stream;
        }

        co_return co_await asio::async_initiate<const asio::use_awaitable_t<> &, void(std::shared_ptr<QuicStream>)>(
            [this]<typename T0>(T0 handler) {
                using HandlerType = std::decay_t<T0>;
                auto shared_h = std::make_shared<HandlerType>(std::move(handler));
                auto executor = asio::get_associated_executor(*shared_h);

                std::lock_guard inner_lock(mtx_);
                if (!accepted_streams_.empty()) {
                    auto stream = accepted_streams_.front();
                    accepted_streams_.pop_front();
                    asio::post(executor, [shared_h, stream] {
                        (*shared_h)(stream);
                    });
                    return;
                }
                stream_acceptor_ = [shared_h, executor](std::shared_ptr<QuicStream> s) {
                    asio::post(executor, [shared_h, s] {
                        (*shared_h)(s);
                    });
                };
            },
            asio::use_awaitable
        );
    }

    void QuicConnection::queue_stream_data(const uint64_t stream_id, const std::string_view data, const bool fin) {
        OutboundCallback cb; {
            std::lock_guard lock(mtx_);
            StreamFrame sf;
            sf.stream_id = stream_id;
            sf.data = std::string(data);
            sf.fin = fin;
            sf.has_length = true;

            uint64_t &cur_offset = stream_send_offsets_[stream_id];
            sf.offset = cur_offset;
            sf.has_offset = (cur_offset > 0);
            cur_offset += data.size();

            std::string payload;
            serialize_frame(sf, payload);

            PacketHeader hdr;
            hdr.is_long = false;
            hdr.type = PacketType::OneRTT;
            hdr.dcid = peer_cid_;
            hdr.packet_number = allocate_next_pn(PacketType::OneRTT);

            std::string packet;
            const auto &keys = (one_rtt_keys_local_.valid)
                                   ? one_rtt_keys_local_
                                   : (one_rtt_keys_.valid ? one_rtt_keys_ : initial_keys_local_);
            if (CryptoSuite::protect_packet(keys, hdr, payload, packet)) {
                track_sent_packet(PacketType::OneRTT, hdr.packet_number, packet.size(), {sf});
                pending_outbound_datagrams_.push_back(std::move(packet));
            }
            cb = on_outbound_;
        }
        if (cb) cb();
    }

    uint64_t QuicConnection::open_unidirectional_stream() {
        auto stream = create_stream(false);
        return stream->stream_id();
    }

    void QuicConnection::write_stream(const uint64_t stream_id, const std::string_view data, const bool fin) {
        queue_stream_data(stream_id, data, fin);
    }

    void QuicConnection::write_stream(const uint64_t stream_id, const std::vector<uint8_t> &data, const bool fin) {
        queue_stream_data(stream_id, std::string_view(reinterpret_cast<const char *>(data.data()), data.size()), fin);
    }

    void QuicConnection::initialize_http3_session() {
        if (!is_server_) return;
        http3_session_initialized_ = true;

        // 1. Establish HTTP/3 Control Stream (Stream Type 0x00)
        const uint64_t control_stream_id = open_unidirectional_stream();
        std::string control_stream_data;

        // Prepend Unidirectional Stream Type (0x00)
        VarInt::encode(0x00, control_stream_data);

        // Construct SETTINGS Frame (Type 0x04)
        std::string settings_payload;

        // SETTINGS_MAX_FIELD_SECTION_SIZE (Identifier 0x06) = 65,536 bytes
        VarInt::encode(0x06, settings_payload);
        VarInt::encode(65536, settings_payload);

        // SETTINGS_QPACK_MAX_TABLE_CAPACITY (Identifier 0x01) = 0 (Static table only)
        VarInt::encode(0x01, settings_payload);
        VarInt::encode(0, settings_payload);

        // SETTINGS_QPACK_BLOCKED_STREAMS (Identifier 0x07) = 0
        VarInt::encode(0x07, settings_payload);
        VarInt::encode(0, settings_payload);

        // Frame Header: Frame Type (0x04) followed by Payload Length
        VarInt::encode(0x04, control_stream_data);
        VarInt::encode(settings_payload.size(), control_stream_data);
        control_stream_data.append(settings_payload);

        write_stream(control_stream_id, control_stream_data, false);

        // 2. Establish QPACK Encoder Stream (Stream Type 0x02)
        const uint64_t qpack_enc_id = open_unidirectional_stream();
        std::string enc_init_data;
        VarInt::encode(0x02, enc_init_data);
        write_stream(qpack_enc_id, enc_init_data, false);

        // 3. Establish QPACK Decoder Stream (Stream Type 0x03)
        const uint64_t qpack_dec_id = open_unidirectional_stream();
        std::string dec_init_data;
        VarInt::encode(0x03, dec_init_data);
        write_stream(qpack_dec_id, dec_init_data, false);

        wavex::log::info("[QUIC] HTTP/3 session initialized: control_stream={}, qpack_enc={}, qpack_dec={}",
                         control_stream_id, qpack_enc_id, qpack_dec_id);
    }

    std::vector<std::string> QuicConnection::poll_outgoing_datagrams() {
        std::lock_guard lock(mtx_);
        std::vector<std::string> pkts;
        pkts.reserve(pending_outbound_datagrams_.size());
        while (!pending_outbound_datagrams_.empty()) {
            pkts.push_back(std::move(pending_outbound_datagrams_.front()));
            pending_outbound_datagrams_.pop_front();
        }
        if (!pkts.empty()) {
            wavex::log::info("[QUIC] poll_outgoing_datagrams: drained {} datagram(s)", pkts.size());
        }
        return pkts;
    }

    void QuicConnection::close(const TransportError err, const std::string_view reason) {
        OutboundCallback cb; {
            std::lock_guard lock(mtx_);
            if (state_ == ConnectionState::Closed) return;
            state_ = ConnectionState::Closed;

            ConnectionCloseFrame ccf;
            ccf.error_code = static_cast<uint64_t>(err);
            ccf.reason_phrase = std::string(reason);

            std::string payload;
            serialize_frame(ccf, payload);

            PacketHeader hdr;
            hdr.is_long = false;
            hdr.type = PacketType::OneRTT;
            hdr.dcid = peer_cid_;
            hdr.packet_number = allocate_next_pn(PacketType::OneRTT);

            std::string packet;
            const auto &keys = (one_rtt_keys_local_.valid)
                                   ? one_rtt_keys_local_
                                   : (one_rtt_keys_.valid ? one_rtt_keys_ : initial_keys_local_);
            if (CryptoSuite::protect_packet(keys, hdr, payload, packet)) {
                pending_outbound_datagrams_.push_back(std::move(packet));
            }
            cb = on_outbound_;
        }
        if (cb) cb();
    }

} // namespace wavex::network::quic

#endif // WAVEX_HAS_SSL

