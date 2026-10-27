#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL

#include <ranges>
#include <wavex/Network/QUIC/QuicConnection.hpp>
#include <wavex/Base/Logger.hpp>

#include <openssl/x509v3.h>

#include "wavex/Network/QUIC/VarInt.hpp"

#if defined(min)
#undef min
#endif
#if defined(max)
#undef max
#endif

#include <asio/co_spawn.hpp>
#include <asio/as_tuple.hpp>
#include <asio/redirect_error.hpp>
#include <asio/post.hpp>
#include <future>

#include <algorithm>
#include <filesystem>
#include <random>
#include <fstream>
#include <cassert>

namespace wavex::network::quic {
    namespace {
        /// RFC 9000 §14.1: every UDP datagram a client sends that carries an Initial packet (including
        /// ACK-only and CONNECTION_CLOSE packets) must be at least 1200 bytes, or servers discard it.
        void pad_client_initial(const PacketHeader &hdr, std::string &payload) {
            const std::size_t est_overhead =
                    1 + 4 + (1 + hdr.dcid.length()) + (1 + hdr.scid.length()) + 1 + 2 + 4 + 16;
            if (payload.size() + est_overhead < 1200) {
                payload.resize(1200 - est_overhead, '\0');
            }
        }
    } // namespace

    // ─── 7. QuicConnection Implementation ──────────────────────────────────────

#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
    QuicConnection::TlsCtx::~TlsCtx() {
        if (ssl) {
            SSL_free(ssl);
            ssl = nullptr;
        }
        if (ctx && owns_ctx) {
            SSL_CTX_free(ctx);
            ctx = nullptr;
        }
    }

    QuicConnection::TlsCtx::TlsCtx(TlsCtx &&other) noexcept
        : ssl(std::exchange(other.ssl, nullptr)),
          ctx(std::exchange(other.ctx, nullptr)),
          current_write_level(other.current_write_level),
          current_read_level(other.current_read_level),
          initialized(other.initialized),
          owns_ctx(other.owns_ctx) {
        other.current_write_level = 0;
        other.current_read_level = 0;
        other.initialized = false;
        other.owns_ctx = true;
    }

    QuicConnection::TlsCtx &QuicConnection::TlsCtx::operator=(TlsCtx &&other) noexcept {
        if (this != &other) {
            if (ssl) {
                SSL_free(ssl);
                ssl = nullptr;
            }
            if (ctx && owns_ctx) {
                SSL_CTX_free(ctx);
                ctx = nullptr;
            }
            ssl = std::exchange(other.ssl, nullptr);
            ctx = std::exchange(other.ctx, nullptr);
            current_write_level = other.current_write_level;
            current_read_level = other.current_read_level;
            initialized = other.initialized;
            owns_ctx = other.owns_ctx;

            other.current_write_level = 0;
            other.current_read_level = 0;
            other.initialized = false;
            other.owns_ctx = true;
        }
        return *this;
    }

    extern "C" {
    static int quic_tls_crypto_send(
        SSL * /*s*/, const unsigned char *buf, const size_t buf_len,
        size_t *consumed, void *arg) {
        if (!arg || !buf || buf_len == 0) return 0;
        auto *conn = static_cast<QuicConnection *>(arg);
        conn->queue_crypto_frame(std::string_view(reinterpret_cast<const char *>(buf), buf_len));
        if (consumed) *consumed = buf_len;
        return 1;
    }

    static int quic_tls_crypto_recv_rcd(
        SSL * /*s*/, const unsigned char **buf, size_t *bytes_read,
        void *arg) {
        if (!arg || !buf || !bytes_read) return 0;
        auto *conn = static_cast<QuicConnection *>(arg);
        return conn->on_tls_crypto_recv(buf, bytes_read);
    }

    static int quic_tls_crypto_release_rcd(
        SSL * /*s*/, const size_t bytes_read, void *arg) {
        if (!arg) return 0;
        auto *conn = static_cast<QuicConnection *>(arg);
        return conn->on_tls_crypto_release(bytes_read);
    }

    static int quic_tls_yield_secret(
        SSL * /*s*/, const uint32_t prot_level, const int direction,
        const unsigned char *secret, const size_t secret_len, void *arg) {
        if (!arg || !secret) return 0;
        auto *conn = static_cast<QuicConnection *>(arg);
        return conn->on_tls_secret(prot_level, direction, secret, secret_len);
    }

    static int quic_tls_got_transport_params(
        SSL * /*s*/, const unsigned char *params, const size_t params_len,
        void *arg) {
        if (!arg) return 0;
        const auto *conn = static_cast<QuicConnection *>(arg);
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

    bool QuicConnection::CryptoStreamReassembler::insert(const uint64_t offset, const std::string_view data) {
        if (data.empty()) return true;
        if (offset + data.size() <= next_offset) return true;
        if (offset > next_offset + kMaxCryptoBufferSize) return false;
        if (pending_bytes + data.size() > kMaxCryptoBufferSize) return false;

        pending_bytes += data.size();
        pending.emplace(offset, std::string(data));
        while (!pending.empty()) {
            const auto it = pending.begin();
            if (it->first > next_offset) break;
            if (const uint64_t end = it->first + it->second.size(); end > next_offset) {
                const std::size_t overlap = static_cast<std::size_t>(next_offset - it->first);
                ready.append(it->second.data() + overlap, it->second.size() - overlap);
                next_offset = end;
            }
            pending_bytes -= it->second.size();
            pending.erase(it);
        }
        return true;
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
                    if (const auto prev = std::prev(it); prev->second + 1 == it->first) {
                        prev->second = it->second;
                        intervals.erase(it);
                    }
                }
                return;
            }
        }

        if (it != intervals.begin()) {
            if (const auto prev = std::prev(it); prev->second + 1 == pn) {
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
            evicted_below = (std::max)(evicted_below, intervals.front().second + 1);
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
                const auto &[curr1, curr2] = intervals[i - 1];
                const auto &[prev1, prev2] = intervals[i];
                const uint64_t gap = (prev1 > curr2 + 2) ? (prev1 - curr2 - 2) : 0;
                const uint64_t range_len = curr2 - curr1;
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
        if (idle_timer_) {
            asio::error_code ec;
            idle_timer_->cancel(ec);
        }
        initial_keys_peer_.cleanse();
        initial_keys_local_.cleanse();
        handshake_keys_peer_.cleanse();
        handshake_keys_local_.cleanse();
        one_rtt_keys_peer_.cleanse();
        one_rtt_keys_local_.cleanse();
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

        if (shared_ssl_ctx_) {
            tls_->ctx = shared_ssl_ctx_;
            tls_->owns_ctx = false;
        } else {
            tls_->ctx = SSL_CTX_new(is_server_ ? TLS_server_method() : TLS_client_method());
            tls_->owns_ctx = true;
            if (!tls_->ctx) {
                wavex::log::error("[QUIC] init_tls_handshake_engine: SSL_CTX_new failed");
                return false;
            }

            SSL_CTX_set_min_proto_version(tls_->ctx, TLS1_3_VERSION);
            SSL_CTX_set_max_proto_version(tls_->ctx, TLS1_3_VERSION);

            // Standard TLS 1.3 cipher suite preferred for QUIC
            SSL_CTX_set_ciphersuites(tls_->ctx, "TLS_AES_128_GCM_SHA256");

            // Ground-truth tooling: support SSLKEYLOGFILE for Wireshark / diagnostic interop
            if ([[maybe_unused]] const char *keylog_path = std::getenv("SSLKEYLOGFILE")) {
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
                    if (SSL_CTX_use_certificate_file(tls_->ctx, tls_cert_file_.c_str(), SSL_FILETYPE_PEM) != 1) {
                        wavex::log::error("[QUIC] init_tls_handshake_engine: SSL_CTX_use_certificate_file failed for '{}'",
                                          tls_cert_file_);
                        return false;
                    }
                    if (SSL_CTX_use_PrivateKey_file(tls_->ctx, tls_key_file_.c_str(), SSL_FILETYPE_PEM) != 1) {
                        wavex::log::error("[QUIC] init_tls_handshake_engine: SSL_CTX_use_PrivateKey_file failed for '{}'",
                                          tls_key_file_);
                        return false;
                    }
                    wavex::log::debug("[QUIC] init_tls_handshake_engine: loaded cert '{}' and key '{}'", tls_cert_file_,
                                      tls_key_file_);
                } else {
                    wavex::log::warn(
                        "[QUIC] init_tls_handshake_engine: is_server=true but cert ('{}') or key ('{}') is empty!",
                        tls_cert_file_, tls_key_file_);
                }

                // ALPN selection callback for server (mandated by RFC 9001 §8.1)
                SSL_CTX_set_alpn_select_cb(
                    tls_->ctx,
                    [](SSL * /*ssl*/,
                       const unsigned char **out,
                       unsigned char *outlen,
                       const unsigned char *in,
                       const unsigned int inlen,
                       void * /*arg*/) -> int {
                        unsigned int i = 0;
                        while (i < inlen) {
                            const unsigned char proto_len = in[i++];
                            if (i + proto_len > inlen) break;
                            if (const std::string_view proto(reinterpret_cast<const char *>(in + i), proto_len);
                                proto == "h3") {
                                *out = in + i;
                                *outlen = proto_len;
                                return SSL_TLSEXT_ERR_OK;
                            }
                            i += proto_len;
                        }
                        return SSL_TLSEXT_ERR_ALERT_FATAL; // no_application_protocol
                    },
                    nullptr);
            }
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
            if (verify_peer_) {
                // Verify the server chain against the default trust store and check the name/IP.
                SSL_CTX_set_default_verify_paths(tls_->ctx);
                SSL_set_verify(tls_->ssl, SSL_VERIFY_PEER, nullptr);
                if (!sni_hostname_.empty()) {
                    X509_VERIFY_PARAM *param = SSL_get0_param(tls_->ssl);
                    if (X509_VERIFY_PARAM_set1_ip_asc(param, sni_hostname_.c_str()) != 1) {
                        SSL_set1_host(tls_->ssl, sni_hostname_.c_str());
                    }
                }
            } else {
                wavex::log::warn("[QUIC] Client certificate verification is DISABLED (set_verify_peer(false))");
                SSL_set_verify(tls_->ssl, SSL_VERIFY_NONE, nullptr);
            }
            if (!sni_hostname_.empty()) {
                // SNI must not carry an IP literal (RFC 6066 §3).
                asio::error_code addr_ec;
                (void) asio::ip::make_address(sni_hostname_, addr_ec);
                if (addr_ec) {
                    SSL_set_tlsext_host_name(tls_->ssl, sni_hostname_.c_str());
                }
            }
            static constexpr unsigned char kAlpnProtos[] = "\x02h3";
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
        wavex::log::debug("[QUIC] init_tls_handshake_engine: TLS engine initialized successfully (is_server={})",
                          is_server_);
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
        auto add_varint_param = [&out](const uint64_t id, const uint64_t val) {
            VarInt::encode(id, out);
            const std::size_t val_len = VarInt::encoded_size(val);
            VarInt::encode(val_len, out);
            VarInt::encode(val, out);
        };

        // original_destination_connection_id is server-only: a client sending it is a
        // TRANSPORT_PARAMETER_ERROR (RFC 9000 §18.2).
        const ConnectionId &orig_cid = (!original_dcid_.empty()) ? original_dcid_ : local_cid_;
        if (is_server_ && !orig_cid.empty()) {
            VarInt::encode(0x00, out); // original_destination_connection_id
            VarInt::encode(orig_cid.length(), out);
            out.append(reinterpret_cast<const char *>(orig_cid.data()), orig_cid.length());
        }

        if (!local_cid_.empty()) {
            VarInt::encode(0x0f, out); // initial_source_connection_id (RFC 9000 §18.2)
            VarInt::encode(local_cid_.length(), out);
            out.append(reinterpret_cast<const char *>(local_cid_.data()), local_cid_.length());
        }

        add_varint_param(0x01, static_cast<uint64_t>(idle_timeout_.count())); // max_idle_timeout (ms)
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
        const auto &r = reassembler_for_level(current_read_level_);
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
        wavex::log::debug("[QUIC] on_tls_secret: prot_level={} direction={} (0=read, 1=write) secret_len={}",
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
                handshake_keys_local_ = std::move(keys);
                wavex::log::debug("[QUIC] on_tls_secret: handshake_keys_local_ set (write)");
            } else if (prot_level >= 3) {
                // OSSL_RECORD_PROTECTION_LEVEL_APPLICATION
                one_rtt_keys_local_ = std::move(keys);
                wavex::log::debug("[QUIC] on_tls_secret: one_rtt_keys_local_ set (write)");
            }
        } else {
            // 0 = read (peer/receiver)
            current_read_level_ = prot_level;
            if (prot_level == 2) {
                // OSSL_RECORD_PROTECTION_LEVEL_HANDSHAKE
                handshake_keys_peer_ = std::move(keys);
                wavex::log::debug("[QUIC] on_tls_secret: handshake_keys_peer_ set (read)");
                // Buffered packets are drained by run_tls_engine() once SSL_do_handshake() has returned:
                // draining here would re-enter SSL_do_handshake() from inside its own callback.
            } else if (prot_level >= 3) {
                // OSSL_RECORD_PROTECTION_LEVEL_APPLICATION
                one_rtt_keys_peer_ = std::move(keys);
                wavex::log::debug(
                    "[QUIC] on_tls_secret: one_rtt_keys_peer_ set (read)");
            }
        }
        keys.cleanse();
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
                cf.data = chunk;

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
                cf.data = chunk;

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
                hdr.key_phase = (local_key_phase_ != 0);
                hdr.packet_number = allocate_next_pn(PacketType::OneRTT);
                cf.offset = crypto_send_offset_app_;
                crypto_send_offset_app_ += chunk.size();
                cf.data = chunk;
                if (ack_trackers_[2].has_packets && ack_trackers_[2].needs_ack()) {
                    AckFrame ack = ack_trackers_[2].build_ack_frame();
                    serialize_frame(ack, payload);
                    ack_trackers_[2].mark_ack_sent();
                }
                serialize_frame(cf, payload);
                keys = one_rtt_keys_local_.valid
                           ? &one_rtt_keys_local_
                           : (!tls_ || !tls_->initialized ? &initial_keys_local_ : nullptr);
            }

            if (!keys || !keys->valid) {
                wavex::log::error(
                    "[QUIC] queue_crypto_frame: No valid keys for write_level={}! Dropping crypto packet.",
                    current_write_level_);
            } else if (std::string packet; !CryptoSuite::protect_packet(*keys, hdr, payload, packet)) {
                wavex::log::error("[QUIC] queue_crypto_frame: CryptoSuite::protect_packet failed for write_level={}!",
                                  current_write_level_);
            } else {
                cf.owned_data = std::make_shared<const std::string>(cf.data);
                cf.data = *cf.owned_data;
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

        // OpenSSL must never be re-entered from one of its own callbacks. A nested request is
        // recorded and served by looping once the outer SSL_do_handshake() call has returned.
        if (in_tls_engine_) {
            tls_rerun_pending_ = true;
            return;
        }

        int ret = 0;
        int err = SSL_ERROR_NONE;
        in_tls_engine_ = true;
        do {
            tls_rerun_pending_ = false;
            ret = SSL_do_handshake(tls_->ssl);
            err = (ret == 1) ? SSL_ERROR_NONE : SSL_get_error(tls_->ssl, ret);
        } while (tls_rerun_pending_ && ret != 1 && err == SSL_ERROR_WANT_READ);
        in_tls_engine_ = false;

        if (ret != 1) {
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                wavex::log::debug("[QUIC] SSL_do_handshake: waiting for IO (rc={}, err={})", ret, err);
                // New read keys may have been installed during the call: process what was waiting on them.
                drain_buffered_packets();
                if (on_outbound_) on_outbound_();
                return;
            }
            wavex::log::error("[QUIC] SSL_do_handshake fatal error rc={} SSL_get_error={}", ret, err);
            // RFC 9001 §4.8: TLS failures are reported as CRYPTO_ERROR (0x0100 + alert). The alert is not
            // plumbed through yet, so use the generic handshake_failure alert (40).
            close(static_cast<TransportError>(0x0100 + 40), "TLS handshake failed");
            return;
        }

        // ret == 1: Handshake completed successfully
        if (handshake_done_) {
            return;
        }

        wavex::log::info("[QUIC] SSL_do_handshake succeeded (rc=1)! Handshake complete.");
        handshake_done_ = true;
        state_ = ConnectionState::Connected;
        drain_buffered_packets();
        flush_stream_send_queues();

        ConnectedCallback connected_cb; {
            std::lock_guard lock(mtx_);
            connected_cb = on_connected_;
        }
        if (connected_cb) connected_cb();

        if (is_server_) {
            send_handshake_done();

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
            hdr.key_phase = (local_key_phase_ != 0);
            hdr.dcid = peer_cid_;
            hdr.packet_number = allocate_next_pn(PacketType::OneRTT);
            keys = one_rtt_send_keys();
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
        if (!is_server_ && type == PacketType::Initial) {
            pad_client_initial(hdr, payload);
        }

        if (std::string packet; CryptoSuite::protect_packet(*keys, hdr, payload, packet)) {
            pending_outbound_datagrams_.push_back(std::move(packet));
        }
        if (on_outbound_) on_outbound_();
    }

    void QuicConnection::send_ack(const uint64_t pn, const PacketType type) {
        const std::size_t s = space_index(type);
        ack_trackers_[s].add_packet(pn, true);
        send_ack_for_space(type);
    }

    void QuicConnection::track_sent_packet(const PacketType type, const uint64_t pn, const std::size_t bytes,
                                           std::vector<Frame> frames) {
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
        wavex::log::debug("[QUIC] on_ack_received: enter space={} pkts.size()={} largest_ack={} ranges={}",
                          s, pkts.size(), ack.largest_acknowledged, ack.ranges.size());
        if (pkts.empty()) return;

        // Decode all acknowledged ranges
        std::vector<std::pair<uint64_t, uint64_t> > acked_ranges;
        uint64_t largest = ack.largest_acknowledged;
        const uint64_t first_range_len = ack.ranges.empty() ? 0 : ack.ranges[0].ack_range_len;
        uint64_t smallest = (largest >= first_range_len) ? (largest - first_range_len) : 0;
        acked_ranges.emplace_back(smallest, largest);

        for (std::size_t i = 1; i < ack.ranges.size(); ++i) {
            if (smallest < ack.ranges[i].gap + 2) break;
            largest = smallest - ack.ranges[i].gap - 2;
            const uint64_t len = ack.ranges[i].ack_range_len;
            smallest = (largest >= len) ? (largest - len) : 0;
            acked_ranges.emplace_back(smallest, largest);
        }

        auto is_acked = [&](const uint64_t pn) noexcept {
            for (const auto &[min_pn, max_pn]: acked_ranges) {
                if (pn >= min_pn && pn <= max_pn) return true;
            }
            return false;
        };

        bool newly_acked_any = false;
        const auto now = std::chrono::steady_clock::now();
        std::vector<SentPacket> remaining;
        remaining.reserve(pkts.size());

        for (auto &pkt: pkts) {
            if (is_acked(pkt.packet_number)) {
                newly_acked_any = true;
                congestion_controller_.on_packet_acked(pkt.bytes_sent);
                if (pkt.packet_number == ack.largest_acknowledged) {
                    const auto rtt_sample = std::chrono::duration_cast<std::chrono::microseconds>(now - pkt.time_sent);
                    // ACK Delay is encoded in units of 2^ack_delay_exponent microseconds. The peer's
                    // transport parameters are not parsed yet, so the default exponent (3) is assumed.
                    congestion_controller_.update_rtt(rtt_sample, std::chrono::microseconds(ack.ack_delay << 3));
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
            flush_stream_send_queues();
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
        std::vector<std::pair<Frame, PacketType> > lost_frames;

        for (auto &pkt: pkts) {
            if (pkt.packet_number > largest_acked) {
                remaining.push_back(std::move(pkt));
                continue;
            }

            const bool packet_loss = (largest_acked >= pkt.packet_number + CongestionController::kPacketThreshold);

            if (const bool time_loss = (now >= pkt.time_sent + time_threshold); packet_loss || time_loss) {
                wavex::log::debug(
                    "[QUIC] Declaring packet lost: space={}, pn={}, bytes={}, packet_loss={}, time_loss={}",
                    space, pkt.packet_number, pkt.bytes_sent, packet_loss, time_loss);
                congestion_controller_.on_congestion_event(pkt.time_sent, now);
                for (const auto &f: pkt.retransmittable_frames) {
                    lost_frames.emplace_back(f, pkt.packet_type);
                }
            } else {
                remaining.push_back(std::move(pkt));
            }
        }

        pkts = std::move(remaining);

        for (const auto &[f, pt]: lost_frames) {
            retransmit_frame(f, pt);
        }
    }

    void QuicConnection::arm_loss_detection_timer() {
        if (!executor_) return;
        if (state_ == ConnectionState::Closed) return;

        bool has_in_flight = false;
        auto earliest_sent = (std::chrono::steady_clock::time_point::max)();

        for (std::size_t s = 0; s < 3; ++s) {
            for (const auto &pkt: sent_packets_[s]) {
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
        if (const auto now = std::chrono::steady_clock::now(); timeout_point < now) {
            timeout_point = now;
        }

        asio::error_code ec;
        loss_detection_timer_->expires_at(timeout_point, ec);
        auto weak_self = weak_from_this();
        loss_detection_timer_->async_wait([weak_self](const asio::error_code &timer_ec) {
            if (timer_ec) return;
            if (const auto self = weak_self.lock()) {
                self->on_loss_detection_timeout();
            }
        });
    }

    void QuicConnection::on_loss_detection_timeout() {
        std::lock_guard lock(mtx_);
        if (state_ == ConnectionState::Closed) return;

        std::vector<std::pair<Frame, PacketType> > frames_to_retransmit;
        for (std::size_t s = 0; s < 3; ++s) {
            auto &pkts = sent_packets_[s];
            if (pkts.empty()) continue;

            for (auto &pkt: pkts) {
                if (!pkt.retransmittable_frames.empty()) {
                    wavex::log::debug(
                        "[QUIC] PTO timeout fired (pto_count={}): retransmitting {} frames from space={}, pn={}",
                        pto_count_, pkt.retransmittable_frames.size(), s, pkt.packet_number);
                    for (const auto &f: pkt.retransmittable_frames) {
                        frames_to_retransmit.emplace_back(f, pkt.packet_type);
                    }
                    pkt.retransmittable_frames.clear();
                    break;
                }
            }
            if (!frames_to_retransmit.empty()) break;
        }

        for (const auto &[f, pt]: frames_to_retransmit) {
            retransmit_frame(f, pt);
        }

        pto_count_++;
        arm_loss_detection_timer();

        if (on_outbound_) on_outbound_();
    }

    void QuicConnection::refresh_idle_timer() {
        std::lock_guard lock(mtx_);
        if (state_ == ConnectionState::Closed) return;

        if (!idle_timer_) {
            idle_timer_ = std::make_unique<asio::steady_timer>(executor_);
        }

        idle_timer_->expires_after(idle_timeout_);

        auto weak_self = std::weak_ptr<QuicConnection>(shared_from_this());
        idle_timer_->async_wait([weak_self](const asio::error_code &timer_ec) {
            if (timer_ec) return;
            if (const auto self = weak_self.lock()) {
                std::lock_guard lk(self->mtx_);
                if (self->state_ != ConnectionState::Closed) {
                    wavex::log::debug("[QUIC] Idle timeout expired ({} ms) for DCID={} -> closing connection",
                                      self->idle_timeout_.count(), self->peer_cid_.to_string());
                    self->close(TransportError::NoError, "Idle timeout expired");
                }
            }
        });
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
                    const std::size_t est_overhead =
                            1 + 4 + (1 + hdr.dcid.length()) + (1 + hdr.scid.length()) + 1 + 2 + 4 + 16;
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
                    hdr.key_phase = (local_key_phase_ != 0);
                    hdr.dcid = peer_cid_;
                    keys = one_rtt_send_keys();
                    if (!keys) return;
                    hdr.packet_number = allocate_next_pn(PacketType::OneRTT);
                }

                if (keys && keys->valid) {
                    if (std::string packet; CryptoSuite::protect_packet(*keys, hdr, payload, packet)) {
                        wavex::log::debug(
                            "[QUIC] retransmit_frame: resending CRYPTO frame (space={}, new_pn={}, bytes={})",
                            space_index(hdr.type), hdr.packet_number, packet.size());
                        track_sent_packet(hdr.type, hdr.packet_number, packet.size(), {cf});
                        pending_outbound_datagrams_.push_back(std::move(packet));
                    }
                }
            } else if constexpr (std::is_same_v<T, StreamFrame>) {
                StreamFrame sf = f;
                // Do NOT skip streams that were closed or erased locally: a response's last packets are
                // typically sent right before the stream finishes, and they still need to arrive. The
                // frame owns its bytes (owned_data), so it is safe to resend after the stream is gone.
                const ProtectionKeys *keys = one_rtt_send_keys();
                if (!keys) return;

                std::string payload;
                serialize_frame(sf, payload);

                PacketHeader hdr;
                hdr.is_long = false;
                hdr.type = PacketType::OneRTT;
                hdr.key_phase = (local_key_phase_ != 0);
                hdr.dcid = peer_cid_;
                hdr.packet_number = allocate_next_pn(PacketType::OneRTT);

                std::string packet;
                if (CryptoSuite::protect_packet(*keys, hdr, payload, packet)) {
                    wavex::log::debug(
                        "[QUIC] retransmit_frame: resending STREAM frame (sid={}, offset={}, size={}, new_pn={})",
                        sf.stream_id, sf.offset, sf.data.size(), hdr.packet_number);
                    track_sent_packet(PacketType::OneRTT, hdr.packet_number, packet.size(), {sf});
                    pending_outbound_datagrams_.push_back(std::move(packet));
                }
            } else if constexpr (std::is_same_v<T, HandshakeDoneFrame>) {
                PacketHeader hdr;
                hdr.is_long = false;
                hdr.type = PacketType::OneRTT;
                hdr.key_phase = (local_key_phase_ != 0);
                hdr.dcid = peer_cid_;
                hdr.packet_number = allocate_next_pn(PacketType::OneRTT);

                HandshakeDoneFrame hdf = f;
                std::string payload;
                serialize_frame(hdf, payload);

                const ProtectionKeys *keys = one_rtt_send_keys();
                if (!keys) return;
                if (std::string packet; CryptoSuite::protect_packet(*keys, hdr, payload, packet)) {
                    wavex::log::debug("[QUIC] retransmit_frame: resending HANDSHAKE_DONE frame (new_pn={})",
                                      hdr.packet_number);
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
                handle_datagram(pkt);
                progress = true;
                continue;
            }

            if (one_rtt_keys_peer_.valid && !buffered_one_rtt_packets_.empty()) {
                auto pkt = std::move(buffered_one_rtt_packets_.front());
                buffered_one_rtt_packets_.pop_front();
                handle_datagram(pkt);
                progress = true;
                continue;
            }
        }

        draining_buffered_packets_ = false;
    }

    void QuicConnection::handle_datagram(const std::string_view datagram) {
        refresh_idle_timer();
        std::vector<std::shared_ptr<QuicStream> > created_streams;
        OutboundCallback outbound_cb;
        StreamCreatedCallback stream_created_cb; {
            std::lock_guard lock(mtx_);
            cumulative_bytes_received_ += datagram.size();
            std::string_view remaining = datagram;

            while (!remaining.empty()) {
                if (state_ == ConnectionState::Closed) break;
                PacketHeader hdr;
                if (std::size_t hdr_len = 0;
                    !unpack_packet_header(remaining, hdr, hdr_len, local_cid_.length())) {
                    wavex::log::debug("[QUIC] handle_datagram: failed to unpack packet header from remaining {} bytes",
                                      remaining.size());
                    break;
                }

                std::size_t packet_size = remaining.size();
                if (hdr.is_long && hdr.length > 0) {
                    if (const std::size_t expected_size = hdr.pn_offset + static_cast<std::size_t>(hdr.length);
                        expected_size <= remaining.size()) {
                        packet_size = expected_size;
                    }
                }

                const std::string_view packet_bytes = remaining.substr(0, packet_size);
                remaining.remove_prefix(packet_size);

                ProtectionKeys *keys = nullptr;
                if (hdr.is_long) {
                    if (hdr.type == PacketType::Initial) {
                        keys = &initial_keys_peer_;
                    } else if (hdr.type == PacketType::Handshake) {
                        // Address validation happens below, after the packet has been decrypted: an
                        // unauthenticated header must never lift the anti-amplification limit.
                        if (!handshake_keys_peer_.valid) {
                            if (buffered_handshake_packets_.size() < 16) {
                                buffered_handshake_packets_.emplace_back(packet_bytes);
                            } else {
                                wavex::log::warn("[QUIC] Dropping Handshake packet ({} bytes) - buffer limit reached",
                                                 packet_bytes.size());
                            }
                            continue;
                        }
                        keys = &handshake_keys_peer_;
                    }
                } else {
                    // Short header (1-RTT packet)
                    if (!one_rtt_keys_peer_.valid) {
                        if (!tls_ || !tls_->initialized) {
                            // Non-TLS or mock test fallback
                            keys = &initial_keys_peer_;
                        } else {
                            if (buffered_one_rtt_packets_.size() < 16) {
                                buffered_one_rtt_packets_.emplace_back(packet_bytes);
                                wavex::log::debug("[QUIC] Buffering 1-RTT packet ({} bytes) - waiting for keys",
                                                  packet_bytes.size());
                            } else {
                                wavex::log::warn("[QUIC] Dropping 1-RTT packet ({} bytes) - buffer limit reached",
                                                 packet_bytes.size());
                            }
                            continue;
                        }
                    } else {
                        keys = &one_rtt_keys_peer_;
                        wavex::log::debug("[QUIC] Using one_rtt_keys_peer_ for incoming 1-RTT packet");
                    }
                }

                // Drop packet if we don't have the right keys for this level yet
                if (!keys || !keys->valid) {
                    wavex::log::debug("[QUIC] handle_datagram: no valid keys for packet type={}! Dropping packet.",
                                      static_cast<int>(hdr.type));
                    continue;
                }

                const std::size_t space_idx = space_index(hdr.type);
                const uint64_t largest_pn_in_space = ack_trackers_[space_idx].largest_pn;

                std::string plaintext;
                if (!CryptoSuite::unprotect_packet(*keys, hdr, packet_bytes, plaintext, largest_pn_in_space,
                                                   local_cid_.length())) {
                    wavex::log::debug("[QUIC] handle_datagram: unprotect_packet failed for packet type={} ({} bytes)!",
                                      static_cast<int>(hdr.type), packet_bytes.size());
                    continue;
                }

                // RFC 9000 §12.3: a packet number that was already received is a duplicate (retransmitted
                // by the network or replayed by an attacker) and must not be processed a second time.
                if (ack_trackers_[space_idx].contains(hdr.packet_number)) {
                    wavex::log::debug("[QUIC] handle_datagram: dropping duplicate packet pn={} type={}",
                                      hdr.packet_number, static_cast<int>(hdr.type));
                    continue;
                }

                if (hdr.is_long) {
                    if (hdr.type == PacketType::Initial) {
                        has_received_initial_ = true;
                        // RFC 9000 §7.2: the client switches to the server-chosen SCID from the first
                        // Initial packet it receives, and keeps using it for the rest of the connection.
                        if (!is_server_ && !peer_cid_switched_ && !hdr.scid.empty()) {
                            peer_cid_ = hdr.scid;
                            peer_cid_switched_ = true;
                        }
                    } else if (hdr.type == PacketType::Handshake) {
                        has_received_handshake_ = true;
                        // RFC 9000 §8.1: a successfully processed Handshake packet validates the address.
                        if (is_server_) peer_address_validated_ = true;
                    }
                } else {
                    peer_address_validated_ = true; // RFC 9000 §8.1: Authenticated 1-RTT validates address
                    if (one_rtt_keys_peer_.valid && one_rtt_keys_peer_.key_phase != peer_key_phase_) {
                        peer_key_phase_ = one_rtt_keys_peer_.key_phase;
                        wavex::log::info("[QUIC] Peer initiated Key Update to phase {}", peer_key_phase_);
                        if (one_rtt_keys_local_.valid) {
                            CryptoSuite::update_keys(one_rtt_keys_local_);
                            local_key_phase_ = peer_key_phase_;
                            one_rtt_keys_local_.key_phase = local_key_phase_;
                        }
                    }
                }

                if (std::vector<Frame> frames; parse_frames(plaintext, frames)) {
                    // RFC 9000 §12.4: only PADDING, PING, ACK, CRYPTO and CONNECTION_CLOSE (0x1c) may be
                    // carried by Initial and Handshake packets. Initial keys are derived from the public
                    // DCID, so accepting e.g. STREAM frames there would let anyone who sees the CID inject
                    // requests that bypass TLS. (Mock/non-TLS test mode keeps the old permissive behaviour.)
                    if (tls_ && tls_->initialized) {
                        bool allowed = true;
                        for (const auto &f: frames) {
                            if (!frame_allowed_in(f, hdr.type)) {
                                allowed = false;
                                break;
                            }
                        }
                        if (!allowed) {
                            wavex::log::warn("[QUIC] Frame not permitted in packet type={} (pn={}): PROTOCOL_VIOLATION",
                                             static_cast<int>(hdr.type), hdr.packet_number);
                            close(TransportError::ProtocolViolation, "frame not permitted in packet type");
                            return;
                        }
                    }

                    bool is_ack_eliciting = false;
                    bool has_crypto_frame = false;
                    for (const auto &f: frames) {
                        if (!std::holds_alternative<AckFrame>(f) &&
                            !std::holds_alternative<PaddingFrame>(f) &&
                            !std::holds_alternative<ConnectionCloseFrame>(f)) {
                            is_ack_eliciting = true;
                        }

                        if (const auto *cf = std::get_if<CryptoFrame>(&f)) {
#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
                            if (tls_ && tls_->initialized) {
                                if (auto &reassembler = reassembler_for_pkt_type(hdr.type); !reassembler.insert(cf->offset, cf->data)) {
                                    wavex::log::warn("[QUIC] CRYPTO stream buffer limit exceeded (>64KB) at offset {}",
                                                     cf->offset);
                                    close(TransportError::CryptoBufferExceeded, "CRYPTO buffer limit exceeded");
                                    return;
                                }
                                has_crypto_frame = true;
                            } else {
                                wavex::log::warn(
                                    "[QUIC] Received CryptoFrame ({} bytes) but TLS engine not initialized! tls_={} initialized={}",
                                    cf->data.size(), (tls_ != nullptr), (tls_ ? tls_->initialized : false));
                            }
#endif
                        }
                    }

                    // Record packet into tracker ONCE per packet
                    ack_trackers_[space_idx].add_packet(hdr.packet_number, is_ack_eliciting);

                    if (has_crypto_frame) {
                        run_tls_engine();
                    }

                    // Pass the packet type so process_frames can handle frames
                    process_frames(frames, hdr.packet_number, hdr.type, created_streams);
                    wavex::log::debug("[QUIC] handle_datagram: process_frames returned for pn={}", hdr.packet_number);
                } else {
                    log::warn("[QUIC] parse_frames failed for packet pn={} (plaintext_len={}): FRAME_ENCODING_ERROR",
                              hdr.packet_number, plaintext.size());
                    close(TransportError::FrameEncodingError, "malformed or unknown frame");
                    return;
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

            if (is_server_ && state_ == ConnectionState::Initial && has_received_initial_) {
                // For mock or non-TLS connections (e.g. unit tests without certs), auto-complete handshake
                if (!tls_ || !tls_->initialized) {
                    wavex::log::debug(
                        "[QUIC] Non-TLS or uninitialized fallback: calling send_initial_handshake_response()");
                    send_initial_handshake_response();
                    state_ = ConnectionState::Connected;
                    ConnectedCallback connected_cb; {
                        std::lock_guard lock1(mtx_);
                        connected_cb = on_connected_;
                    }
                    if (connected_cb) connected_cb();
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
                    std::shared_ptr<QuicStream> target_stream; {
                        const bool is_bidi = (frame.stream_id & 0x02) == 0x00;
                        const bool peer_initiated = ((frame.stream_id & 0x01) != 0) == !is_server_;
                        // RFC 9000 §19.8: STREAM frames on a locally initiated unidirectional stream are
                        // a STREAM_STATE_ERROR (we are the only sender on it).
                        if (!peer_initiated && !is_bidi) {
                            close(TransportError::StreamStateError, "STREAM frame on send-only stream");
                            return;
                        }
                        auto it = streams_.find(frame.stream_id);
                        if (it == streams_.end()) {
                            if (!peer_initiated) {
                                // Locally initiated stream that we already closed (late retransmission), or one
                                // we never opened. Neither may create a new stream.
                                return;
                            }

                            const uint64_t stream_idx = frame.stream_id >> 2;
                            auto &next_idx = next_peer_stream_idx_[is_bidi ? 0 : 1];
                            if (stream_idx < next_idx) {
                                // Below the high-water mark: either implicitly opened earlier and seen now for
                                // the first time, or already finished and closed. A late or duplicated frame for
                                // a closed stream must NOT be dispatched as a brand-new request.
                                if (unseen_peer_stream_ids_.erase(frame.stream_id) == 0) {
                                    return;
                                }
                            } else {
                                // B8: Enforce advertised stream count limits (RFC 9000 §4.6)
                                if (const uint64_t max_allowed = is_bidi ? max_peer_bidi_streams_ : max_peer_uni_streams_;
                                    stream_idx >= max_allowed) {
                                    wavex::log::warn(
                                        "[QUIC] Peer exceeded stream limit: sid={} (idx={}) >= max_allowed={}",
                                        frame.stream_id, stream_idx, max_allowed);
                                    close(TransportError::StreamLimitError, "Stream limit exceeded");
                                    return;
                                }
                                // Lower-numbered streams of the same type are implicitly opened (RFC 9000 §3.2).
                                for (uint64_t idx = next_idx; idx < stream_idx; ++idx) {
                                    unseen_peer_stream_ids_.insert((idx << 2) | (frame.stream_id & 0x03));
                                }
                                next_idx = stream_idx + 1;
                            }

                            auto stream = std::make_shared<QuicStream>(shared_from_this(), frame.stream_id, executor_);
                            streams_[frame.stream_id] = stream;

                            // A11 & B3: Prevent double delivery and monotonic queue accumulation.
                            // If stream_acceptor_ is waiting, deliver directly to it without queueing in accepted_streams_.
                            if (stream_acceptor_) {
                                auto cb = std::move(*stream_acceptor_);
                                stream_acceptor_.reset();
                                cb(stream);
                            } else if (!on_stream_created_) {
                                // Only queue when server uses the accept_stream() pull API and cap at 128
                                // ReSharper disable once CppTooWideScopeInitStatement
                                constexpr std::size_t kMaxAcceptQueueSize = 128;
                                if (accepted_streams_.size() < kMaxAcceptQueueSize) {
                                    accepted_streams_.push_back(stream);
                                } else {
                                    wavex::log::warn(
                                        "[QUIC] accepted_streams_ queue full ({}), dropping unaccepted stream {}",
                                        kMaxAcceptQueueSize, frame.stream_id);
                                }
                            }

                            new_streams.push_back(stream);
                            target_stream = stream;
                        } else {
                            target_stream = it->second;
                        }
                    }

                    if (target_stream) {
                        target_stream->push_inbound(frame.offset, frame.data, frame.fin);
                        if (target_stream->has_final_size_error()) {
                            wavex::log::error("[QUIC] Stream {} FINAL_SIZE_ERROR: final size mismatch with peer",
                                              frame.stream_id);
                        }
                    }
                } else if constexpr (std::is_same_v<T, MaxDataFrame>) {
                    if (frame.max_data > max_data_) {
                        max_data_ = frame.max_data;
                        flush_stream_send_queues();
                    }
                } else if constexpr (std::is_same_v<T, MaxStreamDataFrame>) {
                    if (frame.max_stream_data > max_stream_data_) {
                        max_stream_data_ = frame.max_stream_data;
                        flush_stream_send_queues();
                    }
                } else if constexpr (std::is_same_v<T, ResetStreamFrame>) {
                    std::shared_ptr<QuicStream> s;
                    auto it = streams_.find(frame.stream_id);
                    if (it != streams_.end()) s = it->second;
                    if (s) {
                        s->close();
                    }
                } else if constexpr (std::is_same_v<T, StopSendingFrame>) {
                    std::shared_ptr<QuicStream> s;
                    auto it = streams_.find(frame.stream_id);
                    if (it != streams_.end()) s = it->second;
                    if (s) {
                        s->close();
                    }
                } else if constexpr (std::is_same_v<T, ConnectionCloseFrame>) {
                    if (frame.error_code == 0 || (frame.is_application && frame.error_code == 0x0100)) {
                        wavex::log::info(
                            "[QUIC] Received graceful CONNECTION_CLOSE from peer: reason=\"{}\" (pkt_type={} pn={})",
                            frame.reason_phrase, static_cast<int>(pkt_type), pn);
                    } else {
                        wavex::log::warn(
                            "[QUIC] Received CONNECTION_CLOSE from peer: is_application={} error_code=0x{:x} ({}) frame_type=0x{:x} reason=\"{}\" (pkt_type={} pn={})",
                            frame.is_application, frame.error_code, frame.error_code,
                            frame.frame_type, frame.reason_phrase,
                            static_cast<int>(pkt_type), pn);
                    }
                    // Tear down properly (timers, streams, closed callback) so the server's connection
                    // table entry is released. RFC 9000 §10.2.2: no CONNECTION_CLOSE is sent in reply.
                    terminate(false, TransportError::NoError, "");
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
        if (const auto &keys = initial_keys_local_; CryptoSuite::protect_packet(keys, hdr, payload, packet)) {
            pending_outbound_datagrams_.push_back(std::move(packet));
        }

        // Send HANDSHAKE_DONE in a 1-RTT packet (RFC 9000 §19.20)
        send_handshake_done();
    }

    void QuicConnection::send_handshake_done() {
        if (!is_server_ || handshake_done_sent_) return;
        const ProtectionKeys *keys = one_rtt_send_keys();
        if (!keys) return; // HANDSHAKE_DONE is only valid in a 1-RTT packet
        handshake_done_sent_ = true;

        PacketHeader one_rtt_hdr;
        one_rtt_hdr.is_long = false;
        one_rtt_hdr.type = PacketType::OneRTT;
        one_rtt_hdr.key_phase = (local_key_phase_ != 0);
        one_rtt_hdr.dcid = peer_cid_;
        one_rtt_hdr.packet_number = allocate_next_pn(PacketType::OneRTT);

        HandshakeDoneFrame hdf;
        std::string one_rtt_payload;
        serialize_frame(hdf, one_rtt_payload);

        if (std::string one_rtt_packet; CryptoSuite::protect_packet(*keys, one_rtt_hdr, one_rtt_payload, one_rtt_packet)) {
            track_sent_packet(PacketType::OneRTT, one_rtt_hdr.packet_number, one_rtt_packet.size(), {hdf});
            pending_outbound_datagrams_.push_back(std::move(one_rtt_packet));
            wavex::log::info("[QUIC] HANDSHAKE_DONE sent on 1-RTT (keys_valid={})", one_rtt_keys_local_.valid);
        }
    }

    void QuicConnection::initiate_key_update() {
        std::lock_guard lock(mtx_);
        if (!one_rtt_keys_local_.valid) return;
        if (CryptoSuite::update_keys(one_rtt_keys_local_)) {
            local_key_phase_ ^= 1;
            one_rtt_keys_local_.key_phase = local_key_phase_;
            wavex::log::info("[QUIC] Local endpoint initiated Key Update to phase {}", local_key_phase_);
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
        if (const auto it = streams_.find(stream_id); it != streams_.end()) return it->second;

        auto stream = std::make_shared<QuicStream>(shared_from_this(), stream_id, executor_);
        streams_[stream_id] = stream;
        return stream;
    }

    void QuicConnection::close_stream(const uint64_t stream_id) {
        std::shared_ptr<QuicStream> stream_to_close; {
            std::lock_guard lock(mtx_);
            if (const auto it = streams_.find(stream_id); it != streams_.end()) {
                stream_to_close = it->second;
                streams_.erase(it);
                // Send-side state (queue, offset, pending FIN) is intentionally kept: bytes that flow
                // control or congestion has not let out yet would otherwise be silently truncated.
                // flush_stream_send_queues() drops it once everything has been packetized.
                flush_stream_send_queues();
            }
        }
        if (stream_to_close) {
            stream_to_close->close();
        }
    }

    asio::awaitable<std::shared_ptr<QuicStream> > QuicConnection::accept_stream() { {
            std::lock_guard lock(mtx_);
            if (!accepted_streams_.empty()) {
                auto stream = accepted_streams_.front();
                accepted_streams_.pop_front();
                co_return stream;
            }
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
            stream_send_queues_[stream_id].append(data);
            if (fin) {
                stream_send_fin_[stream_id] = true;
            }
            flush_stream_send_queues();
            cb = on_outbound_;
        }
        if (cb) cb();
    }

    void QuicConnection::flush_stream_send_queues() {
        if (state_ == ConnectionState::Closed) return;

        // STREAM frames are only valid in 1-RTT (or 0-RTT) packets. Never fall back to Initial keys on a
        // real TLS connection: data queued before the handshake completes waits here instead.
        const ProtectionKeys *keys = one_rtt_send_keys();
        if (!keys) return;

        // MTU packetization: safe stream frame payload fitting inside typical network MTU (RFC 9000 §14.1)
        // ReSharper disable once CppTooWideScopeInitStatement
        constexpr std::size_t kMaxStreamFramePayload = 1150;

        for (auto q_it = stream_send_queues_.begin(); q_it != stream_send_queues_.end();) {
            const uint64_t sid = q_it->first;
            auto &queue = q_it->second;
            bool &fin_pending = stream_send_fin_[sid];

            while (!queue.empty() || fin_pending) {
                // Flow control limits (A4)
                const uint64_t conn_credit = (max_data_ > data_sent_) ? (max_data_ - data_sent_) : 0;
                uint64_t &stream_sent = stream_data_sent_[sid];
                const uint64_t stream_credit = (max_stream_data_ > stream_sent) ? (max_stream_data_ - stream_sent) : 0;

                if (!queue.empty() && (conn_credit == 0 || stream_credit == 0)) {
                    wavex::log::debug("[QUIC] Flow control credit blocked on sid={} (conn_credit={}, stream_credit={})",
                                      sid, conn_credit, stream_credit);
                    break;
                }

                std::size_t chunk_len = queue.size();
                if (chunk_len > kMaxStreamFramePayload) {
                    chunk_len = kMaxStreamFramePayload;
                }
                if (chunk_len > conn_credit) {
                    chunk_len = static_cast<std::size_t>(conn_credit);
                }
                if (chunk_len > stream_credit) {
                    chunk_len = static_cast<std::size_t>(stream_credit);
                }

                if (chunk_len == 0 && !queue.empty()) {
                    break;
                }

                const bool is_last = (chunk_len == queue.size());
                const bool chunk_fin = is_last && fin_pending;

                StreamFrame sf;
                sf.stream_id = sid;
                sf.data = queue.peek(chunk_len);
                sf.fin = chunk_fin;
                sf.has_length = true;

                uint64_t &cur_offset = stream_send_offsets_[sid];
                sf.offset = cur_offset;
                sf.has_offset = (cur_offset > 0);

                std::string payload;
                serialize_frame(sf, payload);

                PacketHeader hdr;
                hdr.is_long = false;
                hdr.type = PacketType::OneRTT;
                hdr.key_phase = (local_key_phase_ != 0);
                hdr.dcid = peer_cid_;
                hdr.packet_number = allocate_next_pn(PacketType::OneRTT);

                std::string packet;
                if (!CryptoSuite::protect_packet(*keys, hdr, payload, packet)) {
                    // Keep the bytes queued rather than silently dropping them.
                    wavex::log::error("[QUIC] flush_stream_send_queues: protect_packet failed for sid={}", sid);
                    break;
                }
                sf.owned_data = std::make_shared<const std::string>(sf.data);
                sf.data = *sf.owned_data;
                track_sent_packet(PacketType::OneRTT, hdr.packet_number, packet.size(), {sf});
                pending_outbound_datagrams_.push_back(std::move(packet));

                cur_offset += chunk_len;
                data_sent_ += chunk_len;
                stream_sent += chunk_len;
                queue.consume(chunk_len);
                if (chunk_fin) {
                    fin_pending = false;
                }

                if (chunk_len == 0 && chunk_fin) {
                    break;
                }
            }

            // A stream that close_stream() already removed keeps its send state only until everything
            // queued (including FIN) has been handed to the packetizer.
            if (queue.empty() && !fin_pending && !streams_.contains(sid)) {
                stream_send_fin_.erase(sid);
                stream_send_offsets_.erase(sid);
                stream_data_sent_.erase(sid);
                q_it = stream_send_queues_.erase(q_it);
            } else {
                ++q_it;
            }
        }
    }

    uint64_t QuicConnection::open_unidirectional_stream() {
        const auto stream = create_stream(false);
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
        if (http3_session_initialized_) return;
        http3_session_initialized_ = true;

        // 1. Establish HTTP/3 Control Stream (Stream Type 0x00)
        const uint64_t control_stream_id = open_unidirectional_stream();
        std::string control_stream_data;

        // Prepend Unidirectional Stream Type (0x00)
        VarInt::encode(0x00, control_stream_data);

        // Construct SETTINGS Frame (Type 0x04)
        std::string settings_payload;

        // SETTINGS_MAX_FIELD_SECTION_SIZE (Identifier 0x06)
        VarInt::encode(0x06, settings_payload);
        VarInt::encode(max_field_section_size_, settings_payload);

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

        flush_stream_send_queues();

        wavex::log::info("[QUIC] HTTP/3 session initialized and flushed: control_stream={}, qpack_enc={}, qpack_dec={}",
                         control_stream_id, qpack_enc_id, qpack_dec_id);
    }

    std::vector<std::string> QuicConnection::poll_outgoing_datagrams() {
        std::lock_guard lock(mtx_);
        std::vector<std::string> datagrams;
        std::string current_dgram;
        bool current_dgram_ends_with_short = false;

        const std::size_t max_dgram_limit = static_cast<std::size_t>(max_datagram_size_);

        while (!pending_outbound_datagrams_.empty()) {
            std::string pkt = std::move(pending_outbound_datagrams_.front());
            pending_outbound_datagrams_.pop_front();
            if (pkt.empty()) continue;

            const auto first_byte = static_cast<uint8_t>(pkt[0]);
            const bool is_long = (first_byte & 0x80) != 0;

            // RFC 9000 §12.2 Coalescing rules:
            // 1. Packets must not exceed maximum datagram size (default 1200 bytes).
            // 2. Only long-header packets can be followed by another packet in the same datagram
            //    (long headers contain an explicit Length field).
            // 3. Short-header packets lack a Length field, so senders MUST NOT coalesce multiple short-header
            //    packets into a single datagram, and a short-header packet can only be the last packet in a datagram.
            if (!current_dgram.empty() && !current_dgram_ends_with_short &&
                (current_dgram.size() + pkt.size() <= max_dgram_limit)) {
                current_dgram.append(pkt);
                if (!is_long) {
                    current_dgram_ends_with_short = true;
                }
            } else {
                if (!current_dgram.empty()) {
                    datagrams.push_back(std::move(current_dgram));
                    current_dgram.clear();
                    current_dgram_ends_with_short = false;
                }

                current_dgram = std::move(pkt);
                current_dgram_ends_with_short = !is_long;
            }
        }

        if (!current_dgram.empty()) {
            datagrams.push_back(std::move(current_dgram));
        }

        // RFC 9000 §8.1: until the client's address is validated the server may send at most three
        // times the bytes it has received. This covers every datagram (the TLS flight with the
        // certificate chain is the main amplification vector), not just STREAM data. Datagrams over
        // budget are held back and released as more client bytes arrive or the address validates.
        if (is_server_ && tls_ && tls_->initialized) {
            std::vector<std::string> ready;
            ready.reserve(amplification_held_datagrams_.size() + datagrams.size());
            for (auto &d: amplification_held_datagrams_) ready.push_back(std::move(d));
            amplification_held_datagrams_.clear();
            for (auto &d: datagrams) ready.push_back(std::move(d));

            datagrams.clear();
            for (auto &d: ready) {
                if (!peer_address_validated_ &&
                    (!amplification_held_datagrams_.empty() ||
                     cumulative_bytes_sent_ + d.size() > 3 * cumulative_bytes_received_)) {
                    amplification_held_datagrams_.push_back(std::move(d));
                    continue;
                }
                cumulative_bytes_sent_ += d.size();
                datagrams.push_back(std::move(d));
            }
            if (!amplification_held_datagrams_.empty()) {
                wavex::log::debug("[QUIC] Anti-amplification limit: holding {} datagram(s) (sent={}, recv={})",
                                  amplification_held_datagrams_.size(), cumulative_bytes_sent_,
                                  cumulative_bytes_received_);
            }
        } else {
            for (const auto &d: datagrams) cumulative_bytes_sent_ += d.size();
        }

        return datagrams;
    }

    const ProtectionKeys *QuicConnection::one_rtt_send_keys() const noexcept {
        if (one_rtt_keys_local_.valid) return &one_rtt_keys_local_;
        // Mock / non-TLS unit-test mode only. On a TLS connection a short-header packet protected with
        // Initial keys is readable by anyone and is rejected by every conforming peer.
        if (!tls_ || !tls_->initialized) return &initial_keys_local_;
        return nullptr;
    }

    bool QuicConnection::frame_allowed_in(const Frame &frame, const PacketType type) noexcept {
        if (type == PacketType::OneRTT) return true;
        if (type == PacketType::ZeroRTT) {
            // RFC 9000 Table 3: no ACK, CRYPTO, NEW_TOKEN or HANDSHAKE_DONE in 0-RTT.
            return !std::holds_alternative<AckFrame>(frame) &&
                   !std::holds_alternative<CryptoFrame>(frame) &&
                   !std::holds_alternative<NewTokenFrame>(frame) &&
                   !std::holds_alternative<HandshakeDoneFrame>(frame);
        }
        // Initial / Handshake ("IH" in RFC 9000 Table 3)
        if (std::holds_alternative<PaddingFrame>(frame) ||
            std::holds_alternative<PingFrame>(frame) ||
            std::holds_alternative<AckFrame>(frame) ||
            std::holds_alternative<CryptoFrame>(frame)) {
            return true;
        }
        if (const auto *ccf = std::get_if<ConnectionCloseFrame>(&frame)) {
            return !ccf->is_application; // only the transport variant (0x1c)
        }
        return false;
    }

    void QuicConnection::close(const TransportError err, const std::string_view reason) {
        terminate(true, err, reason);
    }

    void QuicConnection::terminate(const bool send_close, const TransportError err, const std::string_view reason) {
        OutboundCallback cb;
        ClosedCallback closed_cb;
        ConnectionId lcid, pcid, orig_dcid;
        std::vector<std::shared_ptr<QuicStream> > open_streams; {
            std::lock_guard lock(mtx_);
            if (state_ == ConnectionState::Closed) return;
            state_ = ConnectionState::Closed;

            if (loss_detection_timer_) {
                asio::error_code ec;
                loss_detection_timer_->cancel(ec);
            }
            if (idle_timer_) {
                asio::error_code ec;
                idle_timer_->cancel(ec);
            }

            if (send_close) {
                ConnectionCloseFrame ccf;
                ccf.error_code = static_cast<uint64_t>(err);
                // reason_phrase is a string_view; `reason` outlives this function, a temporary std::string would not.
                ccf.reason_phrase = reason;

                std::string payload;
                serialize_frame(ccf, payload);

                // Send CONNECTION_CLOSE at the highest level the peer can currently read
                // (RFC 9000 §10.2.3): 1-RTT once available, otherwise Handshake, otherwise Initial.
                PacketHeader hdr;
                const ProtectionKeys *keys = one_rtt_send_keys();
                if (keys) {
                    hdr.is_long = false;
                    hdr.type = PacketType::OneRTT;
                    hdr.key_phase = (local_key_phase_ != 0);
                } else {
                    hdr.is_long = true;
                    hdr.version = version_;
                    hdr.scid = local_cid_;
                    if (handshake_keys_local_.valid) {
                        hdr.type = PacketType::Handshake;
                        keys = &handshake_keys_local_;
                    } else {
                        hdr.type = PacketType::Initial;
                        keys = &initial_keys_local_;
                    }
                }
                hdr.dcid = peer_cid_;
                hdr.packet_number = allocate_next_pn(hdr.type);
                if (!is_server_ && hdr.type == PacketType::Initial) {
                    pad_client_initial(hdr, payload);
                }

                std::string packet;
                if (keys && keys->valid && CryptoSuite::protect_packet(*keys, hdr, payload, packet)) {
                    pending_outbound_datagrams_.push_back(std::move(packet));
                }
            }

            open_streams.reserve(streams_.size());
            for (auto &s: streams_ | std::views::values) {
                if (s) open_streams.push_back(s);
            }
            streams_.clear();
            stream_send_offsets_.clear();
            stream_data_sent_.clear();
            stream_send_queues_.clear();
            stream_send_fin_.clear();

            cb = on_outbound_;
            closed_cb = on_closed_;
            lcid = local_cid_;
            pcid = peer_cid_;
            orig_dcid = original_dcid_;
        }
        for (auto &s: open_streams) {
            s->close();
        }
        if (cb && send_close) cb();
        if (closed_cb) closed_cb(lcid, pcid, orig_dcid);
    }

    void QuicConnection::set_tls_credentials(std::string cert_file, std::string key_file) {
        std::error_code ec;
        if (!cert_file.empty() && !std::filesystem::exists(cert_file, ec)) {
            wavex::log::error("[QuicConnection] TLS certificate file not found: '{}'", cert_file);
            throw std::runtime_error("QuicConnection::set_tls_credentials: Certificate file not found: '" + cert_file + "'");
        }
        if (!key_file.empty() && !std::filesystem::exists(key_file, ec)) {
            wavex::log::error("[QuicConnection] TLS private key file not found: '{}'", key_file);
            throw std::runtime_error("QuicConnection::set_tls_credentials: Private key file not found: '" + key_file + "'");
        }
        std::scoped_lock lock(mtx_);
        tls_cert_file_ = std::move(cert_file);
        tls_key_file_ = std::move(key_file);
    }
} // namespace wavex::network::quic

#endif // WAVEX_HAS_SSL
