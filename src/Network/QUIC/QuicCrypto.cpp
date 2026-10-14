// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * @file QuicCrypto.cpp
 * @brief Implementation of RFC 9001 QUIC-TLS cryptography.
 */

#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL

#include <wavex/Network/QUIC/QuicCrypto.hpp>
#include <wavex/Base/Logger.hpp>

#ifdef __MINGW32__
#include <cstring>
#endif

#if defined(min)
#undef min
#endif
#if defined(max)
#undef max
#endif

#include <algorithm>

#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/crypto.h>

namespace wavex::network::quic {
    // RFC 9001 §5.2 Initial Salt for QUIC Version 1
    static constexpr uint8_t INITIAL_SALT_V1[20] = {
        0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
        0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a
    };

    // RFC 9000 §A.3 Packet Number Reconstruction
    static uint64_t full_pn(const uint64_t truncated, const uint8_t pn_len, const uint64_t largest_pn) noexcept {
        const uint64_t pn_nbits = static_cast<uint64_t>(pn_len) * 8;
        const uint64_t win = 1ULL << pn_nbits;
        const uint64_t half = win / 2;
        const uint64_t expected = largest_pn + 1;
        uint64_t candidate = (expected & ~(win - 1)) | truncated;
        if (candidate + half <= expected) {
            candidate += win;
        } else if (candidate > expected + half && candidate >= win) {
            candidate -= win;
        }
        return candidate;
    }

#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
    static bool hkdf_expand_label(
        const uint8_t *secret, const std::size_t secret_len,
        const std::string_view label,
        uint8_t *out, const std::size_t out_len) noexcept {
        // Construct HkdfLabel: Length (2 bytes), "tls13 " + Label (1 byte len + chars), Context (0 len)
        std::string hkdf_label;
        hkdf_label.push_back(static_cast<char>((out_len >> 8) & 0xff));
        hkdf_label.push_back(static_cast<char>(out_len & 0xff));

        const std::string full_label = "tls13 " + std::string(label);
        hkdf_label.push_back(static_cast<char>(full_label.size()));
        hkdf_label.append(full_label);
        hkdf_label.push_back(0); // empty context

        // Multi-block RFC 5869 HKDF-Expand loop
        std::size_t pos = 0;
        uint8_t counter = 1;
        std::string prev_t;

        while (pos < out_len) {
            std::string info;
            info.reserve(prev_t.size() + hkdf_label.size() + 1);
            info.append(prev_t);
            info.append(hkdf_label);
            info.push_back(static_cast<char>(counter++));

            unsigned int block_len = 0;
            unsigned char block[EVP_MAX_MD_SIZE];
            if (!HMAC(EVP_sha256(), secret, static_cast<int>(secret_len),
                      reinterpret_cast<const unsigned char *>(info.data()), info.size(),
                      block, &block_len)) {
                return false;
            }

            const std::size_t chunk = (std::min)(static_cast<std::size_t>(block_len), out_len - pos);
            std::memcpy(out + pos, block, chunk);
            pos += chunk;
            prev_t.assign(reinterpret_cast<const char *>(block), block_len);
        }
        return true;
    }
#endif

    void ProtectionKeys::cleanse() noexcept {
#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
        if (enc_ctx) {
            EVP_CIPHER_CTX_free(enc_ctx);
            enc_ctx = nullptr;
        }
        if (dec_ctx) {
            EVP_CIPHER_CTX_free(dec_ctx);
            dec_ctx = nullptr;
        }
        if (hp_ctx) {
            EVP_CIPHER_CTX_free(hp_ctx);
            hp_ctx = nullptr;
        }
        OPENSSL_cleanse(secret.data(), secret.size());
        OPENSSL_cleanse(key.data(), key.size());
        OPENSSL_cleanse(hp.data(), hp.size());
        OPENSSL_cleanse(iv.data(), iv.size());
#else
        std::fill(secret.begin(), secret.end(), 0);
        std::fill(key.begin(), key.end(), 0);
        std::fill(hp.begin(), hp.end(), 0);
        std::fill(iv.begin(), iv.end(), 0);
#endif
        key_phase = 0;
        valid = false;
    }

    ProtectionKeys::~ProtectionKeys() noexcept {
        cleanse();
    }

    ProtectionKeys::ProtectionKeys(const ProtectionKeys &other) noexcept
        :
#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
          enc_ctx(nullptr),
          dec_ctx(nullptr),
          hp_ctx(nullptr),
#endif
          secret(other.secret),
          key(other.key),
          hp(other.hp),
          iv(other.iv),
          key_phase(other.key_phase),
          valid(other.valid) {}

    ProtectionKeys &ProtectionKeys::operator=(const ProtectionKeys &other) noexcept {
        if (this != &other) {
            cleanse();
            secret = other.secret;
            key = other.key;
            hp = other.hp;
            iv = other.iv;
            key_phase = other.key_phase;
            valid = other.valid;
        }
        return *this;
    }

    ProtectionKeys::ProtectionKeys(ProtectionKeys &&other) noexcept
        :
#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
          enc_ctx(other.enc_ctx),
          dec_ctx(other.dec_ctx),
          hp_ctx(other.hp_ctx),
#endif
          secret(other.secret),
          key(other.key),
          hp(other.hp),
          iv(other.iv),
          key_phase(other.key_phase),
          valid(other.valid) {
#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
        other.enc_ctx = nullptr;
        other.dec_ctx = nullptr;
        other.hp_ctx = nullptr;
#endif
        other.cleanse();
    }

    ProtectionKeys &ProtectionKeys::operator=(ProtectionKeys &&other) noexcept {
        if (this != &other) {
            cleanse();
#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
            enc_ctx = other.enc_ctx;
            dec_ctx = other.dec_ctx;
            hp_ctx = other.hp_ctx;
            other.enc_ctx = nullptr;
            other.dec_ctx = nullptr;
            other.hp_ctx = nullptr;
#endif
            secret = other.secret;
            key = other.key;
            hp = other.hp;
            iv = other.iv;
            key_phase = other.key_phase;
            valid = other.valid;
            other.cleanse();
        }
        return *this;
    }

    bool CryptoSuite::derive_initial_secrets(
        const ConnectionId &client_dcid,
        ProtectionKeys &client_keys,
        ProtectionKeys &server_keys) noexcept {
#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
        // 1. Initial Secret = HKDF-Extract(salt=INITIAL_SALT_V1, ikm=client_dcid)
        uint8_t initial_secret[32];
        unsigned int is_len = 0;
        if (!HMAC(EVP_sha256(), INITIAL_SALT_V1, sizeof(INITIAL_SALT_V1),
                  client_dcid.data(), client_dcid.length(),
                  initial_secret, &is_len)) {
            return false;
        }

        bool ok = true;
        // 2. Client Initial Secret = HKDF-Expand-Label(initial_secret, "client in", "", 32)
        if (!hkdf_expand_label(initial_secret, 32, "client in", client_keys.secret.data(), 32)) ok = false;
        // 3. Server Initial Secret = HKDF-Expand-Label(initial_secret, "server in", "", 32)
        if (ok && !hkdf_expand_label(initial_secret, 32, "server in", server_keys.secret.data(), 32)) ok = false;

        // Securely wipe intermediate initial_secret from stack
        OPENSSL_cleanse(initial_secret, sizeof(initial_secret));

        if (!ok) return false;

        // 4. Expand keys for client and server
        if (!expand_quic_keys(client_keys.secret.data(), 32, client_keys)) return false;
        if (!expand_quic_keys(server_keys.secret.data(), 32, server_keys)) return false;

        client_keys.valid = true;
        server_keys.valid = true;
        return true;
#else
        (void) client_dcid;
        client_keys.valid = true;
        server_keys.valid = true;
        return true;
#endif
    }

    bool CryptoSuite::expand_quic_keys(
        const uint8_t *secret, const std::size_t secret_len,
        ProtectionKeys &keys) noexcept {
#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
        if (keys.enc_ctx) {
            EVP_CIPHER_CTX_free(keys.enc_ctx);
            keys.enc_ctx = nullptr;
        }
        if (keys.dec_ctx) {
            EVP_CIPHER_CTX_free(keys.dec_ctx);
            keys.dec_ctx = nullptr;
        }
        if (keys.hp_ctx) {
            EVP_CIPHER_CTX_free(keys.hp_ctx);
            keys.hp_ctx = nullptr;
        }
        std::memcpy(keys.secret.data(), secret, (std::min)(secret_len, keys.secret.size()));
        // Key: HKDF-Expand-Label(secret, "quic key", "", 16)
        if (!hkdf_expand_label(secret, secret_len, "quic key", keys.key.data(), 16)) return false;
        // IV: HKDF-Expand-Label(secret, "quic iv", "", 12)
        if (!hkdf_expand_label(secret, secret_len, "quic iv", keys.iv.data(), 12)) return false;
        // HP: HKDF-Expand-Label(secret, "quic hp", "", 16)
        if (!hkdf_expand_label(secret, secret_len, "quic hp", keys.hp.data(), 16)) return false;
        keys.valid = true;
        return true;
#else
        (void) secret; (void) secret_len;
        keys.valid = true;
        return true;
#endif
    }

    bool CryptoSuite::update_keys(ProtectionKeys &keys) noexcept {
#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
        if (!keys.valid) return false;

        // RFC 9001 §6.1:
        // secret_<i+1> = HKDF-Expand-Label(secret_<i>, "quic ku", "", 32)
        std::array<uint8_t, 32> next_secret{};
        if (!hkdf_expand_label(keys.secret.data(), keys.secret.size(), "quic ku",
                               next_secret.data(), next_secret.size())) {
            return false;
        }

        // key_<i+1> = HKDF-Expand-Label(secret_<i+1>, "quic key", "", 16)
        std::array<uint8_t, 16> next_key{};
        if (!hkdf_expand_label(next_secret.data(), next_secret.size(), "quic key",
                               next_key.data(), next_key.size())) {
            OPENSSL_cleanse(next_secret.data(), next_secret.size());
            return false;
        }

        // iv_<i+1> = HKDF-Expand-Label(secret_<i+1>, "quic iv", "", 12)
        std::array<uint8_t, 12> next_iv{};
        if (!hkdf_expand_label(next_secret.data(), next_secret.size(), "quic iv",
                               next_iv.data(), next_iv.size())) {
            OPENSSL_cleanse(next_secret.data(), next_secret.size());
            OPENSSL_cleanse(next_key.data(), next_key.size());
            return false;
        }

        // Header protection keys (hp) are NOT updated across key updates (RFC 9001 §6.1)
        if (keys.enc_ctx) {
            EVP_CIPHER_CTX_free(keys.enc_ctx);
            keys.enc_ctx = nullptr;
        }
        if (keys.dec_ctx) {
            EVP_CIPHER_CTX_free(keys.dec_ctx);
            keys.dec_ctx = nullptr;
        }

        // Cleanse existing keys before overwriting
        OPENSSL_cleanse(keys.secret.data(), keys.secret.size());
        OPENSSL_cleanse(keys.key.data(), keys.key.size());
        OPENSSL_cleanse(keys.iv.data(), keys.iv.size());

        keys.secret = next_secret;
        keys.key = next_key;
        keys.iv = next_iv;

        // Cleanse stack temporaries
        OPENSSL_cleanse(next_secret.data(), next_secret.size());
        OPENSSL_cleanse(next_key.data(), next_key.size());
        OPENSSL_cleanse(next_iv.data(), next_iv.size());

        keys.key_phase ^= 1;
        return true;
#else
        keys.key_phase ^= 1;
        return true;
#endif
    }

    bool CryptoSuite::protect_packet(
        const ProtectionKeys &keys,
        PacketHeader &hdr,
        const std::string_view plaintext,
        std::string &ciphertext_out) noexcept {
        if (!keys.valid) return false;
        if (hdr.packet_number_len == 0) {
            hdr.packet_number_len = 4;
        }
        if (hdr.is_long) {
            hdr.length = plaintext.size() + 16 + hdr.packet_number_len; // + 16 auth tag
        }
        ciphertext_out.clear();
        pack_packet_header(hdr, ciphertext_out);
        const std::size_t header_len = ciphertext_out.size();
        const std::size_t pn_offset = header_len - hdr.packet_number_len;

#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
        // Calculate Nonce = IV ^ PacketNumber
        std::array<uint8_t, 12> nonce = keys.iv;
        for (int i = 0; i < 8; ++i) {
            nonce[11 - i] ^= static_cast<uint8_t>((hdr.packet_number >> (i * 8)) & 0xff);
        }

        if (!keys.enc_ctx) {
            keys.enc_ctx = EVP_CIPHER_CTX_new();
            if (!keys.enc_ctx) return false;
        } else {
            EVP_CIPHER_CTX_reset(keys.enc_ctx);
        }

        ciphertext_out.resize(header_len + plaintext.size() + 16);
        auto *enc_dest = reinterpret_cast<uint8_t *>(ciphertext_out.data() + header_len);

        bool ok = true;
        int out_len = 0;

        if (EVP_EncryptInit_ex(keys.enc_ctx, EVP_aes_128_gcm(), nullptr, keys.key.data(), nonce.data()) != 1) ok = false;
        if (ok && EVP_EncryptUpdate(keys.enc_ctx, nullptr, &out_len, reinterpret_cast<const uint8_t *>(ciphertext_out.data()),
                                    static_cast<int>(header_len)) != 1)
            ok = false;
        if (ok && EVP_EncryptUpdate(keys.enc_ctx, enc_dest, &out_len,
                                    reinterpret_cast<const uint8_t *>(plaintext.data()),
                                    static_cast<int>(plaintext.size())) != 1)
            ok = false;
        int final_len = 0;
        if (ok && EVP_EncryptFinal_ex(keys.enc_ctx, enc_dest + out_len, &final_len) != 1) ok = false;
        if (ok && EVP_CIPHER_CTX_ctrl(keys.enc_ctx, EVP_CTRL_GCM_GET_TAG, 16, enc_dest + plaintext.size()) != 1)
            ok = false;

        if (!ok) {
            ciphertext_out.clear();
            return false;
        }

        // Apply RFC 9001 §5.4 Header Protection
        if (const std::size_t sample_offset = pn_offset + 4; ciphertext_out.size() >= sample_offset + 16) {
            const auto *sample = reinterpret_cast<const uint8_t *>(ciphertext_out.data() + sample_offset);
            uint8_t mask[16] = {0};

            if (!keys.hp_ctx) {
                keys.hp_ctx = EVP_CIPHER_CTX_new();
            }
            if (keys.hp_ctx) {
                EVP_CIPHER_CTX_reset(keys.hp_ctx);
                int hp_len = 0;
                if (EVP_EncryptInit_ex(keys.hp_ctx, EVP_aes_128_ecb(), nullptr, keys.hp.data(), nullptr) == 1 &&
                    EVP_CIPHER_CTX_set_padding(keys.hp_ctx, 0) == 1 &&
                    EVP_EncryptUpdate(keys.hp_ctx, mask, &hp_len, sample, 16) == 1) {
                    // Mask first byte
                    if (hdr.is_long) {
                        ciphertext_out[0] ^= static_cast<char>(mask[0] & 0x0f);
                    } else {
                        ciphertext_out[0] ^= static_cast<char>(mask[0] & 0x1f);
                    }

                    // Mask packet number bytes
                    for (std::size_t i = 0; i < hdr.packet_number_len; ++i) {
                        ciphertext_out[pn_offset + i] ^= static_cast<char>(mask[1 + i]);
                    }
                }
            }
        }
        return true;
#else
        // Passthrough with 16 zero tag bytes for non-SSL mock builds
        ciphertext_out.append(plaintext);
        ciphertext_out.append(16, '\0');
        return true;
#endif
    }

    bool CryptoSuite::unprotect_packet(
        ProtectionKeys &keys,
        PacketHeader &hdr,
        const std::string_view packet_bytes,
        std::string &plaintext_out,
        const uint64_t largest_pn,
        const std::size_t expected_dcid_len) noexcept {
        if (packet_bytes.empty()) return false;

        std::size_t hdr_len = 0;
        if (!unpack_packet_header(packet_bytes, hdr, hdr_len, expected_dcid_len)) {
            wavex::log::debug("[QUIC] unprotect_packet: unpack_packet_header failed (bytes={})", packet_bytes.size());
            return false;
        }

        const std::size_t pn_offset = hdr.pn_offset;

#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
        // Step 1: Remove Header Protection (RFC 9001 §5.4)
        const std::size_t sample_offset = pn_offset + 4;
        if (packet_bytes.size() < sample_offset + 16) {
            wavex::log::debug("[QUIC] unprotect_packet: packet too small for sample (size={}, needed={})",
                              packet_bytes.size(), sample_offset + 16);
            return false;
        }

        const auto *sample = reinterpret_cast<const uint8_t *>(packet_bytes.data() + sample_offset);
        uint8_t mask[16] = {0};

        if (!keys.hp_ctx) {
            keys.hp_ctx = EVP_CIPHER_CTX_new();
            if (!keys.hp_ctx) return false;
        } else {
            EVP_CIPHER_CTX_reset(keys.hp_ctx);
        }

        int hp_len = 0;
        const bool hp_ok = (EVP_EncryptInit_ex(keys.hp_ctx, EVP_aes_128_ecb(), nullptr, keys.hp.data(), nullptr) == 1 &&
                            EVP_CIPHER_CTX_set_padding(keys.hp_ctx, 0) == 1 &&
                            EVP_EncryptUpdate(keys.hp_ctx, mask, &hp_len, sample, 16) == 1);
        if (!hp_ok) {
            wavex::log::debug("[QUIC] unprotect_packet: HP cipher failed");
            return false;
        }

        // Unmask first byte
        uint8_t first_byte = static_cast<uint8_t>(packet_bytes[0]);
        if (hdr.is_long) {
            first_byte ^= (mask[0] & 0x0f);
        } else {
            first_byte ^= (mask[0] & 0x1f);
            hdr.key_phase = (first_byte & 0x04) != 0;
        }
        const auto pn_len = static_cast<uint8_t>((first_byte & 0x03) + 1);
        hdr.packet_number_len = pn_len;

        if (packet_bytes.size() < pn_offset + pn_len + 16) {
            wavex::log::debug("[QUIC] unprotect_packet: packet too small for PN and tag (size={}, needed={})",
                              packet_bytes.size(), pn_offset + pn_len + 16);
            return false;
        }

        // Unmask packet number
        uint64_t truncated_pn = 0;
        for (std::size_t i = 0; i < pn_len; ++i) {
            const uint8_t b = static_cast<uint8_t>(packet_bytes[pn_offset + i]) ^ mask[1 + i];
            truncated_pn = (truncated_pn << 8) | b;
        }

        // Reconstruct full 64-bit packet number (RFC 9000 §A.3)
        const uint64_t full_packet_num = full_pn(truncated_pn, pn_len, largest_pn);
        hdr.packet_number = full_packet_num;

        // Step 2: Reconstruct the UNMASKED header for AAD
        const std::size_t real_hdr_len = pn_offset + pn_len;
        char hdr_buf_storage[128];
        char *unmasked_hdr_ptr = hdr_buf_storage;
        std::string unmasked_hdr_str;
        if (real_hdr_len > sizeof(hdr_buf_storage)) {
            unmasked_hdr_str.assign(packet_bytes.substr(0, real_hdr_len));
            unmasked_hdr_ptr = unmasked_hdr_str.data();
        } else {
            std::memcpy(unmasked_hdr_ptr, packet_bytes.data(), real_hdr_len);
        }
        unmasked_hdr_ptr[0] = static_cast<char>(first_byte);
        for (std::size_t i = 0; i < pn_len; ++i) {
            unmasked_hdr_ptr[pn_offset + i] = static_cast<char>(
                static_cast<uint8_t>(packet_bytes[pn_offset + i]) ^ mask[1 + i]);
        }

        // Step 3: Payload starts at real_hdr_len
        std::size_t total_packet_len = packet_bytes.size();
        if (hdr.is_long && hdr.length > 0) {
            if (const std::size_t expected_long_len = pn_offset + static_cast<std::size_t>(hdr.length);
                expected_long_len <= packet_bytes.size()) {
                total_packet_len = expected_long_len;
            }
        }

        if (total_packet_len < real_hdr_len + 16) {
            wavex::log::debug("[QUIC] unprotect_packet: total_packet_len < real_hdr_len + 16 (total={}, hdr={})",
                              total_packet_len, real_hdr_len);
            return false;
        }
        const std::string_view payload = packet_bytes.substr(real_hdr_len, total_packet_len - real_hdr_len);

        // Step 4: Handle RFC 9001 §6 Key Update if Key Phase bit has changed
        ProtectionKeys candidate_keys;
        bool key_updated = false;
        if (!hdr.is_long && hdr.key_phase != (keys.key_phase != 0)) {
            candidate_keys = keys;
            if (!update_keys(candidate_keys)) {
                return false;
            }
            key_updated = true;
        }

        const ProtectionKeys &effective_keys = key_updated ? candidate_keys : keys;

        // Step 5: Calculate Nonce = IV ^ FullPacketNumber (RFC 9001 §5.3)
        std::array<uint8_t, 12> nonce = effective_keys.iv;
        for (int i = 0; i < 8; ++i) {
            nonce[11 - i] ^= static_cast<uint8_t>((full_packet_num >> (i * 8)) & 0xff);
        }

        const std::size_t cipher_len = payload.size() - 16;
        const auto *cipher_data = reinterpret_cast<const uint8_t *>(payload.data());
        const auto *tag_data = cipher_data + cipher_len;

        if (!effective_keys.dec_ctx) {
            effective_keys.dec_ctx = EVP_CIPHER_CTX_new();
            if (!effective_keys.dec_ctx) return false;
        } else {
            EVP_CIPHER_CTX_reset(effective_keys.dec_ctx);
        }

        plaintext_out.resize(cipher_len);
        auto *plain_dest = reinterpret_cast<uint8_t *>(plaintext_out.data());
        int out_len = 0;
        bool ok = true;

        if (EVP_DecryptInit_ex(effective_keys.dec_ctx, EVP_aes_128_gcm(), nullptr, effective_keys.key.data(), nonce.data()) != 1) ok = false;
        if (ok && EVP_DecryptUpdate(effective_keys.dec_ctx, nullptr, &out_len, reinterpret_cast<const uint8_t *>(unmasked_hdr_ptr),
                                    static_cast<int>(real_hdr_len)) != 1)
            ok = false;
        if (ok && EVP_DecryptUpdate(effective_keys.dec_ctx, plain_dest, &out_len, cipher_data, static_cast<int>(cipher_len)) != 1)
            ok = false;
        if (ok && EVP_CIPHER_CTX_ctrl(effective_keys.dec_ctx, EVP_CTRL_GCM_SET_TAG, 16, const_cast<uint8_t *>(tag_data)) != 1) ok = false;
        int final_len = 0;
        if (ok && EVP_DecryptFinal_ex(effective_keys.dec_ctx, plain_dest + out_len, &final_len) <= 0) {
            wavex::log::debug("[QUIC] unprotect_packet: AEAD GCM tag verification failed (pn={}, type={})",
                              full_packet_num, static_cast<int>(hdr.type));
            ok = false;
        }

        if (!ok) {
            plaintext_out.clear();
            return false;
        }

        // Only commit updated keys if authentication tag verified successfully (RFC 9001 §6.2)
        if (key_updated) {
            keys = std::move(candidate_keys);
        }

        return true;
#else
        // Mock decode: strip 16 byte trailing tag
        if (hdr_len >= packet_bytes.size()) return false;
        const std::string_view payload = packet_bytes.substr(hdr_len);
        if (payload.size() < 16) return false;
        plaintext_out.assign(payload.data(), payload.size() - 16);
        return true;
#endif
    }
} // namespace wavex::network::quic

#endif // WAVEX_HAS_SSL
