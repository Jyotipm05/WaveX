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

#if defined(min)
#undef min
#endif
#if defined(max)
#undef max
#endif

#include <algorithm>
#include <vector>

#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/hmac.h>

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
        const uint8_t *secret, std::size_t secret_len,
        const std::string_view label,
        uint8_t *out, std::size_t out_len) noexcept {
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

        // 2. Client Initial Secret = HKDF-Expand-Label(initial_secret, "client in", "", 32)
        if (!hkdf_expand_label(initial_secret, 32, "client in", client_keys.secret.data(), 32)) return false;
        // 3. Server Initial Secret = HKDF-Expand-Label(initial_secret, "server in", "", 32)
        if (!hkdf_expand_label(initial_secret, 32, "server in", server_keys.secret.data(), 32)) return false;

        // 4. Expand keys for client and server
        if (!expand_quic_keys(client_keys.secret.data(), 32, client_keys)) return false;
        if (!expand_quic_keys(server_keys.secret.data(), 32, server_keys)) return false;

        client_keys.valid = true;
        server_keys.valid = true;
        return true;
#else
        (void)client_dcid;
        client_keys.valid = true;
        server_keys.valid = true;
        return true;
#endif
    }

    bool CryptoSuite::expand_quic_keys(
        const uint8_t *secret, const std::size_t secret_len,
        ProtectionKeys &keys) noexcept {
#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
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
        (void)secret; (void)secret_len;
        keys.valid = true;
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
        std::string header_bytes;
        pack_packet_header(hdr, header_bytes);
        const std::size_t pn_offset = header_bytes.size() - hdr.packet_number_len;

#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
        // Calculate Nonce = IV ^ PacketNumber
        std::array<uint8_t, 12> nonce = keys.iv;
        for (int i = 0; i < 8; ++i) {
            nonce[11 - i] ^= static_cast<uint8_t>((hdr.packet_number >> (i * 8)) & 0xff);
        }

        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx) return false;

        bool ok = true;
        int out_len = 0;
        std::vector<uint8_t> encrypted(plaintext.size() + 16);

        if (EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, keys.key.data(), nonce.data()) != 1) ok = false;
        if (ok && EVP_EncryptUpdate(ctx, nullptr, &out_len, reinterpret_cast<const uint8_t *>(header_bytes.data()),
                                    static_cast<int>(header_bytes.size())) != 1) ok = false;
        if (ok && EVP_EncryptUpdate(ctx, encrypted.data(), &out_len,
                                    reinterpret_cast<const uint8_t *>(plaintext.data()),
                                    static_cast<int>(plaintext.size())) != 1) ok = false;
        if (ok && EVP_EncryptFinal_ex(ctx, encrypted.data() + out_len, &out_len) != 1) ok = false;
        if (ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, encrypted.data() + plaintext.size()) != 1)
            ok = false;

        EVP_CIPHER_CTX_free(ctx);
        if (!ok) return false;

        ciphertext_out = header_bytes;
        ciphertext_out.append(reinterpret_cast<const char *>(encrypted.data()), encrypted.size());

        // Apply RFC 9001 §5.4 Header Protection
        const std::size_t sample_offset = pn_offset + 4;
        if (ciphertext_out.size() >= sample_offset + 16) {
            const auto *sample = reinterpret_cast<const uint8_t *>(ciphertext_out.data() + sample_offset);
            uint8_t mask[16] = {0};

            if (EVP_CIPHER_CTX *hp_ctx = EVP_CIPHER_CTX_new()) {
                int hp_len = 0;
                if (EVP_EncryptInit_ex(hp_ctx, EVP_aes_128_ecb(), nullptr, keys.hp.data(), nullptr) == 1 &&
                    EVP_CIPHER_CTX_set_padding(hp_ctx, 0) == 1 &&
                    EVP_EncryptUpdate(hp_ctx, mask, &hp_len, sample, 16) == 1) {
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
                EVP_CIPHER_CTX_free(hp_ctx);
            }
        }
        return true;
#else
        // Passthrough with 16 zero tag bytes for non-SSL mock builds
        ciphertext_out = header_bytes;
        ciphertext_out.append(plaintext);
        ciphertext_out.append(16, '\0');
        return true;
#endif
    }

    bool CryptoSuite::unprotect_packet(
        const ProtectionKeys &keys,
        PacketHeader &hdr,
        const std::string_view packet_bytes,
        std::string &plaintext_out,
        const uint64_t largest_pn,
        const std::size_t expected_dcid_len) noexcept {
        if (packet_bytes.empty()) return false;

        std::size_t hdr_len = 0;
        if (!unpack_packet_header(packet_bytes, hdr, hdr_len, expected_dcid_len)) {
            wavex::log::warn("[QUIC] unprotect_packet: unpack_packet_header failed (bytes={})", packet_bytes.size());
            return false;
        }

        const std::size_t pn_offset = hdr.pn_offset;

#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
        // Step 1: Remove Header Protection (RFC 9001 §5.4)
        const std::size_t sample_offset = pn_offset + 4;
        if (packet_bytes.size() < sample_offset + 16) {
            wavex::log::warn("[QUIC] unprotect_packet: packet too small for sample (size={}, needed={})",
                             packet_bytes.size(), sample_offset + 16);
            return false;
        }

        const auto *sample = reinterpret_cast<const uint8_t *>(packet_bytes.data() + sample_offset);
        uint8_t mask[16] = {0};

        EVP_CIPHER_CTX *hp_ctx = EVP_CIPHER_CTX_new();
        if (!hp_ctx) return false;

        int hp_len = 0;
        bool hp_ok = (EVP_EncryptInit_ex(hp_ctx, EVP_aes_128_ecb(), nullptr, keys.hp.data(), nullptr) == 1 &&
                      EVP_CIPHER_CTX_set_padding(hp_ctx, 0) == 1 &&
                      EVP_EncryptUpdate(hp_ctx, mask, &hp_len, sample, 16) == 1);
        EVP_CIPHER_CTX_free(hp_ctx);
        if (!hp_ok) {
            wavex::log::warn("[QUIC] unprotect_packet: HP cipher failed");
            return false;
        }

        // Unmask first byte
        uint8_t first_byte = static_cast<uint8_t>(packet_bytes[0]);
        if (hdr.is_long) {
            first_byte ^= (mask[0] & 0x0f);
        } else {
            first_byte ^= (mask[0] & 0x1f);
        }
        const auto pn_len = static_cast<uint8_t>((first_byte & 0x03) + 1);
        hdr.packet_number_len = pn_len;

        if (packet_bytes.size() < pn_offset + pn_len + 16) {
            wavex::log::warn("[QUIC] unprotect_packet: packet too small for PN and tag (size={}, needed={})",
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
        std::string unmasked_hdr(packet_bytes.substr(0, real_hdr_len));
        unmasked_hdr[0] = static_cast<char>(first_byte);
        for (std::size_t i = 0; i < pn_len; ++i) {
            unmasked_hdr[pn_offset + i] = static_cast<char>(
                static_cast<uint8_t>(packet_bytes[pn_offset + i]) ^ mask[1 + i]);
        }

        // Step 3: Payload starts at real_hdr_len
        std::size_t total_packet_len = packet_bytes.size();
        if (hdr.is_long && hdr.length > 0) {
            const std::size_t expected_long_len = pn_offset + static_cast<std::size_t>(hdr.length);
            if (expected_long_len <= packet_bytes.size()) {
                total_packet_len = expected_long_len;
            }
        }

        if (total_packet_len < real_hdr_len + 16) {
            wavex::log::warn("[QUIC] unprotect_packet: total_packet_len < real_hdr_len + 16 (total={}, hdr={})",
                             total_packet_len, real_hdr_len);
            return false;
        }
        const std::string_view payload = packet_bytes.substr(real_hdr_len, total_packet_len - real_hdr_len);

        // Step 4: Calculate Nonce = IV ^ FullPacketNumber (RFC 9001 §5.3)
        std::array<uint8_t, 12> nonce = keys.iv;
        for (int i = 0; i < 8; ++i) {
            nonce[11 - i] ^= static_cast<uint8_t>((full_packet_num >> (i * 8)) & 0xff);
        }

        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx) return false;

        const std::size_t cipher_len = payload.size() - 16;
        const auto *cipher_data = reinterpret_cast<const uint8_t *>(payload.data());
        const auto *tag_data = cipher_data + cipher_len;

        std::vector<uint8_t> decrypted(cipher_len);
        int out_len = 0;
        bool ok = true;

        if (EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, keys.key.data(), nonce.data()) != 1) ok = false;
        if (ok && EVP_DecryptUpdate(ctx, nullptr, &out_len, reinterpret_cast<const uint8_t *>(unmasked_hdr.data()),
                                    static_cast<int>(unmasked_hdr.size())) != 1) ok = false;
        if (ok && EVP_DecryptUpdate(ctx, decrypted.data(), &out_len, cipher_data, static_cast<int>(cipher_len)) != 1)
            ok = false;
        if (ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, const_cast<uint8_t *>(tag_data)) != 1) ok = false;
        if (ok && EVP_DecryptFinal_ex(ctx, decrypted.data() + out_len, &out_len) <= 0) {
            wavex::log::warn("[QUIC] unprotect_packet: AEAD GCM tag verification failed (pn={}, type={})",
                             full_packet_num, static_cast<int>(hdr.type));
            ok = false;
        }

        EVP_CIPHER_CTX_free(ctx);
        if (!ok) return false;

        plaintext_out.assign(reinterpret_cast<const char *>(decrypted.data()), cipher_len);
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
