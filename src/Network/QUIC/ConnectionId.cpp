// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * @file ConnectionId.cpp
 * @brief Implementation of RFC 9000 §5 Connection ID representation.
 */

#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL

#include <wavex/Network/QUIC/ConnectionId.hpp>

#if defined(min)
#undef min
#endif
#if defined(max)
#undef max
#endif

#include <algorithm>
#include <atomic>
#include <bit>
#include <chrono>
#include <cstring>
#include <iomanip>
#include <random>
#include <sstream>

#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
#include <openssl/rand.h>
#endif

namespace wavex::network::quic {

    ConnectionId::ConnectionId(const uint8_t *src, const std::size_t len) noexcept {
        length_ = static_cast<uint8_t>((std::min)(len, MAX_CONNECTION_ID_LEN));
        if (src && length_ > 0) {
            std::memcpy(data_.data(), src, length_);
        }
    }

    ConnectionId::ConnectionId(const std::string_view sv) noexcept {
        length_ = static_cast<uint8_t>((std::min)(sv.size(), MAX_CONNECTION_ID_LEN));
        if (length_ > 0) {
            std::memcpy(data_.data(), sv.data(), length_);
        }
    }

    std::string ConnectionId::to_string() const {
        std::ostringstream oss;
        for (std::size_t i = 0; i < length_; ++i) {
            oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data_[i]);
        }
        return oss.str();
    }

    ConnectionId ConnectionId::from_hex(const std::string_view hex) {
        if (hex.empty() || hex.size() % 2 != 0 || hex.size() / 2 > MAX_CONNECTION_ID_LEN) {
            return ConnectionId{};
        }
        ConnectionId cid;
        for (std::size_t i = 0; i < hex.size() / 2; ++i) {
            const char c1 = hex[i * 2];
            const char c2 = hex[i * 2 + 1];
            auto hex_val = [](char c) noexcept -> int {
                if (c >= '0' && c <= '9') return c - '0';
                if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                return -1;
            };
            const int v1 = hex_val(c1);
            const int v2 = hex_val(c2);
            if (v1 < 0 || v2 < 0) {
                return ConnectionId{};
            }
            cid.data_[i] = static_cast<uint8_t>((v1 << 4) | v2);
        }
        cid.length_ = static_cast<uint8_t>(hex.size() / 2);
        return cid;
    }

    ConnectionId ConnectionId::random(const std::size_t len) {
        ConnectionId cid;
        cid.length_ = static_cast<uint8_t>((std::min)(len, MAX_CONNECTION_ID_LEN));
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<int> dist(0, 255);
        for (std::size_t i = 0; i < cid.length_; ++i) {
            cid.data_[i] = static_cast<uint8_t>(dist(gen));
        }
        return cid;
    }

    bool ConnectionId::operator==(const ConnectionId &other) const noexcept {
        if (length_ != other.length_) return false;
        if (length_ == 0) return true;
        return std::memcmp(data_.data(), other.data_.data(), length_) == 0;
    }

    uint64_t siphash24(const uint8_t *data, const std::size_t len, const uint64_t k0, const uint64_t k1) noexcept {
        auto sipround = [](uint64_t &v0, uint64_t &v1, uint64_t &v2, uint64_t &v3) noexcept {
            v0 += v1;
            v1 = std::rotl(v1, 13);
            v1 ^= v0;
            v0 = std::rotl(v0, 32);

            v2 += v3;
            v3 = std::rotl(v3, 16);
            v3 ^= v2;

            v0 += v3;
            v3 = std::rotl(v3, 21);
            v3 ^= v0;

            v2 += v1;
            v1 = std::rotl(v1, 17);
            v1 ^= v2;
            v2 = std::rotl(v2, 32);
        };

        auto load_u64_le = [](const uint8_t *p) noexcept -> uint64_t {
            return static_cast<uint64_t>(p[0]) |
                   (static_cast<uint64_t>(p[1]) << 8) |
                   (static_cast<uint64_t>(p[2]) << 16) |
                   (static_cast<uint64_t>(p[3]) << 24) |
                   (static_cast<uint64_t>(p[4]) << 32) |
                   (static_cast<uint64_t>(p[5]) << 40) |
                   (static_cast<uint64_t>(p[6]) << 48) |
                   (static_cast<uint64_t>(p[7]) << 56);
        };

        uint64_t v0 = k0 ^ 0x736f6d6570736575ULL;
        uint64_t v1 = k1 ^ 0x646f72616e646f6dULL;
        uint64_t v2 = k0 ^ 0x6c7967656e657261ULL;
        uint64_t v3 = k1 ^ 0x7465646279746573ULL;

        const std::size_t left = len & 7;
        const uint8_t *end = data + (len - left);

        for (const uint8_t *p = data; p != end; p += 8) {
            const uint64_t m = load_u64_le(p);
            v3 ^= m;
            sipround(v0, v1, v2, v3);
            sipround(v0, v1, v2, v3);
            v0 ^= m;
        }

        uint64_t b = static_cast<uint64_t>(len) << 56;
        for (std::size_t i = 0; i < left; ++i) {
            b |= static_cast<uint64_t>(end[i]) << (8 * i);
        }

        v3 ^= b;
        sipround(v0, v1, v2, v3);
        sipround(v0, v1, v2, v3);
        v0 ^= b;

        v2 ^= 0xff;
        sipround(v0, v1, v2, v3);
        sipround(v0, v1, v2, v3);
        sipround(v0, v1, v2, v3);
        sipround(v0, v1, v2, v3);

        return v0 ^ v1 ^ v2 ^ v3;
    }

    namespace {
        struct ProcessSipHashSeed {
            std::atomic<uint64_t> k0{0};
            std::atomic<uint64_t> k1{0};
            std::atomic<bool> initialized{false};

            void ensure_initialized() noexcept {
                if (initialized.load(std::memory_order_acquire)) {
                    return;
                }
                uint64_t seed0 = 0;
                uint64_t seed1 = 0;
                bool ok = false;
#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
                if (RAND_bytes(reinterpret_cast<unsigned char *>(&seed0), static_cast<int>(sizeof(seed0))) == 1 &&
                    RAND_bytes(reinterpret_cast<unsigned char *>(&seed1), static_cast<int>(sizeof(seed1))) == 1) {
                    ok = true;
                }
#endif
                if (!ok) {
                    std::random_device rd;
                    seed0 = (static_cast<uint64_t>(rd()) << 32) | rd();
                    seed1 = (static_cast<uint64_t>(rd()) << 32) | rd();
                    const auto now = static_cast<uint64_t>(
                        std::chrono::steady_clock::now().time_since_epoch().count());
                    seed0 ^= now;
                    seed1 ^= ((now << 32) | (now >> 32));
                }

                uint64_t exp0 = 0;
                k0.compare_exchange_strong(exp0, seed0, std::memory_order_acq_rel);
                uint64_t exp1 = 0;
                k1.compare_exchange_strong(exp1, seed1, std::memory_order_acq_rel);
                initialized.store(true, std::memory_order_release);
            }
        };

        ProcessSipHashSeed &global_siphash_seed() noexcept {
            static ProcessSipHashSeed inst;
            inst.ensure_initialized();
            return inst;
        }
    } // namespace

    void set_process_siphash_seed(const uint64_t k0, const uint64_t k1) noexcept {
        auto &seed = global_siphash_seed();
        seed.k0.store(k0, std::memory_order_release);
        seed.k1.store(k1, std::memory_order_release);
        seed.initialized.store(true, std::memory_order_release);
    }

    std::pair<uint64_t, uint64_t> get_process_siphash_seed() noexcept {
        auto &seed = global_siphash_seed();
        return {seed.k0.load(std::memory_order_acquire), seed.k1.load(std::memory_order_acquire)};
    }

    uint64_t siphash24(const uint8_t *data, const std::size_t len) noexcept {
        const auto [k0, k1] = get_process_siphash_seed();
        return siphash24(data, len, k0, k1);
    }

} // namespace wavex::network::quic

namespace std {
    std::size_t hash<wavex::network::quic::ConnectionId>::operator()(
        const wavex::network::quic::ConnectionId &cid) const noexcept {
        return static_cast<std::size_t>(
            wavex::network::quic::siphash24(cid.data(), cid.length()));
    }
} // namespace std

#endif // WAVEX_HAS_SSL

