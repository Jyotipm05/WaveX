// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * @file StreamBuffer.hpp
 * @brief Contiguous chunk stream buffer for high-throughput zero-allocation read/write piping.
 */

#pragma once

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>

namespace wavex::utils {

    /**
     * @class StreamBuffer
     * @brief Contiguous chunk stream buffer for high-performance zero-allocation read/write piping.
     * Provides bulk append and memcpy draining with zero allocations on steady-state reuse.
     */
    class StreamBuffer {
        // ─── 2. Member Variables (SECOND - Ordered for Minimal Padding) ────
        std::string buffer_{};
        std::size_t read_offset_{0};

    public:
        // ─── 3. Constructors & Destructor (MIDDLE) ─────────────────────────
        StreamBuffer() = default;
        ~StreamBuffer() = default;

        StreamBuffer(const StreamBuffer &) = delete;
        StreamBuffer &operator=(const StreamBuffer &) = delete;
        StreamBuffer(StreamBuffer &&) noexcept = default;
        StreamBuffer &operator=(StreamBuffer &&) noexcept = default;

        // ─── 4. Member Functions (LAST) ────────────────────────────────────
        [[nodiscard]] std::size_t size() const noexcept {
            return buffer_.size() - read_offset_;
        }

        [[nodiscard]] bool empty() const noexcept {
            return read_offset_ >= buffer_.size();
        }

        [[nodiscard]] std::size_t capacity() const noexcept {
            return buffer_.capacity();
        }

        void reserve(const std::size_t new_cap) {
            buffer_.reserve(new_cap);
        }

        void append(const std::string_view chunk) {
            if (chunk.empty()) return;
            if (read_offset_ >= buffer_.size()) {
                buffer_.clear();
                read_offset_ = 0;
            } else if (read_offset_ >= 16384 && read_offset_ >= buffer_.size() / 2) {
                buffer_.erase(0, read_offset_);
                read_offset_ = 0;
            }
            buffer_.append(chunk.data(), chunk.size());
        }

        [[nodiscard]] std::string_view peek(const std::size_t max_bytes = static_cast<std::size_t>(-1)) const noexcept {
            if (empty()) return {};
            const std::size_t to_view = (std::min)(max_bytes, size());
            return {buffer_.data() + read_offset_, to_view};
        }

        void consume(const std::size_t bytes) noexcept {
            if (bytes == 0) return;
            const std::size_t to_consume = (std::min)(bytes, size());
            read_offset_ += to_consume;
            if (read_offset_ >= buffer_.size()) {
                buffer_.clear();
                read_offset_ = 0;
            } else if (read_offset_ >= 16384 && read_offset_ >= buffer_.size() / 2) {
                buffer_.erase(0, read_offset_);
                read_offset_ = 0;
            }
        }

        std::size_t read(uint8_t *dest, const std::size_t max_bytes) noexcept {
            if (!dest || max_bytes == 0 || empty()) return 0;
            const std::size_t to_copy = (std::min)(max_bytes, size());
            std::memcpy(dest, buffer_.data() + read_offset_, to_copy);
            read_offset_ += to_copy;
            if (read_offset_ >= buffer_.size()) {
                buffer_.clear();
                read_offset_ = 0;
            }
            return to_copy;
        }

        void clear() noexcept {
            buffer_.clear();
            read_offset_ = 0;
        }
    };

} // namespace wavex::utils
