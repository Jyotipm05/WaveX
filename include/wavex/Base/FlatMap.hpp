// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * @file FlatMap.hpp
 * @brief Cache-line contiguous key-value container for short-lived HTTP state.
 *
 * FlatMap<K, V> stores up to InlineCap key-value pairs in a contiguous inline
 * array, spilling into a heap-backed (or arena-backed) std::vector only when
 * capacity is exceeded. For small N (≤ 16) a linear scan over contiguous
 * cache lines is significantly faster than hashing.
 *
 * Designed for:
 *  - Request path parameters        (req.params,  typically 0–5 items)
 *  - Request query string parameters (req.query,   typically 0–8 items)
 *  - Response headers               (res.headers_, typically 3–12 items)
 *
 * API surface mirrors std::map / std::unordered_map for drop-in compatibility:
 *   operator[], at(), find(), find_ci(), contains(), size(), empty(),
 *   begin(), end(), insert_or_assign(), clear()
 *
 * Safety contract for string_view keys/values:
 *   Views must remain valid for the lifetime of the FlatMap. In WaveX the map
 *   is scoped to a single request arena; views into stream_buf or arena storage
 *   are always valid throughout that request lifecycle.
 */

#pragma once

#include <array>
#include <cassert>
#include <stdexcept>
#include <string_view>
#include <vector>
#include <utility>
#include <cctype>

namespace wavex::base {
    /**
     * @class FlatMap
     * @brief Cache-line contiguous key-value container — zero heap allocation for N ≤ InlineCap.
     *
     * @tparam K          Key type. Must support equality comparison with std::string_view.
     * @tparam V          Value type.
     * @tparam InlineCap  Maximum number of pairs stored in the inline array (default 16).
     *                    Pairs beyond this spill into a heap-backed overflow vector.
     */
    template<typename K = std::string_view, typename V = std::string_view, std::size_t InlineCap = 16>
    class FlatMap {
    public:
        using key_type = K;
        using mapped_type = V;
        using value_type = std::pair<K, V>;
        using size_type = std::size_t;

        // ── Iterators ────────────────────────────────────────────────────────

        struct iterator {
            const FlatMap *map;
            size_type idx;

            iterator &operator++() noexcept {
                ++idx;
                return *this;
            }

            bool operator==(const iterator &o) const noexcept { return idx == o.idx; }
            bool operator!=(const iterator &o) const noexcept { return idx != o.idx; }
            const value_type &operator*() const noexcept { return map->pair_at(idx); }
            const value_type *operator->() const noexcept { return &map->pair_at(idx); }
        };

        using const_iterator = iterator;

        // ── Capacity ─────────────────────────────────────────────────────────

        [[nodiscard]] size_type size() const noexcept { return size_; }
        [[nodiscard]] bool empty() const noexcept { return size_ == 0; }

        // ── Iteration ─────────────────────────────────────────────────────────

        [[nodiscard]] iterator begin() const noexcept { return {this, 0}; }
        [[nodiscard]] iterator end() const noexcept { return {this, size_}; }

        // ── Lookup ────────────────────────────────────────────────────────────

        /**
         * @brief Case-sensitive linear scan for key.
         * @return Iterator to matching pair, or end() if not found.
         */
        [[nodiscard]] iterator find(std::string_view key) const noexcept {
            for (size_type i = 0; i < size_; ++i) {
                if (std::string_view(pair_at(i).first) == key)
                    return {this, i};
            }
            return end();
        }

        /**
         * @brief Case-insensitive linear scan (for HTTP headers).
         * @return Iterator to matching pair, or end() if not found.
         */
        [[nodiscard]] iterator find_ci(std::string_view key) const noexcept {
            for (size_type i = 0; i < size_; ++i) {
                const std::string_view k(pair_at(i).first);
                if (k.size() == key.size()) {
                    bool match = true;
                    for (size_type c = 0; c < k.size(); ++c) {
                        if (std::tolower(static_cast<unsigned char>(k[c])) !=
                            std::tolower(static_cast<unsigned char>(key[c]))) {
                            match = false;
                            break;
                        }
                    }
                    if (match) return {this, i};
                }
            }
            return end();
        }

        /**
         * @brief Case-sensitive membership test.
         */
        [[nodiscard]] bool contains(std::string_view key) const noexcept {
            return find(key) != end();
        }

        /**
         * @brief Access value by key — returns default-constructed V if not found.
         * Inserts a default-constructed entry on access (mirrors std::map).
         */
        V &operator[](std::string_view key) {
            if (auto it = find(key); it != end())
                return mutable_pair_at(it.idx).second;
            // Insert default entry
            insert_or_assign(K(key), V{});
            return mutable_pair_at(size_ - 1).second;
        }

        /**
         * @brief Const access by key — returns empty string_view if not found.
         */
        [[nodiscard]] V get(std::string_view key) const noexcept {
            if (const auto it = find(key); it != end())
                return it->second;
            return V{};
        }

        /**
         * @brief Throwing access — throws std::out_of_range if key not found.
         */
        [[nodiscard]] const V &at(std::string_view key) const {
            const auto it = find(key);
            if (it == end()) [[unlikely]]
                throw std::out_of_range("FlatMap::at: key not found");
            return it->second;
        }

        // ── Mutation ─────────────────────────────────────────────────────────

        /**
         * @brief Insert or update a key-value pair.
         * Updates the value in-place if key already exists.
         * Appends a new pair if the key is absent.
         */
        void insert_or_assign(K key, V value) {
            // Update in-place (case-sensitive)
            if (const auto it = find(std::string_view(key)); it != end()) {
                mutable_pair_at(it.idx).second = std::move(value);
                return;
            }
            // Append
            if (size_ < InlineCap) [[likely]] {
                inline_[size_] = {std::move(key), std::move(value)};
            } else [[unlikely]] {
                overflow_.emplace_back(std::move(key), std::move(value));
            }
            ++size_;
        }

        /**
         * @brief Case-insensitive insert or update (for HTTP headers).
         */
        void insert_or_assign_ci(K key, V value) {
            if (const auto it = find_ci(std::string_view(key)); it != end()) {
                mutable_pair_at(it.idx).second = std::move(value);
                return;
            }
            if (size_ < InlineCap) [[likely]] {
                inline_[size_] = {std::move(key), std::move(value)};
            } else [[unlikely]] {
                overflow_.emplace_back(std::move(key), std::move(value));
            }
            ++size_;
        }

        /**
         * @brief Erase an entry at the given index.
         */
        void erase_at(size_type idx) {
            if (idx >= size_) return;
            for (size_type i = idx; i + 1 < size_; ++i) {
                mutable_pair_at(i) = std::move(mutable_pair_at(i + 1));
            }
            --size_;
            if (!overflow_.empty()) {
                overflow_.pop_back();
            }
        }

        /**
         * @brief Case-sensitive erase by key. Returns true if removed, false if not found.
         */
        bool erase(std::string_view key) {
            const auto it = find(key);
            if (it == end()) return false;
            erase_at(it.idx);
            return true;
        }

        /**
         * @brief Case-insensitive erase by key. Returns true if removed, false if not found.
         */
        bool erase_ci(std::string_view key) {
            const auto it = find_ci(key);
            if (it == end()) return false;
            erase_at(it.idx);
            return true;
        }

        /**
         * @brief Remove all entries.
         */
        void clear() noexcept {
            size_ = 0;
            overflow_.clear();
        }

    private:
        // Inline storage — zero heap allocation for N ≤ InlineCap
        std::array<value_type, InlineCap> inline_{};
        // Overflow storage for N > InlineCap (rare; pathological requests only)
        std::vector<value_type> overflow_;
        size_type size_{0};

        [[nodiscard]] const value_type &pair_at(size_type idx) const noexcept {
            if (idx < InlineCap) [[likely]]
                return inline_[idx];
            [[assume(idx >= InlineCap)]];
            return overflow_[idx - InlineCap];
        }

        [[nodiscard]] value_type &mutable_pair_at(size_type idx) noexcept {
            if (idx < InlineCap) [[likely]]
                return inline_[idx];
            [[assume(idx >= InlineCap)]];
            return overflow_[idx - InlineCap];
        }
    };
} // namespace wavex::base
