// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * @file ConnectionTracker.hpp
 * @brief Thread-safe registry of active and idle socket connections for graceful drain.
 *
 * @note Method implementations are defined in ConnectionTracker.cpp.
 */

#pragma once

#include <cstdint>
#include <functional>
#include <mutex>
#include <unordered_map>
#include <unordered_set>

namespace wavex::server {

    /**
     * @struct ConnectionTracker
     * @brief Thread-safe registry of active and idle socket connections for graceful drain.
     */
    struct ConnectionTracker {
        // ─── 1. Nested Types & Definitions ───────────────────────────────────
        struct Entry {
            std::function<void()> cancel;
            std::function<void()> close;

            Entry() = default;
            Entry(std::function<void()> c, std::function<void()> cl)
                : cancel(std::move(c)), close(std::move(cl)) {}
        };

        // ─── 2. Member Variables (Arranged for minimum padding) ──────────────
        mutable std::mutex mtx;
        std::unordered_map<uint64_t, Entry> all_sockets;
        std::unordered_set<uint64_t> idle_sockets;
        uint64_t next_id{1};

        // ─── 3. Constructors & Destructor ────────────────────────────────────
        ConnectionTracker() = default;
        ~ConnectionTracker() = default;

        ConnectionTracker(const ConnectionTracker &) = delete;
        ConnectionTracker &operator=(const ConnectionTracker &) = delete;
        ConnectionTracker(ConnectionTracker &&) = delete;
        ConnectionTracker &operator=(ConnectionTracker &&) = delete;

        // ─── 4. Member Functions (Implemented in ConnectionTracker.cpp) ──────
        uint64_t register_socket(std::function<void()> cancel_fn,
                                 std::function<void()> close_fn);
        void unregister_socket(uint64_t id);
        void mark_idle(uint64_t id);
        void mark_active(uint64_t id);
        void cancel_all_idle();
        void force_close_all();
        [[nodiscard]] std::size_t count() const;
    };

} // namespace wavex::server
