// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * @file ConnectionTracker.cpp
 * @brief Out-of-line method definitions for ConnectionTracker.
 */

#include <wavex/Server/ConnectionTracker.hpp>

#include <functional>
#include <ranges>
#include <vector>

namespace wavex::server {

    uint64_t ConnectionTracker::register_socket(std::function<void()> cancel_fn,
                                                 std::function<void()> close_fn) {
        std::lock_guard lock(mtx);
        uint64_t id = next_id++;
        all_sockets.emplace(id, Entry{std::move(cancel_fn), std::move(close_fn)});
        return id;
    }

    void ConnectionTracker::unregister_socket(const uint64_t id) {
        std::lock_guard lock(mtx);
        all_sockets.erase(id);
        idle_sockets.erase(id);
    }

    void ConnectionTracker::mark_idle(const uint64_t id) {
        std::lock_guard lock(mtx);
        if (all_sockets.contains(id)) {
            idle_sockets.insert(id);
        }
    }

    void ConnectionTracker::mark_active(const uint64_t id) {
        std::lock_guard lock(mtx);
        idle_sockets.erase(id);
    }

    void ConnectionTracker::cancel_all_idle() {
        std::vector<std::function<void()>> to_cancel;
        {
            std::lock_guard lock(mtx);
            to_cancel.reserve(idle_sockets.size());
            for (const uint64_t id : idle_sockets) {
                if (auto it = all_sockets.find(id); it != all_sockets.end()) {
                    to_cancel.push_back(it->second.cancel);
                }
            }
            idle_sockets.clear();
        }
        for (auto &fn : to_cancel) {
            if (fn) fn();
        }
    }

    void ConnectionTracker::force_close_all() {
        std::vector<std::function<void()>> to_close;
        {
            std::lock_guard lock(mtx);
            to_close.reserve(all_sockets.size());
            for (auto &entry : all_sockets | std::views::values) {
                to_close.push_back(entry.close);
            }
            all_sockets.clear();
            idle_sockets.clear();
        }
        for (auto &fn : to_close) {
            if (fn) fn();
        }
    }

    std::size_t ConnectionTracker::count() const {
        std::lock_guard lock(mtx);
        return all_sockets.size();
    }

} // namespace wavex::server
