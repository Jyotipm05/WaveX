// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
/**
 * @file WorkStealingQueue.ixx
 * @brief C++ module interface partition for the Tokio-style dual-queue system in WaveX.
 *
 * Exports:
 *   - Task         : std::function<void()> type alias
 *   - LocalQueue   : Bounded 256-slot lock-free ring buffer (per-worker)
 *   - InjectorQueue: Unbounded lock-based global MPMC overflow queue
 */

module;

#include <wavex/Server/WorkStealingQueue.hpp>

export module wavex:server_queue;

export namespace wavex::server {
    using server::Task;
    using server::LocalQueue;
    using server::InjectorQueue;
}
