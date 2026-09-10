// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
/**
 * @file ThreadPool.ixx
 * @brief C++ module interface partition for ThreadPool in WaveX.
 */

module;

#include <wavex/Server/ThreadPool.hpp>

export module wavex:server_pool;

export namespace wavex::server {
    using server::ThreadPoolConfig;
    using server::WorkerNode;
    using server::ThreadPool;
}
