// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
/**
 * @file Server.ixx
 * @brief Primary C++ module interface partition for Server in WaveX.
 */

module;

#include <wavex/Server/TlsConfig.hpp>
#include <wavex/Server/WorkStealingQueue.hpp>
#include <wavex/Server/ThreadPool.hpp>
#include <wavex/Server/BlockingPool.hpp>
#include <wavex/Server/Server.hpp>
#include <wavex/Async/SpawnBlocking.hpp>

export module wavex:server;

export import :server_queue;
export import :server_pool;

export namespace wavex::server {
    using server::TlsConfig;
    using server::Task;
    using server::LocalQueue;
    using server::InjectorQueue;
    using server::ThreadPoolConfig;
    using server::WorkerNode;
    using server::ThreadPool;
    using server::BlockingTask;
    using server::BlockingThreadPool;
    using server::ConnectionTracker;
    using server::Server;
    using server::Http1Server;
    using server::http1server;
    using server::Http2Server;
    using server::http2server;
    using server::HttpServer;
    using server::httpserver;
}

export namespace wavex {
    using wavex::spawn_blocking;
}
