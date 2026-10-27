// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
/**
 * @file ThreadPool.hpp
 * @brief Tokio-like adaptive work-stealing thread pool.
 *
 * Each worker owns a bounded, lock-free LocalQueue (256-slot ring buffer).
 * A shared InjectorQueue (unbounded, lock-based) acts as the global overflow
 * and external submission point.
 *
 * Task dispatch priority per worker (highest → lowest):
 *   1. Pop from own LocalQueue  (lock-free, LIFO, cache-local)
 *   2. Steal from a random peer LocalQueue  (lock-free, FIFO)
 *   3. Pop from the shared InjectorQueue  (lock-based, FIFO)
 *   4. Poll the worker's asio::io_context for coroutine continuations
 *   5. Yield (1 ms sleep) to avoid tight CPU spin
 *
 * Task submission priority (ThreadPool::dispatch):
 *   Always push to the InjectorQueue (LocalQueues are single-owner and filled only by stealing)
 */

#pragma once

#ifndef ASIO_HAS_CO_AWAIT
#define ASIO_HAS_CO_AWAIT 1
#endif

#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <random>
#include <thread>
#include <vector>

#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/executor_work_guard.hpp>
#include <asio/io_context.hpp>

#include <wavex/Server/WorkStealingQueue.hpp>

namespace wavex::server {
    // ─────────────────────────────────────────────────────────────────────────
    // ThreadPoolConfig
    // ─────────────────────
    class ThreadPoolConfig {
    public:
        // ─── 1. Member Variables (Arranged for minimum padding) ──────────────
        std::vector<std::size_t> upper_thresholds = {10, 25, 50, 100};
        std::vector<std::size_t> lower_thresholds = {5, 15, 30, 60};
        std::chrono::milliseconds check_interval{100};
        std::size_t min_workers = default_min_workers();
        std::size_t max_workers = default_max_workers();
        std::size_t scale_up_divider = 2;
        std::size_t scale_down_cooldown_cycles = 3;

        // ─── 2. Constructors & Destructor ────────────────────────────────────
        ThreadPoolConfig() {
            if (upper_thresholds.size() < max_workers - 1)
                upper_thresholds.resize(max_workers - 1, 50);
            if (lower_thresholds.size() < max_workers - 1)
                lower_thresholds.resize(max_workers - 1, 10);
        }

        ~ThreadPoolConfig() = default;

        // ─── 3. Member Functions & Helpers ───────────────────────────────────
        static ThreadPoolConfig &instance() {
            static ThreadPoolConfig s_config;
            return s_config;
        }

        static std::size_t default_max_workers() noexcept {
            const auto hw = std::thread::hardware_concurrency();
            return hw > 0 ? std::max<std::size_t>(4, hw) : 4;
        }

        static std::size_t default_min_workers() noexcept {
            return std::max<std::size_t>(1, default_max_workers() / 4);
        }

        void set_limits(const std::size_t min_w, const std::size_t max_w) {
            min_workers = min_w;
            max_workers = max_w;
            if (upper_thresholds.size() < max_workers - 1)
                upper_thresholds.resize(max_workers - 1, 50);
            if (lower_thresholds.size() < max_workers - 1)
                lower_thresholds.resize(max_workers - 1, 10);
        }
    };

    // ─────────────────────────────────────────────────────────────────────────
    // WorkerNode
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * @struct WorkerNode
     * @brief State for a single worker thread: its local ring queue, io_context,
     *        and lifecycle flags.
     */
    struct WorkerNode {
        // ─── 1. Member Variables (Arranged for minimum padding) ──────────────
        std::shared_ptr<asio::io_context> io_ctx; // 16 bytes
        std::unique_ptr<LocalQueue> queue; // 8 bytes
        std::thread thread; // 8 bytes
        asio::executor_work_guard<asio::io_context::executor_type> work_guard; // 8 bytes
        std::size_t id{0}; // 8 bytes
        std::atomic<bool> is_retiring{false}; // 1 byte
        std::atomic<bool> is_busy{false}; // 1 byte
        std::atomic<bool> stop_requested{false}; // 1 byte
        /// Coroutines spawned onto this worker's io_context that have not finished yet. Shared so the
        /// coroutine's guard can outlive the node (e.g. frames destroyed when the io_context is torn down).
        std::shared_ptr<std::atomic<std::size_t> > live_coroutines =
                std::make_shared<std::atomic<std::size_t> >(0);

        // ─── 2. Constructors & Destructor ────────────────────────────────────
        explicit WorkerNode(const std::size_t worker_id)
            : io_ctx(std::make_shared<asio::io_context>()),
              queue(std::make_unique<LocalQueue>()),
              work_guard(asio::make_work_guard(*io_ctx)),
              id(worker_id) {
        }

        ~WorkerNode() = default;
    };

    // ─────────────────────────────────────────────────────────────────────────
    // ThreadPool
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * @class ThreadPool
     * @brief Adaptive Tokio-style work-stealing thread pool.
     *
     * Maintains a vector of WorkerNodes (each with a LocalQueue) and a single
     * shared InjectorQueue for overflow and external task submission.
     */
    class ThreadPool {
        // ─── 1. Nested Types & Constants ─────────────────────────────────────
        static constexpr std::size_t kMaxWorkerSlots = 128;
        /// Worker fairness: poll the io_context at least every this many tasks ...
        static constexpr std::size_t kTasksPerIoTick = 16;
        /// ... or after this much wall time since its last turn, whichever comes first.
        static constexpr std::chrono::microseconds kIoBudget{250};

        // ─── 2. Member Variables (Arranged for minimum padding) ──────────────
        ThreadPoolConfig &config_;
        mutable std::mutex workers_mutex_;
        mutable std::mutex monitor_mutex_;
        std::condition_variable cv_monitor_;
        InjectorQueue injector_; ///< Global overflow & external submission queue
        std::vector<std::shared_ptr<WorkerNode> > workers_;
        std::array<std::atomic<WorkerNode *>, kMaxWorkerSlots> worker_table_{};
        /// Threads currently probing peers' queues through raw pointers from worker_table_. A retired node is
        /// only destroyed once this has been observed at zero *after* it was unpublished (see reclaim_retired()).
        alignas(64) std::atomic<std::size_t> active_thieves_{0};
        /// Retired (unpublished, joined) nodes waiting for safe reclamation. Touched only by the monitor
        /// thread, and by stop_pool() after the monitor has been joined.
        std::vector<std::shared_ptr<WorkerNode> > retired_;
        std::thread monitor_thread_;
        std::atomic<std::size_t> worker_count_{0};
        std::atomic<std::size_t> burst_spill_count_{0};
        std::atomic<std::size_t> next_worker_idx_{0};
        std::size_t scale_down_cooldown_counter_{0};
        std::atomic<bool> pool_stopping_{false};
        bool monitor_signal_{false};

    public:
        // ─── 3. Constructors & Destructor ────────────────────────────────────
        explicit ThreadPool(ThreadPoolConfig &config = ThreadPoolConfig::instance())
            : config_(config) {
            start_pool();
        }

        ~ThreadPool() {
            stop_pool();
        }

        ThreadPool(const ThreadPool &) = delete;

        ThreadPool &operator=(const ThreadPool &) = delete;

        ThreadPool(ThreadPool &&) = delete;

        ThreadPool &operator=(ThreadPool &&) = delete;

        // ─── 4. Member Functions ─────────────────────────────────────────────

        /**
         * @brief Submit a generic task to the pool (callable from any thread).
         *
         * Always goes through the InjectorQueue: a LocalQueue is a single-owner deque (only its worker may
         * push or pop at the back), so external producers must never touch it. Idle workers drain the
         * injector within one poll interval; the worker-local rings are filled only by their owner, from
         * batches stolen off busy peers.
         */
        void dispatch(Task task) {
            injector_.push(std::move(task));
            // A deep backlog is the signal to wake the monitor early (this replaces the old "local ring full"
            // spill); ordinary load is picked up by the periodic check.
            if (injector_.size() >= LocalQueue::CAPACITY - 1) check_burst_spill();
        }

        /**
         * @brief A worker reserved for one coroutine. The reservation counts as a live coroutine, so the
         *        worker cannot be retired while the lease is held; it is released when the lease is destroyed
         *        unused, or handed to spawn_leased().
         */
        class WorkerLease {
        public:
            WorkerLease() = default;
            WorkerLease(WorkerLease &&o) noexcept = default;
            WorkerLease &operator=(WorkerLease &&) = delete;
            WorkerLease(const WorkerLease &) = delete;
            WorkerLease &operator=(const WorkerLease &) = delete;

            ~WorkerLease() {
                if (live_) live_->fetch_sub(1, std::memory_order_seq_cst);
            }

            explicit operator bool() const noexcept { return ctx_ != nullptr; }

            /// The worker's io_context: create sockets/timers for the leased coroutine on it.
            [[nodiscard]] asio::io_context &context() const noexcept { return *ctx_; }

        private:
            friend class ThreadPool;
            WorkerLease(std::shared_ptr<asio::io_context> ctx, std::shared_ptr<std::atomic<std::size_t> > live)
                : ctx_(std::move(ctx)), live_(std::move(live)) {
            }

            std::shared_ptr<asio::io_context> ctx_{};
            std::shared_ptr<std::atomic<std::size_t> > live_{};
        };

        /**
         * @brief Reserve one worker (round-robin, lock-free). Empty lease if no worker is available.
         */
        [[nodiscard]] WorkerLease lease_worker() {
            // Retry a few times: a worker can be retired between picking it and registering on it.
            for (int attempt = 0; attempt < 4; ++attempt) {
                const std::size_t count = worker_count_.load(std::memory_order_acquire);
                if (count == 0) [[unlikely]] return {};
                const std::size_t idx = next_worker_idx_.fetch_add(1, std::memory_order_relaxed) % count;
                WorkerNode *w = (idx < kMaxWorkerSlots) ? worker_table_[idx].load(std::memory_order_seq_cst) : nullptr;
                if (!w || !w->io_ctx) [[unlikely]] continue;

                // Register first, then re-check the slot (seq_cst on both sides pairs with the retire path in
                // check_and_scale): either the retirer sees our count and keeps the worker, or we see the
                // cleared slot and pick another worker. A coroutine can never land on a retiring worker.
                w->live_coroutines->fetch_add(1, std::memory_order_seq_cst);
                if (worker_table_[idx].load(std::memory_order_seq_cst) != w) [[unlikely]] {
                    w->live_coroutines->fetch_sub(1, std::memory_order_seq_cst);
                    continue;
                }
                return WorkerLease(w->io_ctx, w->live_coroutines);
            }
            return {};
        }

        /**
         * @brief Run a coroutine on the leased worker; the lease's reservation becomes the coroutine's
         *        live count and is released when the coroutine finishes.
         */
        template<typename Coro>
        void spawn_leased(WorkerLease lease, Coro coro) {
            if (!lease) return;
            auto ctx = lease.ctx_;
            auto live = std::move(lease.live_);
            asio::co_spawn(*ctx, track_live(std::move(live), std::move(coro)), asio::detached);
        }

        /**
         * @brief Spawn an Asio coroutine onto one of the worker io_contexts (lock-free fast path).
         */
        template<typename Coro>
        void spawn_coroutine(Coro coro) {
            if (auto lease = lease_worker()) spawn_leased(std::move(lease), std::move(coro));
        }

        /**
         * @brief Post a callable to every active worker's io_context.
         *
         * Primarily used for per-thread teardown or memory trimming tasks
         * (e.g. wavex::memory::get_thread_local_pool().release()).
         * The callable is executed on the worker's thread, so it is safe to access
         * thread_local state (like the slab pool) without synchronization.
         *
         * @tparam F  Any callable with signature void().
         * @param fn  The callable to post to each worker.
         */
        template<typename F>
        void post_all(F fn) {
            std::lock_guard lock(workers_mutex_);
            for (const auto &w: workers_) {
                if (w && w->io_ctx) {
                    asio::post(*w->io_ctx, fn);
                }
            }
        }

        /// Get current active worker count (lock-free).
        [[nodiscard]] std::size_t worker_count() const noexcept {
            return worker_count_.load(std::memory_order_acquire);
        }

        /// Force an immediate scaling evaluation.
        void evaluate_scaling() {
            check_and_scale();
        }

        /// Get current scale-down cooldown counter (for diagnostics/testing).
        [[nodiscard]] std::size_t cooldown_counter() const {
            std::lock_guard lock(workers_mutex_);
            return scale_down_cooldown_counter_;
        }

        // ── Lifecycle ──────────────────────────────────────────────────────

        void start_pool() {
            std::lock_guard lock(workers_mutex_);
            for (std::size_t i = 0; i < config_.min_workers; ++i)
                add_worker_unlocked();
            pool_stopping_ = false;
            monitor_thread_ = std::thread([this] { monitor_loop(); });
        }

        void stop_pool() { {
                std::lock_guard lock(monitor_mutex_);
                pool_stopping_ = true;
            }
            cv_monitor_.notify_all();
            if (monitor_thread_.joinable())
                monitor_thread_.join();

            std::vector<std::shared_ptr<WorkerNode> > to_join; {
                std::lock_guard lock(workers_mutex_);
                worker_count_.store(0, std::memory_order_release);
                for (std::size_t i = 0; i < kMaxWorkerSlots; ++i) {
                    worker_table_[i].store(nullptr, std::memory_order_relaxed);
                }
                for (const auto &w: workers_) {
                    w->stop_requested = true;
                    w->work_guard.reset();
                    if (w->io_ctx) w->io_ctx->stop();
                }
                to_join = std::move(workers_);
            }

            for (const auto &w: to_join) {
                if (w->thread.joinable())
                    w->thread.join();
            }
            // Every worker thread is joined, so no thief remains: retired nodes can go too.
            retired_.clear();
        }

    private:
        /// Decrements the worker's live-coroutine count when the wrapped coroutine finishes or is destroyed.
        template<typename Coro>
        static asio::awaitable<void> track_live(std::shared_ptr<std::atomic<std::size_t> > live, Coro coro) {
            struct Guard {
                std::shared_ptr<std::atomic<std::size_t> > n;
                ~Guard() { n->fetch_sub(1, std::memory_order_seq_cst); }
            } guard{std::move(live)};
            co_await std::move(coro);
        }

        void check_burst_spill() noexcept {
            if (burst_spill_count_.fetch_add(1, std::memory_order_relaxed) + 1 >= 8) {
                burst_spill_count_.store(0, std::memory_order_relaxed);
                notify_monitor();
            }
        }

        void notify_monitor() { {
                std::lock_guard lock(monitor_mutex_);
                monitor_signal_ = true;
            }
            cv_monitor_.notify_one();
        }

        void add_worker_unlocked() {
            const std::size_t new_id = workers_.size() + 1;
            auto worker = std::make_shared<WorkerNode>(new_id);
            if (const std::size_t slot = workers_.size(); slot < kMaxWorkerSlots) {
                worker_table_[slot].store(worker.get(), std::memory_order_release);
                worker_count_.store(slot + 1, std::memory_order_release);
            }
            worker->thread = std::thread([this, w = worker] { worker_loop(w); });
            workers_.emplace_back(std::move(worker));
        }

        // ── Worker loop ────────────────────────────────────────────────────

        void worker_loop(const std::shared_ptr<WorkerNode> &w) {
            // Seed per-thread RNG for randomized steal target selection.
            std::mt19937 rng{std::random_device{}()};

            // Fairness: connection I/O (socket completions, timers, coroutine resumptions) lives on this
            // worker's io_context, and a queue of tasks must not starve it. After kTasksPerIoTick tasks, or
            // kIoBudget of task time, the io_context gets a turn before the next task is taken.
            std::size_t tasks_since_io = 0;
            auto last_io = std::chrono::steady_clock::now();
            const auto io_tick = [&] {
                if (++tasks_since_io < kTasksPerIoTick &&
                    std::chrono::steady_clock::now() - last_io < kIoBudget) {
                    return;
                }
                w->io_ctx->poll();
                tasks_since_io = 0;
                last_io = std::chrono::steady_clock::now();
            };

            while (!w->stop_requested && !w->is_retiring) {
                // ── 1. Pop from own LocalQueue (LIFO, cache-local) ──────────
                if (auto task = w->queue->pop()) [[likely]] {
                    w->is_busy = true;
                    (*task)();
                    w->is_busy = false;
                    io_tick();
                    continue;
                }

                // ── 2. Steal from a random peer's LocalQueue (FIFO, lock-free)
                {
                    // seq_cst pairs with the unpublish/observe sequence in reclaim_retired(): once a retired node
                    // is unpublished and this counter reads zero, no thief can still hold its pointer.
                    struct ThiefScope {
                        std::atomic<std::size_t> &n;
                        explicit ThiefScope(std::atomic<std::size_t> &c) : n(c) { n.fetch_add(1, std::memory_order_seq_cst); }
                        ~ThiefScope() { n.fetch_sub(1, std::memory_order_seq_cst); }
                    } thief_scope{active_thieves_};
                    if (const std::size_t n = worker_count_.load(std::memory_order_acquire); n > 1) {
                        // Pick a random start to avoid thundering-herd on worker 0.
                        const std::size_t start = rng() % n;
                        for (std::size_t i = 0; i < n; ++i) {
                            if (const auto *other = worker_table_[(start + i) % n].load(std::memory_order_acquire); other && other->id != w->id && !other->is_retiring.load(std::memory_order_relaxed)) {
                                if (auto stolen = other->queue->steal_half(*w->queue)) {
                                    w->is_busy = true;
                                    (*stolen)();
                                    w->is_busy = false;
                                    io_tick();
                                    goto next_iteration; // restart priority chain
                                }
                            }
                        }
                    }
                }

                // ── 3. Drain one task from the global InjectorQueue ──────────
                if (auto task = injector_.pop()) {
                    w->is_busy = true;
                    (*task)();
                    w->is_busy = false;
                    io_tick();
                    continue;
                }

                // ── 4. Poll asio::io_context for coroutine continuations ─────
                // With work_guard active, io_ctx does not prematurely stop.
                // Drain ready handlers non-blocking via poll(), or sleep efficiently
                // in the OS kernel (IOCP/epoll) for up to 100 microseconds if idle.
                if (!w->stop_requested) {
                    if (w->io_ctx->poll() == 0) {
                        w->io_ctx->run_one_for(std::chrono::microseconds(100));
                    }
                    tasks_since_io = 0;
                    last_io = std::chrono::steady_clock::now();
                }

            next_iteration:;
            }

            // On thread exit (retire or stop), owner thread drains its local ring into global InjectorQueue
            auto remaining = w->queue->drain_all();
            for (auto &task: remaining) {
                injector_.push(std::move(task));
            }
        }

        // ── Monitor & scaling ──────────────────────────────────────────────

        void monitor_loop() {
            while (true) {
                std::unique_lock lock(monitor_mutex_);
                cv_monitor_.wait_for(lock, config_.check_interval, [this] {
                    return pool_stopping_ || monitor_signal_;
                });
                if (pool_stopping_) {
                    break;
                }
                monitor_signal_ = false;
                lock.unlock();

                check_and_scale();
            }
        }

        void check_and_scale() {
            std::shared_ptr<WorkerNode> retiring_worker = nullptr; {
                std::lock_guard lock(workers_mutex_);
                if (workers_.empty()) return;

                std::size_t total_queue_depth = injector_.size();
                std::size_t active_busy = 0;

                for (const auto &w: workers_) {
                    total_queue_depth += w->queue->size();
                    if (w->is_busy) ++active_busy;
                }

                const std::size_t aggregate_load = total_queue_depth + active_busy;
                const std::size_t current_count = workers_.size();

                // ── 1. Scale UP (Proportional Step Scaling) ──────────────────
                if (current_count < config_.max_workers) {
                    const std::size_t tidx = current_count - 1;
                    const std::size_t high_thresh = (tidx < config_.upper_thresholds.size())
                                                        ? config_.upper_thresholds[tidx]
                                                        : 50;

                    if (aggregate_load > high_thresh) {
                        scale_down_cooldown_counter_ = 0;

                        // Determine target worker count based on upper thresholds
                        std::size_t target_workers = current_count + 1;
                        for (std::size_t k = current_count + 1; k <= config_.max_workers; ++k) {
                            const std::size_t k_idx = k - 1;
                            const std::size_t k_thresh = (k_idx < config_.upper_thresholds.size())
                                                             ? config_.upper_thresholds[k_idx]
                                                             : (50 * k_idx);
                            if (aggregate_load > k_thresh) {
                                target_workers = k;
                            } else {
                                break;
                            }
                        }

                        const std::size_t needed = (target_workers > current_count)
                                                       ? (target_workers - current_count)
                                                       : 1;
                        const std::size_t divider = (config_.scale_up_divider > 0) ? config_.scale_up_divider : 1;
                        const std::size_t step = std::max<std::size_t>(1, needed / divider);
                        const std::size_t to_add = std::min(step, config_.max_workers - current_count);

                        for (std::size_t i = 0; i < to_add; ++i) {
                            add_worker_unlocked();
                        }
                        return;
                    }
                }

                // ── 2. Scale DOWN (Hysteresis Cooldown Buffer) ───────────────
                if (current_count > config_.min_workers) {
                    const std::size_t tidx = current_count - 2;
                    const std::size_t low_thresh = (tidx < config_.lower_thresholds.size())
                                                       ? config_.lower_thresholds[tidx]
                                                       : 5;

                    if (aggregate_load < low_thresh) {
                        ++scale_down_cooldown_counter_;
                        if (scale_down_cooldown_counter_ >= config_.scale_down_cooldown_cycles) {
                            scale_down_cooldown_counter_ = 0;
                            // A worker that owns live connection coroutines must not be retired: stopping its
                            // io_context would strand them (sockets stay open, frames never resume, and the
                            // reactor keeps handlers that point at a destroyed context). Unpublish the slot
                            // first, then look at the count; if anything is (or just became) live, put it back.
                            const std::size_t slot = workers_.size() - 1;
                            const auto &candidate = workers_.back();
                            if (slot < kMaxWorkerSlots) {
                                worker_table_[slot].store(nullptr, std::memory_order_seq_cst);
                            }
                            worker_count_.store(slot, std::memory_order_seq_cst);
                            if (candidate->live_coroutines->load(std::memory_order_seq_cst) != 0) {
                                if (slot < kMaxWorkerSlots) {
                                    worker_table_[slot].store(candidate.get(), std::memory_order_seq_cst);
                                }
                                worker_count_.store(slot + 1, std::memory_order_seq_cst);
                            } else {
                                retiring_worker = candidate;
                                workers_.pop_back();
                            }
                        }
                    } else {
                        scale_down_cooldown_counter_ = 0;
                    }
                } else {
                    scale_down_cooldown_counter_ = 0;
                }
            }

            if (retiring_worker) {
                decommission_worker(retiring_worker);
                retired_.push_back(std::move(retiring_worker));
            }
            reclaim_retired();
        }

        /// Destroy retired nodes once no thread can still hold a raw pointer to them. They were unpublished
        /// (worker_table_ slot cleared, seq_cst) before being parked, and thieves bump active_thieves_
        /// (seq_cst) before reading the table, so a zero here means every thief that could have seen the node
        /// has left the steal loop and any later one cannot find it.
        void reclaim_retired() {
            if (!retired_.empty() && active_thieves_.load(std::memory_order_seq_cst) == 0) {
                retired_.clear();
            }
        }

        static void decommission_worker(const std::shared_ptr<WorkerNode> &retiring) {
            retiring->is_retiring = true;
            retiring->stop_requested = true;
            retiring->work_guard.reset();
            if (retiring->io_ctx) retiring->io_ctx->stop();

            if (retiring->thread.joinable())
                retiring->thread.join();
        }
    };
} // namespace wavex::server
