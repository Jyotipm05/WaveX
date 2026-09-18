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
 *   1. Try to push into the next round-robin worker's LocalQueue
 *   2. If the LocalQueue is full (≥255 tasks), spill to InjectorQueue
 */

#pragma once

#ifndef ASIO_HAS_CO_AWAIT
#define ASIO_HAS_CO_AWAIT 1
#endif


#include <array>
#include <atomic>
#include <chrono>
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
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * @class ThreadPoolConfig
     * @brief Singleton configuration for thread pool limits and scaling thresholds.
     */
    class ThreadPoolConfig {
    public:
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

        ThreadPoolConfig() {
            if (upper_thresholds.size() < max_workers - 1)
                upper_thresholds.resize(max_workers - 1, 50);
            if (lower_thresholds.size() < max_workers - 1)
                lower_thresholds.resize(max_workers - 1, 10);
        }

        std::size_t min_workers = default_min_workers();
        std::size_t max_workers = default_max_workers();

        /// Scale-up divider for proportional step calculation: step = max(1, (target - current) / scale_up_divider)
        std::size_t scale_up_divider = 2;

        /// Number of consecutive low-load evaluation cycles before decommissioning a worker thread
        std::size_t scale_down_cooldown_cycles = 3;

        /// Upper load thresholds to trigger scale-up at N threads (index N-1)
        std::vector<std::size_t> upper_thresholds = {10, 25, 50, 100};

        /// Lower load thresholds to trigger scale-down at N threads (index N-2)
        std::vector<std::size_t> lower_thresholds = {5, 15, 30, 60};

        /// Interval between hysteresis scaling evaluations
        std::chrono::milliseconds check_interval{100};

        void set_limits(std::size_t min_w, std::size_t max_w) {
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
        std::size_t id = 0;
        std::shared_ptr<asio::io_context> io_ctx;
        asio::executor_work_guard<asio::io_context::executor_type> work_guard;
        std::unique_ptr<LocalQueue> queue; ///< Bounded 256-slot lock-free ring buffer
        std::atomic<bool> is_retiring{false};
        std::atomic<bool> is_busy{false};
        std::atomic<bool> stop_requested{false};
        std::thread thread;

        explicit WorkerNode(const std::size_t worker_id)
            : id(worker_id),
              io_ctx(std::make_shared<asio::io_context>()),
              work_guard(asio::make_work_guard(*io_ctx)),
              queue(std::make_unique<LocalQueue>()) {
        }
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
    public:
        explicit ThreadPool(ThreadPoolConfig &config = ThreadPoolConfig::instance())
            : config_(config) {
            start_pool();
        }

        ~ThreadPool() {
            stop_pool();
        }

        ThreadPool(const ThreadPool &) = delete;

        ThreadPool &operator=(const ThreadPool &) = delete;

        /**
         * @brief Submit a generic task to the pool.
         *
         * Tries to push into the next round-robin worker's LocalQueue first.
         * Falls back to the InjectorQueue if the local ring is full (lock-free fast path).
         */
        void dispatch(Task task) {
            const std::size_t count = worker_count_.load(std::memory_order_acquire);
            if (count == 0) {
                // No workers yet — queue directly into injector
                injector_.push(std::move(task));
                check_burst_spill();
                return;
            }
            const std::size_t idx = next_worker_idx_.fetch_add(1, std::memory_order_relaxed) % count;
            auto *w = (idx < kMaxWorkerSlots) ? worker_table_[idx].load(std::memory_order_acquire) : nullptr;
            if (!w || !w->queue->push(std::move(task))) {
                // LocalQueue full or slot unavailable → spill to global injector
                injector_.push(std::move(task));
                check_burst_spill();
            }
        }

        /**
         * @brief Spawn an Asio coroutine onto one of the worker io_contexts (lock-free fast path).
         */
        template<typename Coro>
        void spawn_coroutine(Coro coro) {
            const std::size_t count = worker_count_.load(std::memory_order_acquire);
            if (count == 0) return;
            const std::size_t idx = next_worker_idx_.fetch_add(1, std::memory_order_relaxed) % count;
            auto *w = (idx < kMaxWorkerSlots) ? worker_table_[idx].load(std::memory_order_acquire) : nullptr;
            if (w && w->io_ctx) {
                asio::co_spawn(*w->io_ctx, std::move(coro), asio::detached);
            }
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
            std::lock_guard<std::mutex> lock(workers_mutex_);
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
            std::lock_guard<std::mutex> lock(workers_mutex_);
            return scale_down_cooldown_counter_;
        }

        // ── Lifecycle ──────────────────────────────────────────────────────

        void start_pool() {
            std::lock_guard<std::mutex> lock(workers_mutex_);
            for (std::size_t i = 0; i < config_.min_workers; ++i)
                add_worker_unlocked();
            pool_stopping_ = false;
            monitor_thread_ = std::thread([this] { monitor_loop(); });
        }

        void stop_pool() { {
                std::lock_guard<std::mutex> lock(monitor_mutex_);
                pool_stopping_ = true;
            }
            cv_monitor_.notify_all();
            if (monitor_thread_.joinable())
                monitor_thread_.join();

            std::vector<std::shared_ptr<WorkerNode> > to_join; {
                std::lock_guard<std::mutex> lock(workers_mutex_);
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

            for (auto &w: to_join) {
                if (w->thread.joinable())
                    w->thread.join();
            }
        }

    private:
        static constexpr std::size_t kMaxWorkerSlots = 128;

        ThreadPoolConfig &config_;
        mutable std::mutex workers_mutex_;
        std::vector<std::shared_ptr<WorkerNode> > workers_;
        std::array<std::atomic<WorkerNode *>, kMaxWorkerSlots> worker_table_{};
        std::atomic<std::size_t> worker_count_{0};
        std::atomic<std::size_t> burst_spill_count_{0};
        InjectorQueue injector_; ///< Global overflow & external submission queue
        std::atomic<bool> pool_stopping_{false};
        std::thread monitor_thread_;
        std::condition_variable cv_monitor_;
        mutable std::mutex monitor_mutex_;
        bool monitor_signal_{false};
        std::atomic<std::size_t> next_worker_idx_{0};
        std::size_t scale_down_cooldown_counter_{0};

        void check_burst_spill() noexcept {
            if (burst_spill_count_.fetch_add(1, std::memory_order_relaxed) + 1 >= 8) {
                burst_spill_count_.store(0, std::memory_order_relaxed);
                notify_monitor();
            }
        }

        void notify_monitor() { {
                std::lock_guard<std::mutex> lock(monitor_mutex_);
                monitor_signal_ = true;
            }
            cv_monitor_.notify_one();
        }

        void add_worker_unlocked() {
            const std::size_t new_id = workers_.size() + 1;
            auto worker = std::make_shared<WorkerNode>(new_id);
            const std::size_t slot = workers_.size();
            if (slot < kMaxWorkerSlots) {
                worker_table_[slot].store(worker.get(), std::memory_order_release);
                worker_count_.store(slot + 1, std::memory_order_release);
            }
            worker->thread = std::thread([this, w = worker] { worker_loop(w); });
            workers_.emplace_back(std::move(worker));
        }

        // ── Worker loop ────────────────────────────────────────────────────

        void worker_loop(const std::shared_ptr<WorkerNode> &w) {
            // Seed per-thread RNG for randomised steal target selection.
            std::mt19937 rng{std::random_device{}()};

            while (!w->stop_requested && !w->is_retiring) {
                // ── 1. Pop from own LocalQueue (LIFO, cache-local) ──────────
                if (auto task = w->queue->pop()) {
                    w->is_busy = true;
                    (*task)();
                    w->is_busy = false;
                    continue;
                }

                // ── 2. Steal from a random peer's LocalQueue (FIFO, lock-free)
                {
                    const std::size_t n = worker_count_.load(std::memory_order_acquire);
                    if (n > 1) {
                        // Pick a random start to avoid thundering-herd on worker 0.
                        const std::size_t start = rng() % n;
                        for (std::size_t i = 0; i < n; ++i) {
                            auto *other = worker_table_[(start + i) % n].load(std::memory_order_acquire);
                            if (other && other->id != w->id && !other->is_retiring.load(std::memory_order_relaxed)) {
                                if (auto stolen = other->queue->steal_half(*w->queue)) {
                                    w->is_busy = true;
                                    (*stolen)();
                                    w->is_busy = false;
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
                std::unique_lock<std::mutex> lock(monitor_mutex_);
                cv_monitor_.wait_for(lock, config_.check_interval, [this] {
                    return pool_stopping_ || monitor_signal_;
                });
                if (pool_stopping_) break;
                monitor_signal_ = false;
                lock.unlock();

                check_and_scale();
            }
        }

        void check_and_scale() {
            std::shared_ptr<WorkerNode> retiring_worker = nullptr; {
                std::lock_guard<std::mutex> lock(workers_mutex_);
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
                            retiring_worker = workers_.back();
                            const std::size_t slot = workers_.size() - 1;
                            worker_count_.store(slot, std::memory_order_release);
                            if (slot < kMaxWorkerSlots) {
                                worker_table_[slot].store(nullptr, std::memory_order_release);
                            }
                            workers_.pop_back();
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
