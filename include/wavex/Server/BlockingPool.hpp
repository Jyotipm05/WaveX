// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * @file BlockingPool.hpp
 * @brief Elastic thread pool for offloading synchronous, blocking, or CPU-heavy tasks.
 *
 * Employs a dynamic circular ring queue for zero-allocation task dispatching in
 * steady state, with elastic worker thread scaling modeled after Tokio's spawn_blocking pool.
 */

#pragma once

#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>
#include <algorithm>

namespace wavex::server {
    /**
     * @class BlockingTask
     * @brief Type-erased, move-only callable container for blocking task dispatch.
     *        Avoids std::function constraint evaluation issues on MSVC STL with Clangd.
     */
    class BlockingTask {
        struct Concept {
            virtual ~Concept() = default;

            virtual void invoke() = 0;
        };

        template<typename F>
        struct Model final : Concept {
            F fn;

            explicit Model(F &&f) : fn(std::forward<F>(f)) {
            }

            void invoke() override { fn(); }
        };

        std::unique_ptr<Concept> self_;

    public:
        BlockingTask() = default;

        template<typename F>
            requires (!std::is_same_v<std::decay_t<F>, BlockingTask> && std::is_invocable_v<F>)
        BlockingTask(F &&f) : self_(std::make_unique<Model<std::decay_t<F> > >(std::forward<F>(f))) {
        }

        BlockingTask(BlockingTask &&) noexcept = default;

        BlockingTask &operator=(BlockingTask &&) noexcept = default;

        BlockingTask(const BlockingTask &) = delete;

        BlockingTask &operator=(const BlockingTask &) = delete;

        explicit operator bool() const noexcept { return static_cast<bool>(self_); }

        void operator()() const {
            if (self_) self_->invoke();
        }
    };

    /**
     * @class RingQueue
     * @brief High-performance dynamic circular ring buffer.
     *        Pre-allocates slots and operates with O(1) push/pop and zero heap
     *        allocations during steady-state execution.
     */
    template<typename T>
    class RingQueue {
    private:
        // ─── 1. Member Variables (Arranged for minimum padding) ──────────────
        std::vector<T> buffer_;
        std::size_t capacity_{0};
        std::size_t mask_{0};
        std::size_t head_{0};
        std::size_t tail_{0};
        std::size_t count_{0};

    public:
        // ─── 2. Constructors & Destructor ────────────────────────────────────
        explicit RingQueue(std::size_t initial_capacity = 256)
            : buffer_(),
              capacity_(std::max<std::size_t>(16, round_up_pow2(initial_capacity))),
              mask_(capacity_ - 1),
              head_(0),
              tail_(0),
              count_(0) {
            buffer_.resize(capacity_);
        }

        ~RingQueue() = default;

        RingQueue(RingQueue &&) noexcept = default;
        RingQueue &operator=(RingQueue &&) noexcept = default;
        RingQueue(const RingQueue &) = default;
        RingQueue &operator=(const RingQueue &) = default;

        // ─── 3. Member Functions ─────────────────────────────────────────────
        void push(T &&item) {
            if (count_ == capacity_) {
                grow();
            }
            buffer_[tail_ & mask_] = std::move(item);
            ++tail_;
            ++count_;
        }

        T pop() {
            T item = std::move(buffer_[head_ & mask_]);
            ++head_;
            --count_;
            return item;
        }

        [[nodiscard]] bool empty() const noexcept {
            return count_ == 0;
        }

        [[nodiscard]] std::size_t size() const noexcept {
            return count_;
        }

        void clear() {
            buffer_.clear();
            capacity_ = 256;
            mask_ = capacity_ - 1;
            buffer_.resize(capacity_);
            head_ = 0;
            tail_ = 0;
            count_ = 0;
        }

    private:
        static std::size_t round_up_pow2(std::size_t v) {
            --v;
            v |= v >> 1;
            v |= v >> 2;
            v |= v >> 4;
            v |= v >> 8;
            v |= v >> 16;
            v |= v >> 32;
            return ++v;
        }

        void grow() {
            const std::size_t new_capacity = capacity_ * 2;
            std::vector<T> new_buffer;
            new_buffer.resize(new_capacity);

            for (std::size_t i = 0; i < count_; ++i) {
                new_buffer[i] = std::move(buffer_[(head_ + i) & mask_]);
            }

            buffer_ = std::move(new_buffer);
            head_ = 0;
            tail_ = count_;
            capacity_ = new_capacity;
            mask_ = capacity_ - 1;
        }
    };

    /**
     * @class BlockingThreadPool
     * @brief Dedicated thread pool executing blocking operations without starving
     *        the low-latency async I/O worker threads.
     */
    class BlockingThreadPool {
    public:
        // ─── 1. Nested Types & Definitions ──────────────────────────────────
        using Task = BlockingTask;

    private:
        // ─── 2. Member Variables (Arranged for minimum padding) ──────────────
        const std::size_t min_threads_;
        const std::size_t max_threads_;
        const std::chrono::milliseconds idle_timeout_;
        std::size_t total_count_{0};
        std::size_t idle_count_{0};
        mutable std::mutex mutex_;
        std::condition_variable cv_;
        RingQueue<Task> tasks_;
        std::vector<std::thread> threads_;
        bool stopping_{false};

    public:
        // ─── 3. Constructors & Destructor ────────────────────────────────────
        explicit BlockingThreadPool(
            std::size_t min_threads = 2,
            std::size_t max_threads = 128,
            std::chrono::milliseconds idle_timeout = std::chrono::milliseconds(10000))
            : min_threads_(std::max<std::size_t>(1, min_threads)),
              max_threads_(std::max<std::size_t>(min_threads_, max_threads)),
              idle_timeout_(idle_timeout),
              total_count_(0),
              idle_count_(0),
              mutex_(),
              cv_(),
              tasks_(256),
              threads_(),
              stopping_(false) {
            std::lock_guard<std::mutex> lock(mutex_);
            for (std::size_t i = 0; i < min_threads_; ++i) {
                spawn_worker_unlocked();
            }
        }

        ~BlockingThreadPool() {
            shutdown();
        }

        BlockingThreadPool(const BlockingThreadPool &) = delete;
        BlockingThreadPool &operator=(const BlockingThreadPool &) = delete;
        BlockingThreadPool(BlockingThreadPool &&) = delete;
        BlockingThreadPool &operator=(BlockingThreadPool &&) = delete;

        // ─── 4. Member Functions ─────────────────────────────────────────────
        /**
         * @brief Global singleton instance for blocking task offloading across the process.
         */
        static BlockingThreadPool &instance() {
            static BlockingThreadPool s_pool;
            return s_pool;
        }

        /**
         * @brief Dispatches a blocking task to the pool. Spawns an elastic worker if all
         *        existing workers are busy and the max thread limit has not been reached.
         * @param task Callable object representing the blocking work.
         */
        void dispatch(Task task) {
            std::lock_guard<std::mutex> lock(mutex_);
            if (stopping_) {
                return;
            }

            tasks_.push(std::move(task));

            // If there are no idle threads available to pick up this task immediately
            // ,and we have not hit max_threads_, scale up by spawning a new worker thread.
            if (idle_count_ == 0 && total_count_ < max_threads_) {
                spawn_worker_unlocked();
            }

            cv_.notify_one();
        }

        /**
         * @brief Returns current total number of worker threads (busy + idle).
         */
        [[nodiscard]] std::size_t thread_count() const {
            std::lock_guard<std::mutex> lock(mutex_);
            return total_count_;
        }

        /**
         * @brief Returns current number of idle worker threads waiting on the queue.
         */
        [[nodiscard]] std::size_t idle_count() const {
            std::lock_guard<std::mutex> lock(mutex_);
            return idle_count_;
        }

        /**
         * @brief Returns the number of tasks pending execution in the queue.
         */
        [[nodiscard]] std::size_t queue_size() const {
            std::lock_guard<std::mutex> lock(mutex_);
            return tasks_.size();
        }

        /**
         * @brief Shuts down the thread pool and joins all worker threads.
         */
        void shutdown() { {
                std::lock_guard<std::mutex> lock(mutex_);
                if (stopping_) {
                    return;
                }
                stopping_ = true;
            }
            cv_.notify_all();

            for (auto &t: threads_) {
                if (t.joinable()) {
                    t.join();
                }
            }

            std::lock_guard<std::mutex> lock(mutex_);
            threads_.clear();
            tasks_.clear();
            total_count_ = 0;
            idle_count_ = 0;
        }

    private:
        void spawn_worker_unlocked() {
            ++total_count_;
            threads_.emplace_back([this] {
                worker_loop();
            });
        }

        void worker_loop() {
            while (true) {
                Task task; {
                    std::unique_lock<std::mutex> lock(mutex_);
                    ++idle_count_;

                    while (!stopping_ && tasks_.empty()) {
                        // If we are above min_threads_, wait with timeout to allow elastic scale-down
                        if (total_count_ > min_threads_) {
                            if (cv_.wait_for(lock, idle_timeout_) == std::cv_status::timeout) {
                                if (tasks_.empty() && total_count_ > min_threads_) {
                                    // Worker timed out and can retire
                                    --idle_count_;
                                    --total_count_;
                                    return;
                                }
                            }
                        } else {
                            cv_.wait(lock);
                        }
                    }

                    --idle_count_;

                    if (stopping_ && tasks_.empty()) {
                        --total_count_;
                        return;
                    }

                    if (!tasks_.empty()) {
                        task = tasks_.pop();
                    }
                }

                if (task) {
                    try {
                        task();
                    } catch (...) {
                        // Exceptions are captured and propagated back to callers via spawn_blocking
                    }
                }
            }
        }
    };
} // namespace wavex::server
