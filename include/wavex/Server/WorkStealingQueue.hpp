// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
/**
 * @file WorkStealingQueue.hpp
 * @brief Tokio-style dual-queue system:
 *
 *   - LocalQueue   : Bounded, lock-free ring buffer (256 slots) per worker thread.
 *                    Owner pushes/pops from the back (LIFO, cache-local).
 *                    Thieves steal from the front (FIFO, work-stealing).
 *                    Uses Chase-Lev style atomic top/bottom indices.
 *
 *   - InjectorQueue: Unbounded, lock-based global MPMC queue.
 *                    Accepts tasks from any thread (external submitters, overflowed locals).
 *                    Workers drain it when their local queue is empty and stealing fails.
 */

#pragma once

#include <array>
#include <atomic>
#include <cstddef>
#include <functional>
#include <mutex>
#include <new>
#include <optional>
#include <type_traits>
#include <utility>
#include <vector>

namespace wavex::server {
    /**
     * @class InlineTask
     * @brief Zero-heap-allocation type-erased move-only task wrapper with SBO.
     *
     * In high-performance work-stealing systems (such as Tokio, Seastar, and WaveX),
     * task dispatch is on the ultra-hot path. Using std::function causes heap allocations
     * when captures exceed 16-24 bytes, and requires copy-constructibility.
     *
     * InlineTask provides:
     *   - In-place storage up to `Capacity` bytes (default 64) with std::max_align_t alignment.
     *   - Move-only semantics (supports unique_ptr, coroutine handles, etc.).
     *   - Transparent heap fallback if a closure exceeds Capacity (safe & universal).
     *   - Zero dynamic allocation overhead on all standard dispatch closures.
     */
    template<std::size_t Capacity = 64>
    class InlineTask {
        enum class Op { Destroy, Move };
        using InvokerFn = void (*)(void *);
        using ManagerFn = void (*)(Op, void *src, void *dst) noexcept;

        InvokerFn invoker_{nullptr};
        ManagerFn manager_{nullptr};
        alignas(std::max_align_t) std::byte storage_[Capacity];

    public:
        constexpr InlineTask() noexcept = default;

        constexpr InlineTask(std::nullptr_t) noexcept : invoker_(nullptr), manager_(nullptr) {}

        ~InlineTask() {
            reset();
        }

        InlineTask(const InlineTask &) = delete;
        InlineTask &operator=(const InlineTask &) = delete;

        InlineTask(InlineTask &&other) noexcept {
            if (other.manager_) [[likely]] {
                other.manager_(Op::Move, other.storage_, storage_);
                invoker_ = other.invoker_;
                manager_ = other.manager_;
                other.invoker_ = nullptr;
                other.manager_ = nullptr;
            }
        }

        InlineTask &operator=(InlineTask &&other) noexcept {
            if (this != &other) {
                reset();
                if (other.manager_) [[likely]] {
                    other.manager_(Op::Move, other.storage_, storage_);
                    invoker_ = other.invoker_;
                    manager_ = other.manager_;
                    other.invoker_ = nullptr;
                    other.manager_ = nullptr;
                }
            }
            return *this;
        }

        InlineTask &operator=(std::nullptr_t) noexcept {
            reset();
            return *this;
        }

        template<typename F>
            requires (!std::is_same_v<std::decay_t<F>, InlineTask> &&
                      !std::is_same_v<std::decay_t<F>, std::nullptr_t> &&
                      std::is_invocable_v<std::decay_t<F>&>)
        InlineTask(F &&f) {
            using DecayF = std::decay_t<F>;
            if constexpr (sizeof(DecayF) <= Capacity && alignof(DecayF) <= alignof(std::max_align_t)) {
                ::new (static_cast<void*>(storage_)) DecayF(std::forward<F>(f));
                invoker_ = [](void *ptr) {
                    (*reinterpret_cast<DecayF *>(ptr))();
                };
                manager_ = [](Op op, void *src, void *dst) noexcept {
                    auto *src_fn = reinterpret_cast<DecayF *>(src);
                    if (op == Op::Destroy) {
                        src_fn->~DecayF();
                    } else if (op == Op::Move) {
                        ::new (dst) DecayF(std::move(*src_fn));
                        src_fn->~DecayF();
                    }
                };
            } else {
                auto *heap_ptr = new DecayF(std::forward<F>(f));
                *reinterpret_cast<DecayF **>(storage_) = heap_ptr;
                invoker_ = [](void *ptr) {
                    auto *heap_ptr = *reinterpret_cast<DecayF **>(ptr);
                    (*heap_ptr)();
                };
                manager_ = [](Op op, void *src, void *dst) noexcept {
                    auto **src_ptr = reinterpret_cast<DecayF **>(src);
                    if (op == Op::Destroy) {
                        delete *src_ptr;
                        *src_ptr = nullptr;
                    } else if (op == Op::Move) {
                        auto **dst_ptr = reinterpret_cast<DecayF **>(dst);
                        *dst_ptr = *src_ptr;
                        *src_ptr = nullptr;
                    }
                };
            }
        }

        template<typename F>
            requires (!std::is_same_v<std::decay_t<F>, InlineTask> &&
                      !std::is_same_v<std::decay_t<F>, std::nullptr_t> &&
                      std::is_invocable_v<std::decay_t<F>&>)
        InlineTask &operator=(F &&f) {
            *this = InlineTask(std::forward<F>(f));
            return *this;
        }

        void reset() noexcept {
            if (manager_) {
                manager_(Op::Destroy, storage_, nullptr);
                invoker_ = nullptr;
                manager_ = nullptr;
            }
        }

        [[nodiscard]] explicit operator bool() const noexcept {
            return invoker_ != nullptr;
        }

        void operator()() {
            if (invoker_) [[likely]] {
                invoker_(storage_);
            }
        }

        void operator()() const {
            if (invoker_) [[likely]] {
                invoker_(const_cast<std::byte *>(storage_));
            }
        }
    };

    using Task = InlineTask<64>;

    // ─────────────────────────────────────────────────────────────────────────
    // LocalQueue — Bounded, lock-free ring buffer (256 slots)
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * @class LocalQueue
     * @brief Per-worker bounded lock-free ring buffer with 256 task slots.
     *
     * Based on the Chase-Lev work-stealing deque:
     *   - The **owner** thread calls push() and pop() (back operations).
     *   - **Thief** threads call steal() (front operation).
     *
     * Capacity is fixed at exactly 256 (CAPACITY). push() returns false on
     * overflow — the caller must spill into the InjectorQueue.
     *
     * Memory ordering:
     *   - bottom_ is only written by the owner thread (relaxed write, release on publish).
     *   - top_ is read by all threads, written only by thieves under CAS.
     *   - The slot array uses seq_cst to prevent reordering of the write-then-bottom-publish.
     */
    class LocalQueue {
    public:
        static constexpr std::size_t CAPACITY = 256;

        LocalQueue() : top_(0), bottom_(0) {
        }

        LocalQueue(const LocalQueue &) = delete;

        LocalQueue &operator=(const LocalQueue &) = delete;

        /**
         * @brief Owner-only: push a task onto the back of the ring.
         * @return true if queued, false if the ring is full (spill to InjectorQueue).
         * Note: If full, task is NOT moved from, allowing the caller to spill it to InjectorQueue.
         */
        [[nodiscard]] bool push(Task &&task) {
            [[assume((CAPACITY & (CAPACITY - 1)) == 0)]];
            const std::size_t b = bottom_.load(std::memory_order_relaxed);

            // Full check: ring has CAPACITY-1 usable slots to avoid ambiguity.
            if (const std::size_t t = top_.load(std::memory_order_acquire);
                b - t >= CAPACITY - 1) [[unlikely]]
                return false;

            slots_[b & MASK] = std::move(task);
            // Release so steal() readers see the fully-written task.
            bottom_.store(b + 1, std::memory_order_release);
            return true;
        }

        [[nodiscard]] bool push(Task &task) {
            return push(std::move(task));
        }

        /**
         * @brief Owner-only: pop a task from the back (LIFO — cache-hot).
         * @return The task, or std::nullopt if empty.
         */
        std::optional<Task> pop() {
            std::size_t b = bottom_.load(std::memory_order_relaxed);
            if (b == 0) [[unlikely]] return std::nullopt;
            b -= 1;
            bottom_.store(b, std::memory_order_relaxed);
            std::atomic_thread_fence(std::memory_order_seq_cst);

            if (std::size_t t = top_.load(std::memory_order_relaxed); t <= b) {
                if (t == b) [[unlikely]] {
                    // Last element in queue — race with a stealing thread.
                    if (!top_.compare_exchange_strong(t, t + 1,
                                                      std::memory_order_seq_cst, std::memory_order_relaxed)) [[unlikely]] {
                        // Lost race to a thief.
                        bottom_.store(b + 1, std::memory_order_relaxed);
                        return std::nullopt;
                    }
                    bottom_.store(b + 1, std::memory_order_relaxed);
                }
                // Won race (or t < b where thief operates on a different slot)
                Task task = std::move(slots_[b & MASK]);
                return task;
            }
            // Empty queue: restore bottom.
            bottom_.store(b + 1, std::memory_order_relaxed);
            return std::nullopt;
        }

        /**
         * @brief Thief-only: steal a single task from the front (FIFO).
         * @return The stolen task, or std::nullopt if empty or lost race.
         */
        std::optional<Task> steal() {
            std::size_t t = top_.load(std::memory_order_acquire);
            std::atomic_thread_fence(std::memory_order_seq_cst);

            if (const std::size_t b = bottom_.load(std::memory_order_acquire);
                t >= b) [[unlikely]]
                return std::nullopt; // Empty.

            // CAS first: claim slot t atomically BEFORE moving content
            if (!top_.compare_exchange_strong(t, t + 1,
                                              std::memory_order_seq_cst, std::memory_order_relaxed)) [[unlikely]] {
                return std::nullopt; // Lost race to another thief
            }
            Task task = std::move(slots_[t & MASK]);
            return task;
        }

        /**
         * @brief Thief-only: steal half of the tasks from this queue into dest_queue (batch stealing).
         * @param dest_queue The thief thread's own LocalQueue to push stolen batch into.
         * @return A task to execute immediately by the thief, or std::nullopt if empty or lost race.
         */
        std::optional<Task> steal_half(LocalQueue &dest_queue) {
            std::size_t t = top_.load(std::memory_order_acquire);
            std::atomic_thread_fence(std::memory_order_seq_cst);

            const std::size_t b = bottom_.load(std::memory_order_acquire);
            if (t >= b) [[unlikely]] return std::nullopt; // Empty.

            const std::size_t num_tasks = b - t;
            // Steal half of the available tasks (at least 1 task)
            const std::size_t steal_count = (num_tasks + 1) / 2;

            // Atomically reserve slots [t, t + steal_count)
            if (!top_.compare_exchange_strong(t, t + steal_count,
                                              std::memory_order_seq_cst, std::memory_order_relaxed)) [[unlikely]] {
                return std::nullopt; // Lost race to another thief
            }

            // 1 task to return to thief for immediate execution
            Task first_task = std::move(slots_[t & MASK]);

            // Remaining (steal_count - 1) tasks are pushed into dest_queue (the thief's local queue)
            for (std::size_t i = 1; i < steal_count; ++i) {
                if (Task remaining_task = std::move(slots_[(t + i) & MASK]); !dest_queue.
                    push(std::move(remaining_task))) {
                    // If thief's local queue overflows, remaining tasks are dropped/spilled
                    break;
                }
            }

            return first_task;
        }

        /// Approximate size (may race; used for load metrics only).
        [[nodiscard]] std::size_t size() const {
            const std::size_t b = bottom_.load(std::memory_order_relaxed);
            const std::size_t t = top_.load(std::memory_order_relaxed);
            return (b > t) ? (b - t) : 0;
        }

        [[nodiscard]] bool empty() const { return size() == 0; }

        /**
         * @brief Drain all remaining tasks (used only during worker retirement).
         * Called by the retiring owner thread after setting the stop flag,
         * so no concurrent steals occur.
         */
        std::vector<Task> drain_all() {
            std::vector<Task> drained;
            while (auto t = pop()) {
                drained.emplace_back(std::move(*t));
            }
            return drained;
        }

    private:
        static constexpr std::size_t MASK = CAPACITY - 1;
        static_assert((CAPACITY & MASK) == 0, "CAPACITY must be a power of 2");

        static constexpr std::size_t WAVEX_CACHE_LINE_SIZE = 64;

        alignas(WAVEX_CACHE_LINE_SIZE) std::atomic<std::size_t> top_{0};
        alignas(WAVEX_CACHE_LINE_SIZE) std::atomic<std::size_t> bottom_{0};
        alignas(WAVEX_CACHE_LINE_SIZE) std::array<Task, CAPACITY> slots_;
    };

    // ─────────────────────────────────────────────────────────────────────────
    // InjectorQueue — Unbounded, lock-based global MPMC queue
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * @class InjectorQueue
     * @brief Shared global task queue (the "injector" in Tokio terminology).
     *
     * Multiple producers and multiple consumers are supported under a single
     * std::mutex. This queue accepts:
     *   - Overflow tasks from LocalQueue::push() returning false.
     *   - Externally submitted tasks (e.g. ThreadPool::dispatch()).
     *
     * Workers drain this queue as a last resort when both their local ring
     * and work-stealing from peers have yielded nothing.
     */
    class InjectorQueue {
    public:
        InjectorQueue() = default;

        InjectorQueue(const InjectorQueue &) = delete;

        InjectorQueue &operator=(const InjectorQueue &) = delete;

        /// Push a task (any thread).
        void push(Task task) {
            std::lock_guard<std::mutex> lock(mutex_);
            queue_.push_back(std::move(task));
            size_.fetch_add(1, std::memory_order_relaxed);
        }

        /// Pop a task from the front (FIFO). Returns nullopt if empty.
        std::optional<Task> pop() {
            std::lock_guard<std::mutex> lock(mutex_);
            if (head_ >= queue_.size()) {
                if (!queue_.empty()) {
                    queue_.clear();
                    head_ = 0;
                    size_.store(0, std::memory_order_relaxed);
                }
                return std::nullopt;
            }
            Task task = std::move(queue_[head_++]);
            size_.fetch_sub(1, std::memory_order_relaxed);
            if (head_ >= queue_.size()) {
                queue_.clear();
                head_ = 0;
                size_.store(0, std::memory_order_relaxed);
            }
            return task;
        }

        /// Lock-free size query
        [[nodiscard]] std::size_t size() const {
            return size_.load(std::memory_order_relaxed);
        }

        /// Lock-free empty check
        [[nodiscard]] bool empty() const {
            return size_.load(std::memory_order_relaxed) == 0;
        }

    private:
        static constexpr std::size_t WAVEX_CACHE_LINE_SIZE = 64;

        alignas(WAVEX_CACHE_LINE_SIZE) mutable std::mutex mutex_;
        alignas(WAVEX_CACHE_LINE_SIZE) std::vector<Task> queue_;
        alignas(WAVEX_CACHE_LINE_SIZE) std::size_t head_ = 0;
        alignas(WAVEX_CACHE_LINE_SIZE) std::atomic<std::size_t> size_{0};
    };
} // namespace wavex::server
