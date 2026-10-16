// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * @file Memory.hpp
 * @brief Per-request monotonic arena allocator and thread-local slab pool.
 *
 * Architecture (3-tier):
 *   Tier 0: 4KB alignas(64) inline buffer — bump allocation, 0 malloc calls
 *   Tier 1: thread_local unsynchronized_pool_resource — 0 locks, fast slab alloc
 *   Tier 2: std::pmr::new_delete_resource() — global heap fallback (rare)
 *
 * Lifecycle:
 *   - RequestArena is constructed at the *start* of processing each HTTP request
 *     (request-scoped, NOT connection-scoped).
 *   - arena.release() is called at the *end* of each request to reclaim all
 *     arena memory in O(1) — a single pointer reset with zero free() calls.
 *   - The 4KB inline buffer lives on the stack/frame of the request block and
 *     is destroyed when the request scope exits.
 *
 * Idle trimming:
 *   - Call wavex::memory::get_thread_local_pool().release() when a worker thread
 *     is idle to return cached slab memory to the OS.
 *   - server.trim_memory() posts this call to all worker threads.
 *
 * string_view safety contract:
 *   - Views allocated into the arena (req.params, req.query, res.headers_) are
 *     valid ONLY within the current request coroutine turn, until the next
 *     co_await point that could reach arena.release().
 *   - For ephemeral in-turn use (filters, validators, DB queries): use string_view directly.
 *   - For escaping use (spawn_blocking, global cache): convert to std::string at boundary.
 */

#pragma once

#include <array>
#include <cstddef>
#include <memory_resource>

namespace wavex::memory {
    /**
     * @brief Returns the default thread-safe upstream memory resource for RequestArena.
     *
     * In multi-worker architectures where coroutines can suspend, migrate,
     * or be stolen across worker threads, using an unsynchronized thread-local pool
     * causes data races on cross-thread deallocation and use-after-free if a worker
     * thread terminates during scale-down.
     *
     * std::pmr::new_delete_resource() provides global, thread-safe fallback allocation
     * for the rare requests whose memory footprint exceeds the 4KB inline buffer.
     */
    [[nodiscard]] inline std::pmr::memory_resource *get_default_upstream_resource() noexcept {
        return std::pmr::new_delete_resource();
    }

    /**
     * @brief Returns the calling thread's lock-free slab pool.
     *
     * NOTE: This pool is strictly thread-local (unsynchronized_pool_resource).
     * It must ONLY be used for single-threaded tasks where execution is guaranteed
     * never to migrate across threads (no task stealing or multi-threaded coroutine resumptions).
     * For coroutines and RequestArena, use get_default_upstream_resource() or
     * ConnectionMemoryPool to avoid data races and use-after-free on worker thread exit.
     */
    [[nodiscard]] inline std::pmr::unsynchronized_pool_resource &get_thread_local_pool() noexcept {
        // Upstream fallback is the global new/delete heap (Tier 2).
        thread_local std::pmr::unsynchronized_pool_resource pool{
            std::pmr::pool_options{
                .max_blocks_per_chunk = 64,
                .largest_required_pool_block = 1024 * 1024 // 1MB max slab
            },
            std::pmr::new_delete_resource()
        };
        return pool;
    }

    /**
     * @class ConnectionMemoryPool
     * @brief Per-connection memory resource that outlives any single request
     *        and travels safely with the connection coroutine across worker thread hops.
     *
     * Tied to the connection lifetime rather than any single worker thread. Provides pooling
     * across sequential requests on keep-alive connections without risk of worker
     * thread-local lifetime hazards or cross-thread data races.
     */
    class ConnectionMemoryPool {
    private:
        // ─── 2. Member Variables (SECOND - Ordered for Minimal Padding) ────
        std::pmr::synchronized_pool_resource pool_;

    public:
        // ─── 3. Constructors & Destructor (MIDDLE) ─────────────────────────
        ConnectionMemoryPool()
            : pool_(std::pmr::pool_options{
                        .max_blocks_per_chunk = 32,
                        .largest_required_pool_block = 512 * 1024
                    },
                    std::pmr::new_delete_resource()) {}

        explicit ConnectionMemoryPool(const std::pmr::pool_options &opts)
            : pool_(opts, std::pmr::new_delete_resource()) {}

        ~ConnectionMemoryPool() = default;

        ConnectionMemoryPool(const ConnectionMemoryPool &) = delete;
        ConnectionMemoryPool &operator=(const ConnectionMemoryPool &) = delete;
        ConnectionMemoryPool(ConnectionMemoryPool &&) = delete;
        ConnectionMemoryPool &operator=(ConnectionMemoryPool &&) = delete;

        // ─── 4. Member Functions & Friend Declarations (LAST) ──────────────
        [[nodiscard]] std::pmr::memory_resource *resource() noexcept {
            return &pool_;
        }
    };

    /**
     * @class RequestArena
     * @brief RAII wrapper combining a 4KB inline buffer with a monotonic bump allocator.
     *
     * Constructed once per HTTP request, destroyed (or reset via release()) at
     * the end of each request. All allocations within a request advance a single
     * bump pointer — O(1) allocation with zero calls to global malloc for
     * requests whose total allocation footprint fits within 4KB.
     *
     * Fallback for allocations > 4KB uses get_default_upstream_resource() (global new/delete)
     * or a custom per-connection resource, guaranteeing safety across multi-worker thread
     * transitions and worker scale-down events (Issue F2).
     *
     * Usage in Server::handle_connection():
     * @code
     *   while (is_running_) {
     *       wavex::memory::RequestArena arena;
     *       RequestType  req(arena.resource());
     *       ResponseType res(arena.resource());
     *       // ... parse, route, handle, serialize, write ...
     *       arena.release(); // O(1) reclamation
     *   }
     * @endcode
     */
    class RequestArena {
    public:
        // ─── 1. Constants & Definitions ──────────────────────────────────────
        static constexpr std::size_t kInlineBytes = 4096;

    private:
        // ─── 2. Member Variables (Arranged for cache-line alignment) ─────────
        alignas(64) std::array<std::byte, kInlineBytes> buf_{};
        std::pmr::monotonic_buffer_resource mr_;

    public:
        // ─── 3. Constructors & Destructor ────────────────────────────────────
        RequestArena() noexcept
            : buf_{}, mr_(buf_.data(), buf_.size(), get_default_upstream_resource()) {
        }

        explicit RequestArena(std::pmr::memory_resource *upstream) noexcept
            : buf_{}, mr_(buf_.data(), buf_.size(), upstream ? upstream : get_default_upstream_resource()) {
        }

        ~RequestArena() = default;

        // Non-copyable, non-movable — lifetime is tied to the request block.
        RequestArena(const RequestArena &) = delete;

        RequestArena &operator=(const RequestArena &) = delete;

        RequestArena(RequestArena &&) = delete;

        RequestArena &operator=(RequestArena &&) = delete;

        // ─── 4. Member Functions ─────────────────────────────────────────────
        /**
         * @brief Returns the PMR memory resource backed by this arena.
         * Pass this pointer to any PMR-aware container or allocator.
         */
        [[nodiscard]] std::pmr::memory_resource *resource() noexcept {
            return &mr_;
        }

        /**
         * @brief O(1) release — resets the bump pointer to offset 0.
         *
         * All memory allocated from this arena since construction (or since the
         * last release()) is reclaimed instantly. No destructors are called on
         * trivially reclaimable objects (FlatMap entries, string_view pairs).
         *
         * After calling release(), the arena is ready for a fresh request.
         */
        void release() noexcept {
            mr_.release();
        }
    };

    /**
     * @brief Construct a T directly in the arena using placement new.
     *
     * The constructed object's memory is reclaimed by arena.release(). If T is
     * not trivially destructible, the caller is responsible for calling its
     * destructor before the arena is released.
     *
     * @tparam T    Type to construct. Must be allocatable from `mr`.
     * @param mr    Memory resource to allocate from (typically arena.resource()).
     * @param args  Constructor arguments forwarded to T.
     * @return      Pointer to the constructed object (valid until arena.release()).
     */
    template<typename T, typename... Args>
    [[nodiscard]] T *make_in_arena(std::pmr::memory_resource *mr, Args &&... args) {
        [[assume(mr != nullptr)]];
        void *raw = mr->allocate(sizeof(T), alignof(T));
        [[assume(raw != nullptr)]];
        return ::new(raw) T(std::forward<Args>(args)...);
    }
} // namespace wavex::memory
