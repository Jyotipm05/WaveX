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
     * @brief Returns the calling thread's lock-free slab pool.
     *
     * Each worker thread owns its own unsynchronized_pool_resource, so there
     * is zero mutex contention between threads. Connections are pinned to a
     * single worker thread, guaranteeing single-threaded access to this pool
     * during any given request lifecycle.
     *
     * Call .release() on the returned pool when the worker thread is idle to
     * return cached slab memory back to the global heap / OS.
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
     * @class RequestArena
     * @brief RAII wrapper combining a 4KB inline buffer with a monotonic bump allocator.
     *
     * Constructed once per HTTP request, destroyed (or reset via release()) at
     * the end of each request. All allocations within a request advance a single
     * bump pointer — O(1) allocation with zero calls to global malloc for
     * requests whose total allocation footprint fits within 4KB.
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
        static constexpr std::size_t kInlineBytes = 4096;

        RequestArena() noexcept
            : mr_(buf_.data(), buf_.size(), &get_thread_local_pool()) {
        }

        // Non-copyable, non-movable — lifetime is tied to the request block.
        RequestArena(const RequestArena &) = delete;

        RequestArena &operator=(const RequestArena &) = delete;

        RequestArena(RequestArena &&) = delete;

        RequestArena &operator=(RequestArena &&) = delete;

        ~RequestArena() = default;

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

    private:
        /// 4KB inline buffer, cache-line aligned to avoid false sharing
        alignas(64) std::array<std::byte, kInlineBytes> buf_{};
        /// Monotonic bump allocator backed by buf_, overflowing to thread-local pool
        std::pmr::monotonic_buffer_resource mr_;
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
        void *raw = mr->allocate(sizeof(T), alignof(T));
        return ::new(raw) T(std::forward<Args>(args)...);
    }
} // namespace wavex::memory
