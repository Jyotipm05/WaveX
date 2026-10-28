// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * @file Memory.hpp
 * @brief Per-request monotonic arena allocator and connection-scoped slab pool.
 *
 * Architecture (3-tier):
 *   Tier 0: RequestArena (std::pmr::monotonic_buffer_resource) — 4KB initial block size
 *           allocated lazily from connection pool, bump allocation, 0 malloc calls
 *   Tier 1: ConnectionMemoryPool (std::pmr::unsynchronized_pool_resource) — connection-scoped
 *           thread-safe slab pool
 *   Tier 2: std::pmr::new_delete_resource() — global heap fallback (thread-safe)
 *
 * Lifecycle:
 *   - ConnectionMemoryPool is created once per connection (connection-scoped).
 *   - RequestArena is constructed at the start of processing each HTTP request
 *     (request-scoped). Its initial 4KB block is allocated lazily from ConnectionMemoryPool.
 *   - The arena is declared before the request/response objects, so scope exit destroys
 *     them first and then the arena, reclaiming all memory in O(1) and returning slabs
 *     to the ConnectionMemoryPool. An explicit arena.release() is only valid once every
 *     object allocated from the arena has been destroyed.
 *   - When the connection becomes idle (no request in flight), conn_pool.release() returns every
 *     block the pool holds to the heap. It does not distinguish cached from live blocks, so it is
 *     only valid while nothing allocated from the pool is still alive.
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
#include <memory>
#include <memory_resource>
#include <new>

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
     * for requests exceeding the initial block size.
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
        // Deliberately unsynchronized. A connection's coroutine runs serialized (one resumption at a time, with
        // the executor hand-off providing the happens-before edge when it hops workers), so the pool is never
        // used concurrently. synchronized_pool_resource is not an option: libstdc++ allocates a pthread key per
        // instance and Linux caps keys at 1024 (PTHREAD_KEYS_MAX), so the 1025th live connection would throw
        // EAGAIN from its constructor.
        std::pmr::unsynchronized_pool_resource pool_;

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

        /**
         * @brief Return every block held by the pool to the upstream heap.
         * @warning This frees live allocations too (std::pmr::unsynchronized_pool_resource::release()
         *          semantics). Call it only when nothing allocated from resource() is still alive, e.g.
         *          while the connection idles between requests. The pool stays usable afterwards.
         */
        void release() noexcept {
            pool_.release();
        }
    };

    /**
     * @class RequestArena
     * @brief Movable RAII handle owning a monotonic bump allocator (4KB initial block).
     *
     * Constructed once per HTTP request and destroyed (or reset via release()) at the
     * end of each request. All allocations within a request advance a single bump
     * pointer — O(1) allocation. Blocks come from upstream (ConnectionMemoryPool or
     * global new/delete).
     *
     * The monotonic_buffer_resource itself is neither copyable nor movable, and every
     * object allocated from it stores a pointer to it. RequestArena therefore keeps the
     * resource at a *stable heap address* (carved from the same upstream) and is itself
     * only a 2-pointer handle: moving the handle never changes resource(), so objects
     * already allocated from the arena stay valid. The destructor releases all blocks
     * and returns the control block to upstream.
     *
     * Moved-from state: resource() returns nullptr, release() is a no-op. Request and
     * Response treat a null resource as the default resource.
     *
     * LIFETIME RULE: every object that allocated from this arena (pmr::string, Request,
     * Response, ...) must be destroyed BEFORE release() or the arena's destruction.
     * Some standard libraries (e.g. MSVC STL with iterator debugging) touch allocator
     * memory inside container destructors, so destroying such an object after
     * release() is a use-after-free even though pmr deallocation is a no-op.
     * Declare the arena before the objects that use it so reverse-order destruction
     * is correct automatically, and prefer scope exit over an explicit release().
     *
     * Fallback for allocations > 4KB uses ConnectionMemoryPool or get_default_upstream_resource()
     * (global new/delete), guaranteeing safety across multi-worker thread transitions and
     * worker scale-down events (Issue F2).
     */
    class RequestArena {
    public:
        // ─── 1. Constants & Definitions (TOP) ────────────────────────────────
        static constexpr std::size_t kInitialBlockSize = 4096;
        static constexpr std::size_t kInlineBytes = kInitialBlockSize; ///< Backward compatibility alias

    private:
        using Resource = std::pmr::monotonic_buffer_resource;

        /// Destroys the resource (returning its blocks to upstream) and then
        /// returns the control block itself to the upstream it was carved from.
        struct Deleter {
            std::pmr::memory_resource *host;

            void operator()(Resource *p) const noexcept {
                if (p == nullptr) return;
                p->~Resource();
                host->deallocate(p, sizeof(Resource), alignof(Resource));
            }
        };

        using Handle = std::unique_ptr<Resource, Deleter>;

        static Handle make(std::pmr::memory_resource *upstream) {
            std::pmr::memory_resource *const up = upstream ? upstream : get_default_upstream_resource();
            void *raw = up->allocate(sizeof(Resource), alignof(Resource));
            // monotonic_buffer_resource's constructor is noexcept and allocates lazily,
            // so nothing can leak between allocate() and the unique_ptr taking ownership.
            return Handle(::new(raw) Resource(kInitialBlockSize, up), Deleter{up});
        }

        // ─── 2. Member Variables (SECOND - Ordered for Minimal Padding) ────
        Handle mr_;

    public:
        // ─── 3. Constructors & Destructor (MIDDLE) ─────────────────────────
        RequestArena()
            : mr_(make(nullptr)) {
        }

        /// @throws std::bad_alloc if the upstream cannot provide the control block.
        explicit RequestArena(std::pmr::memory_resource *upstream)
            : mr_(make(upstream)) {
        }

        ~RequestArena() = default;

        // Not copyable: allocated objects point at the resource, so a copy is meaningless.
        RequestArena(const RequestArena &) = delete;
        RequestArena &operator=(const RequestArena &) = delete;

        // Movable: the resource keeps its address, so existing allocations stay valid.
        // Move-assignment destroys this arena's previous resource (and its blocks).
        RequestArena(RequestArena &&) noexcept = default;
        RequestArena &operator=(RequestArena &&) noexcept = default;

        // ─── 4. Member Functions & Friend Declarations (LAST) ──────────────
        /**
         * @brief Returns the PMR memory resource backed by this arena.
         * Pass this pointer to any PMR-aware container or allocator.
         * Returns nullptr for a moved-from arena.
         */
        [[nodiscard]] std::pmr::memory_resource *resource() const noexcept {
            return mr_.get();
        }

        /**
         * @brief O(1) release — resets the bump pointer and returns overflow blocks to upstream.
         *
         * All memory allocated from this arena since construction (or since the
         * last release()) is reclaimed instantly. Every object allocated from the
         * arena must already be destroyed (see the lifetime rule above).
         */
        void release() const noexcept {
            if (mr_) mr_->release();
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
