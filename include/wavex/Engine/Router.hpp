// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * @file Router.hpp
 * @brief Protocol-agnostic hybrid radix-tree router with RE2 regex constraints.
 *
 * The Router<Proto> template is parameterised on a protocol type that must
 * provide a `Proto::method` enum type. This allows the same routing engine
 * to serve HTTP, MCP, GraphQL, or any future protocol.
 *
 * Static segments use compressed radix-tree edges.
 * Dynamic segments (:param, {name:regex}) and wildcards (*, *name) are checked
 * in priority order after static children fail.
 *
 * Provides a thread-safe singleton access pattern (`Router<Proto>::instance()`)
 * that maintains unique instance identity across both header inclusions and C++20
 * module imports according to the C++ standard ODR rules.
 *
 * Performance notes (resolve() hot path):
 *  - Path normalisation is allocation-free when the incoming path is already
 *    well-formed (leading '/', no trailing '/'), which is the common case for
 *    paths coming straight off an HTTP request line.
 *  - Segments are std::string_view slices into the (possibly caller-owned)
 *    path buffer instead of individually heap-allocated std::string objects.
 *  - Static-child dispatch is O(1) average via a string_view-keyed hash index
 *    rather than a linear scan; the index's views are safe because children
 *    are stored as unique_ptr<Node>, so a Node's address (and its `prefix`
 *    storage) never moves once created, even as sibling vectors reallocate.
 */

#pragma once

#ifndef ASIO_HAS_CO_AWAIT
#define ASIO_HAS_CO_AWAIT 1
#endif

#include <cassert>
#include <string>
#include <string_view>
#include <vector>
#include <unordered_map>
#include <optional>
#include <memory>
#include <functional>
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <array>
#include <span>

#include <re2/re2.h>

#include <wavex/Base/FlatMap.hpp>
#include <wavex/Base/MiddleWare.hpp>
#include <wavex/Base/Chainable.hpp>
#include <wavex/Base/MimeTypes.hpp>
#include <asio/awaitable.hpp>

namespace wavex::engine {
    /**
     * @class Router
     * @brief Protocol-agnostic radix-tree router.
     *
     * @tparam Proto Protocol type. Must have nested `method`, `request`, and `response` types.
     */
    template<typename Proto>
    class Router {
    public:
        using MethodType = Proto::method;
        using RequestType = Proto::request;
        using ResponseType = Proto::response;

        /// Handler signature for this router's protocol
        using Handler = std::function<asio::awaitable<void>(RequestType &, ResponseType &)>;

        /// 404 Not Found handler signature
        using NotFoundHandler = std::function<asio::awaitable<void>(RequestType &, ResponseType &)>;

        /// Middleware function signature for this router's protocol
        using MiddlewareFn = base::GenericMiddlewareFn<RequestType, ResponseType>;

        /**
         * @struct RouteMatch
         * @brief Result of a successful route resolution.
         *
         * `middlewares` is a span into the Node's pre-compiled static chain —
         * zero heap allocation, zero std::function copies per request.
         * `params` uses FlatMap<string_view, string_view> for zero-node allocation;
         * the string_view values slice directly into the request path buffer.
         */
        struct RouteMatch {
            // ─── 2. Member Variables (SECOND - Ordered for Minimal Padding) ────
            Handler handler;
            /// Pre-compiled middleware span into the matched Node's compiled_middlewares.
            /// Valid for the Server's lifetime (route table is never modified after listen()).
            std::span<const MiddlewareFn> middlewares;
            /// Path parameters extracted by the router — views into the request path buffer.
            base::FlatMap<std::string_view, std::string_view> params;

            // ─── 3. Constructors & Destructor (MIDDLE) ─────────────────────────
            RouteMatch() = default;
            RouteMatch(Handler h, std::span<const MiddlewareFn> mws, base::FlatMap<std::string_view, std::string_view> p)
                : handler(std::move(h)), middlewares(mws), params(std::move(p)) {}
            ~RouteMatch() = default;
            RouteMatch(const RouteMatch &) = default;
            RouteMatch &operator=(const RouteMatch &) = default;
            RouteMatch(RouteMatch &&) noexcept = default;
            RouteMatch &operator=(RouteMatch &&) noexcept = default;
        };

        /**
         * @struct ScopedMiddleware
         * @brief A middleware bound to a path prefix.
         */
        struct ScopedMiddleware {
            // ─── 2. Member Variables (SECOND - Ordered for Minimal Padding) ────
            std::string prefix;
            MiddlewareFn fn;

            // ─── 3. Constructors & Destructor (MIDDLE) ─────────────────────────
            ScopedMiddleware() = default;
            ScopedMiddleware(std::string p, MiddlewareFn f)
                : prefix(std::move(p)), fn(std::move(f)) {}
            ~ScopedMiddleware() = default;
            ScopedMiddleware(const ScopedMiddleware &) = default;
            ScopedMiddleware &operator=(const ScopedMiddleware &) = default;
            ScopedMiddleware(ScopedMiddleware &&) noexcept = default;
            ScopedMiddleware &operator=(ScopedMiddleware &&) noexcept = default;
        };

    protected:
        /**
         * @struct Node
         * @brief A single radix-tree node: a static edge, a param/wildcard
         *        binder, or both a route leaf (handlers) and an internal
         *        branch simultaneously.
         */
        struct Node {
            // ─── 2. Member Variables (SECOND - Ordered for Minimal Padding) ────
            std::unordered_map<MethodType, Handler> handlers{};
            std::unordered_map<MethodType, std::vector<MiddlewareFn>> route_middlewares{};
            /// Pre-compiled, immutable middleware chain for this node keyed by method:
            /// [global] -> [prefix-scoped] -> [per-route] middlewares.
            /// Built during freeze(). resolve() returns a std::span into this vector
            /// — zero heap allocation, zero std::function copies per request.
            std::unordered_map<MethodType, std::vector<MiddlewareFn>> compiled_middlewares{};
            std::unordered_map<std::string_view, Node *> static_index{};
            std::vector<std::unique_ptr<Node>> children{}; // static children (ownership)
            std::vector<std::unique_ptr<Node>> param_children{}; // dynamic/regex children
            std::string prefix{}; // segment label for static nodes
            std::string pattern{}; // original regex pattern string
            std::string param_name{}; // extracted parameter name
            std::shared_ptr<re2::RE2> constraint{}; // compiled RE2 regex constraint (shared via regex cache)
            std::unique_ptr<Node> wildcard_child{}; // * or *name catch-all child
            bool is_param{false}; // dynamic/wildcard flag (placed at end to minimize padding)

            // ─── 3. Constructors & Destructor (MIDDLE) ─────────────────────────
            Node() = default;
            ~Node() = default;
            Node(const Node &) = delete;
            Node &operator=(const Node &) = delete;
            Node(Node &&) noexcept = default;
            Node &operator=(Node &&) noexcept = default;
        };

        // ─── 2. Member Variables (SECOND - Ordered for Minimal Padding) ────
        // Cache of compiled RE2 constraints keyed by pattern text.
        std::unordered_map<std::string, std::shared_ptr<re2::RE2>> regex_cache_{};
        NotFoundHandler not_found_handler_{[](RequestType &, ResponseType &res) -> asio::awaitable<void> {
            res.status(404).send("Not Found");
            co_return;
        }};
        std::vector<ScopedMiddleware> middlewares_{};
        std::unique_ptr<Node> root_{};
        mutable bool frozen_{false}; ///< set by freeze(); resolve() uses pre-compiled chains when true

    public:
        // ─── 3. Constructors & Destructor (MIDDLE) ─────────────────────────
        /**
         * @brief Constructs an empty router with a single root node at "/".
         */
        Router() {
            root_ = std::make_unique<Node>();
            root_->prefix = "/";
        }

        ~Router() = default;
        Router(const Router &) = delete;
        Router &operator=(const Router &) = delete;
        Router(Router &&) noexcept = default;
        Router &operator=(Router &&) noexcept = default;

        // ─── 4. Member Functions & Friend Declarations (LAST) ──────────────

        /**
         * @brief Singleton instance for a given protocol type.
         * @return Reference to the process-wide Router<Proto> instance, guaranteed
         *         unique across translation units and C++20 module boundaries by
         *         C++ ODR inline rules.
         */
        static Router &instance() {
            static Router s_instance;
            return s_instance;
        }

        /**
         * @brief Creates a distinct, local Router instance.
         * @return A new local Router instance independent of the process-wide singleton.
         */
        static Router make_instance() {
            return Router{};
        }

        /**
         * @brief Clears all registered routes and middlewares, resetting router state.
         */
        void clear() {
            root_ = std::make_unique<Node>();
            root_->prefix = "/";
            middlewares_.clear();
            regex_cache_.clear();
        }

        // ---------------------------------------------------------------
        //  Route registration
        // ---------------------------------------------------------------

        /**
         * @brief Registers a handler for a given method + pattern.
         * @param m Method to associate the handler with.
         * @param pattern Route pattern; may contain static segments, `:param`,
         *        `{name}` / `{name:regex}` params, or `*` / `*name` wildcards.
         * @param h Coroutine handler invoked on a match.
         */
        void route(MethodType m, const std::string_view pattern, Handler h) {
            route(m, pattern, {}, std::move(h));
        }

        /**
         * @brief Registers a handler with per-route middlewares for a given method + pattern.
         * @param m Method to associate the handler with.
         * @param pattern Route pattern (see the single-middleware overload for syntax).
         * @param mws Middlewares run only for this specific route, after global/scoped ones.
         * @param h Coroutine handler invoked on a match.
         */
        void route(MethodType m, const std::string_view pattern,
                   std::vector<MiddlewareFn> mws, Handler h) {
            // Normalise + split without allocating for the common case of an
            // already-well-formed literal pattern (e.g. "/api/users/:id").
            // `insert_segment` only allocates an owned std::string when it
            // actually needs to create a *new* node — matching an existing
            // static child is a pure view comparison.
            std::string scratch;
            const std::string_view normalized = normalize_path_view(pattern, scratch);
            const auto segments = split_path_view(normalized);

            // Walk/create the tree
            Node *current = root_.get();
            for (const auto &seg: segments) {
                current = insert_segment(current, seg);
            }

            // Store handler and per-route middlewares at the leaf
            current->handlers[m] = std::move(h);
            if (!mws.empty()) {
                current->route_middlewares[m] = std::move(mws);
            }
            frozen_ = false;
        }

        /**
         * @brief Registers a route using a StaticChain.
         */
        template<typename... Handlers>
        void route(MethodType m, const std::string_view pattern, StaticChain<Handlers...> chain) {
            route(m, pattern, [c = std::move(chain)](RequestType &req,
                                                     ResponseType &res) mutable -> asio::awaitable<void> {
                co_await c.process_all_async(req, res);
            });
        }

        // ---------------------------------------------------------------
        //  Middleware registration
        // ---------------------------------------------------------------

        /**
         * @brief Registers a global middleware, applied to all routes.
         * @param mw Middleware function to add to the global chain.
         */
        void use(MiddlewareFn mw) {
            middlewares_.emplace_back("", std::move(mw));
            frozen_ = false;
        }

        /**
         * @brief Registers a scoped middleware, applied only to routes whose
         *        normalised path starts with `prefix`.
         * @param prefix Path prefix to scope the middleware to; empty behaves
         *        like the global overload.
         * @param mw Middleware function to add to the chain.
         */
        void use(const std::string_view prefix, MiddlewareFn mw) {
            if (prefix.empty()) [[unlikely]] {
                middlewares_.emplace_back("", std::move(mw));
            } else [[likely]] {
                middlewares_.emplace_back(normalize_path(prefix), std::move(mw));
            }
            frozen_ = false;
        }

        /**
         * @brief Registers a global static middleware chain.
         */
        template<typename... Handlers>
        void use(StaticChain<Handlers...> chain) {
            use([c = std::move(chain)](RequestType &req, ResponseType &res,
                                       base::Next next) mutable -> asio::awaitable<void> {
                if (const bool ok = co_await c.process_all_async(req, res); ok) {
                    co_await next();
                }
            });
        }

        /**
         * @brief Registers a scoped static middleware chain.
         */
        template<typename... Handlers>
        void use(const std::string_view prefix, StaticChain<Handlers...> chain) {
            use(prefix, [c = std::move(chain)](RequestType &req, ResponseType &res,
                                               base::Next next) mutable -> asio::awaitable<void> {
                if (const bool ok = co_await c.process_all_async(req, res); ok) {
                    co_await next();
                }
            });
        }

        // ---------------------------------------------------------------
        //  404 Not Found handling
        // ---------------------------------------------------------------

        /**
         * @brief Configures a custom coroutine handler for 404 Not Found responses.
         * @param h Custom handler lambda or function.
         */
        void not_found(NotFoundHandler h) {
            not_found_handler_ = std::move(h);
        }

        /**
         * @brief Configures a custom static body and Content-Type for 404 Not Found responses.
         * @param body Custom response payload string (e.g. custom text, JSON string, or HTML).
         * @param content_type Optional Content-Type header (defaults to "text/plain").
         */
        void not_found(std::string body, std::string content_type = "text/plain") {
            not_found_handler_ = [b = std::move(body), ct = std::move(content_type)](
                RequestType &, ResponseType &res) -> asio::awaitable<void> {
                        res.status(404);
                        if (!ct.empty()) {
                            res.set("Content-Type", ct);
                        }
                        res.send(b);
                        co_return;
                    };
        }

        /**
         * @brief Configures a static file or HTML page from disk for 404 Not Found responses.
         *
         * Automatically infers Content-Type via wavex::base::mime_type_from_path.
         * If the file is not found or unreadable, falls back to default "Not Found".
         *
         * @param file_path Path to the error page file.
         */
        void not_found_page(const std::filesystem::path &file_path) {
            if (std::filesystem::exists(file_path)) {
                std::ifstream file(file_path, std::ios::binary);
                if (file) {
                    std::string content((std::istreambuf_iterator<char>(file)),
                                        std::istreambuf_iterator<char>());
                    std::string mime = std::string(base::mime_type_from_path(file_path.string()));
                    not_found(std::move(content), std::move(mime));
                    return;
                }
            }
            not_found("Not Found", "text/plain");
        }

        /// Access the currently active 404 Not Found handler
        [[nodiscard]] const NotFoundHandler &not_found_handler() const noexcept {
            return not_found_handler_;
        }

        /// Access the currently active 404 Not Found handler (mutable)
        [[nodiscard]] NotFoundHandler &not_found_handler() noexcept {
            return not_found_handler_;
        }

        // ---------------------------------------------------------------
        //  Middleware chain pre-compilation
        // ---------------------------------------------------------------

        /**
         * @brief Pre-compiles middleware chains for every registered route node.
         *
         * Walks the entire radix tree and builds `Node::compiled_middlewares` for each
         * leaf node that has registered handlers. The chain for each node is:
         *   [global middlewares] → [prefix-scoped middlewares] → [per-route middlewares]
         *
         * Call this once after all routes and middlewares have been registered, before
         * calling server.run(). Server::run() calls freeze() automatically.
         *
         * After freeze(), resolve() returns a std::span into the pre-compiled chain —
         * zero heap allocations, zero std::function copies per request.
         */
        void freeze() const {
            freeze_node(root_.get(), "");
            frozen_ = true;
        }

        // ---------------------------------------------------------------
        //  Route resolution — O(path_length), hot path
        // ---------------------------------------------------------------

        /**
         * @brief Resolves a method + path to a registered handler.
         * @param m Method to look up.
         * @param path Request path to resolve; need not be pre-normalised.
         * @return A RouteMatch (handler, resolved params, and the full ordered
         *         middleware chain as a std::span) on success, or std::nullopt
         *         if no route matches.
         */
        [[nodiscard]] std::optional<RouteMatch> resolve(MethodType m, const std::string_view path) const {
            if (!frozen_) [[unlikely]] {
                freeze();
            }

            // `scratch` only actually allocates when `path` isn't already
            // normalised (no leading '/', or a trailing '/'); the common
            // case coming off a parsed HTTP request line needs no copy.
            std::string scratch;
            const std::string_view normalized = normalize_path_view(path, scratch);

            // Inline stack segment array — zero heap allocation for paths ≤ 16 segments
            std::array<std::string_view, 16> seg_buf;
            std::size_t seg_count = 0;
            std::vector<std::string_view> seg_overflow; // only used for paths > 16 segments

            if (!normalized.empty() && normalized != "/") {
                std::size_t start = 1;
                while (start < normalized.size()) {
                    const std::size_t end = normalized.find('/', start);
                    const std::size_t actual_end = (end == std::string_view::npos) ? normalized.size() : end;
                    if (actual_end != start) {
                        if (seg_count < seg_buf.size()) [[likely]] {
                            seg_buf[seg_count++] = normalized.substr(start, actual_end - start);
                        } else [[unlikely]] {
                            // Rare overflow path (> 16 segments)
                            if (seg_overflow.empty()) {
                                seg_overflow.assign(seg_buf.begin(), seg_buf.begin() + seg_count);
                            }
                            seg_overflow.emplace_back(normalized.substr(start, actual_end - start));
                        }
                    }
                    if (end == std::string_view::npos) break;
                    start = end + 1;
                }
            }

            const std::span<const std::string_view> segments =
                    seg_overflow.empty()
                        ? std::span<const std::string_view>(seg_buf.data(), seg_count)
                        : std::span<const std::string_view>(seg_overflow);

            base::FlatMap<std::string_view, std::string_view> params;
            const Node *node = resolve_node(root_.get(), segments, 0, params);

            if (!node) [[unlikely]] return std::nullopt;

            const auto it = node->handlers.find(m);
            if (it == node->handlers.end()) [[unlikely]] return std::nullopt;

            const auto mw_it = node->compiled_middlewares.find(m);
            const std::span<const MiddlewareFn> mws_span =
                    (mw_it != node->compiled_middlewares.end())
                        ? std::span<const MiddlewareFn>(mw_it->second)
                        : std::span<const MiddlewareFn>{};

            return RouteMatch{
                it->second,
                mws_span,
                std::move(params)
            };
        }



    private:
        // ---------------------------------------------------------------
        //  Middleware chain compilation (called once by freeze())
        // ---------------------------------------------------------------

        /**
         * @brief Recursively compiles `compiled_middlewares` for every handler-leaf node.
         *
         * For each node with at least one registered handler, builds a combined chain:
         *   1. Global middlewares (empty prefix)
         *   2. Prefix-scoped middlewares whose prefix is a prefix of `node_path`
         *   3. Per-route middlewares for each registered method
         *
         * @param node      Node to compile middlewares for.
         * @param node_path Accumulated path string for prefix-matching.
         */
        void freeze_node(Node *node, const std::string &node_path) const {
            if (!node->handlers.empty()) {
                node->compiled_middlewares.clear();
                for (const auto &[m, _]: node->handlers) {
                    auto &chain = node->compiled_middlewares[m];
                    // 1. Global and prefix-scoped middlewares
                    for (const auto &[prefix, fn]: middlewares_) {
                        if (prefix.empty() || std::string_view(node_path).starts_with(prefix)) {
                            chain.emplace_back(fn);
                        }
                    }
                    // 2. Per-route middlewares for this method
                    if (const auto r_it = node->route_middlewares.find(m); r_it != node->route_middlewares.end()) {
                        for (const auto &fn: r_it->second) {
                            chain.emplace_back(fn);
                        }
                    }
                }
            }

            // Recurse into all children
            for (const auto &child: node->children) {
                freeze_node(child.get(), node_path + "/" + child->prefix);
            }
            for (const auto &child: node->param_children) {
                freeze_node(child.get(), node_path + "/:" + child->param_name);
            }
            if (node->wildcard_child) {
                freeze_node(node->wildcard_child.get(), node_path + "/*" + node->wildcard_child->param_name);
            }
        }

        // ---------------------------------------------------------------
        //  Path utilities — registration-time (owning; not perf-critical)
        // ---------------------------------------------------------------

        /**
         * @brief Normalises a path into an owned string: ensures a leading
         *        '/' and strips any trailing '/'.
         * @param path Path to normalise.
         * @return Owned, normalized copy of `path`.
         */
        static std::string normalize_path(const std::string_view path) {
            if (path.empty() || path == "/") return "/";
            std::string p(path);
            if (p.front() != '/') [[unlikely]] p.insert(p.begin(), '/');
            if (p.size() > 1 && p.back() == '/') [[likely]] p.pop_back();
            return p;
        }

        // ---------------------------------------------------------------
        //  Path utilities — shared by registration and resolve(): allocation-
        //  free normalisation when possible, string_view segments (no "per-
        //  segment" heap allocation). Used by both route() and resolve().
        // ---------------------------------------------------------------

        /**
         * @brief Normalises `path`, writing into `scratch` only if needed,
         *        and returns a view of the result.
         *
         * `scratch` is owned by the caller so the returned view is valid for
         * exactly as long as the caller's `scratch` object is alive — no
         * dangling self-reference risk from returning a view-into-local by
         * value. `scratch` is cleared unconditionally before use, so this
         * function is safe to call with a *reused* buffer (e.g. a
         * thread-local scratch pool) — it never relies on the caller having
         * passed in an empty string.
         *
         * @param path Path to normalise; need not already be well-formed.
         * @param scratch Caller-owned buffer used only if `path` isn't
         *        already normalised (no leading '/', or has a trailing '/').
         * @return A view of the normalised path — either `path` unchanged
         *         (zero-copy fast path) or `scratch`.
         */
        [[nodiscard]] static std::string_view normalize_path_view(const std::string_view path, std::string &scratch) {
            if (path.empty() || path == "/") return "/";

            const bool needs_front = path.front() != '/';
            const bool needs_trim = path.size() > 1 && path.back() == '/';

            if (!needs_front && !needs_trim) [[likely]] {
                // ReSharper disable once CppDFALocalValueEscapesFunction
                return path; // zero-copy: caller's buffer is already normalised
            }

            scratch.clear();
            scratch.reserve(path.size() + (needs_front ? 1 : 0));
            if (needs_front) scratch.push_back('/');
            scratch.append(path);
            if (needs_trim && scratch.size() > 1 && scratch.back() == '/') {
                scratch.pop_back();
            }
            return scratch;
        }

        /**
         * @brief Splits an already-normalised path into segment views.
         * @param path Normalized path (see normalise_path_view()).
         * @return Segments as views into `path`; empty for "/" or an empty path.
         */
        [[nodiscard]] static std::vector<std::string_view> split_path_view(std::string_view path) {
            std::vector<std::string_view> segments;
            if (path.empty() || path == "/") return segments;

            segments.reserve(static_cast<size_t>(std::ranges::count(path, '/')));

            size_t start = 1;
            while (start < path.size()) {
                size_t end = path.find('/', start);
                if (end == std::string_view::npos) end = path.size();
                if (end != start) {
                    segments.emplace_back(path.substr(start, end - start));
                }
                start = end + 1;
            }
            return segments;
        }

        // ---------------------------------------------------------------
        //  Tree insertion (registration-time, but startup-cost-sensitive
        //  for large route tables). `segment` is a view — no allocation
        //  happens on the (common) path where it matches an existing
        //  child; a std::string is only materialised when a genuinely new
        //  node needs to own its label/param name/pattern.
        // ---------------------------------------------------------------

        /**
         * @brief Inserts (or finds) the child of `parent` for a single path segment.
         *
         * `segment` is a view — no allocation happens on the common path
         * where it matches an existing child; a std::string is only
         * materialised when a genuinely new node needs to own its
         * label/param name/pattern.
         *
         * @param parent Node to insert under.
         * @param segment Single path segment (e.g. "users", ":id", "{id:[0-9]+}", "*rest").
         * @return The existing or newly created child node for `segment`.
         */
        Node *insert_segment(Node *parent, std::string_view segment) {
            // 1. Check if param segment: :name
            if (!segment.empty() && segment[0] == ':') {
                std::string pname(segment.substr(1)); // direct-init: string_view -> string ctor is explicit
                for (const auto &child: parent->param_children) {
                    if (child->is_param && !child->constraint && child->param_name == pname) {
                        return child.get();
                    }
                }
                auto new_node = std::make_unique<Node>();
                new_node->is_param = true;
                new_node->param_name = pname;
                Node *res = new_node.get();
                parent->param_children.emplace_back(std::move(new_node));
                return res;
            }

            // 2. Check if brace param segment: {name} or {name:pattern}
            if (segment.size() >= 2 && segment[0] == '{' && segment.back() == '}') {
                const auto inner = segment.substr(1, segment.size() - 2);
                if (const size_t colon = inner.find(':'); colon != std::string_view::npos) {
                    auto pname = std::string(inner.substr(0, colon));
                    auto pat = std::string(inner.substr(colon + 1));
                    for (const auto &child: parent->param_children) {
                        if (child->is_param && child->constraint && child->param_name == pname && child->pattern ==
                            pat) {
                            return child.get();
                        }
                    }
                    auto new_node = std::make_unique<Node>();
                    new_node->is_param = true;
                    new_node->param_name = pname;
                    new_node->pattern = pat;
                    // Reuse a compiled RE2 for this pattern text if some
                    // other route already registered it (common: the same
                    // constraint, e.g. "[0-9]+", reused under many prefixes).
                    if (auto &cached = regex_cache_[pat]; cached) {
                        new_node->constraint = cached;
                    } else {
                        cached = std::make_shared<re2::RE2>(pat);
                        new_node->constraint = cached;
                    }
                    Node *res = new_node.get();
                    parent->param_children.emplace_back(std::move(new_node));
                    return res;
                }
                // Unconstrained brace param: {name} (works identically to :name)
                auto pname = std::string(inner);
                for (const auto &child: parent->param_children) {
                    if (child->is_param && !child->constraint && child->param_name == pname) {
                        return child.get();
                    }
                }
                auto new_node = std::make_unique<Node>();
                new_node->is_param = true;
                new_node->param_name = pname;
                Node *res = new_node.get();
                parent->param_children.emplace_back(std::move(new_node));
                return res;
            }

            // 3. Check if wildcard: * or *name
            if (!segment.empty() && segment[0] == '*') {
                if (!parent->wildcard_child) {
                    parent->wildcard_child = std::make_unique<Node>();
                    parent->wildcard_child->param_name = segment.size() > 1 ? segment.substr(1) : "*";
                    parent->wildcard_child->is_param = true;
                }
                return parent->wildcard_child.get();
            }

            // 4. Static segment — O(1) average lookup via static_index.
            if (const auto found = parent->static_index.find(segment); found != parent->static_index.end()) {
                return found->second;
            }

            auto new_node = std::make_unique<Node>();
            new_node->prefix = segment;
            Node *res = new_node.get();
            // Index by a view into the child's own storage (see Node comment).
            parent->static_index.emplace(std::string_view(new_node->prefix), res);
            parent->children.emplace_back(std::move(new_node));
            return res;
        }

        // ---------------------------------------------------------------
        //  Tree resolution (hot path)
        // ---------------------------------------------------------------

        /**
         * @brief Recursively resolves `segments[depth…]` against `node`,
         *        trying static, then param/regex, then wildcard children in
         *        priority order, and backtracking on dead ends.
         * @param node Node to resolve from.
         * @param segments Full path segment list for the request.
         * @param depth Index into `segments` currently being matched.
         * @param params Accumulator for resolved param values; entries for a
         *        param/regex child are erased again on backtrack.
         * @return The matching leaf node (with a non-empty handler map), or
         *         nullptr if no match exists under `node`.
         */
        const Node *resolve_node(const Node *node,
                                 const std::span<const std::string_view> &segments,
                                 const size_t depth,
                                 base::FlatMap<std::string_view, std::string_view> &params) const {
            [[assume(depth <= segments.size())]];
            if (depth == segments.size()) {
                if (!node->handlers.empty()) return node;
                return nullptr;
            }

            const auto &segment = segments[depth];

            // 1. Static children first (highest priority) — O(1) average.
            if (const auto found = node->static_index.find(segment); found != node->static_index.end()) [[likely]] {
                if (auto result = resolve_node(found->second, segments, depth + 1, params)) [[likely]] return result;
            }

            // 2. Dynamic / Regex param children
            for (const auto &child: node->param_children) {
                bool match = true;
                if (child->constraint) {
                    match = re2::RE2::FullMatch(re2::StringPiece(segment.data(), segment.size()), *child->constraint);
                }
                if (match) {
                    params.insert_or_assign(std::string_view(child->param_name), segment);
                    if (auto result = resolve_node(child.get(), segments, depth + 1, params)) return result;
                    // Backtrack: remove the param we just inserted
                    // FlatMap doesn't have "erase", so rebuild from scratch (rare backtrack path)
                    base::FlatMap<std::string_view, std::string_view> rebuilt;
                    for (const auto &[k, v]: params) {
                        if (k != std::string_view(child->param_name))
                            rebuilt.insert_or_assign(k, v);
                    }
                    params = std::move(rebuilt);
                }
            }

            // 3. Wildcard child (*) — captures all remaining segments.
            // INVARIANT: All string_views in `segments` are non-empty, contiguous slices
            // of the single normalized path buffer parsed in resolve(). Therefore,
            // (segments.back().data() + segments.back().size()) - segments[depth].data()
            // is valid pointer arithmetic spanning the entire wildcard suffix.
            if (node->wildcard_child) {
                if (depth < segments.size()) {
                    const char *w_begin = segments[depth].data();
                    const char *w_end = segments.back().data() + segments.back().size();
                    assert(w_begin <= w_end && "Segments must be contiguous slices of the same path buffer");
                    [[assume(w_begin <= w_end)]];
                    std::string_view wildcard_slice(w_begin, static_cast<size_t>(w_end - w_begin));
                    params.insert_or_assign(
                        std::string_view(node->wildcard_child->param_name),
                        wildcard_slice);
                } else {
                    params.insert_or_assign(
                        std::string_view(node->wildcard_child->param_name),
                        std::string_view{});
                }
                if (!node->wildcard_child->handlers.empty()) {
                    return node->wildcard_child.get();
                }
            }

            return nullptr;
        }
    };
} // namespace wavex::engine
