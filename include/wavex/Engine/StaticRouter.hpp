// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * @file StaticRouter.hpp
 * @brief Router whose routes, route tree and middleware chains are all fixed at compile time.
 *
 * ```cpp
 * using namespace wavex::engine::route;
 * auto router = static_router<Http1Proto>(                       // string_compare by default
 *     use(logging),                                              // global middleware
 *     on<method::GET,  "/">(home),
 *     group<"/api">(
 *         use(auth),                                             // every route of the group
 *         on<method::GET,  "/users/{id:int}">(show_user, rate_limit),
 *         on<method::POST, "/users">(create_user)),
 *     on<method::GET, "/files/*path">(serve));
 * Server<http1codec, decltype(router)> server(router, "0.0.0.0", 8080);
 * ```
 *
 * What is compile-time work (and a compile error when wrong): parsing every pattern, rejecting malformed
 * ones, duplicate method+path pairs and too many segments, building the route tree as a constexpr array,
 * hashing the literal segments (hash_compare) and concatenating group prefixes and middleware lists.
 * What stays at run time: walking the tree for each request and calling the handlers, which are coroutines.
 *
 * Middleware shape: a callable `(Req&, Res&, Next next) -> task<void>`. Awaiting `next()` runs the rest of
 * the chain and finally the handler, so code after it is post-processing. Not calling `next()` short-circuits.
 * `before(fn)` / `after(fn)` adapt plain functions: `bool(Req&, Res&)` (false stops the chain) and
 * `void(Req&, Res&)`.
 *
 * Order for every route: global `use`, enclosing groups outer to inner, the route's own list, the handler.
 * A `use` applies to every route of its scope regardless of where in the list it appears.
 *
 * Differences from DynamicRouter: no RE2 constraints (`{id:int}` etc. are built in), the route set can't
 * change after construction, and a matched route's middleware runs nested (so it can post-process) instead
 * of through the server's flag-based chain.
 */

#ifndef WAVEX_ENGINE_STATICROUTER_HPP
#define WAVEX_ENGINE_STATICROUTER_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <string_view>
#include <tuple>
#include <type_traits>
#include <utility>

#include <wavex/Base/FlatMap.hpp>
#include <wavex/Base/MiddleWare.hpp>
#include <wavex/Base/Task.hpp>
#include <wavex/Engine/RouteCore.hpp>

namespace wavex::engine::route {

    // ─── Route description items (what the user writes) ─────────────────────

    template<auto M, fixed_string P, typename H, typename Mws>
    struct route_item {
        static constexpr auto method = M;
        static constexpr auto path = P;
        H handler;
        Mws mws; ///< std::tuple of middleware, outermost first
    };

    template<typename Mws>
    struct use_item {
        Mws mws;
    };

    template<fixed_string P, typename Items>
    struct group_item {
        static constexpr auto prefix = P;
        Items items;
    };

    /// A route: method (an enumerator of `Proto::method`), pattern, handler and optional per-route middleware.
    template<auto M, fixed_string P, typename H, typename... Mw>
    [[nodiscard]] constexpr auto on(H handler, Mw... mw) {
        return route_item<M, P, H, std::tuple<Mw...> >{std::move(handler), std::tuple<Mw...>{std::move(mw)...}};
    }

    /// Middleware for the enclosing scope (the whole router at top level, the group inside a group).
    template<typename... Mw>
    [[nodiscard]] constexpr auto use(Mw... mw) {
        return use_item<std::tuple<Mw...> >{std::tuple<Mw...>{std::move(mw)...}};
    }

    /// Routes and middleware sharing a path prefix.
    template<fixed_string P, typename... Items>
    [[nodiscard]] constexpr auto group(Items... items) {
        return group_item<P, std::tuple<Items...> >{std::tuple<Items...>{std::move(items)...}};
    }

    /// Adapts `bool(Req&, Res&)`: a false result ends the chain (the hook is expected to have sent a response).
    template<typename F>
    [[nodiscard]] constexpr auto before(F fn) {
        return [fn = std::move(fn)](auto &req, auto &res, auto &next) -> wavex::task<void> {
            if (fn(req, res)) co_await next();
        };
    }

    /// Adapts `void(Req&, Res&)` run after the rest of the chain completed.
    template<typename F>
    [[nodiscard]] constexpr auto after(F fn) {
        return [fn = std::move(fn)](auto &req, auto &res, auto &next) -> wavex::task<void> {
            co_await next();
            fn(req, res);
        };
    }

    // ─── Lowering: flatten groups, resolve prefixes and middleware lists ────

    namespace detail {
        template<typename T>
        constexpr auto use_of(const T &) { return std::tuple<>{}; }

        template<typename Mws>
        constexpr auto use_of(const use_item<Mws> &u) { return u.mws; }

        template<typename... Items>
        constexpr auto collect_use(const Items &... items) {
            return std::tuple_cat(use_of(items)...);
        }

        template<fixed_string Prefix, typename Inherited, auto M, fixed_string P, typename H, typename Mws>
        constexpr auto lower(const Inherited &inherited, const route_item<M, P, H, Mws> &r) {
            using all_mws = decltype(std::tuple_cat(inherited, r.mws));
            return std::tuple<route_item<M, concat(Prefix, P), H, all_mws> >{
                route_item<M, concat(Prefix, P), H, all_mws>{r.handler, std::tuple_cat(inherited, r.mws)}
            };
        }

        template<fixed_string Prefix, typename Inherited, typename Mws>
        constexpr auto lower(const Inherited &, const use_item<Mws> &) { return std::tuple<>{}; }

        template<fixed_string Prefix, typename Inherited, fixed_string P, typename Items>
        constexpr auto lower(const Inherited &inherited, const group_item<P, Items> &g) {
            return std::apply([&](const auto &... items) {
                const auto inner = std::tuple_cat(inherited, collect_use(items...));
                return std::tuple_cat(lower<concat(Prefix, P)>(inner, items)...);
            }, g.items);
        }
    } // namespace detail

    // ─── Compile-time route tree ────────────────────────────────────────────

    enum class table_error : std::uint8_t { none, bad_pattern, duplicate_route };

    template<typename Cmp, typename Method, std::size_t NodeCap, std::size_t RouteCap>
    struct route_table {
        struct node {
            typename Cmp::key_type key{}; ///< prepared literal text (literal nodes only)
            std::string_view name{};      ///< literal text, or parameter / wildcard name
            segment_kind kind{segment_kind::literal};
            param_class cls{param_class::any};
            int next{-1};                 ///< next sibling
            int child{-1};                ///< first child
            int entry{-1};                ///< first (method -> route) entry ending at this node
        };

        struct entry {
            Method method{};
            std::uint32_t route{0};
            int next{-1};
        };

        std::array<node, NodeCap> nodes{};
        std::array<entry, RouteCap> entries{};
        std::size_t node_count{1};
        std::size_t entry_count{0};
        table_error error{table_error::none};
        pattern_error pattern{pattern_error::none};

        constexpr void add(const std::string_view path, const Method method, const std::uint32_t route_index) {
            const parsed_pattern p = parse_pattern(path);
            if (p.error != pattern_error::none) {
                error = table_error::bad_pattern;
                pattern = p.error;
                return;
            }
            int cur = 0;
            for (std::size_t i = 0; i < p.count; ++i) {
                const pattern_segment &seg = p.segs[i];
                int found = -1;
                int tail = -1;
                for (int c = nodes[cur].child; c >= 0; c = nodes[c].next) {
                    tail = c;
                    const node &nd = nodes[c];
                    if (nd.kind == seg.kind && nd.name == seg.text &&
                        (seg.kind != segment_kind::param || nd.cls == seg.cls)) {
                        found = c;
                        break;
                    }
                }
                if (found < 0) {
                    found = static_cast<int>(node_count++);
                    node &nd = nodes[found];
                    nd.kind = seg.kind;
                    nd.cls = seg.cls;
                    nd.name = seg.text;
                    if (seg.kind == segment_kind::literal) nd.key = Cmp::prepare(seg.text);
                    if (tail < 0) nodes[cur].child = found; else nodes[tail].next = found;
                }
                cur = found;
            }
            for (int e = nodes[cur].entry; e >= 0; e = entries[e].next) {
                if (entries[e].method == method) {
                    error = table_error::duplicate_route;
                    return;
                }
            }
            entries[entry_count] = entry{method, route_index, nodes[cur].entry};
            nodes[cur].entry = static_cast<int>(entry_count++);
        }
    };

    template<typename Cmp, typename Method, std::size_t NodeCap, std::size_t RouteCap, std::size_t N>
    [[nodiscard]] consteval auto build_table(const std::array<std::string_view, N> &paths,
                                             const std::array<Method, N> &methods) {
        route_table<Cmp, Method, NodeCap, RouteCap> t;
        for (std::size_t i = 0; i < N; ++i) t.add(paths[i], methods[i], static_cast<std::uint32_t>(i));
        return t;
    }

    // ─── The router ─────────────────────────────────────────────────────────

    /**
     * @tparam Proto   Protocol adapter: nested `method`, `request`, `response` (same contract as DynamicRouter).
     * @tparam Cmp     Segment comparison policy, `string_compare` or `hash_compare<>`.
     * @tparam Routes  Lowered `route_item` types; use `static_router<Proto, Cmp>(...)` instead of naming them.
     */
    template<typename Proto, typename Cmp, typename... Routes>
    class StaticRouter {
    public:
        using MethodType = typename Proto::method;
        using RequestType = typename Proto::request;
        using ResponseType = typename Proto::response;
        using NotFoundHandler = std::function<wavex::task<void>(RequestType &, ResponseType &)>;
        using MiddlewareFn = base::GenericMiddlewareFn<RequestType, ResponseType>;

        /// Placeholder element type for RouteMatch::middlewares, which is always empty: the whole chain is
        /// already folded into RouteMatch::handler.
        struct no_middleware {
            wavex::task<void> operator()(RequestType &, ResponseType &, base::Next) const { co_return; }
        };

        /// Cheap, trivially copyable handle running route `index` (middleware chain, then the handler).
        struct route_handler {
            const StaticRouter *self{nullptr};
            std::uint32_t index{0};

            wavex::task<void> operator()(RequestType &req, ResponseType &res) const {
                return self->invoke(index, req, res);
            }
        };

        struct RouteMatch {
            route_handler handler{};
            std::span<const no_middleware> middlewares{};
            base::FlatMap<std::string_view, std::string_view> params{};
        };

    private:
        static constexpr std::size_t route_count = sizeof...(Routes);
        static constexpr std::size_t node_cap = 1 + (std::size_t{0} + ... + parse_pattern(Routes::path.view()).count);
        static constexpr std::size_t route_cap = route_count == 0 ? 1 : route_count;

        static constexpr std::array<std::string_view, route_count> paths_{Routes::path.view()...};
        static constexpr std::array<MethodType, route_count> methods_{Routes::method...};

        using table_type = route_table<Cmp, MethodType, node_cap, route_cap>;
        static constexpr table_type tbl_ = build_table<Cmp, MethodType, node_cap, route_cap>(paths_, methods_);

        static_assert(tbl_.error != table_error::bad_pattern || tbl_.pattern != pattern_error::too_many_segments,
                      "StaticRouter: a route pattern has more than 16 segments");
        static_assert(tbl_.error != table_error::bad_pattern || tbl_.pattern != pattern_error::wildcard_not_last,
                      "StaticRouter: a wildcard must be the last segment of a route pattern");
        static_assert(tbl_.error != table_error::bad_pattern || tbl_.pattern != pattern_error::unknown_constraint,
                      "StaticRouter: unknown parameter constraint (use any, int, uint, alpha, alnum or hex)");
        static_assert(tbl_.error != table_error::bad_pattern || tbl_.pattern != pattern_error::bad_literal,
                      "StaticRouter: a literal segment contains '{', '}' or '*'");
        static_assert(tbl_.error != table_error::bad_pattern || tbl_.pattern != pattern_error::empty_param_name,
                      "StaticRouter: a route parameter has an empty name");
        static_assert(tbl_.error != table_error::bad_pattern || tbl_.pattern != pattern_error::duplicate_param,
                      "StaticRouter: a route pattern uses the same parameter name twice");
        static_assert(tbl_.error != table_error::duplicate_route,
                      "StaticRouter: the same method and path is registered twice");

        std::tuple<Routes...> routes_;
        NotFoundHandler not_found_handler_{
            [](RequestType &, ResponseType &res) -> wavex::task<void> {
                res.status(404).send("Not Found");
                co_return;
            }
        };

    public:
        explicit StaticRouter(std::tuple<Routes...> routes) : routes_(std::move(routes)) {}

        StaticRouter(const StaticRouter &) = delete;
        StaticRouter &operator=(const StaticRouter &) = delete;
        StaticRouter(StaticRouter &&) noexcept = default;
        StaticRouter &operator=(StaticRouter &&) noexcept = default;
        ~StaticRouter() = default;

        /// Nothing to pre-compile: everything is already fixed. Present because Server calls it.
        void freeze() const noexcept {}

        void not_found(NotFoundHandler h) { not_found_handler_ = std::move(h); }

        void not_found(std::string body, std::string content_type = "text/plain") {
            not_found_handler_ = [b = std::move(body), ct = std::move(content_type)](
                RequestType &, ResponseType &res) -> wavex::task<void> {
                res.status(404);
                if (!ct.empty()) res.set("Content-Type", ct);
                res.send(b);
                co_return;
            };
        }

        [[nodiscard]] const NotFoundHandler &not_found_handler() const noexcept { return not_found_handler_; }
        [[nodiscard]] NotFoundHandler &not_found_handler() noexcept { return not_found_handler_; }

        /// Route lookup: O(path length), no allocation. Unknown path or method yields nullopt (404).
        [[nodiscard]] std::optional<RouteMatch> resolve(const MethodType method, const std::string_view path) const {
            capture caps{};
            std::uint32_t route = 0;
            if (!walk(0, path, method, caps, route)) return std::nullopt;
            RouteMatch m;
            m.handler = route_handler{this, route};
            for (std::size_t i = 0; i < caps.count; ++i) {
                m.params.insert_or_assign(caps.items[i].first, caps.items[i].second);
            }
            return m;
        }

        [[nodiscard]] static constexpr std::size_t size() noexcept { return route_count; }

    private:
        struct capture {
            std::array<std::pair<std::string_view, std::string_view>, max_pattern_segments> items{};
            std::size_t count{0};
        };

        [[nodiscard]] static bool entry_for(const int node, const MethodType method, std::uint32_t &route) noexcept {
            for (int e = tbl_.nodes[node].entry; e >= 0; e = tbl_.entries[e].next) {
                if (tbl_.entries[e].method == method) {
                    route = tbl_.entries[e].route;
                    return true;
                }
            }
            return false;
        }

        /// Depth-first match with backtracking; literal children win over parameters, parameters over wildcard.
        [[nodiscard]] static bool walk(const int node, std::string_view rest, const MethodType method,
                                       capture &caps, std::uint32_t &route) noexcept {
            std::string_view seg;
            if (!next_segment(rest, seg)) return entry_for(node, method, route);

            const auto key = Cmp::prepare(seg);
            for (int c = tbl_.nodes[node].child; c >= 0; c = tbl_.nodes[c].next) {
                const auto &nd = tbl_.nodes[c];
                if (nd.kind == segment_kind::literal && Cmp::equals(nd.key, key) &&
                    walk(c, rest, method, caps, route)) {
                    return true;
                }
            }
            for (int c = tbl_.nodes[node].child; c >= 0; c = tbl_.nodes[c].next) {
                const auto &nd = tbl_.nodes[c];
                if (nd.kind != segment_kind::param || !matches_class(nd.cls, seg)) continue;
                caps.items[caps.count++] = {nd.name, seg};
                if (walk(c, rest, method, caps, route)) return true;
                --caps.count;
            }
            for (int c = tbl_.nodes[node].child; c >= 0; c = tbl_.nodes[c].next) {
                const auto &nd = tbl_.nodes[c];
                if (nd.kind != segment_kind::wildcard) continue;
                std::string_view tail(seg.data(), static_cast<std::size_t>(rest.data() + rest.size() - seg.data()));
                while (!tail.empty() && tail.back() == '/') tail.remove_suffix(1);
                if (entry_for(c, method, route)) {
                    caps.items[caps.count++] = {nd.name, tail};
                    return true;
                }
            }
            return false;
        }

        // Middleware K..N-1 of a route nested around its handler. With none left the handler's task is returned
        // directly; otherwise run_mw is a coroutine, so `next` stays alive while the middleware runs.
        template<std::size_t K, typename R>
        static wavex::task<void> run_mw(const R &r, RequestType &req, ResponseType &res) {
            auto next = [&r, &req, &res]() -> wavex::task<void> { return run_at<K + 1>(r, req, res); };
            co_await std::invoke(std::get<K>(r.mws), req, res, next);
        }

        template<std::size_t K, typename R>
        static wavex::task<void> run_at(const R &r, RequestType &req, ResponseType &res) {
            if constexpr (K == std::tuple_size_v<std::remove_cvref_t<decltype(r.mws)> >) {
                return std::invoke(r.handler, req, res);
            } else {
                return run_mw<K>(r, req, res);
            }
        }

        template<std::size_t... I>
        wavex::task<void> invoke_impl(const std::size_t idx, RequestType &req, ResponseType &res,
                                      std::index_sequence<I...>) const {
            wavex::task<void> out;
            [[maybe_unused]] const bool hit =
                    ((idx == I ? (out = run_at<0>(std::get<I>(routes_), req, res), true) : false) || ...);
            return out;
        }

        wavex::task<void> invoke(const std::size_t idx, RequestType &req, ResponseType &res) const {
            return invoke_impl(idx, req, res, std::index_sequence_for<Routes...>{});
        }
    };

    /// Builds a StaticRouter from route / use / group items.
    template<typename Proto, typename Cmp = string_compare, typename... Items>
    [[nodiscard]] constexpr auto static_router(Items... items) {
        const auto global = detail::collect_use(items...);
        auto flat = std::tuple_cat(detail::lower<fixed_string{""}>(global, items)...);
        return [&]<typename... R>(std::tuple<R...> t) {
            return StaticRouter<Proto, Cmp, R...>(std::move(t));
        }(std::move(flat));
    }

} // namespace wavex::engine::route

namespace wavex::engine {
    using route::static_router;
    using route::StaticRouter;
    using route::string_compare;
    using route::hash_compare;
} // namespace wavex::engine

#endif // WAVEX_ENGINE_STATICROUTER_HPP
