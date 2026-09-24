// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * @file Chainable.hpp
 * @brief C++23 Explicit Object Parameter ("Deducing This") static dispatch interface.
 *
 * Provides the wavex::Chainable base class for zero-overhead compile-time
 * polymorphism, method chaining, static pipeline composition, and semi-static handlers.
 */

#pragma once

#include <utility>
#include <string_view>
#include <concepts>
#include <tuple>
#include <functional>

#ifndef ASIO_HAS_CO_AWAIT
#define ASIO_HAS_CO_AWAIT 1
#endif
#if defined(__MINGW32__) && !defined(ASIO_HAS_PTHREADS)
#define ASIO_HAS_PTHREADS 1
#endif
#include <asio/awaitable.hpp>

namespace wavex {
    /**
     * @class Chainable
     * @brief C++23 "Deducing This" CRTP replacement.
     */
    class Chainable {
    public:
        // ─── 3. Constructors & Destructor (MIDDLE) ─────────────────────────
        Chainable() = default;
        ~Chainable() = default;
        Chainable(const Chainable &) = default;
        Chainable &operator=(const Chainable &) = default;
        Chainable(Chainable &&) noexcept = default;
        Chainable &operator=(Chainable &&) noexcept = default;

        // ─── 4. Member Functions & Friend Declarations (LAST) ──────────────
        template<typename Self, typename... Args>
        decltype(auto) handle(this Self &&self, Args &&... args) {
            return std::forward<Self>(self).handle_impl(std::forward<Args>(args)...);
        }

        template<typename Self>
        decltype(auto) name(this Self &&self) {
            return std::forward<Self>(self).name_impl();
        }
    };

    template<typename T, typename... Args>
    concept ChainableHandler = requires(T &handler, Args &&... args)
    {
        handler.handle(std::forward<Args>(args)...);
    };

    // Helper trait placed in the wavex namespace
    template<typename T>
    struct awaitable_traits {
        static constexpr bool is_awaitable = false;
    };

    // Specialization to match asio::awaitable and extract the result type
    template<typename T, typename Executor>
    struct awaitable_traits<asio::awaitable<T, Executor> > {
        using result_type = T;
        static constexpr bool is_awaitable = true;
    };

    /**
     * @class StaticChain
     * @brief Static compile-time tuple-based pipeline of Chainable handlers.
     */
    template<typename... Handlers>
    class StaticChain {
    private:
        // ─── 2. Member Variables (SECOND - Ordered for Minimal Padding) ────
        std::tuple<Handlers...> handlers_;

    public:
        // ─── 3. Constructors & Destructor (MIDDLE) ─────────────────────────
        constexpr explicit StaticChain(Handlers... handlers)
            : handlers_(std::move(handlers)...) {
        }

        // ─── 4. Member Functions & Friend Declarations (LAST) ──────────────
    private:
        template<typename T>
        static decltype(auto) unwrap(T &t) { return t; }

        template<typename T>
        static decltype(auto) unwrap(std::reference_wrapper<T> &rw) { return rw.get(); }

        template<typename T>
        static decltype(auto) unwrap(const std::reference_wrapper<T> &rw) { return rw.get(); }

    public:
        [[nodiscard]] constexpr const std::tuple<Handlers...> &get_tuple() const {
            return handlers_;
        }

        [[nodiscard]] constexpr std::tuple<Handlers...> &get_tuple() {
            return handlers_;
        }

        template<typename... Args>
        bool process_all(Args &&... args) {
            return std::apply([&](auto &... h) {
                return (unwrap(h).handle(args...) && ...);
            }, handlers_);
        }

        template<typename... Args>
        asio::awaitable<bool> process_all_async(Args &&... args) {
            co_return co_await process_all_async_impl<0>(args...);
        }

    private:
        template<std::size_t Index, typename... Args>
        asio::awaitable<bool> process_all_async_impl(Args &... args) {
            if constexpr (Index < sizeof...(Handlers)) {
                auto &h = std::get<Index>(handlers_);
                using Ret = std::remove_cvref_t<decltype(unwrap(h).handle(args...))>;
                bool ok{};

                if constexpr (std::same_as<Ret, bool>) {
                    ok = unwrap(h).handle(args...);
                } else if constexpr (awaitable_traits<Ret>::is_awaitable) {
                    using AwaitRet = awaitable_traits<Ret>::result_type;

                    if constexpr (std::same_as<AwaitRet, bool>) {
                        ok = co_await unwrap(h).handle(args...);
                    } else {
                        co_await unwrap(h).handle(args...);
                        ok = true;
                    }
                } else {
                    unwrap(h).handle(args...);
                    ok = true;
                }

                if (!ok) {
                    co_return false;
                }

                co_return co_await process_all_async_impl<Index + 1>(args...);
            } else {
                co_return true;
            }
        }
    };

    template<typename... Handlers>
    constexpr auto make_chain(Handlers &&... handlers) {
        return StaticChain<std::decay_t<Handlers>...>(std::forward<Handlers>(handlers)...);
    }

    /**
     * @class ConditionalChainable
     * @brief Semi-static wrapper around a Chainable handler allowing runtime enable/disable toggling.
     */
    template<typename Handler>
    class ConditionalChainable : public Chainable {
    private:
        // ─── 2. Member Variables (SECOND - Ordered for Minimal Padding) ────
        Handler handler_;
        bool enabled_{true};

    public:
        // ─── 3. Constructors & Destructor (MIDDLE) ─────────────────────────
        constexpr explicit ConditionalChainable(Handler h, const bool enabled = true)
            : handler_(std::move(h)), enabled_(enabled) {
        }

        ~ConditionalChainable() = default;
        ConditionalChainable(const ConditionalChainable &) = default;
        ConditionalChainable &operator=(const ConditionalChainable &) = default;
        ConditionalChainable(ConditionalChainable &&) noexcept = default;
        ConditionalChainable &operator=(ConditionalChainable &&) noexcept = default;

        // ─── 4. Member Functions & Friend Declarations (LAST) ──────────────
        void set_enabled(bool enabled) { enabled_ = enabled; }

        [[nodiscard]] bool is_enabled() const { return enabled_; }

        template<typename Self, typename... Args>
        decltype(auto) handle_impl(this Self &&self, Args &&... args) {
            if (!self.enabled_) [[unlikely]] {
                using Ret = std::remove_cvref_t<decltype(self.handler_.handle(std::forward<Args>(args)...))>;
                if constexpr (std::same_as<Ret, bool>) {
                    return true;
                } else if constexpr (awaitable_traits<Ret>::is_awaitable) {
                    auto bypass = []() -> asio::awaitable<bool> { co_return true; };
                    return bypass();
                } else {
                    return;
                }
            }
            return self.handler_.handle(std::forward<Args>(args)...);
        }

        template<typename Self>
        decltype(auto) name_impl(this Self &&self) {
            return self.handler_.name();
        }
    };

    /**
     * @struct KeepAlivePolicy
     */
    template<unsigned TimeoutSec = 5, unsigned MaxRequests = 1000>
    struct KeepAlivePolicy : public Chainable {
        // ─── 3. Constructors & Destructor (MIDDLE) ─────────────────────────
        KeepAlivePolicy() = default;
        ~KeepAlivePolicy() = default;
        KeepAlivePolicy(const KeepAlivePolicy &) = default;
        KeepAlivePolicy &operator=(const KeepAlivePolicy &) = default;
        KeepAlivePolicy(KeepAlivePolicy &&) noexcept = default;
        KeepAlivePolicy &operator=(KeepAlivePolicy &&) noexcept = default;

        // ─── 4. Member Functions & Friend Declarations (LAST) ──────────────
        template<typename Self, typename Req, typename Res>
        bool handle_impl(this Self &&, Req &req, Res &res) {
            if (req.should_keep_alive()) {
                res.set("Connection", "keep-alive");
                res.set("Keep-Alive", "timeout=" + std::to_string(TimeoutSec) + ", max=" + std::to_string(MaxRequests));
            } else {
                res.set("Connection", "close");
            }
            return true;
        }

        template<typename Self>
        [[nodiscard]] constexpr std::string_view name_impl(this Self &&) noexcept {
            return "KeepAlivePolicy";
        }
    };
} // namespace wavex
