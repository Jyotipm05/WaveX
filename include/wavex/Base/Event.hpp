// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
/**
 * @file Event.hpp
 * @brief Thread-safe, generic C++23 publish-subscribe Event and EventBus abstractions.
 *
 * Provides:
 *  - Event<Args...>: Multicast signal/event with unique 64-bit subscription handles,
 *                    RAII scoped subscriptions, and snapshot-isolated dispatch.
 *  - EventBus: Heterogeneous typed publish-subscribe bus for decoupled inter-component
 *              event messaging across the framework.
 *  - ShutdownEvent: Specialized alias and struct for server graceful shutdown.
 */

#pragma once

#include <cstdint>
#include <chrono>
#include <functional>
#include <vector>
#include <mutex>
#include <memory>
#include <typeindex>
#include <unordered_map>
#include <utility>
#include <atomic>

namespace wavex::base {

    using SubscriptionId = std::uint64_t;

    /**
     * @brief Forward declaration of Event template.
     */
    template<typename... Args>
    class Event;

    /**
     * @brief RAII handle managing an active event subscription.
     *
     * Automatically unregisters the listener when the Subscription object goes out of scope,
     * unless detached or manually released.
     */
    class Subscription {
    public:
        Subscription() noexcept = default;

        Subscription(std::function<void()> unbind) noexcept
            : unbind_(std::move(unbind)), active_(true) {}

        ~Subscription() {
            reset();
        }

        Subscription(Subscription &&other) noexcept
            : unbind_(std::move(other.unbind_)), active_(other.active_) {
            other.active_ = false;
        }

        Subscription &operator=(Subscription &&other) noexcept {
            if (this != &other) {
                reset();
                unbind_ = std::move(other.unbind_);
                active_ = other.active_;
                other.active_ = false;
            }
            return *this;
        }

        Subscription(const Subscription &) = delete;
        Subscription &operator=(const Subscription &) = delete;

        /// Manually unbind the subscription immediately
        void reset() noexcept {
            if (active_ && unbind_) {
                active_ = false;
                try {
                    unbind_();
                } catch (...) {
                    // Suppress exceptions in destructor / cleanup
                }
            }
        }

        /// Synonym for reset()
        void unsubscribe() noexcept {
            reset();
        }

        /// Detach this handle, leaving the subscription active permanently
        void detach() noexcept {
            active_ = false;
        }

        [[nodiscard]] bool is_active() const noexcept {
            return active_;
        }

    private:
        std::function<void()> unbind_;
        bool active_{false};
    };

    /**
     * @brief Thread-safe multicast event with typed arguments.
     *
     * Supports multiple concurrent emitters, dynamic subscription/unsubscription,
     * and snapshot-isolated dispatch to guarantee zero iterator invalidation or
     * deadlocks during callback execution.
     *
     * @tparam Args Argument types emitted by this event.
     */
    template<typename... Args>
    class Event {
    public:
        using Handler = std::function<void(Args...)>;

        Event() = default;
        ~Event() = default;

        Event(const Event &) = delete;
        Event &operator=(const Event &) = delete;
        Event(Event &&) = delete;
        Event &operator=(Event &&) = delete;

        /**
         * @brief Subscribes a listener returning an RAII scoped Subscription handle.
         * @param handler Callable taking (Args...).
         * @return RAII Subscription object that unsubscribes on destruction or via .unsubscribe().
         */
        [[nodiscard]] Subscription subscribe(Handler handler) {
            std::lock_guard<std::mutex> lock(mutex_);
            const SubscriptionId id = next_id_++;
            listeners_.push_back({id, std::move(handler)});
            return Subscription([this, id]() {
                unsubscribe(id);
            });
        }

        /**
         * @brief Synonym for subscribe().
         */
        [[nodiscard]] Subscription subscribe_scoped(Handler handler) {
            return subscribe(std::move(handler));
        }

        /**
         * @brief Subscribes a listener returning raw 64-bit ID.
         */
        SubscriptionId subscribe_raw(Handler handler) {
            std::lock_guard<std::mutex> lock(mutex_);
            const SubscriptionId id = next_id_++;
            listeners_.push_back({id, std::move(handler)});
            return id;
        }

        /**
         * @brief Unsubscribes a listener by its subscription ID.
         * @param id Unique ID returned by subscribe().
         * @return True if a matching listener was found and removed, false otherwise.
         */
        bool unsubscribe(SubscriptionId id) {
            std::lock_guard<std::mutex> lock(mutex_);
            for (auto it = listeners_.begin(); it != listeners_.end(); ++it) {
                if (it->id == id) {
                    listeners_.erase(it);
                    return true;
                }
            }
            return false;
        }

        /**
         * @brief Emits the event with the provided arguments to all subscribed listeners.
         *
         * Copies listeners under lock then invokes them outside the lock, ensuring
         * handlers can safely subscribe/unsubscribe other listeners without deadlocks.
         *
         * @param args Arguments to pass to all listeners.
         */
        void emit(Args... args) const {
            std::vector<Handler> snapshot;
            {
                std::lock_guard<std::mutex> lock(mutex_);
                if (listeners_.empty()) return;
                snapshot.reserve(listeners_.size());
                for (const auto &entry : listeners_) {
                    snapshot.push_back(entry.handler);
                }
            }

            for (const auto &fn : snapshot) {
                if (fn) {
                    fn(args...);
                }
            }
        }

        /**
         * @brief Synonym for emit(). Publishes event to all listeners.
         */
        void publish(Args... args) const {
            emit(std::forward<Args>(args)...);
        }

        /**
         * @brief Function call operator shorthand for emit().
         */
        void operator()(Args... args) const {
            emit(std::forward<Args>(args)...);
        }

        /**
         * @brief Removes all subscribed listeners.
         */
        void clear() {
            std::lock_guard<std::mutex> lock(mutex_);
            listeners_.clear();
        }

        /**
         * @brief Returns the current number of active listeners.
         */
        [[nodiscard]] std::size_t listener_count() const {
            std::lock_guard<std::mutex> lock(mutex_);
            return listeners_.size();
        }

        /**
         * @brief Synonym for listener_count().
         */
        [[nodiscard]] std::size_t subscriber_count() const {
            return listener_count();
        }

        /**
         * @brief Checks if any listeners are registered.
         */
        [[nodiscard]] bool empty() const {
            return listener_count() == 0;
        }

    private:
        struct ListenerEntry {
            SubscriptionId id{0};
            Handler handler;
        };

        mutable std::mutex mutex_;
        std::vector<ListenerEntry> listeners_;
        SubscriptionId next_id_{1};
    };

    /**
     * @brief Heterogeneous typed publish-subscribe EventBus.
     *
     * Decouples event publishers and consumers by dispatching events based on
     * the C++ type of the event payload.
     */
    class EventBus {
    public:
        EventBus() = default;
        ~EventBus() = default;

        EventBus(const EventBus &) = delete;
        EventBus &operator=(const EventBus &) = delete;
        EventBus(EventBus &&) = delete;
        EventBus &operator=(EventBus &&) = delete;

        /**
         * @brief Subscribes a handler to a specific EventType returning RAII Subscription.
         * @tparam EventType Arbitrary C++ struct or class representing the event.
         * @param handler Callable taking (const EventType &).
         * @return RAII Subscription object.
         */
        template<typename EventType>
        [[nodiscard]] Subscription subscribe(std::function<void(const EventType &)> handler) {
            std::lock_guard<std::mutex> lock(mutex_);
            auto &holder = get_or_create_holder<EventType>();
            return holder.subscribe(std::move(handler));
        }

        /**
         * @brief Synonym for subscribe().
         */
        template<typename EventType>
        [[nodiscard]] Subscription subscribe_scoped(std::function<void(const EventType &)> handler) {
            return subscribe<EventType>(std::move(handler));
        }

        /**
         * @brief Subscribes a handler returning raw subscription ID.
         */
        template<typename EventType>
        SubscriptionId subscribe_raw(std::function<void(const EventType &)> handler) {
            std::lock_guard<std::mutex> lock(mutex_);
            auto &holder = get_or_create_holder<EventType>();
            return holder.subscribe_raw(std::move(handler));
        }

        /**
         * @brief Publishes an event to all subscribed listeners for EventType.
         * @tparam EventType Type of event being published.
         * @param event The event object to broadcast.
         */
        template<typename EventType>
        void publish(const EventType &event) {
            std::shared_ptr<Event<const EventType &>> holder_copy;
            {
                std::lock_guard<std::mutex> lock(mutex_);
                auto it = channels_.find(typeid(EventType));
                if (it == channels_.end()) return;
                holder_copy = std::static_pointer_cast<Event<const EventType &>>(it->second);
            }
            if (holder_copy) {
                holder_copy->emit(event);
            }
        }

        /**
         * @brief Unsubscribes a listener for EventType by its ID.
         * @tparam EventType Type of event.
         * @param id Unique subscription ID.
         * @return True if listener was found and removed, false otherwise.
         */
        template<typename EventType>
        bool unsubscribe(SubscriptionId id) {
            std::lock_guard<std::mutex> lock(mutex_);
            auto it = channels_.find(typeid(EventType));
            if (it == channels_.end()) return false;
            auto holder = std::static_pointer_cast<Event<const EventType &>>(it->second);
            return holder->unsubscribe(id);
        }

        /**
         * @brief Returns current number of subscribers registered for EventType.
         */
        template<typename EventType>
        [[nodiscard]] std::size_t subscriber_count() const {
            std::lock_guard<std::mutex> lock(mutex_);
            auto it = channels_.find(std::type_index(typeid(EventType)));
            if (it == channels_.end()) return 0;
            auto holder = std::static_pointer_cast<Event<const EventType &>>(it->second);
            return holder->subscriber_count();
        }

        /**
         * @brief Synonym for subscriber_count<EventType>().
         */
        template<typename EventType>
        [[nodiscard]] std::size_t listener_count() const {
            return subscriber_count<EventType>();
        }

        /**
         * @brief Clears all channels and listeners.
         */
        void clear() {
            std::lock_guard<std::mutex> lock(mutex_);
            channels_.clear();
        }

    private:
        template<typename EventType>
        Event<const EventType &> &get_or_create_holder() {
            const auto key = std::type_index(typeid(EventType));
            auto it = channels_.find(key);
            if (it == channels_.end()) {
                auto holder = std::make_shared<Event<const EventType &>>();
                channels_[key] = holder;
                return *holder;
            }
            return *std::static_pointer_cast<Event<const EventType &>>(it->second);
        }

        mutable std::mutex mutex_;
        std::unordered_map<std::type_index, std::shared_ptr<void>> channels_;
    };

    /**
     * @brief Specialized Event alias for server graceful shutdown requests.
     * Emits the requested grace period timeout (e.g., 10 seconds).
     */
    using ShutdownEvent = Event<std::chrono::milliseconds>;

    /**
     * @brief Structured event for publishing shutdown on an EventBus.
     */
    struct ServerShutdownEvent {
        std::chrono::milliseconds timeout{10000};
    };

} // namespace wavex::base
