// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * @file Logger.hpp
 * @brief Modernized leveled logger for WaveX with C++23 source_location and zero-macro API.
 *
 * Provides 6 severity levels (TRACE -> FATAL), global singleton, thread-safe
 * output, ANSI terminal styling, automatic source location capture, and both
 * modern functional API (wavex::log::*) and legacy WX_LOG_* macros.
 */

#pragma once

#include <string>
#include <string_view>
#include <iostream>
#include <wavex/Utils/BinaryFile.hpp>
#include <mutex>
// Required by the standard for what this header uses. MSVC's STL already includes them transitively,
// libstdc++/libc++ do not, so they are only spelled out for non-MSVC toolchains.
#if !defined(_MSC_VER)
#include <atomic>
#include <condition_variable>
#include <cstring>
#include <thread>
#endif
#include <optional>
#include <format>
#include <source_location>
#include <cstdlib>

#include <type_traits>

// Windows SDK headers (pulled in via ASIO/winsock) define these names as macros.
// Save and undef them so the enum class members below compile cleanly on MSVC.
#ifdef ERROR
#  pragma push_macro("ERROR")
#  undef ERROR
#  define WAVEX_LOGGER_HAD_ERROR
#endif
#ifdef DEBUG
#  pragma push_macro("DEBUG")
#  undef DEBUG
#  define WAVEX_LOGGER_HAD_DEBUG
#endif
#ifdef TRACE
#  pragma push_macro("TRACE")
#  undef TRACE
#  define WAVEX_LOGGER_HAD_TRACE
#endif

namespace wavex::base {
    /**
     * @enum LogLevel
     * @brief Severity levels for the WaveX logging system.
     */
    enum class LogLevel : uint8_t {
        TRACE = 0, ///< Fine-grained debug: function entry/exit, buffer dumps
        DEBUG = 1, ///< Development diagnostics: route matching, codec details
        INFO = 2, ///< Lifecycle events: startup, listening, worker counts
        WARN = 3, ///< Recoverable issues: timeouts, retries, deprecation
        ERR = 4, ///< Request failures, socket errors, parse failures
        ERROR = 4, ///< Alias for ERR
        FATAL = 5 ///< Unrecoverable — logs then calls std::abort()
    };

    /**
     * @brief Returns a short string tag for a log level.
     */
    constexpr std::string_view log_level_tag(const LogLevel lvl) {
        switch (lvl) {
            case LogLevel::TRACE: return "TRACE";
            case LogLevel::DEBUG: return "DEBUG";
            case LogLevel::INFO: return "INFO ";
            case LogLevel::WARN: return "WARN ";
            case LogLevel::ERR: return "ERROR";
            case LogLevel::FATAL: return "FATAL";
            default: return "?????";
        }
    }

    /**
     * @brief Returns ANSI color code for a log level.
     */
    constexpr std::string_view log_level_color(const LogLevel lvl) {
        switch (lvl) {
            case LogLevel::TRACE: return "\033[36m"; // Cyan
            case LogLevel::DEBUG: return "\033[34m"; // Blue
            case LogLevel::INFO: return "\033[32m"; // Green
            case LogLevel::WARN: return "\033[33m"; // Yellow
            case LogLevel::ERR: return "\033[31m"; // Red
            case LogLevel::FATAL: return "\033[1;31m"; // Bold Red
            default: return "\033[0m";
        }
    }

    inline constexpr std::string_view ansi_reset = "\033[0m";

    /**
     * @enum OverflowPolicy
     * @brief Queue overflow handling strategies when the log buffer pool or queue is full.
     */
    enum class OverflowPolicy : uint8_t {
        Drop = 0,  ///< Non-blocking: increment dropped_count_ and return immediately (default)
        Block = 1, ///< Blocking: caller waits until queue space becomes available
        Grow = 2   ///< Dynamic growth: expand buffer pool up to max_pool_capacity
    };

    /**
     * @struct LoggerConfig
     * @brief Runtime configuration for the WaveX logger buffer pool and worker thread.
     */
    struct LoggerConfig {
        // ─── 2. Member Variables (SECOND - Ordered for Minimal Padding) ────
        size_t pool_capacity{4096};
        size_t max_pool_capacity{16384};
        std::chrono::milliseconds flush_interval{50};
        OverflowPolicy overflow_policy{OverflowPolicy::Drop};
        bool async_mode{true};
    };

    /**
     * @struct LogBuffer
     * @brief Pre-allocated log record slot leased from LogBufferPool.
     */
    struct LogBuffer {
        // ─── 1. Nested Types & Definitions (TOP) ───────────────────────────
        static constexpr size_t kInlineCapacity = 512;

        // ─── 2. Member Variables (SECOND - Ordered for Minimal Padding) ────
        std::chrono::system_clock::time_point timestamp{};
        std::string fallback{};
        uint32_t line{0};
        uint32_t length{0};
        LogLevel level{LogLevel::INFO};
        uint8_t thread_id_len{0};
        bool has_location{false};
        char thread_id_buf[24]{};
        char filename_buf[64]{};
        char inline_storage[kInlineCapacity]{};

        // ─── 3. Constructors & Destructor (MIDDLE) ─────────────────────────
        LogBuffer() = default;
        ~LogBuffer() = default;

        LogBuffer(const LogBuffer &) = default;
        LogBuffer &operator=(const LogBuffer &) = default;
        LogBuffer(LogBuffer &&) noexcept = default;
        LogBuffer &operator=(LogBuffer &&) noexcept = default;

        // ─── 4. Member Functions & Friend Declarations (LAST) ──────────────
        void clear() noexcept {
            length = 0;
            fallback.clear();
            has_location = false;
            thread_id_len = 0;
        }

        [[nodiscard]] std::string_view message_view() const noexcept {
            if (!fallback.empty()) {
                return fallback;
            }
            return {inline_storage, length};
        }

        [[nodiscard]] std::string_view filename_view() const noexcept {
            if (!has_location) return {};
            return filename_buf;
        }
    };

    /**
     * @class Logger
     * @brief Thread-safe, non-blocking asynchronous singleton logger with log buffer pooling.
     */
    class Logger {
    public:
        // ─── 1. Nested Types & Definitions (TOP) ───────────────────────────
        struct BufferPool;
        struct AsyncQueue;

    private:
        // ─── 2. Member Variables (SECOND - Ordered for Minimal Padding) ────
        size_t pool_capacity_{4096};
        size_t max_pool_capacity_{16384};
        std::atomic<uint64_t> dropped_count_{0};
        std::atomic<uint64_t> submitted_count_{0};
        std::atomic<uint64_t> processed_count_{0};
        std::atomic<int64_t> flush_interval_ms_{50}; ///< read by the worker while configure() may rewrite it
        std::unique_ptr<BufferPool> pool_{};
        std::unique_ptr<AsyncQueue> queue_{};
        std::ostream *sink_{&std::cerr};
        std::thread worker_thread_{};
        std::mutex mutex_{};
        std::mutex flush_mutex_{};
        std::condition_variable cv_flush_{};
        std::optional<utils::BinaryFile> file_sink_{};
        LogLevel min_level_{LogLevel::INFO};
        OverflowPolicy overflow_policy_{OverflowPolicy::Drop};
        bool colored_{true};
        std::atomic<bool> async_mode_{true}; ///< read on every log call, written by set_async()/configure()
        bool explicit_async_{false};
        bool custom_stream_{false};
        std::atomic<bool> running_{false}; ///< shared between the worker, flush() and shutdown()

    public:
        // ─── 3. Constructors & Destructor (MIDDLE) ─────────────────────────
        Logger();
        ~Logger();

        Logger(const Logger &) = delete;
        Logger &operator=(const Logger &) = delete;
        Logger(Logger &&) = delete;
        Logger &operator=(Logger &&) = delete;

        // ─── 4. Member Functions & Friend Declarations (LAST) ──────────────
        /// Global singleton access
        static Logger &instance();

        /// Reconfigure logger buffer pool and worker settings
        void configure(const LoggerConfig &config);

        /// Set the minimum log level — anything below is discarded
        void set_level(const LogLevel level = LogLevel::INFO) noexcept { min_level_ = level; }

        /// Get the current minimum log level
        [[nodiscard]] LogLevel level() const noexcept { return min_level_; }

        /// Enable or disable ANSI terminal colors
        void set_colored(const bool enable) noexcept { colored_ = enable; }

        /// Check if ANSI colors are enabled
        [[nodiscard]] bool colored() const noexcept { return colored_; }

        /// Set queue overflow policy
        void set_overflow_policy(const OverflowPolicy policy) noexcept { overflow_policy_ = policy; }

        /// Get current queue overflow policy
        [[nodiscard]] OverflowPolicy overflow_policy() const noexcept { return overflow_policy_; }

        /// Enable or disable asynchronous mode
        void set_async(bool enable);

        /// Check if asynchronous mode is active
        [[nodiscard]] bool is_async() const noexcept { return async_mode_; }

        /// Get count of dropped messages due to queue overflow
        [[nodiscard]] uint64_t dropped_count() const noexcept {
            return dropped_count_.load(std::memory_order_relaxed);
        }

        /// Direct output to a different stream (default: std::cerr)
        void set_output(std::ostream &os);

        /// Direct output to a file
        void set_output(const std::string &path = "./logs/wavex.log");

        /// Flush pending logs synchronously to sink
        void flush();

        /// Shutdown worker thread and flush
        void shutdown();

        /**
         * @brief Core logging function with std::source_location.
         */
        template<typename... Args>
        void log_loc(const LogLevel lvl,
                     const std::source_location &loc,
                     std::format_string<Args...> fmt,
                     Args &&... args) {
            if (lvl < min_level_) return;
            if (is_sync_path()) {
                const std::string user_msg = std::format(fmt, std::forward<Args>(args)...);
                write_loc_sync(lvl, loc, user_msg);
                return;
            }
            LogBuffer *slot = acquire_buffer(lvl);
            if (!slot) return;
            populate_header(slot, lvl, loc);
            if (auto res = std::format_to_n(slot->inline_storage, LogBuffer::kInlineCapacity, fmt,
                                            std::forward<Args>(args)...);
                static_cast<size_t>(res.size) <= LogBuffer::kInlineCapacity) {
                slot->length = static_cast<uint32_t>(res.size);
            } else {
                slot->fallback = std::format(fmt, std::forward<Args>(args)...);
            }
            enqueue_buffer(slot);
        }

        /**
         * @brief Overload for string_view message with std::source_location.
         */
        void log_loc(const LogLevel lvl,
                     const std::source_location &loc,
                     const std::string_view msg) {
            if (lvl < min_level_) return;
            if (is_sync_path()) {
                write_loc_sync(lvl, loc, msg);
                return;
            }
            LogBuffer *slot = acquire_buffer(lvl);
            if (!slot) return;
            populate_header(slot, lvl, loc);
            if (msg.size() <= LogBuffer::kInlineCapacity) {
                std::memcpy(slot->inline_storage, msg.data(), msg.size());
                slot->length = static_cast<uint32_t>(msg.size());
            } else {
                slot->fallback.assign(msg.data(), msg.size());
            }
            enqueue_buffer(slot);
        }

        /**
         * @brief Core logging function without explicit source location (backward compatible).
         */
        template<typename... Args>
        void log(const LogLevel lvl,
                 std::format_string<Args...> fmt,
                 Args &&... args) {
            if (lvl < min_level_) return;
            if (is_sync_path()) {
                const std::string user_msg = std::format(fmt, std::forward<Args>(args)...);
                write_sync(lvl, user_msg);
                return;
            }
            LogBuffer *slot = acquire_buffer(lvl);
            if (!slot) return;
            populate_header_no_loc(slot, lvl);
            if (auto res = std::format_to_n(slot->inline_storage, LogBuffer::kInlineCapacity, fmt,
                                            std::forward<Args>(args)...);
                static_cast<size_t>(res.size) <= LogBuffer::kInlineCapacity) {
                slot->length = static_cast<uint32_t>(res.size);
            } else {
                slot->fallback = std::format(fmt, std::forward<Args>(args)...);
            }
            enqueue_buffer(slot);
        }

        /**
         * @brief Overload for plain string messages (no format args).
         */
        void log(const LogLevel lvl, const std::string_view msg) {
            if (lvl < min_level_) return;
            if (is_sync_path()) {
                write_sync(lvl, msg);
                return;
            }
            LogBuffer *slot = acquire_buffer(lvl);
            if (!slot) return;
            populate_header_no_loc(slot, lvl);
            if (msg.size() <= LogBuffer::kInlineCapacity) {
                std::memcpy(slot->inline_storage, msg.data(), msg.size());
                slot->length = static_cast<uint32_t>(msg.size());
            } else {
                slot->fallback.assign(msg.data(), msg.size());
            }
            enqueue_buffer(slot);
        }

    private:
        [[nodiscard]] bool is_sync_path() const noexcept {
            if (!async_mode_ || !running_) return true;
            if (!explicit_async_ && custom_stream_) return true;
            return false;
        }

        void notify_flush_waiters();

        static std::string_view extract_filename(std::string_view filepath);
        static void populate_header(LogBuffer *slot, LogLevel lvl, const std::source_location &loc);
        static void populate_header_no_loc(LogBuffer *slot, LogLevel lvl);

        LogBuffer *acquire_buffer(LogLevel lvl);
        void enqueue_buffer(LogBuffer *slot);

        void write_loc_sync(LogLevel lvl, const std::source_location &loc, std::string_view msg);
        void write_sync(LogLevel lvl, std::string_view msg);

        void start_worker();
        void worker_loop();
        void format_record(const LogBuffer *slot, std::string &line) const;
    };
} // namespace wavex::base

// Restore the Windows macros that were saved above, using the sentinel guards.
#ifdef WAVEX_LOGGER_HAD_TRACE
#  pragma pop_macro("TRACE")
#  undef WAVEX_LOGGER_HAD_TRACE
#endif
#ifdef WAVEX_LOGGER_HAD_DEBUG
#  pragma pop_macro("DEBUG")
#  undef WAVEX_LOGGER_HAD_DEBUG
#endif
#ifdef WAVEX_LOGGER_HAD_ERROR
//#  pragma pop_macro("ERROR")
#  undef WAVEX_LOGGER_HAD_ERROR
#endif

/**
 * @namespace wavex::log
 * @brief Modern zero-macro logging interface with automatic source_location capture.
 */
namespace wavex::log {
    using LogLevel = base::LogLevel;
    using OverflowPolicy = base::OverflowPolicy;
    using LoggerConfig = base::LoggerConfig;

    template<typename... Args>
    struct format_with_loc {
        std::format_string<Args...> fmt;
        std::source_location loc;

        template<typename T>
            requires std::constructible_from<std::format_string<Args...>, const T &>
        // ReSharper disable once CppNonExplicitConvertingConstructor
        consteval format_with_loc(const T &s, const std::source_location l = std::source_location::current())
            : fmt(s), loc(l) {
        }
    };

    struct msg_with_loc {
        std::string_view msg;
        std::source_location loc;

        template<typename T>
            requires std::convertible_to<T, std::string_view>
        // ReSharper disable once CppNonExplicitConvertingConstructor
        constexpr msg_with_loc(const T &s, const std::source_location l = std::source_location::current())
            : msg(s), loc(l) {
        }
    };

    // --- Log Level Enablement Invariant ---
    // In Release builds without ENABLE_LOGGING, trace and debug logs are compiled
    // as no-op inline functions that the compiler eliminates completely.
    // INFO, WARN, ERROR, and FATAL logs, as well as base log_loc(), remain unaffected in all builds.
#if defined(ENABLE_LOGGING) || defined(WAVEX_ENABLE_LOGGING)
#  define WAVEX_LOG_ENABLED 1
#elif !defined(NDEBUG) || defined(_DEBUG) || defined(DEBUG)
#  define WAVEX_LOG_ENABLED 1
#else
#  define WAVEX_LOG_ENABLED 0
#endif

    // --- Modern Log Functions (Formatted) ---

#if WAVEX_LOG_ENABLED

    template<typename... Args>
    inline void trace(format_with_loc<std::type_identity_t<Args>...> fwl, Args &&... args) {
        base::Logger::instance().log_loc(LogLevel::TRACE, fwl.loc, fwl.fmt,
                                                  std::forward<Args>(args)...);
    }

    inline void trace(const msg_with_loc &mwl) {
        base::Logger::instance().log_loc(LogLevel::TRACE, mwl.loc, mwl.msg);
    }

    template<typename... Args>
    inline void debug(format_with_loc<std::type_identity_t<Args>...> fwl, Args &&... args) {
        base::Logger::instance().log_loc(LogLevel::DEBUG, fwl.loc, fwl.fmt,
                                                  std::forward<Args>(args)...);
    }

    inline void debug(const msg_with_loc &mwl) {
        base::Logger::instance().log_loc(LogLevel::DEBUG, mwl.loc, mwl.msg);
    }

#else

    template<typename... Args>
    inline void trace([[maybe_unused]] format_with_loc<std::type_identity_t<Args>...> fwl,
                      [[maybe_unused]] Args &&... args) {
    }

    inline void trace([[maybe_unused]] const msg_with_loc &mwl) {
    }

    template<typename... Args>
    inline void debug([[maybe_unused]] format_with_loc<std::type_identity_t<Args>...> fwl,
                      [[maybe_unused]] Args &&... args) {
    }

    inline void debug([[maybe_unused]] const msg_with_loc &mwl) {
    }

#endif

    template<typename... Args>
    inline void info(format_with_loc<std::type_identity_t<Args>...> fwl, Args &&... args) {
        base::Logger::instance().log_loc(LogLevel::INFO, fwl.loc, fwl.fmt,
                                                  std::forward<Args>(args)...);
    }

    inline void info(const msg_with_loc &mwl) {
        base::Logger::instance().log_loc(LogLevel::INFO, mwl.loc, mwl.msg);
    }

    template<typename... Args>
    inline void warn(format_with_loc<std::type_identity_t<Args>...> fwl, Args &&... args) {
        base::Logger::instance().log_loc(LogLevel::WARN, fwl.loc, fwl.fmt,
                                                  std::forward<Args>(args)...);
    }

    inline void warn(const msg_with_loc &mwl) {
        base::Logger::instance().log_loc(LogLevel::WARN, mwl.loc, mwl.msg);
    }

    template<typename... Args>
    inline void error(format_with_loc<std::type_identity_t<Args>...> fwl, Args &&... args) {
        base::Logger::instance().log_loc(LogLevel::ERR, fwl.loc, fwl.fmt,
                                                  std::forward<Args>(args)...);
    }

    inline void error(const msg_with_loc &mwl) {
        base::Logger::instance().log_loc(LogLevel::ERR, mwl.loc, mwl.msg);
    }

    template<typename... Args>
    [[noreturn]] inline void fatal(format_with_loc<std::type_identity_t<Args>...> fwl, Args &&... args) {
        base::Logger::instance().log_loc(LogLevel::FATAL, fwl.loc, fwl.fmt,
                                                  std::forward<Args>(args)...);
        base::Logger::instance().flush();
        std::abort();
    }

    [[noreturn]] inline void fatal(const msg_with_loc &mwl) {
        base::Logger::instance().log_loc(LogLevel::FATAL, mwl.loc, mwl.msg);
        base::Logger::instance().flush();
        std::abort();
    }

    inline void set_level(const LogLevel level) {
        base::Logger::instance().set_level(level);
    }

    inline void set_async(const bool enable) {
        base::Logger::instance().set_async(enable);
    }

    inline void set_overflow_policy(const OverflowPolicy policy) {
        base::Logger::instance().set_overflow_policy(policy);
    }

    inline void configure(const LoggerConfig &config) {
        base::Logger::instance().configure(config);
    }

    inline void flush() {
        base::Logger::instance().flush();
    }

    inline uint64_t dropped_count() {
        return base::Logger::instance().dropped_count();
    }
} // namespace wavex::log

/**
 * Convenience macros for legacy compatibility.
 */
#if WAVEX_LOG_ENABLED

#define WX_LOG_TRACE(...) \
    do { if (::wavex::base::Logger::instance().level() <= ::wavex::base::LogLevel::TRACE) \
        ::wavex::base::Logger::instance().log_loc(::wavex::base::LogLevel::TRACE, std::source_location::current(), __VA_ARGS__); } while(0)

#define WX_LOG_DEBUG(...) \
    do { if (::wavex::base::Logger::instance().level() <= ::wavex::base::LogLevel::DEBUG) \
        ::wavex::base::Logger::instance().log_loc(::wavex::base::LogLevel::DEBUG, std::source_location::current(), __VA_ARGS__); } while(0)

#else

#define WX_LOG_TRACE(...) do {} while(0)
#define WX_LOG_DEBUG(...) do {} while(0)

#endif

#define WX_LOG_INFO(...) \
    do { if (::wavex::base::Logger::instance().level() <= ::wavex::base::LogLevel::INFO) \
        ::wavex::base::Logger::instance().log_loc(::wavex::base::LogLevel::INFO, std::source_location::current(), __VA_ARGS__); } while(0)

#define WX_LOG_WARN(...) \
    do { if (::wavex::base::Logger::instance().level() <= ::wavex::base::LogLevel::WARN) \
        ::wavex::base::Logger::instance().log_loc(::wavex::base::LogLevel::WARN, std::source_location::current(), __VA_ARGS__); } while(0)


#define WX_LOG_ERROR(...) \
    do { if (::wavex::base::Logger::instance().level() <= ::wavex::base::LogLevel::ERR) \
        ::wavex::base::Logger::instance().log_loc(::wavex::base::LogLevel::ERR, std::source_location::current(), __VA_ARGS__); } while(0)

#define WX_LOG_FATAL(...) \
    do { ::wavex::base::Logger::instance().log_loc(::wavex::base::LogLevel::FATAL, std::source_location::current(), __VA_ARGS__); \
         std::abort(); } while(0)
namespace wxlog = wavex::log;
