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
#include <fstream>
#include <mutex>
#include <optional>
#include <format>
#include <chrono>
#include <thread>
#include <source_location>
#include <cstdlib>
#include <filesystem>
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
        FATAL = 5 ///< Unrecoverable — logs then calls std::abort()
    };

    /**
     * @brief Returns a short string tag for a log level.
     */
    constexpr std::string_view log_level_tag(LogLevel lvl) {
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
    constexpr std::string_view log_level_color(LogLevel lvl) {
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

    constexpr std::string_view ansi_reset = "\033[0m";

    /**
     * @class Logger
     * @brief Thread-safe, singleton logger with leveled output and source location support.
     */
    class Logger {
    public:
        /// Global singleton access
        static Logger &instance() {
            static Logger inst;
            return inst;
        }

        /// Set the minimum log level — anything below is discarded
        void set_level(const LogLevel level = LogLevel::INFO) { min_level_ = level; }

        /// Get the current minimum log level
        [[nodiscard]] LogLevel level() const { return min_level_; }

        /// Enable or disable ANSI terminal colors
        void set_colored(bool enable) { colored_ = enable; }

        /// Check if ANSI colors are enabled
        [[nodiscard]] bool colored() const { return colored_; }

        /// Direct output to a different stream (default: std::cerr)
        void set_output(std::ostream &os) {
            std::lock_guard lock(mutex_);
            file_sink_.reset();
            sink_ = &os;
        }

        /// Direct output to a file
        void set_output(const std::filesystem::path &path = "./logs/wavex.log") {
            std::lock_guard lock(mutex_);
            file_sink_.emplace(path, std::ios::app);
            if (file_sink_->is_open()) {
                sink_ = &*file_sink_;
            }
        }

        /**
         * @brief Core logging function with std::source_location.
         */
        template<typename... Args>
        void log_loc(const LogLevel lvl,
                     const std::source_location &loc,
                     std::format_string<Args...> fmt,
                     Args &&... args) {
            if (lvl < min_level_) return;
            const std::string user_msg = std::format(fmt, std::forward<Args>(args)...);
            write_loc(lvl, loc, user_msg);
        }

        /**
         * @brief Overload for string_view message with std::source_location.
         */
        void log_loc(const LogLevel lvl,
                     const std::source_location &loc,
                     const std::string_view msg) {
            if (lvl < min_level_) return;
            write_loc(lvl, loc, msg);
        }

        /**
         * @brief Core logging function without explicit source location (backward compatible).
         */
        template<typename... Args>
        void log(const LogLevel lvl,
                 std::format_string<Args...> fmt,
                 Args &&... args) {
            if (lvl < min_level_) return;
            const std::string user_msg = std::format(fmt, std::forward<Args>(args)...);
            write(lvl, user_msg);
        }

        /**
         * @brief Overload for plain string messages (no format args).
         */
        void log(const LogLevel lvl, const std::string_view msg) {
            if (lvl < min_level_) return;
            write(lvl, msg);
        }

        Logger(const Logger &) = delete;

        Logger &operator=(const Logger &) = delete;

    private:
        Logger() = default;

        static std::string_view extract_filename(std::string_view filepath) {
            auto pos = filepath.find_last_of("/\\");
            return (pos == std::string_view::npos) ? filepath : filepath.substr(pos + 1);
        }

        void write_loc(const LogLevel lvl, const std::source_location &loc, std::string_view msg) {
            const auto now = std::chrono::system_clock::now();
            auto time = std::chrono::floor<std::chrono::milliseconds>(now);
            auto tid = std::this_thread::get_id();
            auto filename = extract_filename(loc.file_name());

            std::string line;
            if (colored_ && !file_sink_.has_value()) {
                // Format: [2026-06-13 15:30:05.123] [INFO ] [tid:1234] [file.cpp:42] message
                line = std::format("{}[{}] [{}] [tid:{}] [{}:{}] {}{}\n",
                                   log_level_color(lvl),
                                   time, log_level_tag(lvl), tid,
                                   filename, loc.line(),
                                   msg, ansi_reset);
            } else {
                line = std::format("[{}] [{}] [tid:{}] [{}:{}] {}\n",
                                   time, log_level_tag(lvl), tid,
                                   filename, loc.line(), msg);
            }

            std::lock_guard lock(mutex_);
            (*sink_) << line;
            sink_->flush();
        }

        void write(const LogLevel lvl, std::string_view msg) {
            const auto now = std::chrono::system_clock::now();
            auto time = std::chrono::floor<std::chrono::milliseconds>(now);
            auto tid = std::this_thread::get_id();

            std::string line;
            if (colored_ && !file_sink_.has_value()) {
                line = std::format("{}[{}] [{}] [tid:{}] {}{}\n",
                                   log_level_color(lvl),
                                   time, log_level_tag(lvl), tid,
                                   msg, ansi_reset);
            } else {
                line = std::format("[{}] [{}] [tid:{}] {}\n",
                                   time, log_level_tag(lvl), tid, msg);
            }

            std::lock_guard lock(mutex_);
            (*sink_) << line;
            sink_->flush();
        }

        LogLevel min_level_ = LogLevel::INFO;
        bool colored_ = true;
        std::ostream *sink_ = &std::cerr;
        std::optional<std::ofstream> file_sink_;
        std::mutex mutex_;
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
    template<typename... Args>
    struct format_with_loc {
        std::format_string<Args...> fmt;
        std::source_location loc;

        template<typename T>
            requires std::constructible_from < std::format_string < Args

        ...
        >
        ,
        T
        >
        consteval format_with_loc(const T &s, std::source_location l = std::source_location::current())
            : fmt(s), loc(l) {
        }
    };

    struct msg_with_loc {
        std::string_view msg;
        std::source_location loc;

        template<typename T>
            requires std::convertible_to<T, std::string_view>
        constexpr msg_with_loc(const T &s, std::source_location l = std::source_location::current())
            : msg(s), loc(l) {
        }
    };

    // --- Modern Log Functions (Formatted) ---

    template<typename... Args>
    inline void trace(format_with_loc<std::type_identity_t<Args>...> fwl, Args &&... args) {
        ::wavex::base::Logger::instance().log_loc(::wavex::base::LogLevel::TRACE, fwl.loc, fwl.fmt,
                                                  std::forward<Args>(args)...);
    }

    inline void trace(const msg_with_loc &mwl) {
        ::wavex::base::Logger::instance().log_loc(::wavex::base::LogLevel::TRACE, mwl.loc, mwl.msg);
    }

    template<typename... Args>
    inline void debug(format_with_loc<std::type_identity_t<Args>...> fwl, Args &&... args) {
        ::wavex::base::Logger::instance().log_loc(::wavex::base::LogLevel::DEBUG, fwl.loc, fwl.fmt,
                                                  std::forward<Args>(args)...);
    }

    inline void debug(const msg_with_loc &mwl) {
        ::wavex::base::Logger::instance().log_loc(::wavex::base::LogLevel::DEBUG, mwl.loc, mwl.msg);
    }

    template<typename... Args>
    inline void info(format_with_loc<std::type_identity_t<Args>...> fwl, Args &&... args) {
        ::wavex::base::Logger::instance().log_loc(::wavex::base::LogLevel::INFO, fwl.loc, fwl.fmt,
                                                  std::forward<Args>(args)...);
    }

    inline void info(const msg_with_loc &mwl) {
        ::wavex::base::Logger::instance().log_loc(::wavex::base::LogLevel::INFO, mwl.loc, mwl.msg);
    }

    template<typename... Args>
    inline void warn(format_with_loc<std::type_identity_t<Args>...> fwl, Args &&... args) {
        ::wavex::base::Logger::instance().log_loc(::wavex::base::LogLevel::WARN, fwl.loc, fwl.fmt,
                                                  std::forward<Args>(args)...);
    }

    inline void warn(const msg_with_loc &mwl) {
        ::wavex::base::Logger::instance().log_loc(::wavex::base::LogLevel::WARN, mwl.loc, mwl.msg);
    }

    template<typename... Args>
    inline void error(format_with_loc<std::type_identity_t<Args>...> fwl, Args &&... args) {
        ::wavex::base::Logger::instance().log_loc(::wavex::base::LogLevel::ERR, fwl.loc, fwl.fmt,
                                                  std::forward<Args>(args)...);
    }

    inline void error(const msg_with_loc &mwl) {
        ::wavex::base::Logger::instance().log_loc(::wavex::base::LogLevel::ERR, mwl.loc, mwl.msg);
    }

    template<typename... Args>
    [[noreturn]] inline void fatal(format_with_loc<std::type_identity_t<Args>...> fwl, Args &&... args) {
        ::wavex::base::Logger::instance().log_loc(::wavex::base::LogLevel::FATAL, fwl.loc, fwl.fmt,
                                                  std::forward<Args>(args)...);
        std::abort();
    }

    [[noreturn]] inline void fatal(const msg_with_loc &mwl) {
        ::wavex::base::Logger::instance().log_loc(::wavex::base::LogLevel::FATAL, mwl.loc, mwl.msg);
        std::abort();
    }
} // namespace wavex::log

/**
 * Convenience macros for legacy compatibility.
 */
#define WX_LOG_TRACE(...) \
    do { if (::wavex::base::Logger::instance().level() <= ::wavex::base::LogLevel::TRACE) \
        ::wavex::base::Logger::instance().log_loc(::wavex::base::LogLevel::TRACE, std::source_location::current(), __VA_ARGS__); } while(0)

#define WX_LOG_DEBUG(...) \
    do { if (::wavex::base::Logger::instance().level() <= ::wavex::base::LogLevel::DEBUG) \
        ::wavex::base::Logger::instance().log_loc(::wavex::base::LogLevel::DEBUG, std::source_location::current(), __VA_ARGS__); } while(0)

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
