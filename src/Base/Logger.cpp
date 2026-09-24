// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * @file Logger.cpp
 * @brief Out-of-line Logger output formatting and sink dispatch implementations.
 */

#include <wavex/Base/Logger.hpp>

#include <charconv>
#include <chrono>
#include <cstdio>
#include <sstream>
#include <thread>

namespace wavex::base {
    namespace {
        void format_timestamp(const std::chrono::system_clock::time_point now, std::string &out) {
            using namespace std::chrono;
            const auto ms = duration_cast<milliseconds>(now.time_since_epoch()).count();
            const auto sec = static_cast<std::time_t>(ms / 1000);
            auto millis = static_cast<int>(ms % 1000);
            if (millis < 0) millis += 1000;

            std::tm tm_buf{};
#if defined(_WIN32)
            gmtime_s(&tm_buf, &sec);
#else
            gmtime_r(&sec, &tm_buf);
#endif

            char buf[32];
            std::snprintf(buf, sizeof(buf), "%04d-%02d-%02d %02d:%02d:%02d.%03d",
                          tm_buf.tm_year + 1900, tm_buf.tm_mon + 1, tm_buf.tm_mday,
                          tm_buf.tm_hour, tm_buf.tm_min, tm_buf.tm_sec, millis);
            out.append(buf);
        }

        void append_thread_id(std::string &out) {
            thread_local std::string tid_str = [] {
                std::ostringstream oss;
                oss << std::this_thread::get_id();
                return oss.str();
            }();
            out.append(tid_str);
        }
    } // anonymous namespace

    std::string_view Logger::extract_filename(const std::string_view filepath) {
        const auto pos = filepath.find_last_of("/\\");
        return (pos == std::string_view::npos) ? filepath : filepath.substr(pos + 1);
    }

    void Logger::write_loc(const LogLevel lvl, const std::source_location &loc, const std::string_view msg) {
        const auto now = std::chrono::system_clock::now();
        const auto filename = extract_filename(loc.file_name());

        std::string line;
        line.reserve(128 + msg.size());

        if (colored_ && !file_sink_.has_value()) {
            line.append(log_level_color(lvl));
        }

        line.push_back('[');
        format_timestamp(now, line);
        line.append("] [");
        line.append(log_level_tag(lvl));
        line.append("] [tid:");
        append_thread_id(line);
        line.append("] [");
        line.append(filename);
        line.push_back(':');
        char line_num_buf[16];
        const auto [ptr, _] = std::to_chars(line_num_buf, line_num_buf + sizeof(line_num_buf), loc.line());
        line.append(line_num_buf, static_cast<size_t>(ptr - line_num_buf));
        line.append("] ");
        line.append(msg);

        if (colored_ && !file_sink_.has_value()) {
            line.append(ansi_reset);
        }
        line.push_back('\n');

        std::lock_guard lock(mutex_);
        if (file_sink_.has_value() && file_sink_->is_open()) {
            std::ignore = file_sink_->write(line);
            std::ignore = file_sink_->flush();
        } else if (sink_) {
            (*sink_) << line;
            sink_->flush();
        }
    }

    void Logger::write(const LogLevel lvl, const std::string_view msg) {
        const auto now = std::chrono::system_clock::now();

        std::string line;
        line.reserve(96 + msg.size());

        if (colored_ && !file_sink_.has_value()) {
            line.append(log_level_color(lvl));
        }

        line.push_back('[');
        format_timestamp(now, line);
        line.append("] [");
        line.append(log_level_tag(lvl));
        line.append("] [tid:");
        append_thread_id(line);
        line.append("] ");
        line.append(msg);

        if (colored_ && !file_sink_.has_value()) {
            line.append(ansi_reset);
        }
        line.push_back('\n');

        std::lock_guard lock(mutex_);
        if (file_sink_.has_value() && file_sink_->is_open()) {
            std::ignore = file_sink_->write(line);
            std::ignore = file_sink_->flush();
        } else if (sink_) {
            (*sink_) << line;
            sink_->flush();
        }
    }
} // namespace wavex::base
