// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * @file Multipart.cpp
 * @brief Implementation of RFC 7578 multipart/form-data parser, composer, and spooler.
 */

#include <wavex/Utils/Multipart.hpp>
#include <wavex/Utils/BinaryFile.hpp>
#include <wavex/Utils/FsUtils.hpp>
#include <wavex/Base/MimeTypes.hpp>
#include <wavex/Server/BlockingPool.hpp>
#include <wavex/Async/SpawnBlocking.hpp>

#include <asio/awaitable.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/async_result.hpp>
#include <asio/post.hpp>
#include <asio/associated_executor.hpp>
#include <asio/executor_work_guard.hpp>

#include <chrono>
#include <atomic>
#include <cctype>
#include <algorithm>
#include <utility>

namespace wavex::utils {
    namespace detail {
        struct SpoolTask {
            std::shared_ptr<TempFileGuard> guard{};
            std::string_view data{};

            SpoolTask() = default;

            SpoolTask(std::shared_ptr<TempFileGuard> g, const std::string_view d)
                : guard(std::move(g)), data(d) {
            }
        };

        struct BatchSpoolState {
            std::atomic<std::size_t> remaining{0};
            std::atomic<bool> success{true};

            BatchSpoolState() = default;
        };

        static bool case_equals(const std::string_view a, const std::string_view b) noexcept {
            if (a.size() != b.size()) return false;
            for (size_t i = 0; i < a.size(); ++i) {
                if (std::tolower(static_cast<unsigned char>(a[i])) !=
                    std::tolower(static_cast<unsigned char>(b[i]))) {
                    return false;
                }
            }
            return true;
        }

        static std::string extract_boundary(const std::string_view ct) {
            constexpr std::string_view key = "boundary=";
            auto pos = ct.find(key);
            if (pos == std::string_view::npos) return "";

            std::string_view val = ct.substr(pos + key.size());
            if (val.starts_with('"')) {
                val.remove_prefix(1);
                auto end_quote = val.find('"');
                if (end_quote != std::string_view::npos) {
                    val = val.substr(0, end_quote);
                }
            } else {
                auto semicolon = val.find(';');
                if (semicolon != std::string_view::npos) {
                    val = val.substr(0, semicolon);
                }
            }
            while (!val.empty() && (val.back() == ' ' || val.back() == '\r' || val.back() == '\n')) {
                val.remove_suffix(1);
            }
            return std::string(val);
        }

        static std::string_view extract_header_value(const std::string_view headers, const std::string_view name) {
            std::size_t pos = 0;
            while (pos < headers.size()) {
                auto line_end = headers.find('\n', pos);
                if (line_end == std::string_view::npos) line_end = headers.size();

                std::string_view line = headers.substr(pos, line_end - pos);
                if (line.ends_with('\r')) line.remove_suffix(1);

                auto colon = line.find(':');
                if (colon != std::string_view::npos) {
                    std::string_view header_name = line.substr(0, colon);
                    while (!header_name.empty() && header_name.back() == ' ') header_name.remove_suffix(1);

                    if (case_equals(header_name, name)) {
                        std::string_view val = line.substr(colon + 1);
                        while (!val.empty() && val.front() == ' ') val.remove_prefix(1);
                        // ReSharper disable once CppDFALocalValueEscapesFunction
                        return val;
                    }
                }

                pos = line_end + 1;
            }
            return "";
        }

        static std::string_view extract_parameter(const std::string_view header, const std::string_view param_name) {
            std::string needle = std::string(param_name) + "=";
            auto pos = header.find(needle);
            if (pos == std::string_view::npos) return "";

            std::string_view val = header.substr(pos + needle.size());
            if (val.starts_with('"')) {
                val.remove_prefix(1);
                auto end_quote = val.find('"');
                if (end_quote != std::string_view::npos) {
                    return val.substr(0, end_quote);
                }
            } else {
                auto end_pos = val.find(';');
                if (end_pos != std::string_view::npos) {
                    val = val.substr(0, end_pos);
                }
            }
            // ReSharper disable once CppDFALocalValueEscapesFunction
            return val;
        }
    } // namespace detail

    // ── UploadedFile Implementation ─────────────────────────────────────────

    bool UploadedFile::save_to(const std::string &destination, const bool overwrite) const {
        if (is_on_disk()) {
            return temp_file->move_to(destination, overwrite);
        }

        std::error_code ec;
        if (fs_utils::has_parent_path(destination)) {
            fs_utils::create_directories(fs_utils::parent_path(destination), ec);
            if (ec) return false;
        }

        if (overwrite && fs_utils::exists(destination, ec)) {
            fs_utils::remove(destination, ec);
        }

        return BinaryFile::write_all(destination, data);
    }

    asio::awaitable<bool> UploadedFile::save_to_async(
        std::string destination, const bool overwrite) const {
        if (is_on_disk()) {
            co_return temp_file->move_to(destination, overwrite);
        }

        auto res = co_await wavex::spawn_blocking(
            [dest = std::move(destination), d = std::string(data), overwrite]() -> bool {
                std::error_code ec;
                if (fs_utils::has_parent_path(dest)) {
                    fs_utils::create_directories(fs_utils::parent_path(dest), ec);
                    if (ec) return false;
                }

                if (overwrite && fs_utils::exists(dest, ec)) {
                    fs_utils::remove(dest, ec);
                }

                return BinaryFile::write_all(dest, d);
            });
        co_return res;
    }

    std::expected<std::string, std::error_code> UploadedFile::decompress(
        const CompressionFormat format) const {
        if (is_on_disk()) {
            auto buffer = BinaryFile::read_all(temp_file->path());
            if (!buffer) {
                return std::unexpected(buffer.error());
            }
            return Compressor::decompress(*buffer, format);
        }
        return Compressor::decompress(data, format);
    }

    // ── MultipartFormData Implementation ────────────────────────────────────

    MultipartFormData MultipartFormData::parse(
        const std::string_view body,
        const std::string_view content_type_header,
        const MultipartLimits &limits) {
        MultipartFormData result;

        if (body.size() > limits.max_total_size) {
            result.valid_ = false;
            return result;
        }

        const auto boundary = detail::extract_boundary(content_type_header);
        if (boundary.empty()) {
            result.valid_ = false;
            return result;
        }

        result.boundary_ = std::string(boundary);
        const std::string delimiter = "--" + std::string(boundary);

        std::size_t pos = 0;
        pos = body.find(delimiter, pos);
        if (pos == std::string_view::npos) {
            result.valid_ = false;
            return result;
        }
        pos += delimiter.size();

        while (pos < body.size()) {
            if (pos + 2 <= body.size() && body.substr(pos, 2) == "--") {
                break;
            }

            if (pos < body.size() && body[pos] == '\r') ++pos;
            if (pos < body.size() && body[pos] == '\n') ++pos;

            std::size_t header_end = body.find("\r\n\r\n", pos);
            std::size_t body_start = header_end + 4;
            if (header_end == std::string_view::npos) {
                header_end = body.find("\n\n", pos);
                if (header_end == std::string_view::npos) break;
                body_start = header_end + 2;
            }

            std::string_view headers_part = body.substr(pos, header_end - pos);

            std::size_t next_boundary = body.find(delimiter, body_start);
            if (next_boundary == std::string_view::npos) {
                break;
            }

            std::size_t part_end = next_boundary;
            if (part_end >= 2 && body.substr(part_end - 2, 2) == "\r\n") {
                part_end -= 2;
            } else if (part_end >= 1 && body[part_end - 1] == '\n') {
                part_end -= 1;
            }

            std::string_view part_body = body.substr(body_start, part_end - body_start);

            auto disposition = detail::extract_header_value(headers_part, "Content-Disposition");
            auto content_type = detail::extract_header_value(headers_part, "Content-Type");

            auto name = detail::extract_parameter(disposition, "name");
            auto filename = detail::extract_parameter(disposition, "filename");

            if (!name.empty()) {
                if (result.files_.size() + result.fields_.size() >= limits.max_parts) {
                    result.valid_ = false;
                    return result;
                }

                if (!filename.empty()) {
                    if (result.files_.size() >= limits.max_files) {
                        result.valid_ = false;
                        return result;
                    }

                    if (part_body.size() > limits.max_file_size) {
                        result.valid_ = false;
                        return result;
                    }

                    UploadedFile file;
                    file.name = std::string(name);
                    file.filename = std::string(filename);
                    file.content_type = content_type.empty() ? "application/octet-stream" : std::string(content_type);

                    if (part_body.size() > limits.max_memory_buffer) {
                        auto guard = std::make_shared<TempFileGuard>(TempFileGuard::create(limits.temp_dir));
                        if (!guard->empty()) {
                            BinaryFile ofs(guard->path(), FileMode::Write);
                            if (ofs.is_open()) {
                                std::ignore = ofs.write(part_body);
                            }
                        }
                        file.temp_file = guard;
                    } else {
                        file.data = part_body;
                    }

                    result.files_.push_back(std::move(file));
                } else {
                    result.fields_.push_back(FormField{std::string(name), std::string(part_body)});
                }
            }

            pos = next_boundary + delimiter.size();
        }

        return result;
    }

    asio::awaitable<MultipartFormData> MultipartFormData::parse_async(
        const std::string_view body,
        const std::string_view content_type_header,
        MultipartLimits limits) {
        MultipartFormData result;

        if (body.size() > limits.max_total_size) {
            result.valid_ = false;
            co_return result;
        }

        const auto boundary = detail::extract_boundary(content_type_header);
        if (boundary.empty()) {
            result.valid_ = false;
            co_return result;
        }

        result.boundary_ = std::string(boundary);
        const std::string delimiter = "--" + std::string(boundary);

        std::size_t pos = 0;
        pos = body.find(delimiter, pos);
        if (pos == std::string_view::npos) {
            result.valid_ = false;
            co_return result;
        }
        pos += delimiter.size();

        std::vector<detail::SpoolTask> spool_tasks;

        while (pos < body.size()) {
            if (pos + 2 <= body.size() && body.substr(pos, 2) == "--") {
                break;
            }

            if (pos < body.size() && body[pos] == '\r') ++pos;
            if (pos < body.size() && body[pos] == '\n') ++pos;

            std::size_t header_end = body.find("\r\n\r\n", pos);
            std::size_t body_start = header_end + 4;
            if (header_end == std::string_view::npos) {
                header_end = body.find("\n\n", pos);
                if (header_end == std::string_view::npos) break;
                body_start = header_end + 2;
            }

            std::string_view headers_part = body.substr(pos, header_end - pos);

            std::size_t next_boundary = body.find(delimiter, body_start);
            if (next_boundary == std::string_view::npos) {
                break;
            }

            std::size_t part_end = next_boundary;
            if (part_end >= 2 && body.substr(part_end - 2, 2) == "\r\n") {
                part_end -= 2;
            } else if (part_end >= 1 && body[part_end - 1] == '\n') {
                part_end -= 1;
            }

            std::string_view part_body = body.substr(body_start, part_end - body_start);

            auto disposition = detail::extract_header_value(headers_part, "Content-Disposition");
            auto content_type = detail::extract_header_value(headers_part, "Content-Type");

            auto name = detail::extract_parameter(disposition, "name");
            auto filename = detail::extract_parameter(disposition, "filename");

            if (!name.empty()) {
                if (result.files_.size() + result.fields_.size() >= limits.max_parts) {
                    result.valid_ = false;
                    co_return result;
                }

                if (!filename.empty()) {
                    if (result.files_.size() >= limits.max_files) {
                        result.valid_ = false;
                        co_return result;
                    }

                    if (part_body.size() > limits.max_file_size) {
                        result.valid_ = false;
                        co_return result;
                    }

                    UploadedFile file;
                    file.name = std::string(name);
                    file.filename = std::string(filename);
                    file.content_type = content_type.empty() ? "application/octet-stream" : std::string(content_type);

                    if (part_body.size() > limits.max_memory_buffer) {
                        auto guard = std::make_shared<TempFileGuard>(TempFileGuard::create(limits.temp_dir));
                        file.temp_file = guard;
                        spool_tasks.push_back(detail::SpoolTask{guard, part_body});
                    } else {
                        file.data = part_body;
                    }

                    result.files_.push_back(std::move(file));
                } else {
                    result.fields_.push_back(FormField{std::string(name), std::string(part_body)});
                }
            }

            pos = next_boundary + delimiter.size();
        }

        if (!spool_tasks.empty()) {
            auto state = std::make_shared<detail::BatchSpoolState>();
            state->remaining.store(spool_tasks.size(), std::memory_order_relaxed);

            co_await asio::async_initiate<const asio::use_awaitable_t<> &, void()>(
                [state, &spool_tasks]<typename T0>(T0 handler) {
                    using HandlerType = std::decay_t<T0>;
                    auto executor = asio::get_associated_executor(handler);
                    auto work = asio::make_work_guard(executor);
                    auto shared_handler = std::make_shared<HandlerType>(std::move(handler));
                    auto &pool = server::BlockingThreadPool::instance();

                    for (const auto &task: spool_tasks) {
                        pool.dispatch([state, guard = task.guard, data = task.data, executor, shared_handler, work]() {
                            {
                                BinaryFile ofs(guard->path(), FileMode::Write);
                                const bool ok = ofs.is_open() && ofs.write(data);
                                if (!ok) {
                                    state->success.store(false, std::memory_order_relaxed);
                                }
                                ofs.close();
                            }
                            if (state->remaining.fetch_sub(1, std::memory_order_acq_rel) == 1) {
                                asio::post(executor, [shared_handler, work]() {
                                    (*shared_handler)();
                                });
                            }
                        });
                    }
                },
                asio::use_awaitable
            );

            if (!state->success.load(std::memory_order_acquire)) {
                result.valid_ = false;
            }
        }

        co_return result;
    }

    MultipartFormData &MultipartFormData::add_field(const std::string_view name, const std::string_view value) {
        fields_.push_back(FormField{std::string(name), std::string(value)});
        return *this;
    }

    MultipartFormData &MultipartFormData::add_file(
        const std::string_view field_name,
        const std::string_view filename,
        const std::string_view content,
        const std::string_view content_type) {
        client_files_.push_back(ClientFile{
            std::string(field_name),
            std::string(filename),
            content_type.empty() ? "application/octet-stream" : std::string(content_type),
            std::string(content)
        });
        return *this;
    }

    MultipartFormData &MultipartFormData::add_file_from_path(
        const std::string_view field_name,
        const std::string &filepath,
        const std::string_view custom_filename,
        const std::string_view custom_mime,
        const bool compress) {
        auto file_content = BinaryFile::read_all(filepath);
        if (!file_content) {
            return *this;
        }
        std::string content = std::move(*file_content);
        std::string fName = custom_filename.empty() ? fs_utils::filename(filepath) : std::string(custom_filename);
        std::string mime = custom_mime.empty()
                               ? std::string(base::mime_type_from_path(fName))
                               : std::string(custom_mime);

        if (compress) {
            if (auto comp = Compressor::compress(content, CompressionFormat::Gzip); comp) {
                content = std::move(*comp);
                fName += ".gz";
                mime = "application/gzip";
            }
        }

        return add_file(field_name, fName, content, mime);
    }

    std::string MultipartFormData::content_type_header() const {
        if (boundary_.empty()) {
            boundary_ = "----WaveXBoundary" + std::to_string(
                            std::chrono::high_resolution_clock::now().time_since_epoch().count());
        }
        return "multipart/form-data; boundary=" + boundary_;
    }

    std::string MultipartFormData::compose(const std::string &boundary) const {
        if (!boundary.empty()) {
            boundary_ = boundary;
        } else if (boundary_.empty()) {
            boundary_ = "----WaveXBoundary" + std::to_string(
                            std::chrono::high_resolution_clock::now().time_since_epoch().count());
        }

        std::size_t total_size = 6 + boundary_.size();
        for (const auto &f: fields_) {
            total_size += 49 + boundary_.size() + f.name.size() + f.value.size();
        }
        for (const auto &cf: client_files_) {
            total_size += 78 + boundary_.size() + cf.name.size() + cf.filename.size() + cf.content_type.size() + cf.
                    content.size();
        }

        std::string body;
        body.reserve(total_size);
        constexpr std::string_view crlf = "\r\n";

        for (const auto &f: fields_) {
            body.append("--").append(boundary_).append(crlf);
            body.append("Content-Disposition: form-data; name=\"").append(f.name).append("\"").append(crlf).
                    append(crlf);
            body.append(f.value).append(crlf);
        }

        for (const auto &cf: client_files_) {
            body.append("--").append(boundary_).append(crlf);
            body.append("Content-Disposition: form-data; name=\"").append(cf.name)
                    .append("\"; filename=\"").append(cf.filename).append("\"").append(crlf);
            body.append("Content-Type: ").append(cf.content_type).append(crlf).append(crlf);
            body.append(cf.content).append(crlf);
        }

        body.append("--").append(boundary_).append("--").append(crlf);

        return body;
    }

    std::pair<std::string, std::string> MultipartFormData::compose_with_header(const std::string &boundary) const {
        std::string b = compose(boundary);
        return {std::move(b), content_type_header()};
    }

    std::optional<UploadedFile> MultipartFormData::file(const std::string_view name) const {
        for (const auto &f: files_) {
            if (f.name == name) return f;
        }
        return std::nullopt;
    }

    std::vector<UploadedFile> MultipartFormData::files(const std::string_view name) const {
        if (name.empty()) return files_;
        std::vector<UploadedFile> matched;
        for (const auto &f: files_) {
            if (f.name == name) matched.push_back(f);
        }
        return matched;
    }

    std::optional<std::string_view> MultipartFormData::field(const std::string_view name) const {
        for (const auto &f: fields_) {
            if (f.name == name) return f.value;
        }
        return std::nullopt;
    }
} // namespace wavex::utils
