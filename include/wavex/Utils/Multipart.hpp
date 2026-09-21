// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * @file Multipart.hpp
 * @brief High-performance RFC 7578 multipart/form-data parser, composer, and disk spooler.
 */

#pragma once

#include <string>
#include <string_view>
#include <vector>
#include <optional>
#include <memory>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <utility>
#include <algorithm>
#include <cctype>

#include <wavex/Base/MimeTypes.hpp>
#include <wavex/Utils/TempFile.hpp>
#include <wavex/Utils/Compression.hpp>

#ifndef ASIO_HAS_CO_AWAIT
#define ASIO_HAS_CO_AWAIT 1
#endif

#include <asio/awaitable.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/async_result.hpp>
#include <asio/post.hpp>
#include <asio/associated_executor.hpp>
#include <wavex/Server/BlockingPool.hpp>
#include <wavex/Async/SpawnBlocking.hpp>

namespace wavex::utils {

    namespace detail {

        struct SpoolTask {
            // ─── 2. Member Variables (SECOND - Ordered for Minimal Padding) ────
            std::shared_ptr<TempFileGuard> guard{};
            std::string_view data{};

            // ─── 3. Constructors & Destructor (MIDDLE) ─────────────────────────
            SpoolTask() = default;
            SpoolTask(std::shared_ptr<TempFileGuard> g, const std::string_view d)
                : guard(std::move(g)), data(d) {}
        };

        struct BatchSpoolState {
            // ─── 2. Member Variables (SECOND - Ordered for Minimal Padding) ────
            std::atomic<std::size_t> remaining{0};
            std::atomic<bool> success{true};

            // ─── 3. Constructors & Destructor (MIDDLE) ─────────────────────────
            BatchSpoolState() = default;
        };

    } // namespace detail

    /**
     * @struct UploadedFile
     * @brief Represents a file uploaded via multipart/form-data or raw request.
     *
     * Invariant: Small files are retained in-memory (`data`), while large files
     * exceeding the memory threshold are automatically spooled to disk (`temp_file`).
     * The `TempFileGuard` ensures the file is purged if the connection is aborted.
     */
    struct UploadedFile {
        // ─── 2. Member Variables (SECOND - Ordered for Minimal Padding) ────
        std::string name{};                          ///< Form field name (e.g. "avatar")
        std::string filename{};                      ///< Original filename sent by client (e.g. "photo.png")
        std::string content_type{};                  ///< MIME type (e.g. "image/png")
        std::string_view data{};                     ///< In-memory data slice (valid if temp_file == nullptr)
        std::shared_ptr<TempFileGuard> temp_file{};  ///< Spooled temporary file on disk (if > max_memory_buffer)

        // ─── 3. Constructors & Destructor (MIDDLE) ─────────────────────────
        UploadedFile() = default;
        ~UploadedFile() = default;
        UploadedFile(const UploadedFile &) = default;
        UploadedFile &operator=(const UploadedFile &) = default;
        UploadedFile(UploadedFile &&) noexcept = default;
        UploadedFile &operator=(UploadedFile &&) noexcept = default;

        // ─── 4. Member Functions & Friend Declarations (LAST) ──────────────
        [[nodiscard]] bool is_in_memory() const noexcept { return temp_file == nullptr; }
        [[nodiscard]] bool is_on_disk() const noexcept { return temp_file != nullptr; }

        [[nodiscard]] std::size_t size() const noexcept {
            if (is_on_disk()) {
                return temp_file->size();
            }
            return data.size();
        }

        [[nodiscard]] bool empty() const noexcept {
            return size() == 0;
        }

        /**
         * @brief Persists the file to a specified filesystem destination.
         *
         * If the file is spooled on disk, this performs an atomic filesystem move/rename!
         * If the file is in-memory, it writes directly to the destination.
         */
        [[nodiscard]] bool save_to(const std::filesystem::path &destination, const bool overwrite = true) const {
            if (is_on_disk()) {
                return temp_file->move_to(destination, overwrite);
            }

            std::error_code ec;
            if (destination.has_parent_path()) {
                std::filesystem::create_directories(destination.parent_path(), ec);
                if (ec) return false;
            }

            if (overwrite && std::filesystem::exists(destination, ec)) {
                std::filesystem::remove(destination, ec);
            }

            std::ofstream ofs(destination, std::ios::binary);
            if (!ofs.is_open()) return false;

            if (!data.empty()) {
                ofs.write(data.data(), static_cast<std::streamsize>(data.size()));
            }
            return ofs.good();
        }

        /**
         * @brief Asynchronously persists the file to a specified filesystem destination.
         *
         * If the file is spooled on disk, this performs an atomic filesystem move/rename.
         * If the file is in-memory, it writes to disk offloaded to the background blocking pool.
         */
        [[nodiscard]] asio::awaitable<bool> save_to_async(
            const std::filesystem::path &destination, const bool overwrite = true) const {
            if (is_on_disk()) {
                co_return temp_file->move_to(destination, overwrite);
            }

            auto res = co_await wavex::spawn_blocking([dest = destination, d = std::string(data), overwrite]() -> bool {
                std::error_code ec;
                if (dest.has_parent_path()) {
                    std::filesystem::create_directories(dest.parent_path(), ec);
                    if (ec) return false;
                }

                if (overwrite && std::filesystem::exists(dest, ec)) {
                    std::filesystem::remove(dest, ec);
                }

                std::ofstream ofs(dest, std::ios::binary);
                if (!ofs.is_open()) return false;

                if (!d.empty()) {
                    ofs.write(d.data(), static_cast<std::streamsize>(d.size()));
                }
                return ofs.good();
            });
            co_return res;
        }

        /**
         * @brief Opens an input stream to read the file contents.
         */
        [[nodiscard]] std::unique_ptr<std::istream> open_stream() const {
            if (is_on_disk()) {
                return std::make_unique<std::ifstream>(temp_file->path(), std::ios::binary);
            }
            return std::make_unique<std::istringstream>(std::string(data));
        }

        /**
         * @brief Returns decompressed content if the file was Gzip/Deflate compressed.
         */
        [[nodiscard]] std::expected<std::string, std::error_code> decompress(
            const CompressionFormat format = CompressionFormat::Gzip) const {
            if (is_on_disk()) {
                std::ifstream ifs(temp_file->path(), std::ios::binary);
                if (!ifs.is_open()) {
                    return std::unexpected(std::make_error_code(std::errc::no_such_file_or_directory));
                }
                std::string buffer((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
                return Compressor::decompress(buffer, format);
            }
            return Compressor::decompress(data, format);
        }
    };

    /**
     * @struct FormField
     * @brief Represents a non-file key-value form field in multipart/form-data.
     */
    struct FormField {
        // ─── 2. Member Variables (SECOND - Ordered for Minimal Padding) ────
        std::string name{};
        std::string value{};

        // ─── 3. Constructors & Destructor (MIDDLE) ─────────────────────────
        FormField() = default;
        FormField(std::string n, std::string v) : name(std::move(n)), value(std::move(v)) {}
        ~FormField() = default;
        FormField(const FormField &) = default;
        FormField &operator=(const FormField &) = default;
        FormField(FormField &&) noexcept = default;
        FormField &operator=(FormField &&) noexcept = default;
    };

    /**
     * @struct MultipartLimits
     * @brief Configurable size ceilings and disk spooling thresholds.
     */
    struct MultipartLimits {
        // ─── 2. Member Variables (SECOND - Ordered for Minimal Padding) ────
        std::filesystem::path temp_dir{};                 // Empty uses system temp directory
        std::size_t max_memory_buffer{10 * 1024 * 1024}; // 10 MB in RAM; above these spools to disk
        std::size_t max_file_size{500 * 1024 * 1024};     // 500 MB max per file
        std::size_t max_total_size{1024 * 1024 * 1024};   // 1 GB max request payload
        std::size_t max_files{1000};                       // 1000 max files per request
        std::size_t max_parts{2000};                       // 2000 max total parts (fields + files)

        // ─── 3. Constructors & Destructor (MIDDLE) ─────────────────────────
        MultipartLimits() = default;
        ~MultipartLimits() = default;
        MultipartLimits(const MultipartLimits &) = default;
        MultipartLimits &operator=(const MultipartLimits &) = default;
        MultipartLimits(MultipartLimits &&) noexcept = default;
        MultipartLimits &operator=(MultipartLimits &&) noexcept = default;
    };

    /**
     * @class MultipartFormData
     * @brief Complete RFC 7578 multipart/form-data parser, builder, and disk spooler.
     */
    class MultipartFormData {
    public:
        // ─── 1. Nested Types & Definitions (TOP) ───────────────────────────
        using Limits = MultipartLimits;

    private:
        struct ClientFile {
            // ─── 2. Member Variables (SECOND - Ordered for Minimal Padding) ────
            std::string name{};
            std::string filename{};
            std::string content_type{};
            std::string content{};

            // ─── 3. Constructors & Destructor (MIDDLE) ─────────────────────────
            ClientFile() = default;
            ClientFile(std::string n, std::string fn, std::string ct, std::string c)
                : name(std::move(n)), filename(std::move(fn)), content_type(std::move(ct)), content(std::move(c)) {}
            ~ClientFile() = default;
            ClientFile(const ClientFile &) = default;
            ClientFile &operator=(const ClientFile &) = default;
            ClientFile(ClientFile &&) noexcept = default;
            ClientFile &operator=(ClientFile &&) noexcept = default;
        };

        // ─── 2. Member Variables (SECOND - Ordered for Minimal Padding) ────
        mutable std::string boundary_{};
        std::vector<FormField> fields_{};
        std::vector<UploadedFile> files_{};
        std::vector<ClientFile> client_files_{};
        bool valid_{true};

    public:
        // ─── 3. Constructors & Destructor (MIDDLE) ─────────────────────────
        MultipartFormData() = default;
        explicit MultipartFormData(std::string boundary)
            : boundary_(std::move(boundary)), valid_(true) {}
        ~MultipartFormData() = default;
        MultipartFormData(const MultipartFormData &) = default;
        MultipartFormData &operator=(const MultipartFormData &) = default;
        MultipartFormData(MultipartFormData &&) noexcept = default;
        MultipartFormData &operator=(MultipartFormData &&) noexcept = default;

        // ─── 4. Member Functions & Friend Declarations (LAST) ──────────────
        [[nodiscard]] bool is_valid() const noexcept { return valid_; }
        [[nodiscard]] explicit operator bool() const noexcept { return valid_; }

        // ── Server-Side Parser ──────────────────────────────────────────

        /**
         * @brief Parses an RFC 7578 multipart body from an HTTP request.
         * @param body Request body raw string view.
         * @param content_type_header Value of the Content-Type header (containing boundary).
         * @param limits Limits and spooling configuration.
         * @return Parsed MultipartFormData containing fields and uploaded files.
         */
        static MultipartFormData parse(
            const std::string_view body,
            const std::string_view content_type_header,
            const MultipartLimits &limits = {}) {

            MultipartFormData result;

            if (body.size() > limits.max_total_size) {
                result.valid_ = false;
                return result;
            }

            // 1. Extract boundary from Content-Type: multipart/form-data; boundary=...
            const auto boundary = extract_boundary(content_type_header);
            if (boundary.empty()) {
                result.valid_ = false;
                return result;
            }

            result.boundary_ = std::string(boundary);
            const std::string delimiter = "--" + std::string(boundary);
            const std::string close_delimiter = "--" + std::string(boundary) + "--";

            std::size_t pos = 0;
            // Find initial boundary
            pos = body.find(delimiter, pos);
            if (pos == std::string_view::npos) {
                result.valid_ = false;
                return result;
            }
            pos += delimiter.size();

            while (pos < body.size()) {
                // Check for closing delimiter
                if (pos + 2 <= body.size() && body.substr(pos, 2) == "--") {
                    break;
                }

                // Skip CRLF or LF after boundary
                if (pos < body.size() && body[pos] == '\r') ++pos;
                if (pos < body.size() && body[pos] == '\n') ++pos;

                // Find header-body separation (\r\n\r\n or \n\n)
                std::size_t header_end = body.find("\r\n\r\n", pos);
                std::size_t body_start = header_end + 4;
                if (header_end == std::string_view::npos) {
                    header_end = body.find("\n\n", pos);
                    if (header_end == std::string_view::npos) break;
                    body_start = header_end + 2;
                }

                std::string_view headers_part = body.substr(pos, header_end - pos);

                // Find next boundary marking end of part body
                std::size_t next_boundary = body.find(delimiter, body_start);
                if (next_boundary == std::string_view::npos) {
                    break;
                }

                // Trim trailing CRLF before next boundary
                std::size_t part_end = next_boundary;
                if (part_end >= 2 && body.substr(part_end - 2, 2) == "\r\n") {
                    part_end -= 2;
                } else if (part_end >= 1 && body[part_end - 1] == '\n') {
                    part_end -= 1;
                }

                std::string_view part_body = body.substr(body_start, part_end - body_start);

                // Parse Content-Disposition and Content-Type from headers_part
                auto disposition = extract_header_value(headers_part, "Content-Disposition");
                auto content_type = extract_header_value(headers_part, "Content-Type");

                auto name = extract_parameter(disposition, "name");
                auto filename = extract_parameter(disposition, "filename");

                if (!name.empty()) {
                    if (result.files_.size() + result.fields_.size() >= limits.max_parts) {
                        result.valid_ = false;
                        return result; // Exceeded total parts limit
                    }

                    if (!filename.empty()) {
                        if (result.files_.size() >= limits.max_files) {
                            result.valid_ = false;
                            return result; // Exceeded max files limit
                        }

                        // It's a file upload
                        if (part_body.size() > limits.max_file_size) {
                            result.valid_ = false;
                            return result; // Exceeded per-file size limit
                        }

                        UploadedFile file;
                        file.name = std::string(name);
                        file.filename = std::string(filename);
                        file.content_type = content_type.empty() ? "application/octet-stream" : std::string(content_type);

                        if (part_body.size() > limits.max_memory_buffer) {
                            // Spool to temporary disk file
                            auto guard = std::make_shared<TempFileGuard>(TempFileGuard::create(limits.temp_dir));
                            std::ofstream ofs(guard->path(), std::ios::binary);
                            if (!ofs.is_open()) {
                                result.valid_ = false;
                                return result;
                            }
                            ofs.write(part_body.data(), static_cast<std::streamsize>(part_body.size()));
                            ofs.close();
                            file.temp_file = std::move(guard);
                        } else {
                            file.data = part_body;
                        }

                        result.files_.push_back(std::move(file));
                    } else {
                        // Regular text form field
                        result.fields_.push_back(FormField{std::string(name), std::string(part_body)});
                    }
                }

                pos = next_boundary + delimiter.size();
            }

            return result;
        }

        /**
         * @brief Asynchronously parses an RFC 7578 multipart body from an HTTP request.
         *
         * Performs boundary scanning in-memory and offloads large file disk spooling
         * concurrently across the dedicated BlockingThreadPool, never blocking the async
         * connection worker thread.
         *
         * @param body Request body raw string view.
         * @param content_type_header Value of the Content-Type header (containing boundary).
         * @param limits Limits and spooling configuration.
         * @return Awaitable yielding parsed MultipartFormData containing fields and uploaded files.
         */
        static asio::awaitable<MultipartFormData> parse_async(
            const std::string_view body,
            const std::string_view content_type_header,
            const MultipartLimits &limits = {}) {

            MultipartFormData result;

            if (body.size() > limits.max_total_size) {
                result.valid_ = false;
                co_return result;
            }

            // 1. Extract boundary from Content-Type: multipart/form-data; boundary=...
            const auto boundary = extract_boundary(content_type_header);
            if (boundary.empty()) {
                result.valid_ = false;
                co_return result;
            }

            result.boundary_ = std::string(boundary);
            const std::string delimiter = "--" + std::string(boundary);
            const std::string close_delimiter = "--" + std::string(boundary) + "--";

            std::size_t pos = 0;
            pos = body.find(delimiter, pos);
            if (pos == std::string_view::npos) {
                result.valid_ = false;
                co_return result;
            }
            pos += delimiter.size();

            std::vector<detail::SpoolTask> spool_tasks;

            while (pos < body.size()) {
                // Check for closing delimiter
                if (pos + 2 <= body.size() && body.substr(pos, 2) == "--") {
                    break;
                }

                // Skip CRLF or LF after boundary
                if (pos < body.size() && body[pos] == '\r') ++pos;
                if (pos < body.size() && body[pos] == '\n') ++pos;

                // Find header-body separation (\r\n\r\n or \n\n)
                std::size_t header_end = body.find("\r\n\r\n", pos);
                std::size_t body_start = header_end + 4;
                if (header_end == std::string_view::npos) {
                    header_end = body.find("\n\n", pos);
                    if (header_end == std::string_view::npos) break;
                    body_start = header_end + 2;
                }

                std::string_view headers_part = body.substr(pos, header_end - pos);

                // Find next boundary marking end of part body
                std::size_t next_boundary = body.find(delimiter, body_start);
                if (next_boundary == std::string_view::npos) {
                    break;
                }

                // Trim trailing CRLF before next boundary
                std::size_t part_end = next_boundary;
                if (part_end >= 2 && body.substr(part_end - 2, 2) == "\r\n") {
                    part_end -= 2;
                } else if (part_end >= 1 && body[part_end - 1] == '\n') {
                    part_end -= 1;
                }

                std::string_view part_body = body.substr(body_start, part_end - body_start);

                // Parse Content-Disposition and Content-Type from headers_part
                auto disposition = extract_header_value(headers_part, "Content-Disposition");
                auto content_type = extract_header_value(headers_part, "Content-Type");

                auto name = extract_parameter(disposition, "name");
                auto filename = extract_parameter(disposition, "filename");

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

            // If any files require disk spooling, execute writes concurrently on the BlockingThreadPool
            if (!spool_tasks.empty()) {
                auto state = std::make_shared<detail::BatchSpoolState>();
                state->remaining.store(spool_tasks.size(), std::memory_order_relaxed);

                co_await asio::async_initiate<const asio::use_awaitable_t<>&, void()>(
                    [state, &spool_tasks](auto handler) {
                        using HandlerType = std::decay_t<decltype(handler)>;
                        auto executor = asio::get_associated_executor(handler);
                        auto shared_handler = std::make_shared<HandlerType>(std::move(handler));
                        auto &pool = server::BlockingThreadPool::instance();

                        for (const auto &task : spool_tasks) {
                            pool.dispatch([state, guard = task.guard, data = task.data, executor, shared_handler]() {
                                std::ofstream ofs(guard->path(), std::ios::binary);
                                const bool ok = ofs.is_open() &&
                                    ofs.write(data.data(), static_cast<std::streamsize>(data.size())).good();
                                if (!ok) {
                                    state->success.store(false, std::memory_order_relaxed);
                                }
                                if (state->remaining.fetch_sub(1, std::memory_order_acq_rel) == 1) {
                                    asio::post(executor, [shared_handler]() {
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

        // ── Client-Side Builder ─────────────────────────────────────────

        MultipartFormData &add_field(const std::string_view name, const std::string_view value) {
            fields_.push_back(FormField{std::string(name), std::string(value)});
            return *this;
        }

        MultipartFormData &add_file(
            const std::string_view field_name,
            const std::string_view filename,
            const std::string_view content,
            const std::string_view mime = "") {

            std::string mime_str(mime);
            if (mime_str.empty()) {
                mime_str = std::string(base::mime_type_from_path(filename));
            }

            client_files_.push_back(ClientFile{
                std::string(field_name),
                std::string(filename),
                std::move(mime_str),
                std::string(content)
            });
            return *this;
        }

        MultipartFormData &add_file_from_path(
            const std::string_view field_name,
            const std::filesystem::path &filepath,
            const std::string_view custom_filename = "",
            const std::string_view custom_mime = "",
            const bool compress = false) {

            std::ifstream ifs(filepath, std::ios::binary);
            if (!ifs.is_open()) {
                return *this;
            }

            std::string content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
            std::string fname = custom_filename.empty() ? filepath.filename().string() : std::string(custom_filename);

            std::string mime = custom_mime.empty() ? std::string(base::mime_type_from_path(fname)) : std::string(custom_mime);

            if (compress) {
                if (auto comp = Compressor::compress(content, CompressionFormat::Gzip); comp) {
                    content = std::move(*comp);
                    fname += ".gz";
                    mime = "application/gzip";
                }
            }

            return add_file(field_name, fname, content, mime);
        }

        /**
         * @brief Returns the Content-Type header with the multipart boundary.
         */
        [[nodiscard]] std::string content_type_header() const {
            if (boundary_.empty()) {
                boundary_ = "----WaveXBoundary" + std::to_string(
                    std::chrono::high_resolution_clock::now().time_since_epoch().count());
            }
            return "multipart/form-data; boundary=" + boundary_;
        }

        /**
         * @brief Composes the full RFC 7578 wire body.
         */
        [[nodiscard]] std::string compose(const std::string &boundary = "") const {
            if (!boundary.empty()) {
                boundary_ = boundary;
            } else if (boundary_.empty()) {
                boundary_ = "----WaveXBoundary" + std::to_string(
                    std::chrono::high_resolution_clock::now().time_since_epoch().count());
            }

            // Precompute exact buffer size to eliminate intermediate reallocations
            std::size_t total_size = 6 + boundary_.size(); // Closing boundary: "--" + boundary_ + "--\r\n"
            for (const auto &f : fields_) {
                total_size += 49 + boundary_.size() + f.name.size() + f.value.size();
            }
            for (const auto &cf : client_files_) {
                total_size += 78 + boundary_.size() + cf.name.size() + cf.filename.size() + cf.content_type.size() + cf.content.size();
            }

            std::string body;
            body.reserve(total_size);
            constexpr std::string_view crlf = "\r\n";

            // 1. Write text fields
            for (const auto &f : fields_) {
                body.append("--").append(boundary_).append(crlf);
                body.append("Content-Disposition: form-data; name=\"").append(f.name).append("\"").append(crlf).append(crlf);
                body.append(f.value).append(crlf);
            }

            // 2. Write client-attached files
            for (const auto &cf : client_files_) {
                body.append("--").append(boundary_).append(crlf);
                body.append("Content-Disposition: form-data; name=\"").append(cf.name)
                    .append("\"; filename=\"").append(cf.filename).append("\"").append(crlf);
                body.append("Content-Type: ").append(cf.content_type).append(crlf).append(crlf);
                body.append(cf.content).append(crlf);
            }

            // 3. Final closing boundary
            body.append("--").append(boundary_).append("--").append(crlf);

            return body;
        }

        [[nodiscard]] std::pair<std::string, std::string> compose_with_header(const std::string &boundary = "") const {
            std::string b = compose(boundary);
            return {std::move(b), content_type_header()};
        }

        // ── Query Accessors ─────────────────────────────────────────────

        [[nodiscard]] std::optional<UploadedFile> file(const std::string_view name) const {
            for (const auto &f : files_) {
                if (f.name == name) return f;
            }
            return std::nullopt;
        }

        [[nodiscard]] std::vector<UploadedFile> files(const std::string_view name = "") const {
            if (name.empty()) return files_;
            std::vector<UploadedFile> matched;
            for (const auto &f : files_) {
                if (f.name == name) matched.push_back(f);
            }
            return matched;
        }

        [[nodiscard]] std::optional<std::string_view> field(const std::string_view name) const {
            for (const auto &f : fields_) {
                if (f.name == name) return f.value;
            }
            return std::nullopt;
        }

        [[nodiscard]] const std::vector<FormField> &fields() const noexcept { return fields_; }



        // Helper: Extract boundary parameter from Content-Type header
        static std::string extract_boundary(const std::string_view ct) {
            constexpr std::string_view key = "boundary=";
            auto pos = ct.find(key);
            if (pos == std::string_view::npos) return "";

            std::string_view val = ct.substr(pos + key.size());
            // Strip quotes if present
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

        // Helper: Extract header value case-insensitively
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
                        return val;
                    }
                }

                pos = line_end + 1;
            }
            return "";
        }

        // Helper: Extract parameter from header value, e.g. name="avatar"
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
            return val;
        }

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
    };

} // namespace wavex::utils
