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
#include <expected>
#include <system_error>
#include <utility>
#include <type_traits>

#include <wavex/Utils/TempFile.hpp>
#include <wavex/Utils/Compression.hpp>

#ifndef ASIO_HAS_CO_AWAIT
#define ASIO_HAS_CO_AWAIT 1
#endif
#include <asio/awaitable.hpp>


namespace wavex::utils {
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
        std::string name{}; ///< Form field name (e.g. "avatar")
        std::string filename{}; ///< Original filename sent by client (e.g. "photo.png")
        std::string content_type{}; ///< MIME type (e.g. "image/png")
        std::string_view data{}; ///< In-memory data slice (valid if temp_file == nullptr)
        std::shared_ptr<TempFileGuard> temp_file{}; ///< Spooled temporary file on disk (if > max_memory_buffer)

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
        [[nodiscard]] bool save_to(const std::string &destination, bool overwrite = true) const;

        template<typename PathLike>
            requires (!std::is_convertible_v<PathLike, const std::string &>)
        [[nodiscard]] bool save_to(const PathLike &destination, bool overwrite = true) const {
            if constexpr (requires { destination.string(); }) {
                return save_to(destination.string(), overwrite);
            } else {
                return save_to(std::string(destination), overwrite);
            }
        }

        /**
         * @brief Asynchronously persists the file to a specified filesystem destination.
         *
         * If the file is spooled on disk, this performs an atomic filesystem move/rename.
         * If the file is in-memory, it writes to disk offloaded to the background blocking pool.
         */
        [[nodiscard]] asio::awaitable<bool> save_to_async(
            std::string destination, bool overwrite = true) const;

        template<typename PathLike>
            requires (!std::is_convertible_v<PathLike, std::string>)
        [[nodiscard]] asio::awaitable<bool> save_to_async(
            const PathLike &destination, bool overwrite = true) const {
            if constexpr (requires { destination.string(); }) {
                return save_to_async(destination.string(), overwrite);
            } else {
                return save_to_async(std::string(destination), overwrite);
            }
        }

        /**
         * @brief Returns decompressed content if the file was Gzip/Deflate compressed.
         */
        [[nodiscard]] std::expected<std::string, std::error_code> decompress(
            CompressionFormat format = CompressionFormat::Gzip) const;
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

        FormField(std::string n, std::string v) : name(std::move(n)), value(std::move(v)) {
        }

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
        std::string temp_dir{}; // Empty uses system temp directory
        std::size_t max_memory_buffer{10 * 1024 * 1024}; // 10 MB in RAM; above these spools to disk
        std::size_t max_file_size{500 * 1024 * 1024}; // 500 MB max per file
        std::size_t max_total_size{1024 * 1024 * 1024}; // 1 GB max request payload
        std::size_t max_files{1000}; // 1000 max files per request
        std::size_t max_parts{2000}; // 2000 max total parts (fields + files)

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
                : name(std::move(n)), filename(std::move(fn)), content_type(std::move(ct)), content(std::move(c)) {
            }

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
            : boundary_(std::move(boundary)), valid_(true) {
        }

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
            std::string_view body,
            std::string_view content_type_header,
            const MultipartLimits &limits = {});

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
            std::string_view body,
            std::string_view content_type_header,
            MultipartLimits limits = {});

        // ── Client-Side Builder ─────────────────────────────────────────

        MultipartFormData &add_field(std::string_view name, std::string_view value);

        MultipartFormData &add_file(
            std::string_view field_name,
            std::string_view filename,
            std::string_view content,
            std::string_view content_type = "");

        MultipartFormData &add_file_from_path(
            std::string_view field_name,
            const std::string &filepath,
            std::string_view custom_filename = "",
            std::string_view custom_mime = "",
            bool compress = false);

        template<typename PathLike>
            requires (!std::is_convertible_v<PathLike, const std::string &>)
        MultipartFormData &add_file_from_path(
            std::string_view field_name,
            const PathLike &filepath,
            std::string_view custom_filename = "",
            std::string_view custom_mime = "",
            bool compress = false) {
            if constexpr (requires { filepath.string(); }) {
                return add_file_from_path(field_name, filepath.string(), custom_filename, custom_mime, compress);
            } else {
                return add_file_from_path(field_name, std::string(filepath), custom_filename, custom_mime, compress);
            }
        }

        /**
         * @brief Returns the Content-Type header with the multipart boundary.
         */
        [[nodiscard]] std::string content_type_header() const;

        /**
         * @brief Composes the full RFC 7578 wire body.
         */
        [[nodiscard]] std::string compose(const std::string &boundary = "") const;

        [[nodiscard]] std::pair<std::string, std::string> compose_with_header(const std::string &boundary = "") const;

        // ── Query Accessors ─────────────────────────────────────────────

        [[nodiscard]] std::optional<UploadedFile> file(std::string_view name) const;

        [[nodiscard]] std::vector<UploadedFile> files(std::string_view name = "") const;

        [[nodiscard]] std::optional<std::string_view> field(std::string_view name) const;

        [[nodiscard]] const std::vector<FormField> &fields() const noexcept { return fields_; }
    };
} // namespace wavex::utils
