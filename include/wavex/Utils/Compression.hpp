// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * @file Compression.hpp
 * @brief High-performance zlib-powered Gzip & Deflate compression/decompression utilities.
 */

#pragma once

#include <string>
#include <string_view>
#include <expected>
#include <system_error>
#include <vector>

#if defined(WAVEX_HAS_ZLIB) && WAVEX_HAS_ZLIB
#define WAVEX_ZLIB_AVAILABLE 1
#include <zlib.h>
#else
#define WAVEX_ZLIB_AVAILABLE 0
#endif

namespace wavex::utils {

    /**
     * @enum CompressionFormat
     * @brief Supported payload compression formats.
     */
    enum class CompressionFormat {
        Gzip,    ///< RFC 1952 Gzip wrapper with CRC-32 (standard HTTP Content-Encoding: gzip)
        Deflate  ///< RFC 1950/1951 Deflate stream (HTTP Content-Encoding: deflate)
    };

    /**
     * @class Compressor
     * @brief Zero-overhead compressor/decompressor for memory buffers and streams.
     */
    class Compressor {
    public:
        /**
         * @brief Check whether zlib support is compiled into the current binary.
         */
        [[nodiscard]] static constexpr bool is_available() noexcept {
            return WAVEX_ZLIB_AVAILABLE != 0;
        }

        /**
         * @brief Compresses a data view into Gzip or Deflate format.
         * @param data Raw input byte sequence.
         * @param format Compression format (Gzip or Deflate).
         * @param level Compression level (1 = fastest, 9 = maximum, -1 = default).
         * @return Compressed byte string or std::error_code.
         */
        static std::expected<std::string, std::error_code> compress(
            const std::string_view data,
            const CompressionFormat format = CompressionFormat::Gzip,
            const int level = -1) {

#if WAVEX_ZLIB_AVAILABLE
            if (data.empty()) {
                return std::string{};
            }

            z_stream strm{};
            // windowBits: 15 is default.
            // Adding 16 enables Gzip header/trailer (31).
            // Negative (-15) produces raw deflate; +15 produces zlib-wrapped deflate.
            const int window_bits = (format == CompressionFormat::Gzip) ? (15 + 16) : 15;

            if (deflateInit2(&strm, level, Z_DEFLATED, window_bits, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
                return std::unexpected(std::make_error_code(std::errc::invalid_argument));
            }

            strm.next_in = reinterpret_cast<Bytef *>(const_cast<char *>(data.data()));
            strm.avail_in = static_cast<uInt>(data.size());

            std::string output;
            output.reserve(deflateBound(&strm, static_cast<uLong>(data.size())));

            char buffer[16384];
            int ret = Z_OK;

            while (ret == Z_OK) {
                strm.next_out = reinterpret_cast<Bytef *>(buffer);
                strm.avail_out = sizeof(buffer);

                ret = deflate(&strm, Z_FINISH);

                const std::size_t written = sizeof(buffer) - strm.avail_out;
                if (written > 0) {
                    output.append(buffer, written);
                }
            }

            deflateEnd(&strm);

            if (ret != Z_STREAM_END) {
                return std::unexpected(std::make_error_code(std::errc::io_error));
            }

            return output;
#else
            (void) data;
            (void) format;
            (void) level;
            return std::unexpected(std::make_error_code(std::errc::not_supported));
#endif
        }

        /**
         * @brief Decompresses a Gzip or Deflate byte sequence.
         * @param compressed Compressed input byte sequence.
         * @param format Expected compression format (or Gzip with auto-detection).
         * @return Decompressed byte string or std::error_code.
         */
        static std::expected<std::string, std::error_code> decompress(
            const std::string_view compressed,
            const CompressionFormat format = CompressionFormat::Gzip) {

#if WAVEX_ZLIB_AVAILABLE
            if (compressed.empty()) {
                return std::string{};
            }

            z_stream strm{};
            // Adding 32 enables auto-detection of both gzip and zlib-wrapped deflate headers (15 + 32 = 47)
            const int window_bits = (format == CompressionFormat::Gzip) ? (15 + 32) : 15;

            if (inflateInit2(&strm, window_bits) != Z_OK) {
                return std::unexpected(std::make_error_code(std::errc::invalid_argument));
            }

            strm.next_in = reinterpret_cast<Bytef *>(const_cast<char *>(compressed.data()));
            strm.avail_in = static_cast<uInt>(compressed.size());

            std::string output;
            output.reserve(compressed.size() * 2);

            char buffer[16384];
            int ret = Z_OK;

            while (ret == Z_OK) {
                strm.next_out = reinterpret_cast<Bytef *>(buffer);
                strm.avail_out = sizeof(buffer);

                ret = inflate(&strm, Z_NO_FLUSH);

                const std::size_t written = sizeof(buffer) - strm.avail_out;
                if (written > 0) {
                    output.append(buffer, written);
                }

                if (ret == Z_STREAM_END) {
                    break;
                }
            }

            inflateEnd(&strm);

            if (ret != Z_STREAM_END && ret != Z_OK) {
                return std::unexpected(std::make_error_code(std::errc::illegal_byte_sequence));
            }

            return output;
#else
            (void) compressed;
            (void) format;
            return std::unexpected(std::make_error_code(std::errc::not_supported));
#endif
        }
    };

} // namespace wavex::utils
