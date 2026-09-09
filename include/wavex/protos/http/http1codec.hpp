// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
/**
 * @file http1codec.hpp
 * @brief HTTP/1.x Protocol Codec — Parser and Encoder Implementation
 *
 * Optimisations over baseline:
 *  - Zero-allocation number serialization  — std::to_chars into stack buffers
 *  - O(1) HTTP method dispatch             — switch on first char + length
 *  - Locale-free case-insensitive compare  — ASCII bitwise (c | 0x20) trick
 *  - RFC 7230 OWS stripping                — strips both SP and HTAB
 *  - Single-pass body-header extraction   — fused Transfer-Encoding / Content-Length scan
 *  - Fused Content-Length check in encoder — no second header scan after writing
 *  - Accurate encoder reserve estimate    — per-header accounting, one allocation
 *  - static constexpr methods array       — guaranteed single initialisation
 *  - headers.reserve(16)                  — avoids log₂n reallocations
 */
#pragma once
#include <string_view>
#include <vector>
#include <array>
#include <string>
#include <optional>
#include <charconv>
#include <wavex/protos/http/Methods.hpp>

namespace wavex::protos::http {
    // ─── Internal helpers ────────────────────────────────────────────────────────
    namespace detail {
        /**
         * @brief Locale-free ASCII lowercase.
         *
         * std::tolower is locale-aware and may acquire a mutex on some platforms.
         * HTTP header names are ASCII-only, so we use the bitwise trick instead.
         */
        [[nodiscard]] constexpr char ascii_lower(const char c) noexcept {
            return (c >= 'A' && c <= 'Z') ? static_cast<char>(c | 0x20) : c;
        }

        /**
         * @brief Case-insensitive ASCII string equality.
         *
         * Used for header name lookups. Checks length first for an early exit
         * before touching any characters.
         */
        [[nodiscard]] inline bool is_equal(const std::string_view a, const std::string_view b) noexcept {
            if (a.size() != b.size()) return false;
            for (std::size_t i = 0; i < a.size(); ++i)
                if (ascii_lower(a[i]) != ascii_lower(b[i])) return false;
            return true;
        }

        /**
         * @brief Strip RFC 7230 Optional Whitespace (SP and HTAB) from both ends.
         * @warning For framework's internal use only.
         * Any external use without understanding may cause memory life cycle issues.
         *
         * The original code only stripped spaces; the RFC also allows horizontal tabs.
         */
        [[nodiscard]] constexpr std::string_view strip_ows(std::string_view sv) noexcept {
            while (!sv.empty() && (sv.front() == ' ' || sv.front() == '\t'))
                sv.remove_prefix(1);
            while (!sv.empty() && (sv.back() == ' ' || sv.back() == '\t'))
                sv.remove_suffix(1);
            // ReSharper disable once CppDFALocalValueEscapesFunction
            return sv;
        }

        /**
         * @brief Append an unsigned int to a std::string with zero heap allocation.
         *
         * Replaces std::to_string(v) which allocates a temporary std::string.
         * std::to_chars writes into a stack buffer; we then append the used range.
         */
        inline void append_uint(std::string &out, const unsigned int v) {
            char buf[10];
            if (const auto [end, ec] = std::to_chars(buf, buf + sizeof(buf), v); ec == std::errc{})
                out.
                        append(buf, end);
        }

        /** @brief Same as append_uint but for std::size_t (Content-Length). */
        inline void append_size(std::string &out, const std::size_t v) {
            char buf[20];
            if (const auto [end, ec] = std::to_chars(buf, buf + sizeof(buf), v); ec == std::errc{})
                out.
                        append(buf, end);
        }
    } // namespace detail
    // ─────────────────────────────────────────────────────────────────────────────


    // ─── Method helpers ───────────────────────────────────────────────────────────

    /**
     * @brief Converts method enum to string representation.
     *
     * The methods array is marked static constexpr so it is guaranteed to live in
     * read-only data rather than being reconstructed on each call at lower
     * optimisation levels.
     */
    inline constexpr std::string_view to_string(method m) noexcept {
        constexpr std::array<std::string_view, 10> names = {
            "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "TRACE", "CONNECT", "QUERY"
        };
        const auto idx = static_cast<std::size_t>(m);
        return idx < names.size() ? names[idx] : "UNKNOWN";
    }

    /**
     * @brief Parses string representation of an HTTP method to its enum value.
     *
     * Dispatches on the first character to prune candidates to at most 3 before
     * doing a full comparison. This avoids up to 8 unnecessary comparisons for
     * every method lookup.
     */
    inline method from_string(const std::string_view m) noexcept {
        if (m.empty()) return method::UNKNOWN;
        switch (m[0]) {
            case 'G': return (m == "GET") ? method::GET : method::UNKNOWN;
            case 'D': return (m == "DELETE") ? method::DELETE : method::UNKNOWN;
            case 'H': return (m == "HEAD") ? method::HEAD : method::UNKNOWN;
            case 'O': return (m == "OPTIONS") ? method::OPTIONS : method::UNKNOWN;
            case 'T': return (m == "TRACE") ? method::TRACE : method::UNKNOWN;
            case 'C': return (m == "CONNECT") ? method::CONNECT : method::UNKNOWN;
            case 'Q': return (m == "QUERY") ? method::QUERY : method::UNKNOWN;
            case 'P':
                if (m == "POST") return method::POST;
                if (m == "PUT") return method::PUT;
                if (m == "PATCH") return method::PATCH;
                return method::UNKNOWN;
            default: return method::UNKNOWN;
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────


    // ─── Message structures ───────────────────────────────────────────────────────

    /**
     * @brief Zero-copy HTTP header field.
     *
     * Both views reference the original parse buffer — no copies made.
     */
    struct header {
        std::string_view name;
        std::string_view value;
    };

    /**
     * @brief Base for HTTP request and response messages.
     */
    struct message_base {
        int version_major = 1;
        int version_minor = 1;
        std::vector<header> headers;
        std::string_view body;

        /**
         * @brief Case-insensitive header lookup.
         *
         * Uses detail::is_equal (locale-free, early-exit on size mismatch)
         * instead of std::ranges::equal + lambda.
         */
        [[nodiscard]] std::optional<std::string_view>
        get_header(const std::string_view name) const noexcept {
            for (const auto &[n, v]: headers)
                if (detail::is_equal(n, name)) return v;
            return std::nullopt;
        }
    };

    /** @brief HTTP request message. */
    struct request : public message_base {
        http::method method_type = method::UNKNOWN;
        std::string_view target;
    };

    /** @brief HTTP response message. */
    struct response : public message_base {
        unsigned int status_code = 200;
        std::string_view status_text = "OK";
    };

    // ─────────────────────────────────────────────────────────────────────────────


    /**
     * @brief Standard HTTP reason phrases.
     */
    inline std::string_view status_text_for(const unsigned int code) noexcept {
        switch (code) {
            case 100: return "Continue";
            case 200: return "OK";
            case 201: return "Created";
            case 204: return "No Content";
            case 301: return "Moved Permanently";
            case 302: return "Found";
            case 304: return "Not Modified";
            case 400: return "Bad Request";
            case 401: return "Unauthorized";
            case 403: return "Forbidden";
            case 404: return "Not Found";
            case 405: return "Method Not Allowed";
            case 408: return "Request Timeout";
            case 413: return "Payload Too Large";
            case 429: return "Too Many Requests";
            case 500: return "Internal Server Error";
            case 502: return "Bad Gateway";
            case 503: return "Service Unavailable";
            default: return "Unknown";
        }
    }


    // ─── Parser ───────────────────────────────────────────────────────────────────

    /**
     * @brief Zero-copy HTTP/1.x message parser.
     *
     * All string_view members of the parsed structures reference the caller's
     * buffer. The buffer must remain valid for the lifetime of those views.
     */
    class parser {
    public:
        enum class result { success, incomplete, error };

        /**
         * @brief Helper to find the next LF (\n) line terminator and strip optional CR (\r).
         */
        static bool find_next_line(const std::string_view buffer,
                                   const std::size_t cursor,
                                   std::size_t &line_end,
                                   std::size_t &next_cursor) {
            const std::size_t pos = buffer.find('\n', cursor);
            if (pos == std::string_view::npos) return false;

            if (pos > cursor && buffer[pos - 1] == '\r') {
                line_end = pos - 1;
            } else {
                line_end = pos;
            }
            next_cursor = pos + 1;
            return true;
        }

        /**
         * @brief Parse a raw buffer into an HTTP request.
         * @param buffer        Raw bytes received from the network.
         * @param req           Output: populated on result::success.
         * @param bytes_consumed Output: how many bytes of buffer were consumed.
         */
        [[nodiscard]]
        static result parse_request(const std::string_view buffer,
                                    request &req,
                                    std::size_t &bytes_consumed) {
            bytes_consumed = 0;
            std::size_t cursor = 0;

            // ── Request line ──────────────────────────────────────────────────────
            std::size_t rl_end = 0;
            std::size_t next_cursor = 0;
            if (!find_next_line(buffer, cursor, rl_end, next_cursor)) return result::incomplete;

            const std::string_view rl = buffer.substr(0, rl_end);
            cursor = next_cursor;

            const std::size_t sp1 = rl.find(' ');
            if (sp1 == std::string_view::npos) return result::error;
            const std::size_t sp2 = rl.find(' ', sp1 + 1);
            if (sp2 == std::string_view::npos) return result::error;

            req.method_type = from_string(rl.substr(0, sp1));
            req.target = rl.substr(sp1 + 1, sp2 - sp1 - 1);

            // Parse "HTTP/X.Y" — starts_with is C++20 and avoids a substr copy
            const std::string_view ver = rl.substr(sp2 + 1);
            if (ver.size() < 8 || !ver.starts_with("HTTP/")) return result::error;
            req.version_major = ver[5] - '0';
            req.version_minor = ver[7] - '0';

            // ── Headers ──────────────────────────────────────────────────────────
            if (const result r = parse_headers(buffer, cursor, req.headers);
                r != result::success)
                return r;

            // ── Body ─────────────────────────────────────────────────────────────
            return extract_body(buffer, cursor, req, bytes_consumed, /*is_request=*/true);
        }

        /**
         * @brief Parse a raw buffer into an HTTP response.
         */
        [[nodiscard]]
        static result parse_response(const std::string_view buffer,
                                     response &res,
                                     std::size_t &bytes_consumed) {
            bytes_consumed = 0;
            std::size_t cursor = 0;

            // ── Status line ───────────────────────────────────────────────────────
            std::size_t sl_end = 0;
            std::size_t next_cursor = 0;
            if (!find_next_line(buffer, cursor, sl_end, next_cursor)) return result::incomplete;

            const std::string_view sl = buffer.substr(0, sl_end);
            cursor = next_cursor;

            if (sl.size() < 12 || !sl.starts_with("HTTP/")) return result::error;

            res.version_major = sl[5] - '0';
            res.version_minor = sl[7] - '0';

            const std::size_t sp1 = sl.find(' ');
            if (sp1 == std::string_view::npos) return result::error;
            const std::size_t sp2 = sl.find(' ', sp1 + 1);

            const std::string_view code_sv = sl.substr(
                sp1 + 1,
                sp2 != std::string_view::npos ? sp2 - sp1 - 1 : std::string_view::npos);

            unsigned int code = 0;
            const auto [ptr, ec] = std::from_chars(
                code_sv.data(), code_sv.data() + code_sv.size(), code);
            if (ec != std::errc{}) return result::error;
            res.status_code = code;

            if (sp2 != std::string_view::npos)
                res.status_text = sl.substr(sp2 + 1);

            // ── Headers ──────────────────────────────────────────────────────────
            if (const result r = parse_headers(buffer, cursor, res.headers);
                r != result::success)
                return r;

            // ── Body ─────────────────────────────────────────────────────────────
            return extract_body(buffer, cursor, res, bytes_consumed);
        }

    private:
        /**
         * @brief Parse header fields from buffer into `headers`.
         *
         * Pre-reserves capacity for 16 headers to eliminate the typical
         * log₂(n) reallocation chain for standard HTTP messages.
         * Also strips OWS per RFC 7230 §3.2.3 (SP and HTAB, not just SP).
         */
        static result parse_headers(const std::string_view buffer,
                                    std::size_t &cursor,
                                    std::vector<header> &headers) {
            headers.reserve(16);

            while (cursor < buffer.size()) {
                std::size_t line_end = 0;
                std::size_t next_cursor = 0;
                if (!find_next_line(buffer, cursor, line_end, next_cursor)) {
                    return result::incomplete;
                }

                // Blank line -> end of header section
                if (line_end == cursor) {
                    cursor = next_cursor;
                    return result::success;
                }

                const std::string_view line = buffer.substr(cursor, line_end - cursor);
                const std::size_t colon = line.find(':');
                if (colon == std::string_view::npos) return result::error;

                headers.emplace_back(
                    line.substr(0, colon),
                    detail::strip_ows(line.substr(colon + 1)) // RFC 7230 OWS
                );
                cursor = next_cursor;
            }
            return result::incomplete;
        }

        /**
         * @brief Resolve body from Content-Length or chunked Transfer-Encoding.
         *
         * Performs a single fused pass through headers to locate both
         * Transfer-Encoding and Content-Length simultaneously, instead of
         * calling get_header() twice (two separate O(n) scans).
         */
        static result extract_body(const std::string_view buffer,
                                   const std::size_t cursor,
                                   message_base &msg,
                                   std::size_t &bytes_consumed,
                                   const bool is_request = false) {
            // Single pass: find both interesting headers at once
            std::optional<std::string_view> te, cl;
            for (const auto &[n, v]: msg.headers) {
                if (!te && detail::is_equal(n, "Transfer-Encoding")) te = v;
                else if (!cl && detail::is_equal(n, "Content-Length")) cl = v;
                if (te && cl) break; // both found — stop early
            }

            if (te && te->find("chunked") != std::string_view::npos)
                return extract_chunked_body(buffer, cursor, msg, bytes_consumed);

            // Content-Length path
            std::size_t content_length = 0;
            if (cl) {
                const auto [ptr, ec] = std::from_chars(
                    cl->data(), cl->data() + cl->size(), content_length);
                if (ec != std::errc{}) return result::error;
            } else if (is_request) {
                // RFC 7230 §3.3.3: In a request message without Transfer-Encoding
                // or Content-Length, message body length is zero.
                content_length = 0;
            } else {
                content_length = buffer.size() - cursor;
            }

            if (buffer.size() - cursor < content_length) {
                if (is_request) {
                    return result::incomplete;
                }
                msg.body = buffer.substr(cursor);
                bytes_consumed = buffer.size();
                return result::success;
            }

            msg.body = buffer.substr(cursor, content_length);
            bytes_consumed = cursor + content_length;
            return result::success;
        }

        /**
         * @brief Parse chunked Transfer-Encoding body.
         *
         * Walks chunk framing to find bytes_consumed, then sets msg.body to the
         * raw chunked region. Callers that need de-chunked data must post-process.
         */
        static result extract_chunked_body(const std::string_view buffer,
                                           std::size_t cursor,
                                           message_base &msg,
                                           std::size_t &bytes_consumed) {
            const std::size_t body_start = cursor;
            bool terminal_reached = false;

            while (cursor < buffer.size()) {
                std::size_t line_end = 0;
                std::size_t next_cursor = 0;
                if (!find_next_line(buffer, cursor, line_end, next_cursor)) {
                    return result::incomplete;
                }

                std::string_view size_sv = buffer.substr(cursor, line_end - cursor);
                if (const std::size_t semi = size_sv.find(';'); semi != std::string_view::npos) {
                    size_sv = size_sv.substr(0, semi);
                }

                size_sv = detail::strip_ows(size_sv);
                if (size_sv.empty()) {
                    cursor = next_cursor;
                    continue;
                }

                std::size_t chunk_size = 0;
                const auto [ptr, ec] = std::from_chars(
                    size_sv.data(), size_sv.data() + size_sv.size(), chunk_size, 16);
                if (ec != std::errc{}) {
                    return result::error;
                }

                cursor = next_cursor;

                if (chunk_size == 0) {
                    if (cursor < buffer.size()) {
                        if (std::size_t dummy_end = 0, after_crlf = 0; find_next_line(
                            buffer, cursor, dummy_end, after_crlf)) {
                            cursor = after_crlf;
                        }
                    }
                    terminal_reached = true;
                    break;
                }

                if (cursor + chunk_size > buffer.size()) {
                    return result::incomplete;
                }

                cursor += chunk_size;

                if (cursor < buffer.size() && buffer[cursor] == '\r') ++cursor;
                if (cursor < buffer.size() && buffer[cursor] == '\n') ++cursor;
            }

            if (!terminal_reached) {
                return result::incomplete;
            }

            msg.body = buffer.substr(body_start, cursor - body_start);
            bytes_consumed = cursor;
            return result::success;
        }
    };


    // ─── Encoder ─────────────────────────────────────────────────────────────────

    /**
     * @brief HTTP/1.x message serializer.
     *
     * Key improvements over baseline:
     *  - std::to_chars for all integer fields (no heap allocation per number)
     *  - Version byte written directly as a char ('0' + digit)
     *  - Reserve computed from actual header sizes to avoid reallocations
     *  - Content-Length presence checked during the header write loop (no second scan)
     */
    class encoder {
    public:
        /**
         * @brief Serialise an HTTP response to wire format.
         *
         * Usage:
         *   response res;
         *   res.status_code = 200;
         *   res.body = "Hello, World!";
         *   auto bytes = encoder::serialize(res);
         */
        static std::string serialize(const response &res) {
            // ── Accurate reserve estimate ─────────────────────────────────────────
            // "HTTP/1.1 200 OK\r\n" ≈ 17 bytes baseline,
            // each header:  name + ": " + value + "\r\n"
            // auto CL header: "Content-Length: " + 20 digits + "\r\n" ≈ 40 bytes
            // blank line:  "\r\n" = 2 bytes
            std::size_t est = 32 + res.body.size() + 40;
            for (const auto &[name, value]: res.headers) est += name.size() + value.size() + 4;

            std::string out;
            out.reserve(est);

            // ── Status line ───────────────────────────────────────────────────────
            out += "HTTP/";
            out += static_cast<char>('0' + res.version_major); // no allocation
            out += '.';
            out += static_cast<char>('0' + res.version_minor);
            out += ' ';
            detail::append_uint(out, res.status_code); // no allocation
            out += ' ';
            out += res.status_text;
            out += "\r\n";

            // ── Headers + fused Content-Length check ──────────────────────────────
            // Detect presence of an existing Content-Length while writing headers
            // to avoid a second get_header() scan afterwards.
            bool has_cl = false;
            for (const auto &[name, value]: res.headers) {
                out += name;
                out += ": ";
                out += value;
                out += "\r\n";
                if (!has_cl && detail::is_equal(name, "Content-Length")) has_cl = true;
            }

            if (!has_cl && !res.body.empty()) {
                out += "Content-Length: ";
                detail::append_size(out, res.body.size()); // no allocation
                out += "\r\n";
            }
            out += "\r\n";
            out += res.body;
            return out;
        }

        /**
         * @brief Serialise an HTTP request to wire format.
         *
         * Usage:
         * @code
         *   request req;
         *   req.method_type = method::GET;
         *   req.target = "/api/users";
         *   auto bytes = encoder::serialize_request(req);
         * @endcode
         */
        static std::string serialize_request(const request &req) {
            std::size_t est = 32 + req.body.size() + 40;
            for (const auto &[name, value]: req.headers) est += name.size() + value.size() + 4;

            std::string out;
            out.reserve(est);

            // ── Request line ──────────────────────────────────────────────────────
            out += to_string(req.method_type);
            out += ' ';
            out += req.target;
            out += " HTTP/";
            out += static_cast<char>('0' + req.version_major);
            out += '.';
            out += static_cast<char>('0' + req.version_minor);
            out += "\r\n";

            // ── Headers + fused Content-Length check ──────────────────────────────
            bool has_cl = false;
            for (const auto &[name, value]: req.headers) {
                out += name;
                out += ": ";
                out += value;
                out += "\r\n";
                if (!has_cl && detail::is_equal(name, "Content-Length")) has_cl = true;
            }

            if (!has_cl && !req.body.empty()) {
                out += "Content-Length: ";
                detail::append_size(out, req.body.size());
                out += "\r\n";
            }
            out += "\r\n";
            out += req.body;
            return out;
        }

        /**
         * @brief Format a single chunk framing header: "size_hex\r\n".
         */
        static std::string format_chunk_header(const std::size_t chunk_size) {
            char hex_buf[32];
            const auto [ptr, ec] = std::to_chars(hex_buf, hex_buf + sizeof(hex_buf), chunk_size, 16);
            std::string out(hex_buf, ptr);
            out += "\r\n";
            return out;
        }

        /**
         * @brief Format a complete HTTP chunk: "size_hex\r\ndata\r\n".
         */
        static std::string format_chunk(const std::string_view data) {
            if (data.empty()) return "0\r\n\r\n";
            std::string out = format_chunk_header(data.size());
            out.reserve(out.size() + data.size() + 2);
            out += data;
            out += "\r\n";
            return out;
        }

        /**
         * @brief Terminal HTTP chunk signaling end of chunked stream: "0\r\n\r\n".
         */
        [[nodiscard]] static constexpr std::string_view format_terminal_chunk() noexcept {
            return "0\r\n\r\n";
        }
    };

    // ─── Decoder ─────────────────────────────────────────────────────────────────

    /**
     * @brief HTTP/1.x response decoder and payload de-chunker.
     */
    class decoder {
    public:
        /**
         * @brief Decode a raw HTTP/1.x response buffer into a response structure.
         * @param buffer Raw network response buffer.
         * @param res Output: populated response structure on success.
         * @param bytes_consumed Output: bytes consumed from the buffer.
         * @return parser::result (success, incomplete, error).
         */
        [[nodiscard]]
        static parser::result decode_response(const std::string_view buffer,
                                              response &res,
                                              std::size_t &bytes_consumed) {
            return parser::parse_response(buffer, res, bytes_consumed);
        }

        /**
         * @brief Un-chunk a Transfer-Encoding: chunked raw body payload into unchunked bytes.
         * @param chunked_raw Raw chunked payload.
         * @return Unchunked decoded body string.
         */
        [[nodiscard]]
        static std::string dechunk(const std::string_view chunked_raw) {
            std::string unchunked;
            std::size_t cursor = 0;
            while (cursor < chunked_raw.size()) {
                std::size_t line_end = 0;
                std::size_t next_cursor = 0;
                if (!parser::find_next_line(chunked_raw, cursor, line_end, next_cursor)) {
                    if (cursor < chunked_raw.size()) {
                        unchunked.append(chunked_raw.substr(cursor));
                    }
                    break;
                }

                std::string_view size_sv = chunked_raw.substr(cursor, line_end - cursor);
                if (const std::size_t semi = size_sv.find(';'); semi != std::string_view::npos) {
                    size_sv = size_sv.substr(0, semi);
                }
                size_sv = detail::strip_ows(size_sv);
                if (size_sv.empty()) {
                    cursor = next_cursor;
                    continue;
                }

                std::size_t chunk_size = 0;
                const auto [ptr, ec] = std::from_chars(
                    size_sv.data(), size_sv.data() + size_sv.size(), chunk_size, 16);
                if (ec != std::errc{} || chunk_size == 0) {
                    if (ec != std::errc{} && cursor < chunked_raw.size()) {
                        unchunked.append(chunked_raw.substr(cursor));
                    }
                    break;
                }

                cursor = next_cursor;
                if (cursor + chunk_size > chunked_raw.size()) {
                    unchunked.append(chunked_raw.substr(cursor));
                    break;
                }

                unchunked.append(chunked_raw.substr(cursor, chunk_size));
                cursor += chunk_size;

                if (cursor < chunked_raw.size() && chunked_raw[cursor] == '\r') ++cursor;
                if (cursor < chunked_raw.size() && chunked_raw[cursor] == '\n') ++cursor;
            }
            return unchunked;
        }
    };

    /**
     * @struct http1codec
     * @brief HTTP/1.x Protocol Codec combining zero-copy parser, encoder, and decoder.
     */
    struct http1codec {
        using parser = wavex::protos::http::parser;
        using encoder = wavex::protos::http::encoder;
        using decoder = wavex::protos::http::decoder;
        using request = wavex::protos::http::request;
        using response = wavex::protos::http::response;

        static std::string_view status_text_for(const unsigned int code) noexcept {
            return wavex::protos::http::status_text_for(code);
        }
    };
}
