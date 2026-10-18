// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * @file Router.cpp
 * @brief Out-of-line implementation of non-template router algorithms and path utilities.
 */

#include <wavex/Engine/Router.hpp>
#include <wavex/Engine/HttpRouter.hpp>
#include <wavex/Utils/BinaryFile.hpp>
#include <wavex/Base/MimeTypes.hpp>

#include <re2/re2.h>
#include <cassert>
#include <algorithm>
#include <span>
#include <vector>
#include <string>
#include <string_view>
#include <memory>

namespace wavex::engine {
    namespace detail {
        auto normalize_path(const std::string_view path) -> std::string {
            if (path.empty() || path == "/") return "/";
            std::string p(path);
            if (p.front() != '/') [[unlikely]] p.insert(p.begin(), '/');
            if (p.size() > 1 && p.back() == '/') [[likely]] p.pop_back();
            return p;
        }

        auto normalize_path_view(const std::string_view path, std::string &scratch) -> std::string_view {
            if (path.empty() || path == "/") return "/";

            const bool needs_front = path.front() != '/';
            const bool needs_trim = path.size() > 1 && path.back() == '/';

            if (!needs_front && !needs_trim) [[likely]] {
                return path;
            }

            scratch.clear();
            scratch.reserve(path.size() + (needs_front ? 1 : 0));
            if (needs_front) scratch.push_back('/');
            scratch.append(path);
            if (needs_trim && scratch.size() > 1 && scratch.back() == '/') {
                scratch.pop_back();
            }
            return scratch;
        }

        auto split_path_view(const std::string_view path) -> std::vector<std::string_view> {
            std::vector<std::string_view> segments;
            if (path.empty() || path == "/") return segments;

            segments.reserve(static_cast<std::size_t>(std::ranges::count(path, '/')));

            std::size_t start = 1;
            while (start < path.size()) {
                std::size_t end = path.find('/', start);
                if (end == std::string_view::npos) end = path.size();
                if (end != start) {
                    segments.emplace_back(path.substr(start, end - start));
                }
                start = end + 1;
            }
            return segments;
        }

        auto split_path_into(
            const std::string_view normalized,
            const std::span<std::string_view> seg_buf,
            std::size_t &seg_count,
            std::vector<std::string_view> &seg_overflow) -> std::span<const std::string_view> {
            seg_count = 0;
            seg_overflow.clear();

            if (!normalized.empty() && normalized != "/") {
                std::size_t start = 1;
                while (start < normalized.size()) {
                    const std::size_t end = normalized.find('/', start);
                    if (const std::size_t actual_end = (end == std::string_view::npos) ? normalized.size() : end;
                        actual_end != start) {
                        if (seg_count < seg_buf.size()) [[likely]] {
                            seg_buf[seg_count++] = normalized.substr(start, actual_end - start);
                        } else [[unlikely]] {
                            if (seg_overflow.empty()) {
                                seg_overflow.assign(seg_buf.begin(),
                                                    seg_buf.begin() + static_cast<std::ptrdiff_t>(seg_count));
                            }
                            seg_overflow.emplace_back(normalized.substr(start, actual_end - start));
                        }
                    }
                    if (end == std::string_view::npos) break;
                    start = end + 1;
                }
            }

            if (seg_overflow.empty()) {
                return seg_buf.subspan(0, seg_count);
            }
            return std::span<const std::string_view>(seg_overflow);
        }

        auto parse_segment(const std::string_view segment) -> ParsedSegment {
            // 1. :param
            if (!segment.empty() && segment[0] == ':') {
                ParsedSegment res;
                res.type = SegmentType::Param;
                res.param_name = std::string(segment.substr(1));
                return res;
            }

            // 2. {name} or {name:pattern}
            if (segment.size() >= 2 && segment[0] == '{' && segment.back() == '}') {
                const auto inner = segment.substr(1, segment.size() - 2);
                if (const std::size_t colon = inner.find(':'); colon != std::string_view::npos) {
                    ParsedSegment res;
                    res.type = SegmentType::RegexParam;
                    res.param_name = std::string(inner.substr(0, colon));
                    res.regex_pattern = std::string(inner.substr(colon + 1));
                    return res;
                }
                ParsedSegment res;
                res.type = SegmentType::Param;
                res.param_name = std::string(inner);
                return res;
            }

            // 3. * or *name
            if (!segment.empty() && segment[0] == '*') {
                ParsedSegment res;
                res.type = SegmentType::Wildcard;
                res.param_name = segment.size() > 1 ? std::string(segment.substr(1)) : "*";
                return res;
            }

            // 4. Static segment
            ParsedSegment res;
            res.type = SegmentType::Static;
            res.static_prefix = segment;
            return res;
        }

        auto get_compiled_regex(
            std::unordered_map<std::string, std::shared_ptr<re2::RE2> > &cache,
            const std::string &pattern) -> std::shared_ptr<re2::RE2> {
            if (auto &cached = cache[pattern]; cached) {
                return cached;
            } else {
                cached = std::make_shared<re2::RE2>(pattern);
                return cached;
            }
        }

        auto match_regex(const std::string_view text, const re2::RE2 &constraint) -> bool {
            return re2::RE2::FullMatch(re2::StringPiece(text.data(), text.size()), constraint);
        }

        auto compute_wildcard_slice(const std::span<const std::string_view> segments,
                                    const std::size_t depth) -> std::string_view {
            if (depth < segments.size()) {
                const char *w_begin = segments[depth].data();
                const char *w_end = segments.back().data() + segments.back().size();
                assert(w_begin <= w_end && "Segments must be contiguous slices of the same path buffer");
                return std::string_view(w_begin, static_cast<std::size_t>(w_end - w_begin));
            }
            return {};
        }

        void backtrack_param(base::FlatMap<std::string_view, std::string_view> &params,
                             const std::string_view param_name) {
            base::FlatMap<std::string_view, std::string_view> rebuilt;
            for (const auto &[k, v]: params) {
                if (k != param_name) {
                    rebuilt.insert_or_assign(k, v);
                }
            }
            params = std::move(rebuilt);
        }

        auto load_not_found_file(const std::string &file_path, std::string &out_body, std::string &out_mime) -> bool {
            if (auto res = wavex::utils::BinaryFile::read_all(file_path)) {
                out_body = std::move(*res);
                out_mime = std::string(base::mime_type_from_path(file_path));
                return true;
            }
            return false;
        }
    } // namespace detail

    // Explicit template instantiations for standard HTTP specializations
    template class Router<Http1Proto>;
    template class Router<Http2Proto>;
#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
    template class Router<Http3Proto>;
#endif
} // namespace wavex::engine
