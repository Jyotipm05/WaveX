// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
/**
 * @file Url.cpp
 * @brief Implementation of RFC 3986 URL parsing and query-string utilities.
 */

#include <wavex/Base/Url.hpp>
#include <wavex/Base/Uri.hpp>   // wavex::uri::decode
#include <charconv>
#include <algorithm>
#include <cctype>

namespace wavex::url {
    // -----------------------------------------------------------------------
    //  Query String Parsing
    // -----------------------------------------------------------------------

    std::unordered_map<std::string, std::string> parse_query(std::string_view qs) {
        std::unordered_map<std::string, std::string> result;

        while (!qs.empty()) {
            // Split off the next key=value pair at '&'
            const size_t amp = qs.find('&');
            const std::string_view pair = amp != std::string_view::npos
                                              ? qs.substr(0, amp)
                                              : qs;

            if (!pair.empty()) {
                if (const size_t eq = pair.find('='); eq != std::string_view::npos) {
                    result[uri::decode(pair.substr(0, eq))] =
                            uri::decode(pair.substr(eq + 1));
                } else {
                    // Key with no value
                    result[uri::decode(pair)] = "";
                }
            }

            if (amp == std::string_view::npos) break;
            qs = qs.substr(amp + 1);
        }
        return result;
    }

    // -----------------------------------------------------------------------
    //  URL Parsing
    // -----------------------------------------------------------------------

    Url Url::parse(std::string_view raw) {
        Url url;
        size_t pos = 0;

        // 1. Scheme — look for "://"
        if (const size_t scheme_end = raw.find("://"); scheme_end != std::string_view::npos) {
            url.scheme = std::string(raw.substr(0, scheme_end));
            // Normalise scheme to lowercase per RFC 3986 §6.2.2.1
            std::ranges::transform(url.scheme,
                                   url.scheme.begin(),
                                   [](const char c) -> int { return std::tolower(static_cast<unsigned char>(c)); });
            pos = scheme_end + 3;
        }

        // 2. Authority — everything before the path, query, or fragment
        //    authority = [userinfo@]host[:port]
        size_t authority_end = raw.find('/', pos);
        if (authority_end == std::string_view::npos) {
            authority_end = raw.find('?', pos);
            if (authority_end == std::string_view::npos) {
                authority_end = raw.find('#', pos);
                if (authority_end == std::string_view::npos) {
                    authority_end = raw.size();
                }
            }
        }

        std::string_view authority = raw.substr(pos, authority_end - pos);
        pos = authority_end;

        // 2a. Userinfo (before '@')
        if (const size_t at = authority.find('@'); at != std::string_view::npos) {
            url.userinfo = std::string(authority.substr(0, at));
            authority = authority.substr(at + 1);
        }

        // 2b. Host and port
        //     Handle IPv6 literals: [::1]:8080
        if (!authority.empty() && authority.front() == '[') {
            if (const size_t bracket = authority.find(']'); bracket != std::string_view::npos) {
                url.host = std::string(authority.substr(1, bracket - 1));
                if (bracket + 1 < authority.size() && authority[bracket + 1] == ':') {
                    const auto port_str = authority.substr(bracket + 2);
                    uint16_t p = 0;
                    std::from_chars(port_str.data(), port_str.data() + port_str.size(), p);
                    url.port = p;
                }
            }
        } else {
            if (const size_t colon = authority.rfind(':'); colon != std::string_view::npos) {
                url.host = std::string(authority.substr(0, colon));
                const auto port_str = authority.substr(colon + 1);
                uint16_t p = 0;
                std::from_chars(port_str.data(), port_str.data() + port_str.size(), p);
                url.port = p;
            } else {
                url.host = std::string(authority);
            }
        }

        // 3. Path
        if (pos < raw.size() && raw[pos] == '/') {
            const size_t path_end = [&] {
                const size_t e = raw.find_first_of("?#", pos);
                return e == std::string_view::npos ? raw.size() : e;
            }();
            url.path = std::string(raw.substr(pos, path_end - pos));
            pos = path_end;
        }

        // 4. Query
        if (pos < raw.size() && raw[pos] == '?') {
            ++pos;
            const size_t query_end = [&] {
                const size_t e = raw.find('#', pos);
                return e == std::string_view::npos ? raw.size() : e;
            }();
            url.query = std::string(raw.substr(pos, query_end - pos));
            pos = query_end;
        }

        // 5. Fragment
        if (pos < raw.size() && raw[pos] == '#') {
            ++pos;
            url.fragment = std::string(raw.substr(pos));
        }

        return url;
    }

    uint16_t Url::effective_port() const {
        if (port != 0) return port;
        if (scheme == "https") return 443;
        if (scheme == "http") return 80;
        return 0;
    }

    std::string Url::to_string() const {
        std::string out;
        if (!scheme.empty()) out += scheme + "://";
        if (!userinfo.empty()) out += userinfo + "@";
        out += host;
        if (port != 0) out += ":" + std::to_string(port);
        out += path;
        if (!query.empty()) out += "?" + query;
        if (!fragment.empty()) out += "#" + fragment;
        return out;
    }
} // namespace wavex::url
