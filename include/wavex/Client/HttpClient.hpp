// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
/**
 * @file HttpClient.hpp
 * @brief Async coroutine-based HTTP/1.1 client for sending requests to 3rd-party services.
 */

#pragma once

#ifndef ASIO_HAS_CO_AWAIT
#define ASIO_HAS_CO_AWAIT 1
#endif

#include <string>
#include <string_view>
#include <vector>
#include <utility>

#include <asio/co_spawn.hpp>
#include <nlohmann/json.hpp>

#include <wavex/protos/http/HttpRequest.hpp>
#include <wavex/protos/http/HttpResponse.hpp>

namespace wavex::client {
    using protos::http::method;
    using protos::http::Http1Request;
    using protos::http::Http1Response;

    /**
     * @class HttpClient
     * @brief Coroutine-native HTTP client for sending requests and receiving responses from 3rd-party services.
     */
    class HttpClient {
    public:
        HttpClient() = default;

        /**
         * @brief Send an Http1Request and await the Http1Response asynchronously.
         * @param req The HTTP request object. Target URL can be full URL ("http://api.site.com/v1/data").
         * @return Coroutine awaitable producing the populated Http1Response.
         */
        static asio::awaitable<Http1Response> send(Http1Request req);

        /**
         * @brief Convenience GET request to a 3rd party URL.
         * @param url Full target URL, e.g. "http://127.0.0.1:8080/api/json"
         * @return Coroutine awaitable producing Http1Response.
         */
        static asio::awaitable<Http1Response> get(std::string_view url);

        /**
         * @brief Convenience POST JSON request to a 3rd party URL.
         * @param url Full target URL
         * @param json_body JSON payload
         * @return Coroutine awaitable producing Http1Response.
         */
        static asio::awaitable<Http1Response> post(std::string_view url, const nlohmann::json &json_body);

        /**
         * @brief Send a generic HTTP request by method and URL.
         * @param m HTTP method (GET, POST, PUT, DELETE, etc.)
         * @param url Full target URL
         * @param body Request body
         * @param headers Extra request headers as key-value pairs
         * @return Coroutine awaitable producing Http1Response.
         */
        static asio::awaitable<Http1Response> request(
            method m,
            std::string_view url,
            std::string_view body = "",
            const std::vector<std::pair<std::string, std::string> > &headers = {});
    };
} // namespace wavex::client
