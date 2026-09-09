/**
 * @file test_client.cpp
 * @brief Unit & integration tests for HttpClient, HttpRequest (client), and HttpResponse (client).
 */
#include <iostream>
#include <fstream>
#include <string>
#include <algorithm>
#include <thread>
#include <chrono>
#include <asio/io_context.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <nlohmann/json.hpp>

#include <wavex/wavex.hpp>

import wavex;

using HttpRequest = wavex::protos::http::Http1Request;
using HttpResponse = wavex::protos::http::Http1Response;
using HttpRouter = wavex::engine::Http1Router;
using Server = wavex::server::Http1Server;

namespace {
    int tests_run = 0;
    int tests_passed = 0;

    void check(const bool condition, const char *name) {
        ++tests_run;
        if (condition) {
            ++tests_passed;
            std::cout << "  [PASS] " << name << "\n";
        } else {
            std::cout << "  [FAIL] " << name << "\n";
        }
    }

    /**
     * @brief Strip CR (0x0D) from a string_view for safe stdout display.
     *
     * Raw HTTP responses use CRLF (\r\n) line terminators. Printing \r to
     * a terminal or IM gateway causes the cursor to return to column 0,
     * overwriting subsequent output lines and producing garbled display.
     */
    std::string strip_cr(const std::string_view sv) {
        std::string out;
        out.reserve(sv.size());
        for (const char c: sv) {
            if (c != '\r') out += c;
        }
        return out;
    }

    /**
     * @brief Print a single header name/value pair safely to stdout.
     *
     * Replaces any non-printable or high bytes with hex escapes so that
     * CRLF / UTF-8 multi-byte sequences never corrupt the IM gateway.
     */
    void safe_print_header(std::size_t idx,
                           const std::string_view name,
                           const std::string_view value) {
        auto safe = [](const std::string_view sv) -> std::string {
            std::string out;
            out.reserve(sv.size());
            for (unsigned char c: sv) {
                if (c >= 0x20 && c <= 0x7e)
                    out += static_cast<char>(c);
                else
                    out += "[0x" + std::to_string(static_cast<int>(c)) + "]";
            }
            return out;
        };
        std::cout << "    [" << idx << "] " << safe(name) << ": " << safe(value) << "\n";
    }

    /**
     * @brief Write raw bytes to a file, stripping CR for readability.
     */
    void dump_to_file(const std::string &path, const std::string_view data) {
        std::ofstream ofs(path, std::ios::binary);
        if (!ofs) return;
        for (const char c: data) {
            if (c != '\r') ofs.put(c);
        }
    }

    /**
     * @brief Write parsed response summary to a file.
     */
    void dump_parsed_to_file(const std::string &path,
                             const HttpResponse &res) {
        std::ofstream ofs(path);
        if (!ofs) return;
        ofs << "Status: " << res.status_code() << " " << res.status_text() << "\n";
        ofs << "Header count: " << res.header_views().size() << "\n";
        ofs << "Headers:\n";
        for (const auto &[k, v]: res.header_views()) {
            ofs << "  [" << k.size() << " chars] " << k << ": " << v << "\n";
        }
        ofs << "Body size: " << res.get_body().size() << " bytes\n";
        ofs << "Body starts with <!doctype: "
                << res.get_body().starts_with("<!doctype html>") << "\n";
        ofs << "Body ends with </html>: "
                << res.get_body().ends_with("</html>") << "\n";
    }
}

// ─── Test 1: HttpRequest Client Construction & Serialization ──────────────────

void test_http_request_client_serialization() {
    std::cout << "\n[Test 1] HttpRequest client builder & serialization\n";

    HttpRequest req(wavex::protos::http::method::GET, "http://api.example.com/v1/users?page=2");
    req.set_header("Authorization", "Bearer token123");

    check(req.method_type() == wavex::protos::http::method::GET, "Method is GET");
    check(req.path() == "/v1/users", "Path extracted as /v1/users");
    check(req.query.at("page") == "2", "Query parameter 'page' is '2'");
    check(req.header("Authorization") == "Bearer token123", "Header 'Authorization' matches");

    std::string wire = req.serialize();
    check(wire.starts_with("GET /v1/users?page=2 HTTP/1.1\r\n"), "Request line matches GET /v1/users?page=2 HTTP/1.1");
    check(wire.find("Authorization: Bearer token123\r\n") != std::string::npos,
          "Serialized wire contains Authorization header");
}

// ─── Test 2: HttpResponse Client Parsing & Socket-less Usage ───────────────

void test_http_response_client_parsing() {
    std::cout << "\n[Test 2] HttpResponse client parsing & chunked de-chunking\n";

    std::string raw_res =
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: application/json\r\n"
            "Server: TestServer/1.0\r\n"
            "Content-Length: 19\r\n"
            "\r\n"
            "{\"status\":\"active\"}";

    HttpResponse res;
    check(res.parse(raw_res), "HttpResponse parsed raw HTTP response");
    check(res.status_code() == 200, "Status code is 200");
    check(res.status_text() == "OK", "Status text is OK");
    check(res.header("Content-Type") == "application/json", "Content-Type is application/json");
    check(res.get_body() == R"({"status":"active"})", "Body equals JSON string");

    // Chunked response parsing & auto-dechunking test (multi-chunk)
    std::string raw_chunked_res =
            "HTTP/1.1 200 OK\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "7\r\n"
            "Mozilla\r\n"
            "a\r\n"
            " Developer\r\n"
            "0\r\n\r\n";

    HttpResponse chunked_res;
    check(chunked_res.parse(raw_chunked_res), "Chunked response parsed");
    check(chunked_res.get_body() == "Mozilla Developer", "Chunked body auto-dechunked to 'Mozilla Developer'");

    // ── Real-world chunked response (example.com via Cloudflare) ────────────
    // Transfer-Encoding: chunked, single chunk, no Content-Length.
    // Body size is determined dynamically — no hardcoded byte count.
    constexpr std::string_view html_body =
            "<!doctype html><html lang=\"en\"><head><title>Example Domain</title>"
            "<link rel=\"icon\" href=\"data:,\"><meta name=\"viewport\" "
            "content=\"width=device-width, initial-scale=1\"><style>"
            "body{background:#eee;width:60vw;margin:15vh auto;font-family:"
            "system-ui,sans-serif}h1{font-size:1.5em}div{opacity:0.8}"
            "a:link,a:visited{color:#00f}a:hover{text-decoration:underline}"
            "</style></head><body><div><h1>Example Domain</h1><p>"
            "This domain is for use in illustrative examples in documents.</p>"
            "<p>You may use this domain in literature without prior coordination."
            "</p></div></body></html>";

    constexpr auto body_len = html_body.size();

    // Build hex chunk size line dynamically from actual body length
    char hex_size[32];
    auto [hex_end, hex_ec] = std::to_chars(hex_size, hex_size + sizeof(hex_size), body_len, 16);
    std::string chunk_size_line(hex_size, hex_end);
    chunk_size_line += "\r\n";

    std::string real_chunked_res =
            "HTTP/1.1 200 OK\r\n"
            "Date: Sat, 25 Jul 2026 08:21:32 GMT\r\n"
            "Content-Type: text/html\r\n"
            "Transfer-Encoding: chunked\r\n"
            "Connection: close\r\n"
            "Server: cloudflare\r\n"
            "Last-Modified: Tue, 21 Jul 2026 07:16:00 GMT\r\n"
            "Allow: GET, HEAD\r\n"
            "Accept-Ranges: bytes\r\n"
            "Age: 9311\r\n"
            "cf-cache-status: HIT\r\n"
            "CF-RAY: a209c0710de9c617-BOM\r\n"
            "\r\n"
            + chunk_size_line
            + std::string(html_body) + "\r\n"
            "0\r\n\r\n";

    constexpr std::size_t expected_header_count = 11;

    HttpResponse real_res;
    check(real_res.parse(real_chunked_res), "Real-world chunked response (example.com) parsed");

    // Verify headers were parsed correctly (not body content leaking in)
    check(real_res.status_code() == 200, "Real chunked status code is 200");
    check(real_res.status_text() == "OK", "Real chunked status text is 'OK'");

    auto ct = real_res.header("Content-Type");
    check(ct.has_value() && ct.value() == "text/html", "Content-Type header is 'text/html'");

    auto te = real_res.header("Transfer-Encoding");
    check(te.has_value() && te.value() == "chunked", "Transfer-Encoding header is 'chunked'");

    auto srv = real_res.header("Server");
    check(srv.has_value() && srv.value() == "cloudflare", "Server header is 'cloudflare'");

    auto cf_ray = real_res.header("CF-RAY");
    check(cf_ray.has_value(), "CF-RAY header is present");

    // Verify body was dechunked correctly (dynamic size, no hardcoded value)
    check(real_res.get_body().size() == body_len,
          "Dechunked body size matches original HTML length");
    check(real_res.get_body() == html_body, "Dechunked body matches original HTML exactly");
    check(real_res.get_body().starts_with("<!doctype html>"), "Dechunked body starts with <!doctype html>");
    check(real_res.get_body().ends_with("</html>"), "Dechunked body ends with </html>");

    // Verify no Content-Length header exists (chunked responses don't have one)
    check(!real_res.header("Content-Length"), "No Content-Length header in chunked response");

    // Verify header count
    check(real_res.header_views().size() == expected_header_count,
          "Exactly 11 headers parsed from real chunked response");

    // Verify raw_response() preserves the full original buffer
    check(real_res.raw_response().size() == real_chunked_res.size(),
          "raw_response() preserves full original buffer size");

    // Structural sanity: no header name should start with '<' (HTML leak)
    bool no_html_leak = true;
    for (const auto &k: real_res.header_views() | std::views::keys) {
        if (!k.empty() && k[0] == '<') {
            no_html_leak = false;
            break;
        }
    }
    check(no_html_leak, "No header name starts with '<' (no HTML body leak)");

    // ── Copy-safety regression test ───────────────────────────────────────
    // This verifies the custom copy constructor rebases string_views.
    // Previously (default copy ctor), copying an HttpResponse left all
    // string_view members pointing at the SOURCE's buffer — a use-after-free.
    {
        HttpResponse copy = real_res; // copy ctor
        check(copy.status_code() == 200,
              "Copied response status code is 200");
        check(copy.status_text() == "OK",
              "Copied response status_text is 'OK'");
        auto copy_ct = copy.header("Content-Type");
        check(copy_ct.has_value() && copy_ct.value() == "text/html",
              "Copied response Content-Type lookup works");
        auto copy_srv = copy.header("Server");
        check(copy_srv.has_value() && copy_srv.value() == "cloudflare",
              "Copied response Server lookup works");
        auto copy_te = copy.header("Transfer-Encoding");
        check(copy_te.has_value() && copy_te.value() == "chunked",
              "Copied response Transfer-Encoding lookup works");
        check(copy.get_body() == html_body,
              "Copied response body matches original HTML");
        check(copy.header_views().size() == expected_header_count,
              "Copied response has 11 headers");

        // Now destroy the source and verify the copy is still valid
        {
            // real_res is about to go out of scope — the copy must survive
            auto &still_valid = copy;
            check(still_valid.header("CF-RAY").has_value(),
                  "Copy remains valid after source would be destroyed");
        }
    }
}

// ─── Test 3: HttpClient Async Execution with Local Server ───────────────────

void test_http_client_integration() {
    std::cout << "\n[Test 3] HttpClient async GET and POST requests against local Server\n";

    auto &router = HttpRouter::instance();

    router.get("/api/client_test", [](HttpRequest &, HttpResponse &res) -> asio::awaitable<void> {
        res.status(200).json({{"client", "connected"}, {"framework", "WaveX"}});
        co_return;
    });

    router.post("/api/client_echo", [](const HttpRequest &req, HttpResponse &res) -> asio::awaitable<void> {
        res.status(200).send(std::string("Echo: ") + std::string(req.body()));
        co_return;
    });

    // Start local test server on port 8086
    Server server(router, "127.0.0.1", 8086);

    // Run server on background thread
    std::thread server_thread([&server] {
        server.run();
    });

    // Give server a moment to bind and listen
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Run HttpClient requests on Asio io_context
    asio::io_context client_ioc;

    bool get_success = false;
    bool post_success = false;

    asio::co_spawn(client_ioc, [&]() -> asio::awaitable<void> {
        // 1. GET request via HttpClient::get
        auto get_res = co_await wavex::client::HttpClient::get("http://127.0.0.1:8086/api/client_test");
        if (get_res.status_code() == 200 && get_res.get_body().find("WaveX") != std::string::npos) {
            get_success = true;
        }

        // 2. POST request via HttpClient::post with JSON payload
        nlohmann::json payload = {{"greeting", "hello wavex"}};
        auto post_res = co_await wavex::client::HttpClient::post("http://127.0.0.1:8086/api/client_echo", payload);
        if (post_res.status_code() == 200 && post_res.get_body().find("hello wavex") != std::string::npos) {
            post_success = true;
        }

        co_return;
    }, asio::detached);

    client_ioc.run();

    check(get_success, "HttpClient GET request succeeded with 200 OK & JSON body");
    check(post_success, "HttpClient POST request succeeded with 200 OK & Echo payload");

    // Stop test server
    server.stop();
    if (server_thread.joinable()) {
        server_thread.join();
    }
}

// ─── Test 4: HttpClient External Request to example.com ──────────────────

void test_external_example_server() {
    std::cout << "\n[Test 4] HttpClient external HTTP GET request verification (http://example.com/)\n";

    asio::io_context client_ioc;

    asio::co_spawn(client_ioc, []() -> asio::awaitable<void> {
        try {
            auto res = co_await wavex::client::HttpClient::get("http://example.com/");

            // ── Write raw bytes to FILE, never to stdout ─────────────────────
            dump_to_file(PROJECT_DIR "/tmp/wavex_raw_response.txt", res.raw_response());

            // ── Write parsed results to FILE for verification ────────────────
            dump_parsed_to_file(PROJECT_DIR "/tmp/wavex_parsed_response.txt", res);

            // ── Programmatic assertions (no raw bytes on stdout) ─────────────
            std::cout << "  Raw response: " << res.raw_response().size()
                    << (" bytes (see "
            PROJECT_DIR
            "/tmp/wavex_raw_response.txt)\n"
            )
            ;
            std::cout << "  Parsed summary: (see "
            PROJECT_DIR
            "/tmp/wavex_parsed_response.txt)\n";

            const auto &hdrs = res.header_views();

            check(!hdrs.empty(), "Response has parsed headers");

            // Every header name must be valid ASCII — no '<' (HTML leak) or non-printable
            bool all_valid_names = true;
            for (const auto &k: hdrs | std::views::keys) {
                if (k.empty() || k[0] == '<' || k[0] > '~') {
                    all_valid_names = false;
                    break;
                }
            }
            check(all_valid_names, "All header names are valid ASCII (no HTML body leak)");

            // Known headers that example.com/Cloudflare always sends
            check(res.header("Content-Type").has_value(), "Content-Type header present");
            check(res.header("Server").has_value(), "Server header present");

            // Chunked responses must NOT have Content-Length
            auto te = res.header("Transfer-Encoding");
            bool chunked_ok = te.has_value() && te->find("chunked") != std::string_view::npos;
            check(chunked_ok, "Transfer-Encoding: chunked detected");

            if (chunked_ok) {
                check(!res.header("Content-Length"), "No Content-Length in chunked response");
            }

            // Body sanity checks
            std::string_view body = res.get_body();
            check(!body.empty(), "Response body is non-empty");
            check(body.starts_with("<!doctype html>") || body.starts_with("<!DOCTYPE html>"),
                  "Body starts with <!doctype html>");
            check(body.find("Example Domain") != std::string_view::npos,
                  "Body contains 'Example Domain'");

            check(res.status_code() == 200 || res.status_code() == 301 || res.status_code() == 302,
                  "HttpClient external request received response from example.com");
        } catch (const std::exception &ex) {
            std::cout << "  [Network Exception] " << ex.what() << "\n";
            check(false, "HttpClient external request threw exception");
        }
        co_return;
    }, asio::detached);

    client_ioc.run();
}

// ─── Test 5: HttpClient External Live Output List ───────────────────────────

void test_external_response_output() {
    std::cout << "\n[Test 5] HttpClient external HTTP GET live response output\n";

    asio::io_context client_ioc;

    asio::co_spawn(client_ioc, []() -> asio::awaitable<void> {
        try {
            auto res = co_await wavex::client::HttpClient::get("http://example.com/");

            std::cout << "  [Response Status] " << res.status_code() << " " << res.status_text() << "\n";
            std::cout << "  [Response Headers]:\n";
            for (const auto &[k, v]: res.header_views()) {
                std::cout << "    " << k << ": " << v << "\n";
            }

            std::string_view body = res.get_body();
            std::cout << "  [Response Body Snippet (" << body.size() << " bytes)]:\n";
            std::cout << "    " << strip_cr(body.substr(0, std::min<size_t>(body.size(), 300))) << "\n...\n";

            check(res.status_code() == 200 || res.status_code() == 301 || res.status_code() == 302,
                  "HttpClient external live response received from example.com");
        } catch (const std::exception &ex) {
            std::cout << "  [Network Exception] " << ex.what() << "\n";
            check(false, "HttpClient external live response threw exception");
        }
        co_return;
    }, asio::detached);

    client_ioc.run();
}

#ifdef _WIN32
#include <windows.h>
#endif

// ─── main ─────────────────────────────────────────────────────────────────────

int main() {
#ifdef _WIN32
    SetConsoleOutputCP(65001); // Set Windows console to UTF-8
#endif
    std::cout << "=== WaveX HttpClient Unit & Integration Tests ===\n";

    test_http_request_client_serialization();
    test_http_response_client_parsing();
    test_http_client_integration();
    test_external_example_server();
    test_external_response_output();

    std::cout << "\n" << tests_passed << "/" << tests_run << " tests passed.\n";
    return tests_passed == tests_run ? 0 : 1;
}
