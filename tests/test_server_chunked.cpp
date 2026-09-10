/**
 * @file test_server_chunked.cpp
 * @brief Integration tests for server-side chunked response streaming and file transfers in WaveX.
 */

#include <iostream>
#include <string>
#include <fstream>
#include <filesystem>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/io_context.hpp>

#include <wavex/wavex.hpp>

static void check(bool condition, const std::string &msg) {
    if (condition) {
        std::cout << "  [PASS] " << msg << "\n";
    } else {
        std::cerr << "  [FAIL] " << msg << "\n";
        std::exit(1);
    }
}

// ─── Test 1: MIME Type Lookup ───────────────────────────────────────────────
void test_mime_types() {
    std::cout << "\n[Test 1] Base/MimeTypes.hpp extension resolution\n";
    check(wavex::base::mime_type_from_ext("html") == "text/html; charset=utf-8", "html -> text/html");
    check(wavex::base::mime_type_from_ext(".json") == "application/json", ".json -> application/json");
    check(wavex::base::mime_type_from_path("public/styles/main.css") == "text/css; charset=utf-8",
          "path.css -> text/css");
    check(wavex::base::mime_type_from_path("images/logo.PNG") == "image/png", "case-insensitive PNG -> image/png");
    check(wavex::base::mime_type_from_path("unknown_file") == "application/octet-stream", "unknown -> octet-stream");
}

// ─── Test 2: Chunk Encoder Formatting ───────────────────────────────────────
void test_chunk_encoder() {
    std::cout << "\n[Test 2] http1codec encoder::format_chunk\n";
    std::string formatted = wavex::protos::http::http1codec::encoder::format_chunk("hello");
    check(formatted == "5\r\nhello\r\n", R"(format_chunk("hello") == "5\r\nhello\r\n")");

    std::string_view term = wavex::protos::http::http1codec::encoder::format_terminal_chunk();
    check(term == "0\r\n\r\n", R"(format_terminal_chunk() == "0\r\n\r\n")");
}

// ─── Test 3: Server Chunked Streaming & File Transfer Integration ─────────
void test_server_streaming_and_files() {
    std::cout << "\n[Test 3] Server chunked response streaming & send_file integration\n";

    // Setup temporary test directory inside tests/
    std::filesystem::path temp_dir = "tests/temp_test_files";
    std::filesystem::create_directories(temp_dir);

    std::filesystem::path html_file = temp_dir / "test_page.html";
    std::filesystem::path bin_file = temp_dir / "data.bin";

    std::string html_content = "<html><body><h1>WaveX Stream Test</h1></body></html>";
    std::string bin_content = "BINARY_WAVEX_DATA_1234567890_XYZ"; {
        std::ofstream f(html_file, std::ios::binary);
        f << html_content;
    } {
        std::ofstream f(bin_file, std::ios::binary);
        f << bin_content;
    }

    wavex::engine::Http1Router router;

    // 1. Chunked Stream Route
    router.get("/stream", [](wavex::protos::http::Http1Request &,
                             wavex::protos::http::Http1Response &res) -> asio::awaitable<void> {
        (void) co_await res.start_chunked();
        (void) co_await res.write_chunk("Part 1: Hello ");
        (void) co_await res.write_chunk("Part 2: WaveX!");
        (void) co_await res.end_chunked();
    });

    // 2. Auto MIME File Route
    router.get("/download_html", [html_file](wavex::protos::http::Http1Request &,
                                             wavex::protos::http::Http1Response &res) -> asio::awaitable<void> {
        (void) co_await res.send_file(html_file.string());
    });

    // 3. Custom MIME File Route
    router.get("/download_custom", [bin_file](wavex::protos::http::Http1Request &,
                                              wavex::protos::http::Http1Response &res) -> asio::awaitable<void> {
        (void) co_await res.send_file(bin_file.string(), "application/x-wavex-custom");
    });

    asio::io_context io;

    // Launch server on port 8099
    wavex::server::Http1Server server(router, "127.0.0.1", 8099);

    asio::co_spawn(io, [&]() -> asio::awaitable<void> {
        // A. Test /stream
        auto stream_res = co_await wavex::client::HttpClient::get("http://127.0.0.1:8099/stream");
        check(stream_res.status_code() == 200, "GET /stream returns 200 OK");
        check(stream_res.get_body() == "Part 1: Hello Part 2: WaveX!", "Streamed body dechunked correctly");

        // B. Test /download_html
        auto html_res = co_await wavex::client::HttpClient::get("http://127.0.0.1:8099/download_html");
        check(html_res.status_code() == 200, "GET /download_html returns 200 OK");
        auto html_ct = html_res.header("Content-Type");
        check(html_ct.has_value() && html_ct->find("text/html") != std::string_view::npos,
              "Auto MIME detected as text/html");
        check(html_res.get_body() == html_content, "HTML file content matches byte-for-byte");

        // C. Test /download_custom
        auto custom_res = co_await wavex::client::HttpClient::get("http://127.0.0.1:8099/download_custom");
        check(custom_res.status_code() == 200, "GET /download_custom returns 200 OK");
        auto custom_ct = custom_res.header("Content-Type");
        check(custom_ct.has_value() && *custom_ct == "application/x-wavex-custom",
              "Custom MIME override set to application/x-wavex-custom");
        check(custom_res.get_body() == bin_content, "Binary file content matches byte-for-byte");

        server.stop();
        io.stop();
    }, asio::detached);

    // Run server acceptor in background thread
    std::thread server_thread([&] {
        server.run();
    });

    io.run();

    if (server_thread.joinable()) {
        server_thread.join();
    }

    // Clean-up temp test files
    std::filesystem::remove_all(temp_dir);
}

int main() {
    std::cout << "=====================================================\n";
    std::cout << " WaveX Chunked Streaming & File Transfer Unit Tests \n";
    std::cout << "=====================================================\n";

    test_mime_types();
    test_chunk_encoder();
    test_server_streaming_and_files();

    std::cout << "\nAll chunked streaming and file transfer tests passed successfully!\n";
    return 0;
}
