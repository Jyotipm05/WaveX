# File Uploads & Compression

RFC 7578 multipart parsing with automatic disk spooling, request/response compression, and the client-side equivalents.

## Receiving multipart uploads (server)

Parse uploaded files and form fields with transparent in-memory and disk spooling thresholds:

```c++
#include <wavex/wavex.hpp>

int main() {
    auto &router = wavex::engine::HttpRouter::instance();

    router.post("/upload", [](auto &req, auto &res) -> wavex::task<void> {
        if (!req.is_multipart()) {
            res.status(400).send("Expected multipart/form-data");
            co_return;
        }

        // Configure thresholds (files > 5MB are automatically spooled to disk!)
        wavex::utils::MultipartLimits limits;
        limits.max_memory_buffer = 5 * 1024 * 1024; // 5MB RAM ceiling

        auto form = req.multipart(limits);

        // Read text fields
        std::string_view user_id = form.field("user_id").value_or("anonymous");

        // Retrieve uploaded file
        if (auto avatar = req.file("avatar"); avatar.has_value()) {
            wavex::log::info("Uploaded file: {} ({} bytes, on disk: {})",
                             avatar->filename, avatar->size(), avatar->is_on_disk());

            // Save file directly or atomically move spooled temp file to destination
            bool saved = avatar->save_to("./uploads/" + avatar->filename);
            if (!saved) {
                res.status(500).send("Failed to save file");
                co_return;
            }
        }

        res.status(200).json({{"status", "uploaded"}, {"user", std::string(user_id)}});
        co_return;
    });

    wavex::server::Server server(router, "127.0.0.1", 8080);
    // Enforce overall request payload limit (50MB) and RAM buffer ceiling (10MB)
    server.set_max_request_size(50 * 1024 * 1024);
    server.set_max_memory_buffer(10 * 1024 * 1024);
    server.run();
}
```

## Uploading and compressing (client)

Compose multipart files, compress client payloads, and save binary responses to disk:

```c++
#include <wavex/Client/HttpClient.hpp>
#include <wavex/Utils/Utils.hpp>

wavex::task<void> upload_file() {
    wavex::client::HttpClient client;

    // 1. Build multipart request with files and fields
    wavex::client::ClientRequest req(wavex::protos::http::method::POST, "http://127.0.0.1:8080/upload");
    req.add_field("user_id", "42")
       .add_file("document", "report.pdf", "%PDF-1.4...", "application/pdf")
       .add_file_from_path("avatar", "./assets/photo.png");

    auto res = co_await client.send(req);
    wavex::log::info("Upload response: {}", res.status_code());

    // 2. Raw binary compressed upload
    wavex::client::ClientRequest binary_req(wavex::protos::http::method::PUT, "http://127.0.0.1:8080/raw");
    binary_req.set_body("Large data payload...")
              .compress(wavex::utils::CompressionFormat::Gzip);

    auto binary_res = co_await client.send(binary_req);

    // 3. Save response directly to disk
    binary_res.save_to_file("./downloaded_file.bin");
    co_return;
}
```

---

**See also:** [HTTP client](http-client.md) · [Memory & lifetimes](memory-and-lifetimes.md)
