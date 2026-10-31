# HTTP Client

A coroutine-native client for HTTP/1.1 and HTTP/2 with ALPN negotiation, cleartext h2c, IPv4/IPv6 endpoints, query builders and JSON/text/binary bodies.

WaveX provides a protocol-agnostic, coroutine-native HTTP client (`HttpClient`) supporting ALPN auto-negotiation, cleartext `h2c`, TLS 1.3 `h2`, domainless IPv4/IPv6 endpoints, query parameter builders, and multi-payload posting:

```cpp
#include <iostream>
#include <asio.hpp>
#include <wavex/wavex.hpp>

using namespace wavex::client;

wavex::task<void> run_client_examples() {
    // 1. GET with automatic protocol negotiation (ALPN h2 / http/1.1)
    ClientResponse res = co_await HttpClient::get("https://api.github.com/zen");
    std::cout << "Status: " << res.status_code() << "\n";
    std::cout << "Protocol: " << (res.http_version() == HttpVersion::Http2 ? "HTTP/2" : "HTTP/1.1") << "\n";
    std::cout << "Body: " << res.body() << "\n";

    // 2. Structured query parameters & non-JSON plain text POST
    auto search_res = co_await HttpClient::get("http://127.0.0.1:8080/search", {{"q", "wavex"}, {"page", "1"}});

    auto text_res = co_await HttpClient::post("http://127.0.0.1:8080/log", "Worker pool scaled to 8 threads", "text/plain");

    // 3. JSON POST with automatic serialization
    nlohmann::json payload = {{"service", "auth"}, {"status", "healthy"}};
    auto json_res = co_await HttpClient::post("http://127.0.0.1:8080/api/status", payload);

    // 4. Domainless IPv6 Endpoint
    auto ipv6_res = co_await HttpClient::get("http://[::1]:8080/v1/health");

    // 5. High-Performance Direct HTTP/2 (Prior Knowledge h2c)
    ClientOptions h2c_opts{ .version = HttpVersion::Http2 };
    auto rpc_res = co_await HttpClient::get("http://127.0.0.1:8082/rpc/status", h2c_opts);

    // 6. Templated Concrete Response (Backward Compatible)
    wavex::protos::http::Http1Response h1_res = 
        co_await HttpClient::get<wavex::protos::http::Http1Response>("http://127.0.0.1:8080/api");
}
```

File uploads and request compression from the client side are covered in [File uploads & compression](file-uploads-and-compression.md).

---

**See also:** [File uploads & compression](file-uploads-and-compression.md)
