# TLS 1.3

WaveX enforces TLS 1.3 (`force_tls13`) and negotiates ALPN (`http/1.1`, `h2`, `h3`). Build with `WAVEX_ENABLE_TLS=ON` (default) and OpenSSL available.

## Enabling TLS

Enable strict TLS 1.3 HTTPS server encryption using `server.enable_tls()` with custom certificate/key paths or a `wavex::server::TlsConfig` struct:

```cpp
#include <wavex/wavex.hpp>
#include <wavex/Server/TlsConfig.hpp>

int main() {
    auto &router = wavex::engine::HttpRouter::instance();

    router.get("/secure", [](auto &, auto &res) -> asio::awaitable<void> {
        res.status(200).json({{"encrypted", true}, {"protocol", "TLS 1.3"}});
        co_return;
    });

    wavex::server::Http1Server server(router, "0.0.0.0", 8443);

    // Option A: Enable TLS 1.3 directly with certificate & key paths
    server.enable_tls("ssl/test.crt", "ssl/test.key");

    // Option B: Advanced configuration via TlsConfig struct
    /*
    wavex::server::TlsConfig cfg;
    cfg.cert_file = "ssl/cert.pem";
    cfg.key_file = "ssl/key.pem";
    cfg.key_password = "secret_passphrase";
    cfg.dh_file = "ssl/dh2048.pem";
    cfg.force_tls13 = true; // Exclusively enforce TLS 1.3
    server.enable_tls(cfg);
    */

    server.run();
    return 0;
}
```

## Generating a development certificate

Certificates are git-ignored (`ssl/*.pem`, `ssl/test.crt`, `ssl/test.key`), so create a self-signed pair once. The examples and dev servers expect them at `ssl/test.crt` and `ssl/test.key`:

```bash
mkdir -p ssl
openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 365 \
  -subj "/CN=localhost" \
  -keyout ssl/test.key -out ssl/test.crt
```

Use `curl -k` (skip verification) when testing against a self-signed certificate.

---

**See also:** [HTTP/2 & HTTP/3](http2-and-http3.md) · [Third-party notices](../../THIRD_PARTY_NOTICES.md)
