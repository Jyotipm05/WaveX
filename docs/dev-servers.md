# Dev Servers, Postman & cURL

WaveX ships four CLI-driven servers for manual testing with Postman, cURL or a browser. They are built when `WAVEX_TEST=ON` (preset `test-profile`).

> [!NOTE]
> TLS examples need a development certificate at `ssl/test.crt` / `ssl/test.key`; see [TLS](guides/tls.md#generating-a-development-certificate). On Linux and macOS drop the `.exe` suffix.

## Dev Server Executables

| Executable                   | Protocol Modes                           | Default Ports                             | Source                                                                        |
|:-----------------------------|:-----------------------------------------|:------------------------------------------|:------------------------------------------------------------------------------|
| `wavex_postman_http1_server` | Plain HTTP / HTTPS (TLS 1.3)             | `8080` (plain), `8443` (`--tls`)          | [tests/postman_demo_http1_server.cpp](../tests/postman_demo_http1_server.cpp) |
| `wavex_postman_http2_server` | Cleartext h2c / HTTP/2 over TLS 1.3 (h2) | `8082` (cleartext), `8444` (`--tls`)      | [tests/postman_demo_http2_server.cpp](../tests/postman_demo_http2_server.cpp) |
| `wavex_postman_http3_server` | HTTP/3 over TLS 1.3 (h3) / Cleartext Dev | `8445` (TLS default), `8083` (`--no-tls`) | [tests/postman_demo_http3_server.cpp](../tests/postman_demo_http3_server.cpp) |
| `wavex_postman_quic_server`  | RFC 9000 & 9001 QUIC Transport Dev Mode  | `8443` (UDP TLS 1.3)                      | [tests/postman_demo_quic_server.cpp](../tests/postman_demo_quic_server.cpp)   |

## Command-Line Options (Built-in CLI)

The servers support the following command-line flags:

| Flag            | Short | Default                                   | Description                                                                     |
|:----------------|:------|:------------------------------------------|:--------------------------------------------------------------------------------|
| `--tls`         | `-s`  | disabled (HTTP/1,2) / active (HTTP/3)     | Enable TLS 1.3 encryption (ALPN `http/1.1`, `h2`, or `h3`)                      |
| `--no-tls`      |       | disabled                                  | Disable TLS encryption (available on HTTP/3 dev server for local debugging)     |
| `--lan`         | `-l`  | disabled                                  | Host on local area network (LAN) using current machine IP (e.g., `192.168.x.x`) |
| `--port <num>`  | `-p`  | 8080/8082/8083 (plain), 8443..8445 (TLS)  | Port to listen on                                                               |
| `--host <ip>`   | `-H`  | `127.0.0.1`                               | Host address to bind                                                            |
| `--cert <path>` | `-c`  | `ssl/test.crt`                            | Path to TLS certificate file                                                    |
| `--key <path>`  | `-k`  | `ssl/test.key`                            | Path to TLS private key file                                                    |
| `--help`        | `-h`  | —                                         | Show CLI help and options                                                       |

## Launching the Servers

```bash
# 1. HTTP/1.1 Server
./build/test-profile/wavex_postman_http1_server.exe                     # Plain HTTP on http://127.0.0.1:8080
./build/test-profile/wavex_postman_http1_server.exe --lan               # Host on LAN using current machine IP
./build/test-profile/wavex_postman_http1_server.exe --tls               # HTTPS/TLS 1.3 on https://127.0.0.1:8443
./build/test-profile/wavex_postman_http1_server.exe -p 9000             # Custom port

# 2. HTTP/2 Server
./build/test-profile/wavex_postman_http2_server.exe                     # Cleartext HTTP/2 (h2c) on http://127.0.0.1:8082
./build/test-profile/wavex_postman_http2_server.exe --lan               # Cleartext HTTP/2 on LAN using current machine IP
./build/test-profile/wavex_postman_http2_server.exe --tls               # HTTP/2 over TLS 1.3 (h2) on https://127.0.0.1:8444
./build/test-profile/wavex_postman_http2_server.exe --tls -p 9444       # Custom port with TLS

# 3. HTTP/3 Server (TLS 1.3 Active by Default)
./build/test-profile/wavex_postman_http3_server.exe                     # HTTP/3 over TLS 1.3 on https://127.0.0.1:8445
./build/test-profile/wavex_postman_http3_server.exe --lan               # Host on LAN using current machine IP
./build/test-profile/wavex_postman_http3_server.exe -p 9445             # Custom port with TLS
./build/test-profile/wavex_postman_http3_server.exe --no-tls            # Cleartext HTTP/3 dev mode on http://127.0.0.1:8083

# 4. QUIC Transport Dev Server (RFC 9000 / RFC 9001)
./build/test-profile/wavex_postman_quic_server.exe                      # QUIC server on udp://127.0.0.1:8443
./build/test-profile/wavex_postman_quic_server.exe --lan                # Host on LAN using current machine IP
./build/test-profile/wavex_postman_quic_server.exe -p 9443              # Custom UDP port
```

## cURL Verification Commands

```bash
# HTTP/1.1 Plain & TLS
curl http://127.0.0.1:8080/api/json
curl -k https://127.0.0.1:8443/api/json

# HTTP/2 Cleartext (h2c prior knowledge) & TLS 1.3 (ALPN h2 negotiation)
curl --http2-prior-knowledge http://127.0.0.1:8082/api/json
curl -k --http2 https://127.0.0.1:8444/api/json

# HTTP/2 Protected Endpoint (Middleware Auth Check)
curl -k --http2 -H "Authorization: Bearer secret123" https://127.0.0.1:8444/api/protected

# HTTP/3 over TLS 1.3 (RFC 9114)
curl --http3 -k https://127.0.0.1:8445/api/json
curl --http3 -k -X POST https://127.0.0.1:8445/api/query -H "Content-Type: application/json" -d '{"domain": "google.com"}'
curl --http3 -k -H "Authorization: Bearer secret123" https://127.0.0.1:8445/api/protected
```

## Querying the DNS example endpoint

`POST` and the RFC 9110 `QUERY` method share one handler:

```bash
# HTTP/1.1 POST or QUERY
curl -X POST http://127.0.0.1:8080/api/query \
     -H "Content-Type: application/json" \
     -d '{"domain": "google.com"}'

curl -X QUERY http://127.0.0.1:8080/api/query \
     -H "Content-Type: application/json" \
     -d '{"domain": "google.com"}'

# HTTP/2 (Cleartext h2c or TLS 1.3 h2)
curl --http2-prior-knowledge -X POST http://127.0.0.1:8082/api/query \
     -H "Content-Type: application/json" \
     -d '{"domain": "google.com"}'

curl -k --http2 -X POST https://127.0.0.1:8444/api/query \
     -H "Content-Type: application/json" \
     -d '{"domain": "google.com"}'
```
