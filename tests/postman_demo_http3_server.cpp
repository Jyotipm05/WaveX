/**
 * @file postman_demo_http3_server.cpp
 * @brief Interactive WaveX HTTP/3 Server (RFC 9114 / RFC 9204 / RFC 9000) for Postman & Manual Testing.
 *
 * Configured via built-in WaveX CLI argument parser (wavex::cli::CliParser).
 * TLS 1.3 encryption is active by default in accordance with HTTP/3 & QUIC specifications.
 *
 * Usage examples:
 *   ./wavex_postman_http3_server                      # HTTP/3 over TLS 1.3 on https://127.0.0.1:8445
 *   ./wavex_postman_http3_server --lan                # HTTP/3 over TLS 1.3 on LAN (0.0.0.0:8445)
 *   ./wavex_postman_http3_server -p 9083              # Custom port with TLS active
 *   ./wavex_postman_http3_server --no-tls             # Cleartext HTTP/3 on http://127.0.0.1:8083 (Dev/Debug)
 *   ./wavex_postman_http3_server -c ssl/test.crt -k ssl/test.key
 *   ./wavex_postman_http3_server --help               # Show CLI usage and option details
 *
 * cURL testing:
 *   curl --http3 -k https://127.0.0.1:8445/api/json
 *   curl --http3 -k -X POST https://127.0.0.1:8445/api/query -H "Content-Type: application/json" -d '{"domain": "google.com"}'
 *   curl --http3 -k https://127.0.0.1:8445/api/protected -H "Authorization: Bearer secret123"
 */

#ifndef ASIO_HAS_CO_AWAIT
#define ASIO_HAS_CO_AWAIT 1
#endif

#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <nlohmann/json.hpp>
#include <wavex/wavex.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/ip/udp.hpp>
#include <asio/ip/host_name.hpp>

using namespace wavex;

// Helper to detect LAN IP address of current machine
inline std::string get_lan_ip() {
    // 1. Try querying outbound interface via UDP routing table lookup (no actual packet sent)
    try {
        asio::io_context ctx;
        asio::ip::udp::socket sock(ctx);
        sock.connect(asio::ip::udp::endpoint(asio::ip::make_address("8.8.8.8"), 53));
        const auto addr = sock.local_endpoint().address();
        if (addr.is_v4() && !addr.is_loopback()) {
            return addr.to_string();
        }
    } catch (...) {
    }

    // 2. Fallback: resolve local hostname to discover network interface IPv4 addresses
    try {
        asio::io_context ctx;
        asio::ip::tcp::resolver resolver(ctx);
        asio::error_code ec;
        const auto host = asio::ip::host_name(ec);
        if (!ec && !host.empty()) {
            const auto results = resolver.resolve(host, "", ec);
            if (!ec) {
                for (const auto &entry : results) {
                    const auto addr = entry.endpoint().address();
                    if (addr.is_v4() && !addr.is_loopback()) {
                        return addr.to_string();
                    }
                }
            }
        }
    } catch (...) {
    }

    return "";
}

// Global Logger Middleware for HTTP/2 and HTTP/3
template<typename Req, typename Res>
asio::awaitable<void> logger_middleware(const Req &req, const Res &res, base::Next next) {
    std::cout << "[" << (req.version_major() == 3 ? "HTTP3" : "HTTP2")
              << "-LOG] Incoming request (stream " << req.stream_id() << "): " << req.path() << "\n";
    co_await next();
    std::cout << "[" << (req.version_major() == 3 ? "HTTP3" : "HTTP2")
              << "-LOG] Response status: " << res.status_code() << " (stream " << res.stream_id()
              << ") for " << req.path() << "\n";
}

// Auth Middleware (Postman header required: Authorization: Bearer secret123)
template<typename Req, typename Res>
asio::awaitable<void> auth_middleware(const Req &req, Res &res, base::Next next) {
    const auto auth_header = req.header("Authorization");
    if (!auth_header || *auth_header != "Bearer secret123") {
        std::cout << "[AUTH] Unauthorized attempt on " << req.path() << "\n";
        res.status(401).json({
            {"error", "Unauthorized"},
            {"protocol", req.version_major() == 3 ? "HTTP/3" : "HTTP/2"},
            {"stream_id", req.stream_id()},
            {"message", "Missing or invalid 'Authorization: Bearer secret123' header"}
        });
        co_return; // Immediate response sent, short-circuits remaining pipeline!
    }

    std::cout << "[AUTH] Access granted for " << req.path() << "\n";
    co_await next();
}

int main(int argc, char *argv[]) {
    cli::CliParser parser("wavex_postman_http3_server",
                          "WaveX HTTP/3 Interactive Dev & Postman Testing Server (RFC 9114 / RFC 9204 / RFC 9000)");

    parser.add_flag("tls", 's', "Enable TLS 1.3 encryption (active by default for HTTP/3)")
          .add_flag("no-tls", "Disable TLS (run HTTP/3 over cleartext for local debugging)")
          .add_flag("lan", 'l', "Host server on local area network (LAN) using current machine IP")
          .add_option("port", 'p', "Port number to listen on (default: 8445 with TLS, 8083 with --no-tls)")
          .add_option("host", 'H', "Host IP address to bind to", "127.0.0.1")
          // .add_option("cert", 'c', "Path to TLS certificate file", "ssl/test.crt")
          .add_option("cert", 'c', "Path to TLS certificate file", "ssl/127.0.0.1.pem")
          // .add_option("key", 'k', "Path to TLS private key file", "ssl/test.key");
          .add_option("key", 'k', "Path to TLS private key file", "ssl/127.0.0.1-key.pem");

    const auto parse_res = parser.parse(argc, argv);
    if (!parse_res.ok()) {
        if (parse_res.help_requested) {
            parser.print_help();
            return 0;
        }
        std::cerr << "Error: " << parse_res.error_message << "\n\n";
        parser.print_help();
        return 1;
    }

    // TLS is active by default for HTTP/3
    const bool is_no_tls = parser.get_bool("no-tls");
    const bool is_tls = !is_no_tls;
    const bool is_lan = parser.get_bool("lan");
    std::string host = parser.get_string("host");
    if (is_lan && !parser.has("host")) {
        const std::string detected_ip = get_lan_ip();
        if (!detected_ip.empty()) {
            host = detected_ip;
        } else {
            std::cerr << "[Warning] Could not automatically detect LAN IP. Falling back to 127.0.0.1.\n";
            host = "127.0.0.1";
        }
    }
    const std::string cert_file = parser.get_string("cert");
    const std::string key_file = parser.get_string("key");

    // Dynamic default port based on TLS mode (8445 for TLS default, 8083 for cleartext)
    const int default_port = is_tls ? 8445 : 8083;
    const int port = parser.has("port") ? parser.get_int("port", default_port) : default_port;

    const std::string scheme = is_tls ? "https" : "http";
    const std::string base_url = scheme + "://" + host + ":" + std::to_string(port);

    std::cout << "=========================================================================\n";
    std::cout << "           WaveX Interactive Dev v" << wx_version
              << " / Postman Server (HTTP/3)             \n";
    std::cout << "=========================================================================\n";
    std::cout << " Protocol : HTTP/3 (RFC 9114 / QPACK RFC 9204 / QUIC RFC 9000) "
              << (is_tls ? "[h3: TLS 1.3 Active by Default]" : "[Cleartext Dev Mode]") << "\n";
    std::cout << " Bound To : " << host << ":" << port << (is_lan ? " [LAN Active - Current Machine IP]" : " [Loopback]") << "\n";
    std::cout << " URL      : " << base_url << "\n";
    if (is_lan) {
        std::cout << " Note     : Hosted on LAN IP. Open " << base_url << " from any device on your network.\n";
    }
    if (is_tls) {
        std::cout << " Cert File: " << cert_file << "\n";
        std::cout << " Key File : " << key_file << "\n";
    }
    std::cout << "=========================================================================\n";
    std::cout << " Quick Test Endpoints Reference for Postman / cURL:\n";
    std::cout << "  1. GET        " << base_url << "/\n";
    std::cout << "  2. GET        " << base_url << "/api/json\n";
    std::cout << "  3. POST       " << base_url << "/api/echo   (Body: JSON payload)\n";
    std::cout << "  4. POST/QUERY " << base_url << "/api/query  (Body: {\"domain\": \"google.com\"})\n";
    std::cout << "  5. GET        " << base_url << "/api/protected  (Header: Authorization: Bearer secret123)\n";
    std::cout << "  6. GET        " << base_url << "/users/42\n";
    std::cout << "  7. GET        " << base_url << "/files/documents/2026/report.pdf  (Wildcard match)\n";
    const auto port_str = std::to_string(port);
    const std::string alt_svc_value = "h3=\":" + port_str + "\"; ma=2592000,h3-29=\":" + port_str + "\"; ma=2592000";

    std::cout << "=========================================================================\n";
    std::cout << " HTTP/3 (QUIC / UDP) vs HTTP/1.1 (TCP) Testing Guide:\n";
    std::cout << "  1. Chrome Browser (DevTools Protocol Inspection):\n";
    std::cout << "     * Standard Request:\n";
    std::cout << "       First navigation to " << base_url << "/api/json uses TCP (shows 'http/1.1').\n";
    std::cout << "       The server sends 'Alt-Svc: " << alt_svc_value << "'. Chrome records this\n";
    std::cout << "       and probes UDP QUIC in the background with seamless fallback to TCP.\n";
    std::cout << "     * Force Native QUIC HTTP/3 (starts immediately with h3 on first request):\n";
    std::cout << "       Note: QUIC in Chrome strictly enforces TLS certificates. For local self-signed certs,\n";
    std::cout << "       Chrome requires the certificate SPKI fingerprint:\n";
    std::cout << "       chrome.exe --enable-quic --origin-to-force-quic-on=" << host << ":" << port
              << " --ignore-certificate-errors-spki-list=6wKWB7o640nE/nBIU/Hih7T1ZHQOWVb1hoPEcfmXM7U= "
              << base_url << "/api/json\n";
    std::cout << "     * Reset: If Chrome previously cached a failed QUIC session, clear it at:\n";
    std::cout << "       chrome://net-internals/#quic (click 'Clear QUIC sessions' or restart Chrome).\n\n";
    std::cout << "  2. cURL Direct HTTP/3 Examples (uses UDP QUIC directly):\n";
    if (is_tls) {
        std::cout << "     curl -k --http3 " << base_url << "/api/json\n";
        std::cout << "     curl -k --http3 -X POST " << base_url << "/api/query -H \"Content-Type: application/json\" -d '{\"domain\": \"google.com\"}'\n";
        std::cout << "     curl -k --http3 " << base_url << "/api/protected -H \"Authorization: Bearer secret123\"\n";
    } else {
        std::cout << "     curl --http3-only " << base_url << "/api/json\n";
        std::cout << "     curl --http3-only -X POST " << base_url << "/api/query -H \"Content-Type: application/json\" -d '{\"domain\": \"google.com\"}'\n";
        std::cout << "     curl --http3-only " << base_url << "/api/protected -H \"Authorization: Bearer secret123\"\n";
    }
    std::cout << "=========================================================================\n\n";

    engine::Http2Router h2_router;
    engine::Http3Router h3_router;

    auto configure_routes = [&]<typename T0>(T0 &r, const std::string &proto) {
        using Req = std::decay_t<T0>::RequestType;
        using Res = std::decay_t<T0>::ResponseType;

        // Attach global logger middleware
        r.use(logger_middleware<Req, Res>);

        // 1. Root Welcome endpoint
        r.get("/", [proto](const Req &, Res &res) -> asio::awaitable<void> {
            res.status(200).send("Welcome to WaveX Composed " + proto + " (RFC 9114 / RFC 9204 / RFC 9000) Dev Server!");
            std::cout.flush();
            co_return;
        });

        // 2. Structured JSON Status endpoint
        r.get("/api/json", [is_tls, is_lan, port, proto](const Req &req, Res &res) -> asio::awaitable<void> {
            res.status(200).json({
                {"server", "WaveX Composed Server"},
                {"version", wx_version},
                {"negotiated_protocol", proto},
                {"stream_id", req.stream_id()},
                {"status", "online"},
                {"alt_svc_advertised", true},
                {"config", {
                    {"tls_encrypted", is_tls},
                    {"lan_mode", is_lan},
                    {"port", port}
                }},
                {"supported_features", {
                    "HTTP/1.1 and HTTP/2 over TCP/TLS with automatic Alt-Svc advertisement",
                    "HTTP/3 over QUIC UDP with 0-RTT and multiplexed independent streams",
                    "QPACK dynamic & static table header compression",
                    "unified coroutine request routing across transports"
                }}
            });
            co_return;
        });

        // 3. POST Echo endpoint (processes JSON body)
        r.post("/api/echo", [proto](const Req &req, Res &res) -> asio::awaitable<void> {
            const std::string raw(req.body());
            nlohmann::json parsed_body;

            if (raw.empty()) {
                parsed_body = nullptr;
            } else {
                auto j = nlohmann::json::parse(raw, nullptr, false);
                if (!j.is_discarded()) {
                    parsed_body = std::move(j);
                } else {
                    parsed_body = raw;
                }
            }

            res.status(200).json({
                {"message", "Echo received"},
                {"protocol", proto},
                {"stream_id", req.stream_id()},
                {"path", std::string(req.path())},
                {"received_body", parsed_body}
            });
            co_return;
        });

        // 4. JSON Query endpoint - Domain to IP DNS Resolver (Supports both POST and QUERY methods)
        auto dns_query_handler = [proto](const Req &req, Res &res) -> asio::awaitable<void> {
            const std::string raw(req.body());
            std::string domain;

            if (!raw.empty()) {
                auto j = nlohmann::json::parse(raw, nullptr, false);
                if (!j.is_discarded()) {
                    if (j.is_object()) {
                        if (j.contains("domain") && j["domain"].is_string()) {
                            domain = j["domain"].get<std::string>();
                        } else if (j.contains("host") && j["host"].is_string()) {
                            domain = j["host"].get<std::string>();
                        }
                    } else if (j.is_string()) {
                        domain = j.get<std::string>();
                    }
                } else {
                    domain = raw;
                }
            }

            // Clean & normalize domain string
            while (!domain.empty() && (domain.front() == ' ' || domain.front() == '\t' || domain.front() == '"')) domain.erase(0, 1);
            while (!domain.empty() && (domain.back() == ' ' || domain.back() == '\t' || domain.back() == '"' || domain.back() == '}')) domain.pop_back();

            if (domain.empty()) {
                res.status(400).json({
                    {"status", "error"},
                    {"protocol", proto},
                    {"stream_id", req.stream_id()},
                    {"error", "Bad Request"},
                    {"message", "Missing 'domain' in query payload. Example body: {\"domain\": \"google.com\"}"}
                });
                co_return;
            }

            // Asynchronously resolve domain via Asio DNS Resolver
            auto executor = co_await asio::this_coro::executor;
            asio::ip::tcp::resolver resolver(executor);
            asio::error_code ec;

            const auto results = co_await resolver.async_resolve(
                domain, "80", asio::redirect_error(asio::use_awaitable, ec));

            if (ec) {
                res.status(502).json({
                    {"status", "error"},
                    {"protocol", proto},
                    {"stream_id", req.stream_id()},
                    {"domain", domain},
                    {"error", "DNS Resolution Failed"},
                    {"details", ec.message()}
                });
                co_return;
            }

            std::string primary_ip;
            std::vector<std::string> all_ips;
            for (const auto &entry : results) {
                std::string ip = entry.endpoint().address().to_string();
                if (primary_ip.empty()) {
                    primary_ip = ip;
                }
                if (std::ranges::find(all_ips, ip) == all_ips.end()) {
                    all_ips.push_back(ip);
                }
            }

            res.status(200).json({
                {"status", "success"},
                {"protocol", proto},
                {"stream_id", req.stream_id()},
                {"domain", domain},
                {"ip", primary_ip},
                {"ips", all_ips}
            });
            co_return;
        };

        r.post("/api/query", dns_query_handler);
        r.query("/api/query", dns_query_handler);
        r.post("/api/dns", dns_query_handler);
        r.query("/api/dns", dns_query_handler);

        // 5. Protected route with Auth Middleware
        r.get("/api/protected", {auth_middleware<Req, Res>},
              [proto](const Req &req, Res &res) -> asio::awaitable<void> {
                  res.status(200).json({
                      {"status", "granted"},
                      {"protocol", proto},
                      {"stream_id", req.stream_id()},
                      {"secret_data", "Super secret information accessible only with valid auth header!"}
                  });
                  co_return;
              });

        // 6. Dynamic path parameter
        r.get("/users/:id", [proto](const Req &req, Res &res) -> asio::awaitable<void> {
            res.status(200).json({
                {"endpoint", "user_details"},
                {"protocol", proto},
                {"stream_id", req.stream_id()},
                {"path", std::string(req.path())}
            });
            co_return;
        });

        // 7. Wildcard endpoint (*filepath matches any nested subpaths under /files/)
        r.get("/files/*filepath", [proto](const Req &req, Res &res) -> asio::awaitable<void> {
            res.status(200).json({
                {"endpoint", "wildcard_file_handler"},
                {"protocol", proto},
                {"stream_id", req.stream_id()},
                {"matched_path", std::string(req.path())},
                {"description", "Wildcard route *filepath caught nested subpath under /files/"}
            });
            co_return;
        });
    };

    configure_routes(h2_router, "HTTP/2");
    configure_routes(h3_router, "HTTP/3");

    try {
        server::ComposedHttpServer server(h2_router, h3_router, host, static_cast<unsigned short>(port));
        if (is_tls) {
#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
            server.enable_tls(cert_file, key_file);
            std::cout << "Server successfully listening on " << base_url
                      << " (Composed HTTP/2 [TCP] + HTTP/3 [QUIC/UDP] TLS 1.3 Active)\n";
#else
            std::cerr << "Fatal Error: WaveX was built without SSL support (WAVEX_HAS_SSL=0)!\n";
            return 1;
#endif
        } else {
            server.allow_insecure();
            std::cout << "Server successfully listening on " << base_url << " (Cleartext Active)\n";
        }

        std::cout << "Press Ctrl+C to stop.\n\n";
        // system((R"(set NO_POSH=1 && powershell.exe -NoProfile; & "C:\Program Files\Google\Chrome\Application\chrome.exe" --origin-to-force-quic-on=)"+base_url+R"( --ignore-certificate-errors https://)"+base_url).data());
        server.run();
    } catch (const std::exception &e) {
        std::cerr << "[Composed Server Error] " << e.what() << "\n";
        return 1;
    }

    return 0;
}
