# DNS resolver

WaveX ships a native, dependency-free stub resolver (`wavex/Network/Dns/Resolver.hpp`), so the client does not
need c-ares and does not park a thread in `getaddrinfo`. It runs on the caller's executor as an ordinary
`wavex::task`.

```cpp
auto r = wavex::dns::resolver::shared();          // process-wide, thread-safe, shared cache
auto a = co_await r->resolve("example.com");      // std::expected<addresses, std::error_code>
if (a) for (auto &ip : a->list) { /* IPv6 first, interleaved with IPv4 */ }

auto https = co_await r->resolve_https("example.com");  // HTTPS/SVCB records: alpn, port, hints, ech
```

## What it does

| Area        | Behaviour                                                                                                                                                                                     |
|-------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Transport   | UDP on a fresh connected socket per query (OS-chosen ephemeral port), EDNS0 (payload 1232), automatic TCP retry when the answer is truncated, retry without EDNS0 on FORMERR                  |
| Servers     | `resolv.conf` (`nameserver`, `search`/`domain`, `options ndots/timeout/attempts/rotate`) or Windows adapter DNS servers; every server is tried, `attempts` rounds, timeouts back off          |
| Names       | IP literals, `localhost` / `*.localhost` (RFC 6761), hosts file, search list with `ndots`, absolute names (trailing dot)                                                                      |
| Answers     | A + AAAA queried in parallel, CNAME chains (in one packet, or followed with a new query), records for unrelated owner names are ignored                                                       |
| Cache       | TTL cache bounded in size, negative caching from the SOA minimum (RFC 2308)                                                                                                                   |
| Concurrency | identical in-flight queries are coalesced: N callers cause one query; each caller resumes on its own executor                                                                                 |
| HTTPS RR    | RFC 9460 parsing, AliasMode followed, ServiceMode sorted by priority                                                                                                                          |
| Hardening   | random 16-bit ID, connected socket, question must match, compression pointers may only point backwards, 255/63 length limits, record counts bounded by packet size, every read bounds-checked |

Errors use `wavex::dns::category()` (`errc::name_not_found`, `no_data`, `timeout`, `server_failure`, `refused`, ...).

## HttpClient

`ClientOptions::dns` selects the strategy:

* `DnsMode::NativeWithSystemFallback` (default): native resolver; if no DNS server answered (timeout, SERVFAIL,
  no servers) the OS resolver is tried. NXDOMAIN is final.
* `DnsMode::Native`: native only.
* `DnsMode::System`: the previous behaviour (`getaddrinfo`).

## Limits

* Plain DNS only (no DoT/DoH, no DNSSEC validation); the system's configuration is read once at first use.
* Both families are awaited together, so an AAAA query that times out delays an otherwise good A answer.
* Addresses are returned IPv6-first and interleaved; connection attempts are sequential, not raced.
