/**
 * @file loadgen.cpp
 * @brief Closed-loop HTTP/1.1 keep-alive load generator (asio only, no external tools).
 *
 * Usage:
 *   wavex_loadgen [--host 127.0.0.1] [--port 18080] [--path /hello] [--conns 64] [--idle 0]
 *                 [--duration 10] [--warmup 2]
 *
 *   --conns   connections that continuously send requests (closed loop: next request after the reply)
 *   --idle    extra connections that connect and then stay silent, to exercise idle-connection cost
 *   --warmup  seconds excluded from the statistics
 *
 * Prints one JSON object. A closed loop under-reports tail latency when the server stalls
 * (coordinated omission), so treat p99 as a relative number for A/B runs on the same machine.
 */
#include <asio.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

namespace {
    using clock_t_ = std::chrono::steady_clock;

    struct Options {
        std::string host{"127.0.0.1"};
        unsigned short port{18080};
        std::string path{"/hello"};
        int conns{64};
        int idle{0};
        int duration{10};
        int warmup{2};
    };

    struct Stats {
        std::vector<std::uint32_t> lat_us; // microseconds, measurement window only
        std::uint64_t errors{0};     // failed connects: the server is refusing or unreachable
        std::string last_reason{};   // first reason a connection was dropped
        std::uint64_t reconnects{0}; // server closed a keep-alive connection (e.g. request cap); we reconnected
    };

    std::size_t content_length_of(const std::string_view head) {
        constexpr std::string_view key = "content-length:";
        for (std::size_t i = 0; i + key.size() < head.size(); ++i) {
            bool match = true;
            for (std::size_t k = 0; k < key.size(); ++k) {
                if (std::tolower(static_cast<unsigned char>(head[i + k])) != key[k]) {
                    match = false;
                    break;
                }
            }
            if (match) return std::strtoull(head.data() + i + key.size(), nullptr, 10);
        }
        return 0;
    }

    asio::awaitable<void> worker(const Options &o, Stats &st, const clock_t_::time_point measure_from,
                                 const clock_t_::time_point stop_at) {
        auto ex = co_await asio::this_coro::executor;
        const asio::ip::tcp::endpoint ep(asio::ip::make_address(o.host), o.port);
        const std::string req = "GET " + o.path + " HTTP/1.1\r\nHost: bench\r\n\r\n";
        std::string buf;
        bool first = true;
        while (clock_t_::now() < stop_at) {
            asio::ip::tcp::socket sock(ex);
            try {
                co_await sock.async_connect(ep, asio::use_awaitable);
                sock.set_option(asio::ip::tcp::no_delay(true));
            } catch (const std::exception &) {
                ++st.errors;
                co_return;
            }
            if (!first) ++st.reconnects;
            first = false;
            try {
                while (clock_t_::now() < stop_at) {
                    const auto t0 = clock_t_::now();
                    co_await asio::async_write(sock, asio::buffer(req), asio::use_awaitable);
                    buf.clear();
                    const auto n = co_await asio::async_read_until(sock, asio::dynamic_buffer(buf), "\r\n\r\n",
                                                                   asio::use_awaitable);
                    const std::size_t need = content_length_of(std::string_view(buf).substr(0, n));
                    const std::size_t have = buf.size() - n;
                    if (have < need) {
                        std::string rest(need - have, '\0');
                        co_await asio::async_read(sock, asio::buffer(rest), asio::use_awaitable);
                    }
                    const auto t1 = clock_t_::now();
                    if (t0 >= measure_from) {
                        st.lat_us.push_back(static_cast<std::uint32_t>(
                            std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count()));
                    }
                }
            } catch (const std::exception &e) {
                // Connection closed mid-run: remember why (first reason only), then reconnect.
                if (st.last_reason.empty()) st.last_reason = e.what();
            }
        }
    }

    asio::awaitable<void> idle_holder(const Options &o, std::atomic<int> &connected, std::atomic<int> &failed,
                                      const clock_t_::time_point stop_at) {
        auto ex = co_await asio::this_coro::executor;
        asio::ip::tcp::socket sock(ex);
        try {
            asio::ip::tcp::endpoint ep(asio::ip::make_address(o.host), o.port);
            co_await sock.async_connect(ep, asio::use_awaitable);
            ++connected;
            asio::steady_timer t(ex);
            t.expires_at(stop_at);
            co_await t.async_wait(asio::use_awaitable);
        } catch (const std::exception &) {
            ++failed;
        }
    }

    double pct(const std::vector<std::uint32_t> &sorted, const double p) {
        if (sorted.empty()) return 0;
        const auto idx = static_cast<std::size_t>(p * static_cast<double>(sorted.size() - 1));
        return sorted[idx];
    }
} // namespace

int main(const int argc, char **argv) {
    Options o;
    for (int i = 1; i + 1 < argc; i += 2) {
        const std::string k = argv[i];
        const char *v = argv[i + 1];
        if (k == "--host") o.host = v;
        else if (k == "--port") o.port = static_cast<unsigned short>(std::atoi(v));
        else if (k == "--path") o.path = v;
        else if (k == "--conns") o.conns = std::atoi(v);
        else if (k == "--idle") o.idle = std::atoi(v);
        else if (k == "--duration") o.duration = std::atoi(v);
        else if (k == "--warmup") o.warmup = std::atoi(v);
        else {
            std::cerr << "unknown option " << k << "\n";
            return 2;
        }
    }

    asio::io_context ioc(1);
    const auto start = clock_t_::now();
    const auto measure_from = start + std::chrono::seconds(o.warmup);
    const auto stop_at = measure_from + std::chrono::seconds(o.duration);

    std::vector<Stats> stats(static_cast<std::size_t>(o.conns));
    std::atomic<int> idle_ok{0}, idle_failed{0};
    for (int i = 0; i < o.idle; ++i) {
        asio::co_spawn(ioc, idle_holder(o, idle_ok, idle_failed, stop_at), asio::detached);
    }
    for (int i = 0; i < o.conns; ++i) {
        asio::co_spawn(ioc, worker(o, stats[static_cast<std::size_t>(i)], measure_from, stop_at), asio::detached);
    }
    ioc.run();

    std::vector<std::uint32_t> all;
    std::uint64_t errors = 0, reconnects = 0;
    for (auto &s: stats) {
        all.insert(all.end(), s.lat_us.begin(), s.lat_us.end());
        errors += s.errors;
        reconnects += s.reconnects;
    }
    for (const auto &s: stats) {
        if (!s.last_reason.empty()) {
            std::cerr << "loadgen: connection dropped: " << s.last_reason << "\n";
            break;
        }
    }
    std::ranges::sort(all);
    const double rps = static_cast<double>(all.size()) / static_cast<double>(o.duration);

    std::printf(
        "{\"path\":\"%s\",\"conns\":%d,\"idle_requested\":%d,\"idle_connected\":%d,\"idle_failed\":%d,"
        "\"duration_s\":%d,\"requests\":%zu,\"rps\":%.0f,\"errors\":%llu,\"reconnects\":%llu,"
        "\"p50_us\":%.0f,\"p90_us\":%.0f,\"p99_us\":%.0f,\"p999_us\":%.0f,\"max_us\":%.0f}\n",
        o.path.c_str(), o.conns, o.idle, idle_ok.load(), idle_failed.load(), o.duration, all.size(), rps,
        static_cast<unsigned long long>(errors), static_cast<unsigned long long>(reconnects), pct(all, 0.50), pct(all, 0.90), pct(all, 0.99), pct(all, 0.999),
        all.empty() ? 0.0 : static_cast<double>(all.back()));
    // Failed connects, or more than 1% of requests needing a reconnect (the bench server allows 1M requests per
    // connection, so churn means the server is dropping connections it should not), fail the run.
    return (errors == 0 && reconnects * 100 <= all.size()) ? 0 : 1;
}
