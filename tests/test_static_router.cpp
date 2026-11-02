/**
 * @file test_static_router.cpp
 * @brief StaticRouter: compile-time pattern parsing and validation, matching (literal / parameter / typed
 *        parameter / wildcard, backtracking, normalization), middleware and group composition order,
 *        string_compare vs hash_compare equivalence, and serving through Server<http1codec, StaticRouter>.
 */

#include <wavex/wavex.hpp>
#include <wavex/Engine/StaticHttpRouter.hpp>

#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/io_context.hpp>

#include <iostream>
#include <string>
#include <thread>

using namespace wavex;
using namespace wavex::engine::route;

namespace {
    int tests_run{0};
    int tests_failed{0};

    void check(const bool condition, const char *name) {
        ++tests_run;
        if (!condition) ++tests_failed;
        std::cout << (condition ? "  [PASS] " : "  [FAIL] ") << name << "\n";
    }

    // ── A tiny protocol so the router can be exercised without a server ──────────────
    enum class fmethod { GET, POST };

    struct freq {
        std::string log;
    };

    struct fres {
        int code{0};
        std::string body;

        fres &status(const int c) {
            code = c;
            return *this;
        }

        fres &set(std::string_view, std::string_view) { return *this; }

        void send(const std::string_view b) { body = b; }
    };

    struct fproto {
        using method = fmethod;
        using request = freq;
        using response = fres;
    };

    template<typename Router>
    std::string call(const Router &r, const fmethod m, const std::string_view path, freq &req, fres &res) {
        std::string params;
        asio::io_context io;
        const auto match = r.resolve(m, path);
        if (!match) return "<none>";
        for (const auto &[k, v]: match->params) params += std::string(k) + "=" + std::string(v) + ";";
        asio::co_spawn(io, [&]() -> wavex::task<void> { co_await match->handler(req, res); }, asio::detached);
        io.run();
        return params;
    }

    // ── compile-time checks ──────────────────────────────────────────────────────────
    constexpr auto p1 = parse_pattern("/users/{id:int}/posts/*rest");
    static_assert(p1.error == pattern_error::none && p1.count == 4);
    static_assert(p1.segs[0].kind == segment_kind::literal && p1.segs[0].text == "users");
    static_assert(p1.segs[1].kind == segment_kind::param && p1.segs[1].cls == param_class::int_ &&
                  p1.segs[1].text == "id");
    static_assert(p1.segs[3].kind == segment_kind::wildcard && p1.segs[3].text == "rest");
    static_assert(parse_pattern("/a/:x/b").count == 3);
    static_assert(parse_pattern("//a///b/").count == 2);
    static_assert(parse_pattern("/").count == 0);
    static_assert(parse_pattern("/a/*x/b").error == pattern_error::wildcard_not_last);
    static_assert(parse_pattern("/a/{id:}").error == pattern_error::unknown_constraint);
    static_assert(parse_pattern("/a/{id:[0-9]{4}}").segs[1].cls == param_class::regex &&
                  parse_pattern("/a/{id:[0-9]{4}}").segs[1].pattern == "[0-9]{4}");
    static_assert(parse_pattern("/a/{}").error == pattern_error::empty_param_name);
    static_assert(parse_pattern("/a/:x/:x").error == pattern_error::duplicate_param);
    static_assert(parse_pattern("/a{b").error == pattern_error::bad_literal);
    static_assert(parse_pattern("/a/x*y").error == pattern_error::bad_literal);
    static_assert(parse_pattern("/1/2/3/4/5/6/7/8/9/10/11/12/13/14/15/16/17").error ==
                  pattern_error::too_many_segments);
    static_assert(matches_class(param_class::int_, "-42") && !matches_class(param_class::int_, "4x") &&
                  !matches_class(param_class::int_, "-"));
    static_assert(matches_class(param_class::uint_, "42") && !matches_class(param_class::uint_, "-42"));
    static_assert(matches_class(param_class::hex, "DeadBeef01") && !matches_class(param_class::hex, "xyz"));
    static_assert(matches_class(param_class::alpha, "abC") && !matches_class(param_class::alpha, "ab1"));
    static_assert(matches_class(param_class::alnum, "ab1") && !matches_class(param_class::alnum, "ab-1"));
    static_assert(!matches_class(param_class::any, ""));
    static_assert(concat(fixed_string{"/api"}, fixed_string{"/v1"}).view() == "/api/v1");
    static_assert(hash_compare<>::equals(hash_compare<>::prepare("abc"), hash_compare<>::prepare("abc")));
    static_assert(!hash_compare<>::equals(hash_compare<>::prepare("abc"), hash_compare<>::prepare("abd")));
    static_assert(router_type<engine::HttpRouter<protos::http::http1codec> >);

    // ── handlers and middleware used by several tests ────────────────────────────────
    auto tag(const char *name) {
        return [name](freq &req, fres &res) -> wavex::task<void> {
            req.log += name;
            res.status(200).send(name);
            co_return;
        };
    }

    auto trace(const char *name) {
        return [name](freq &req, fres &, auto &next) -> wavex::task<void> {
            req.log += std::string(name) + ">";
            co_await next();
            req.log += std::string("<") + name;
        };
    }

    template<typename Cmp>
    auto make_router() {
        return static_router<fproto, Cmp>(
            on<fmethod::GET, "/">(tag("root")),
            on<fmethod::GET, "/users/me">(tag("me")),
            on<fmethod::GET, "/users/{id:int}">(tag("by-id")),
            on<fmethod::GET, "/users/{name:alpha}">(tag("by-name")),
            on<fmethod::POST, "/users">(tag("create")),
            on<fmethod::GET, "/a/:x/b">(tag("axb")),
            on<fmethod::GET, "/files/*path">(tag("files")),
            on<fmethod::GET, "/files/static/info">(tag("info")),
            on<fmethod::GET, "/d/{date:[0-9]{4}-[0-9]{2}-[0-9]{2}}">(tag("date")),
            on<fmethod::GET, "/d/{slug:[a-z]+(-[a-z]+)*}/v">(tag("slug")));
    }

    template<typename Cmp>
    void matching_tests(const char *label) {
        std::cout << "matching (" << label << ")\n";
        const auto r = make_router<Cmp>();
        check(r.size() == 10, "route count is known at compile time");
        freq q;
        fres s;

        auto params = call(r, fmethod::GET, "/", q, s);
        check(s.body == "root" && params.empty(), "root path");

        q = {}; s = {};
        params = call(r, fmethod::GET, "/users/42", q, s);
        check(s.body == "by-id" && params == "id=42;", "typed int parameter");

        q = {}; s = {};
        call(r, fmethod::GET, "/users/me", q, s);
        check(s.body == "me", "literal beats a parameter at the same position");

        q = {}; s = {};
        params = call(r, fmethod::GET, "/users/alice", q, s);
        check(s.body == "by-name" && params == "name=alice;", "second typed parameter tried after the first rejects");

        q = {}; s = {};
        check(call(r, fmethod::GET, "/users/4x2", q, s) == "<none>", "segment matching no constraint is a miss");

        q = {}; s = {};
        call(r, fmethod::POST, "/users", q, s);
        check(s.body == "create", "method selects the handler");
        check(call(r, fmethod::POST, "/users/42", q, s) == "<none>", "unregistered method on a route is a miss");

        q = {}; s = {};
        params = call(r, fmethod::GET, "//users///7/", q, s);
        check(s.body == "by-id" && params == "id=7;", "doubled and trailing slashes are normalized");

        q = {}; s = {};
        params = call(r, fmethod::GET, "/a/xx/b", q, s);
        check(s.body == "axb" && params == "x=xx;", ":name parameter");
        check(call(r, fmethod::GET, "/a/xx/c", q, s) == "<none>", "mismatch after a parameter is a miss");
        check(call(r, fmethod::GET, "/a/xx", q, s) == "<none>", "prefix of a route is a miss");

        q = {}; s = {};
        params = call(r, fmethod::GET, "/files/a/b/c.txt/", q, s);
        check(s.body == "files" && params == "path=a/b/c.txt;", "wildcard captures the rest, trailing slash trimmed");

        q = {}; s = {};
        call(r, fmethod::GET, "/files/static/info", q, s);
        check(s.body == "info", "literal route under a wildcard prefix wins");

        q = {}; s = {};
        params = call(r, fmethod::GET, "/files/static/other", q, s);
        check(s.body == "files" && params == "path=static/other;", "backtracks from literal branch into the wildcard");

        q = {}; s = {};
        params = call(r, fmethod::GET, "/d/2026-11-02", q, s);
        check(s.body == "date" && params == "date=2026-11-02;", "regex parameter");
        check(call(r, fmethod::GET, "/d/2026-1-02", q, s) == "<none>", "regex parameter must match the whole segment");
        q = {}; s = {};
        params = call(r, fmethod::GET, "/d/hello-big-world/v", q, s);
        check(s.body == "slug" && params == "slug=hello-big-world;", "regex with group and repetition");
        check(call(r, fmethod::GET, "/d/Hello/v", q, s) == "<none>", "regex rejects uppercase");
        check(call(r, fmethod::GET, "/nope", q, s) == "<none>", "unknown path is a miss");
        q = {}; s = {};
        call(r, fmethod::GET, "", q, s);
        check(s.body == "root", "empty path means the root, as in DynamicRouter");
    }

    void middleware_tests() {
        std::cout << "middleware and groups\n";
        const auto r = static_router<fproto>(
            use(trace("g")),
            on<fmethod::GET, "/plain">(tag("H")),
            group<"/api">(
                use(trace("a")),
                on<fmethod::GET, "/x">(tag("H"), trace("r1"), trace("r2")),
                group<"/v1">(
                    use(trace("b")),
                    on<fmethod::GET, "/y/:id">(tag("H")))),
            on<fmethod::GET, "/guarded">(tag("H"),
                                          [](freq &req, fres &res, auto &) -> wavex::task<void> {
                                              req.log += "deny";
                                              res.status(401).send("no");
                                              co_return;
                                          }),
            on<fmethod::GET, "/hooks">(tag("H"),
                                       before([](freq &req, fres &) { req.log += "B"; return true; }),
                                       after([](freq &req, fres &) { req.log += "A"; })),
            on<fmethod::GET, "/stop">(tag("H"),
                                      before([](freq &req, fres &res) {
                                          req.log += "S";
                                          res.status(403);
                                          return false;
                                      })));

        freq q;
        fres s;
        call(r, fmethod::GET, "/plain", q, s);
        check(q.log == "g>H<g", "global middleware wraps the handler");

        q = {}; s = {};
        call(r, fmethod::GET, "/api/x", q, s);
        check(q.log == "g>a>r1>r2>H<r2<r1<a<g", "global, group, route middleware nest in that order");

        q = {}; s = {};
        auto p = call(r, fmethod::GET, "/api/v1/y/9", q, s);
        check(q.log == "g>a>b>H<b<a<g" && p == "id=9;", "nested groups concatenate prefixes and middleware");

        q = {}; s = {};
        call(r, fmethod::GET, "/guarded", q, s);
        check(q.log == "g>deny<g" && s.code == 401, "middleware that skips next() short-circuits; outer ones still unwind");

        q = {}; s = {};
        call(r, fmethod::GET, "/hooks", q, s);
        check(q.log == "g>BHA<g", "before()/after() adaptors");

        q = {}; s = {};
        call(r, fmethod::GET, "/stop", q, s);
        check(q.log == "g>S<g" && s.code == 403, "before() returning false stops the chain");
    }

    // ── served through the real server ───────────────────────────────────────────────
    void e2e_tests() {
        std::cout << "served through Server<http1codec, StaticRouter>\n";
        using Proto = engine::Http1Proto;
        using Req = protos::http::Http1Request;
        using Res = protos::http::Http1Response;
        namespace hr = wavex::engine::route::http;

        auto router = static_router<Proto, hash_compare<> >(
            use([](Req &, Res &res, auto &next) -> wavex::task<void> {
                co_await next();
                res.set("x-static", "1");
            }),
            hr::get<"/hello/{name:alpha}">([](Req &req, Res &res) -> wavex::task<void> {
                res.status(200).send("hi " + std::string(req.param("name")));
                co_return;
            }),
            hr::get<"/n/{id:int}">([](Req &req, Res &res) -> wavex::task<void> {
                res.status(200).send("n=" + std::string(req.param("id")));
                co_return;
            }),
            hr::post<"/echo">([](Req &req, Res &res) -> wavex::task<void> {
                res.status(201).send(std::string(req.body()));
                co_return;
            }));
        router.not_found("custom 404");

        server::Server<protos::http::http1codec, decltype(router)> srv(router, "127.0.0.1", 19993);
        std::thread t([&] { srv.run(); });
        for (int i = 0; i < 300 && !srv.is_running(); ++i) std::this_thread::sleep_for(std::chrono::milliseconds(10));
        std::this_thread::sleep_for(std::chrono::milliseconds(150));

        asio::io_context io;
        asio::co_spawn(io, []() -> wavex::task<void> {
            using client::HttpClient;
            using client::ClientRequest;
            auto a = co_await HttpClient::send(ClientRequest(client::method::GET, "http://127.0.0.1:19993/hello/world"));
            check(a.status_code() == 200 && a.body() == "hi world", "GET with typed parameter");
            check(a.header("x-static").value_or("") == "1", "post-processing middleware ran after the handler");
            auto b = co_await HttpClient::send(ClientRequest(client::method::GET, "http://127.0.0.1:19993/n/17"));
            check(b.status_code() == 200 && b.body() == "n=17", "int parameter");
            auto c = co_await HttpClient::send(ClientRequest(client::method::GET, "http://127.0.0.1:19993/n/x"));
            check(c.status_code() == 404 && c.body() == "custom 404", "constraint miss uses the custom not-found handler");
            ClientRequest post(client::method::POST, "http://127.0.0.1:19993/echo");
            post.set_body("payload", "text/plain");
            auto d = co_await HttpClient::send(post);
            check(d.status_code() == 201 && d.body() == "payload", "POST body reaches the handler");
            auto e = co_await HttpClient::send(ClientRequest(client::method::POST, "http://127.0.0.1:19993/hello/x"));
            check(e.status_code() == 404, "wrong method is a 404");
        }, asio::detached);
        io.run();
        srv.stop();
        t.join();
    }
} // namespace

int main() {
    std::cout << "=== StaticRouter tests ===\n";
    matching_tests<string_compare>("string_compare");
    matching_tests<hash_compare<> >("hash_compare");
    middleware_tests();
    e2e_tests();
    std::cout << "\n" << (tests_run - tests_failed) << "/" << tests_run << " passed\n";
    return tests_failed == 0 ? 0 : 1;
}
