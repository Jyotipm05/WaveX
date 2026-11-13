// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// DynamicRouter<Proto, SegmentCompare>: the hash policy must resolve exactly like the default one.

#include <iostream>
#include <string>
#include <vector>

#include <wavex/Engine/HttpRouter.hpp>

using namespace wavex;
using namespace wavex::engine;

namespace {
    int tests_run{0}, tests_failed{0};

    void check(const bool ok, const std::string &name) {
        ++tests_run;
        if (!ok) ++tests_failed;
        std::cout << (ok ? "  [PASS] " : "  [FAIL] ") << name << "\n";
    }

    template<typename R>
    void fill(R &r) {
        auto h = [](auto &, auto &) -> wavex::task<void> { co_return; };
        r.get("/", h);
        r.get("/users", h);
        r.get("/users/{id:[0-9]+}", h);
        r.get("/users/me/posts", h);
        r.get("/users/:name/posts/:pid", h);
        r.get("/static/*path", h);
        r.get("/api/v1/items/{id:[0-9]{4}}", h);
        r.post("/users", h);
    }

    template<typename R>
    std::string probe(R &r, const protos::http::method m, const std::string_view path) {
        const auto match = r.resolve(m, path);
        if (!match) return "<none>";
        std::string out;
        for (const auto &[k, v]: match->params) out += std::string(k) + "=" + std::string(v) + ";";
        return out.empty() ? "<ok>" : out;
    }
}

int main() {
    Http1Router plain;
    HttpRouter<protos::http::http1codec, route::hash_compare<> > hashed;
    fill(plain);
    fill(hashed);
    plain.freeze();
    hashed.freeze();

    using M = protos::http::method;
    const std::vector<std::pair<M, std::string_view> > cases = {
        {M::GET, "/"}, {M::GET, "/users"}, {M::POST, "/users"}, {M::PUT, "/users"}, {M::GET, "/users/42"},
        {M::GET, "/users/abc"}, {M::GET, "/users/me/posts"}, {M::GET, "/users/bob/posts/7"},
        {M::GET, "/static/a/b/c.css"}, {M::GET, "/api/v1/items/1234"}, {M::GET, "/api/v1/items/12"},
        {M::GET, "/nope"}, {M::GET, "/users/42/extra"}, {M::GET, "//users//42/"},
    };
    for (const auto &[m, p]: cases) {
        check(probe(plain, m, p) == probe(hashed, m, p), "same result for " + std::string(p));
    }
    check(probe(hashed, M::GET, "/users/42") != "<none>" && probe(hashed, M::GET, "/users/42") != "<ok>", "typed param captured: " + probe(hashed, M::GET, "/users/42"));
    check(probe(hashed, M::GET, "/users/me/posts") == "<ok>", "literal beats param");

    // Paths that need normalizing: params must stay valid after resolve() returns (ASan checks the lifetime).
    check(probe(plain, M::GET, "/users/42/") == "id=42;", "trailing slash keeps param valid");
    check(probe(plain, M::GET, "users/42") == "id=42;", "missing leading slash keeps param valid");
    check(probe(hashed, M::GET, "static/a/b/") == probe(plain, M::GET, "static/a/b/"), "wildcard on normalized path");

    std::cout << tests_run - tests_failed << "/" << tests_run << " passed\n";
    return tests_failed == 0 ? 0 : 1;
}
