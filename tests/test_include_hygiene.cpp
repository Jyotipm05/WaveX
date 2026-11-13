// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Build-time guard: the public server and client headers must stay cheap to include. They only forward-declare
// nlohmann::json (full json.hpp costs about 2 s per translation unit). Server.hpp does not include the
// composed HTTP/2 + HTTP/3 server either (include <wavex/Server/ComposedHttpServer.hpp> to use it). Users who call `.json(...)` include <nlohmann/json.hpp> themselves; the
// umbrella <wavex/wavex.hpp> still includes everything.

#include <wavex/Client/HttpClient.hpp>
#include <wavex/Server/Server.hpp>

#ifdef INCLUDE_NLOHMANN_JSON_HPP_
#error "a public header pulled in the full <nlohmann/json.hpp>; use <nlohmann/json_fwd.hpp> and move the code into a .cpp"
#endif

// Only now bring in the full json, as a user would, and check the forward-declared APIs still work with it.
#include <nlohmann/json.hpp>

int main() {
    wavex::client::ClientRequest req(wavex::client::method::GET, "http://127.0.0.1/");
    req.json(nlohmann::json{{"ok", true}});
    return req.body().empty() ? 1 : 0;
}
