/**
 * @file test_protocol_traits.cpp
 * @brief The policy seam: the generic server reaches protocol-specific behaviour only through protocol_traits.
 *
 *  - A protocol that specializes nothing needs no HTTP members (status(), headers, query parameters).
 *  - The HTTP specializations phrase kernel-level rejections with the same status codes as before.
 *  - Only the HTTP/3 policy contributes an extra transport listener.
 */
#include <wavex/Server/Server.hpp>

#include <concepts>
#include <iostream>
#include <string>

namespace {
    int run = 0, passed = 0;

    void check(const bool ok, const char *name) {
        ++run;
        if (ok) ++passed;
        std::cout << (ok ? "  [PASS] " : "  [FAIL] ") << name << "\n";
    }

    // A made-up protocol: nothing like HTTP. No status(), no headers, no query string.
    struct ToyCodec {};
    struct ToyRequest {};
    struct ToyResponse {
        bool touched{false};
    };

    // Records what the HTTP policy asked the response to do.
    struct FakeHttpResponse {
        unsigned code{0};
        std::string body;
        FakeHttpResponse &status(const unsigned c) {
            code = c;
            return *this;
        }
        void send(const std::string &b) { body = b; }
        std::string content_type;
        void set(const std::string &, const std::string &v) { content_type = v; }
    };
    struct FakeHttpRequest {
        std::string_view path() const noexcept { return "/x"; }
    };

    template<typename Traits, typename Host>
    concept SuppliesListener = requires(Host &h) { Traits::template make_transport_listener<Host>(h); };

    template<typename Traits, typename Res>
    unsigned code_for(const wavex::protos::protocol_error e) {
        Res r;
        Traits::write_error(r, e);
        return r.code;
    }
} // namespace

int main() {
    using namespace wavex::protos;
    std::cout << "=== protocol_traits seam tests ===\n";

    using Toy = protocol_traits<ToyCodec>;
    ToyRequest toy_req;
    ToyResponse toy_res;
    check(!Toy::exceeds_limits(toy_req, request_limits{1, 1}), "default policy: no structural limits");
    Toy::write_error(toy_res, protocol_error::limits_exceeded);
    Toy::set_default_status(toy_res, false);
    check(!toy_res.touched, "default policy: kernel rejections touch nothing, no HTTP members needed");
    check(!Toy::has_quic_transport && Toy::has_tcp_transport, "default policy: plain TCP");

    using H1 = protocol_traits<http::http1codec>;
    check(code_for<H1, FakeHttpResponse>(protocol_error::bad_request) == 400, "http1: bad_request -> 400");
    check(code_for<H1, FakeHttpResponse>(protocol_error::payload_too_large) == 413, "http1: payload_too_large -> 413");
    check(code_for<H1, FakeHttpResponse>(protocol_error::limits_exceeded) == 431, "http1: limits_exceeded -> 431");
    check(code_for<H1, FakeHttpResponse>(protocol_error::internal_error) == 500, "http1: internal_error -> 500");
    FakeHttpResponse r;
    H1::set_default_status(r, true);
    check(r.code == 200, "http1: matched route defaults to 200");
    H1::set_default_status(r, false);
    check(r.code == 404, "http1: unmatched route defaults to 404");

    FakeHttpResponse nf;
    H1::write_not_found(nf, "gone", "text/plain");
    check(nf.code == 404 && nf.body == "gone" && nf.content_type == "text/plain", "http1: not-found reply is 404 + body + type");
    check(H1::request_label(FakeHttpRequest{}) == "/x", "http1: request label is the path");
    ToyResponse toy_nf;
    Toy::write_not_found(toy_nf, "x", "y");
    check(Toy::request_label(toy_req).empty() && !toy_nf.touched, "default policy: no label, not-found is a no-op");

    using H2 = protocol_traits<http::http2codec>;
    check(code_for<H2, FakeHttpResponse>(protocol_error::limits_exceeded) == 431, "http2: limits_exceeded -> 431");

#if defined(WAVEX_HAS_SSL) && WAVEX_HAS_SSL
    using H3 = protocol_traits<http::http3codec>;
    check(code_for<H3, FakeHttpResponse>(protocol_error::bad_request) == 400, "http3: bad_request -> 400");
    check(H3::has_quic_transport, "http3: declares a QUIC transport");
    static_assert(SuppliesListener<H3, wavex::server::Http3Server>, "http3 policy supplies a transport listener");
    static_assert(!SuppliesListener<H1, wavex::server::Http1Server>, "http1 policy supplies none");
#endif

    // Structural: the generic server holds listeners only through the neutral interface.
    static_assert(std::is_abstract_v<wavex::network::TransportListener>);

    std::cout << passed << "/" << run << " tests passed.\n";
    return passed == run ? 0 : 1;
}
