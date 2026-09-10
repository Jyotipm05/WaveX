#include <wavex/wavex.hpp>
#include <iostream>
#include <cassert>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

// 1. Concrete Chainable handler types
class PrefixHandler : public wavex::Chainable {
    std::string prefix_;

public:
    explicit PrefixHandler(std::string prefix) : prefix_(std::move(prefix)) {
    }

    [[nodiscard]] static std::string_view name_impl() { return "PrefixHandler"; }

    [[nodiscard]] std::string handle_impl(const std::string &input) const {
        return prefix_ + input;
    }
};

class SuffixHandler : public wavex::Chainable {
    std::string suffix_;

public:
    explicit SuffixHandler(std::string suffix) : suffix_(std::move(suffix)) {
    }

    [[nodiscard]] static std::string_view name_impl() { return "SuffixHandler"; }

    [[nodiscard]] std::string handle_impl(const std::string &input) const {
        return input + suffix_;
    }
};

// 2. Mutable and Rvalue handler
class UppercaseHandler : public wavex::Chainable {
public:
    [[nodiscard]] static std::string_view name_impl() { return "UppercaseHandler"; }

    static std::string handle_impl(std::string &&input) {
        for (char &c: input) {
            c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
        }
        return std::move(input);
    }
};

// Pipeline element for boolean chain
struct AuthGuard : public wavex::Chainable {
    bool allow = true;

    explicit AuthGuard(const bool a = true) : allow(a) {
    }

    [[nodiscard]] static std::string_view name_impl() { return "AuthGuard"; }

    [[nodiscard]] bool handle_impl(const std::string &user) const {
        std::cout << "  -> AuthGuard executing for user: '" << user << "'\n";
        const bool result = (allow && user == "admin");
        std::cout << "  <- AuthGuard returning: " << (result ? "true (allow next)" : "false (short-circuit)") << "\n";
        return result;
    }
};

struct AuditLogger : public wavex::Chainable {
    mutable std::vector<std::string> audit_log;

    AuditLogger() = default;

    static std::string_view name_impl() { return "AuditLogger"; }

    bool handle_impl(const std::string &user) const {
        std::cout << "  -> AuditLogger executing for user: '" << user << "'\n";
        audit_log.push_back(user);
        std::cout << "  <- AuditLogger returning: true (allow next)\n";
        return true;
    }
};

int main() {
    std::cout << "[Test] Running Chainable deducing this unit tests...\n";

    // Test 1: Basic static dispatch and name()
    PrefixHandler prefix(">>> ");
    SuffixHandler suffix(" <<<");

    assert(prefix.name() == "PrefixHandler");
    assert(suffix.name() == "SuffixHandler");

    std::string res1 = prefix.handle(std::string("Hello"));
    assert(res1 == ">>> Hello");

    std::string res2 = suffix.handle(res1);
    assert(res2 == ">>> Hello <<<");

    // Test 2: Rvalue perfect forwarding dispatch
    UppercaseHandler upper;
    assert(upper.name() == "UppercaseHandler");
    std::string res3 = upper.handle(std::string("wavex"));
    assert(res3 == "WAVEX");

    // Test 3: Static Concept Verification
    static_assert(wavex::ChainableHandler<PrefixHandler, const std::string &>);
    static_assert(wavex::ChainableHandler<SuffixHandler, const std::string &>);
    static_assert(wavex::ChainableHandler<UppercaseHandler, std::string &&>);

    // Test 4: Static Pipeline execution with wavex::StaticChain & make_chain
    AuthGuard auth{true};
    AuditLogger audit{};
    auto pipeline = wavex::make_chain(std::ref(auth), std::ref(audit));

    std::string user_admin = "admin";
    std::cout << "\n[Test 4.1] Calling process_all for user '" << user_admin << "'...\n";
    const bool ok_admin = pipeline.process_all(user_admin);
    std::cout << "[Test 4.1] process_all returned: " << (ok_admin ? "true" : "false") << "\n";
    assert(ok_admin == true);
    assert(audit.audit_log.size() == 1);
    assert(audit.audit_log[0] == "admin");

    std::string user_guest = "guest";
    std::cout << "\n[Test 4.2] Calling process_all for user '" << user_guest << "'...\n";
    bool ok_guest = pipeline.process_all(user_guest);
    std::cout << "[Test 4.2] process_all returned: " << (ok_guest ? "true" : "false") << "\n";
    assert(ok_guest == false);
    // Short-circuited by AuthGuard, AuditLogger must NOT have run for "guest"
    assert(audit.audit_log.size() == 1);

    // Test 5: ConditionalChainable (semi-static runtime toggling)
    std::cout << "\n[Test 5] Testing ConditionalChainable runtime enable/disable...\n";
    wavex::ConditionalChainable cond_auth(AuthGuard{false}, false); // Disabled AuthGuard
    auto cond_pipeline = wavex::make_chain(std::ref(cond_auth), std::ref(audit));

    // Even though AuthGuard has allow=false, it is disabled via cond_auth so it bypasses and allows next
    bool ok_disabled_auth = cond_pipeline.process_all("guest");
    assert(ok_disabled_auth == true);
    assert(audit.audit_log.size() == 2);
    assert(audit.audit_log[1] == "guest");

    // Enable cond_auth dynamically
    cond_auth.set_enabled(true);
    bool ok_enabled_auth = cond_pipeline.process_all("guest");
    assert(ok_enabled_auth == false); // Now AuthGuard runs and short-circuits!
    assert(audit.audit_log.size() == 2);

    std::cout << "[Test] Chainable deducing this tests PASSED successfully!\n";
    return 0;
}
