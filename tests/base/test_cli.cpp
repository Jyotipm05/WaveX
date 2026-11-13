/**
 * @file test_cli.cpp
 * @brief Comprehensive unit tests for WaveX built-in CLI argument parser (CliParser).
 */

#include <iostream>
#include <string>
#include <vector>

#include <wavex/wavex.hpp>

namespace {
    int tests_run = 0;
    int tests_passed = 0;

    void check(const bool condition, const char *name) {
        ++tests_run;
        if (condition) {
            ++tests_passed;
            std::cout << "  [PASS] " << name << "\n";
        } else {
            std::cout << "  [FAIL] " << name << "\n";
        }
    }
}

// ─── Test 1: Flag Options & Defaults ─────────────────────────────────────────

void test_cli_flags() {
    std::cout << "\n[Test 1] CLI Boolean Flag parsing & default values\n";

    wavex::cli::CliParser parser("test_app", "Test application for WaveX CLI");
    parser.add_flag("verbose", 'v', "Enable verbose output")
            .add_flag("debug", "Enable debug mode");

    // Default state before parsing
    check(!parser.has("verbose"), "Flag 'verbose' is false initially");
    check(!parser.get_bool("verbose"), "get_bool('verbose') is false initially");

    // Parse arguments: -v --debug
    std::vector<std::string_view> args = {"-v", "--debug"};
    auto res = parser.parse(args);

    check(res.ok(), "Parse flags succeeded");
    check(parser.has("verbose"), "Flag 'verbose' specified via -v");
    check(parser.get_bool("verbose"), "get_bool('verbose') returns true");
    check(parser.has("debug"), "Flag 'debug' specified via --debug");
    check(parser.get_bool("debug"), "get_bool('debug') returns true");
}

// ─── Test 2: Value Options & Syntax Variations ────────────────────────────────

void test_cli_value_options() {
    std::cout << "\n[Test 2] CLI Value options (--option val, --option=val, -o val)\n";

    wavex::cli::CliParser parser("wavex_server", "WaveX HTTP Server");
    parser.add_option("port", 'p', "Server port to listen on", "8080")
            .add_option("host", 'h', "Server host address", "127.0.0.1")
            .add_option("workers", 'w', "Thread pool worker count", "4");

    std::vector<std::string_view> args = {"--port", "9090", "--host=0.0.0.0", "-w", "8"};
    auto res = parser.parse(args);

    check(res.ok(), "Parse value options succeeded");
    check(parser.get_int("port") == 9090, "Parsed --port 9090 as integer 9090");
    check(parser.get_string("host") == "0.0.0.0", "Parsed --host=0.0.0.0 as string '0.0.0.0'");
    check(parser.get_size_t("workers") == 8, "Parsed -w 8 as size_t 8");
}

// ─── Test 3: Type Getter Helpers & Fallbacks ──────────────────────────────────

void test_cli_type_getters() {
    std::cout << "\n[Test 3] CLI Type conversion getters & fallback defaults\n";

    wavex::cli::CliParser parser;
    parser.add_option("int_val", "Integer value", "42")
            .add_option("double_val", "Double value", "3.14159")
            .add_option("invalid_int", "Invalid integer", "abc");

    auto res = parser.parse({});
    check(res.ok(), "Empty parse using defaults succeeded");

    check(parser.get_int("int_val") == 42, "get_int returns default 42");
    check(parser.get_double("double_val") == 3.14159, "get_double returns default 3.14159");
    check(parser.get_int("invalid_int", 100) == 100, "get_int fallback returns specified fallback on parse error");
    check(parser.get_int("non_existent", 55) == 55, "get_int fallback for non-existent option returns fallback");
}

// ─── Test 4: Positional Arguments & Extra Positionals ─────────────────────────

void test_cli_positional_arguments() {
    std::cout << "\n[Test 4] CLI Positional arguments & unhandled positionals\n";

    wavex::cli::CliParser parser;
    parser.add_option("port", 'p', "Port", "8080")
            .add_positional("config", "Config file path", true)
            .add_positional("log_dir", "Log directory path", false);

    std::vector<std::string_view> args = {"-p", "3000", "/etc/wavex/app.json", "/var/log/wavex", "extra1", "extra2"};
    auto res = parser.parse(args);

    check(res.ok(), "Parse with positional arguments succeeded");
    check(parser.get_int("port") == 3000, "Option -p 3000 parsed");
    check(parser.get_string("config") == "/etc/wavex/app.json", "Positional 'config' extracted");
    check(parser.get_string("log_dir") == "/var/log/wavex", "Positional 'log_dir' extracted");

    const auto &extra = parser.extra_positionals();
    check(extra.size() == 2, "Captured 2 extra positional arguments");
    if (extra.size() == 2) {
        check(extra[0] == "extra1" && extra[1] == "extra2", "Extra positionals match 'extra1' and 'extra2'");
    }
}

// ─── Test 5: Required Option Validation & Error Messages ──────────────────────

void test_cli_required_validation() {
    std::cout << "\n[Test 5] CLI Required option & positional argument validation\n";

    wavex::cli::CliParser parser;
    parser.add_option("config", 'c', "Config file", "", true)
            .add_positional("target", "Target server", true);

    // Test missing required option
    std::vector<std::string_view> args1 = {"myserver"};
    auto res1 = parser.parse(args1);
    check(!res1.success, "Parse fails when required option --config is missing");
    check(!res1.error_message.empty(), "Error message generated for missing required option");

    // Test missing required positional
    wavex::cli::CliParser parser2;
    parser2.add_positional("target", "Target server", true);
    auto res2 = parser2.parse({});
    check(!res2.success, "Parse fails when required positional argument <target> is missing");
}

// ─── Test 6: Built-in Help Message Generation ─────────────────────────────────

void test_cli_help_message() {
    std::cout << "\n[Test 6] Built-in help message generation & --help handling\n";

    wavex::cli::CliParser parser("wavex_demo", "Interactive WaveX Demo Application");
    parser.add_flag("verbose", 'v', "Enable verbose output")
            .add_option("port", 'p', "HTTP listen port", "8080")
            .add_positional("input", "Input data file", true);

    std::vector<std::string_view> args = {"--help"};
    auto res = parser.parse(args);

    check(res.help_requested, "Help requested flag set when --help is supplied");
    check(!res.ok(), "ok() returns false when help is requested (to prevent execution)");

    std::string help_str = parser.help_message();
    check(help_str.find("Usage: wavex_demo") != std::string::npos, "Help contains program usage line");
    check(help_str.find("--verbose") != std::string::npos, "Help contains --verbose option");
    check(help_str.find("--port") != std::string::npos, "Help contains --port option");
    check(help_str.find("<input>") != std::string::npos, "Help contains required positional <input>");
}

// ─── main ─────────────────────────────────────────────────────────────────────

int main() {
    std::cout << "=== WaveX CliParser Unit Tests ===\n";

    test_cli_flags();
    test_cli_value_options();
    test_cli_type_getters();
    test_cli_positional_arguments();
    test_cli_required_validation();
    test_cli_help_message();

    std::cout << "\n" << tests_passed << "/" << tests_run << " tests passed.\n";
    return tests_passed == tests_run ? 0 : 1;
}
