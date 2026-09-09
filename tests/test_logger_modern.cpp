#include <wavex/wavex.hpp>
#include <iostream>
#include <sstream>
#include <cassert>
#include <string>

int main() {
    std::cout << "[Test] Running Modern Logger unit tests...\n";

    std::ostringstream oss;
    auto &logger = wavex::base::Logger::instance();
    logger.set_output(oss);
    logger.set_colored(false); // disable ANSI for deterministic string testing
    logger.set_level(wavex::base::LogLevel::TRACE);

    // Test 1: Modern zero-macro functions with source location
    // namespace wxlog = wavex::log;

    wxlog::trace("Trace message: {}", 42);
    wxlog::debug("Debug message: {}", "details");
    wxlog::info("Info message: status={}", 200);
    wxlog::warn("Warn message: disk space low");
    wxlog::error("Error message: code={}", 500);

    std::string output = oss.str();
    std::cout << "--- Captured Log Output ---\n" << output << "---------------------------\n";

    // Verify presence of tags and source file location
    assert(output.find("[TRACE]") != std::string::npos);
    assert(output.find("[DEBUG]") != std::string::npos);
    assert(output.find("[INFO ]") != std::string::npos);
    assert(output.find("[WARN ]") != std::string::npos);
    assert(output.find("[ERROR]") != std::string::npos);
    assert(output.find("Trace message: 42") != std::string::npos);
    assert(output.find("test_logger_modern.cpp") != std::string::npos);

    // Test 2: Level Filtering
    oss.str("");
    oss.clear();
    logger.set_level(wavex::base::LogLevel::WARN);

    wxlog::debug("Should NOT appear");
    wxlog::info("Should NOT appear");
    wxlog::warn("Should APPEAR");
    wxlog::error("Should ALSO APPEAR");

    std::string filtered = oss.str();
    assert(filtered.find("Should NOT appear") == std::string::npos);
    assert(filtered.find("Should APPEAR") != std::string::npos);
    assert(filtered.find("Should ALSO APPEAR") != std::string::npos);

    // Test 3: Legacy macro backward compatibility
    oss.str("");
    oss.clear();
    WX_LOG_WARN("Legacy macro warning test: {}", "ok");
    std::string legacy_out = oss.str();
    assert(legacy_out.find("Legacy macro warning test: ok") != std::string::npos);
    assert(legacy_out.find("test_logger_modern.cpp") != std::string::npos);

    // Restore logger to std::cerr
    logger.set_output(std::cerr);
    logger.set_colored(true);
    logger.set_level(wavex::base::LogLevel::INFO);

    // Demonstration of colored output to stderr
    wxlog::info("Modern colorized logger initialized cleanly!");

    std::cout << "[Test] Modern Logger tests PASSED successfully!\n";
    return 0;
}
