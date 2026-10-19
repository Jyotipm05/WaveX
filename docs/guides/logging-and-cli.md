# Logging & Command-Line Parsing

Two small utilities used by the dev servers and available to your own applications.

## Logging

Zero-macro, high-performance logging with automatic `std::source_location` call-site capture and ANSI terminal colors:

```cpp
#include <wavex/Base/Logger.hpp>

int main() {
    // Configure minimum log level (TRACE, DEBUG, INFO, WARN, ERROR, FATAL)
    wavex::base::Logger::instance().set_level(wavex::base::LogLevel::DEBUG);

    // Enable or disable ANSI terminal colors (enabled by default)
    wavex::base::Logger::instance().set_colored(true);

    // Modern functional logging API
    wavex::log::trace("Buffer allocated: {} bytes", 1024);
    wavex::log::debug("Route match resolved in {} us", 12.4);
    wavex::log::info("Worker pool online: {} threads", 8);
    wavex::log::warn("Slow database query detected ({}ms)", 235);
    wavex::log::error("Connection reset by peer: fd={}", 14);

    // Optional: direct logs to file or custom stream
    // wavex::base::Logger::instance().set_output("./logs/wavex.log");

    return 0;
}
```

## CLI parser

`-h` / `--help` is reserved by the parser, so use another short letter for host options.

```cpp
#include <wavex/CLI/CLI.hpp>
#include <iostream>

int main(int argc, char* argv[]) {
    wavex::cli::CliParser parser("wavex-tool", "WaveX High-Performance HTTP Server Utility");

    parser.add_flag("verbose", 'v', "Enable verbose logging")
          .add_option("host", 'H', "Host address to bind server", "127.0.0.1")
          .add_option("port", 'p', "Server port to listen on", "8080");

    auto result = parser.parse(argc, argv);
    if (!result.ok()) {
        if (result.help_requested) {
            parser.print_help();
            return 0;
        }
        std::cerr << "Error: " << result.error_message << "\n";
        return 1;
    }

    std::string host = parser.get_string("host");
    int port = parser.get_int("port", 8080);
    bool verbose = parser.get_bool("verbose");

    std::cout << "Starting server on http://" << host << ":" << port << " (verbose=" << verbose << ")\n";
    return 0;
}
```

---

**See also:** [Dev servers](../dev-servers.md)
