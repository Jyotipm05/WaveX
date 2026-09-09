cmake_minimum_required(VERSION 4.0)
project(wavex VERSION 0.3.0 LANGUAGES CXX)

# ===========================================================================
#  Header Configuration
# ===========================================================================
# Configure wavex.hpp.in to replace @PROJECT_VERSION@ with actual version
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/include/wavex/wavex.hpp.in"
    "${CMAKE_CURRENT_BINARY_DIR}/include/wavex/wavex.hpp"
    @ONLY
)

# ===========================================================================
#  Compiler & Tooling Setup
# ===========================================================================
set(CMAKE_EXPORT_COMPILE_COMMANDS ON) # Required for Clangd
include(GNUInstallDirs)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Override MSVC's -external:I flag → plain -I so compile_commands.json uses
# standard flags that clangd can parse. vcpkg passes all system includes
# (asio, nlohmann, re2, OpenSSL) via -external:I which clangd silently ignores.
#if (MSVC)
#    set(CMAKE_INCLUDE_SYSTEM_FLAG_CXX "-I ")
#endif ()

option(WAVEX_TEST      "Build tests for the wavex library"                           OFF)
option(WAVEX_TEST_TSAN "Build tests with Thread Sanitizer (TSan) only"              OFF)
option(WAVEX_TEST_ASAN "Build tests with Address + UB + Leak Sanitizers (ASan+UBSan+LSan)" OFF)

# TSan and ASan/UBSan are mutually exclusive — the runtimes conflict.
if (WAVEX_TEST_TSAN AND WAVEX_TEST_ASAN)
    message(FATAL_ERROR
        "WAVEX_TEST_TSAN and WAVEX_TEST_ASAN cannot both be ON. "
        "Thread Sanitizer and Address Sanitizer runtimes are mutually exclusive."
    )
endif ()

# Enabling either sanitizer build implicitly enables the base test build.
if (WAVEX_TEST_TSAN OR WAVEX_TEST_ASAN)
    set(WAVEX_TEST ON)
endif ()

include(FetchContent)

# ===========================================================================
#  Dependencies (Vcpkg First, Git Fallback Second)
# ===========================================================================

# ---------------------------------------------------------------------------
# asio
# ---------------------------------------------------------------------------
find_package(asio CONFIG QUIET)

if (NOT asio_FOUND)
    message(STATUS "asio not found via find_package — fetching and patching like vcpkg")

    FetchContent_Declare(
            asio
            GIT_REPOSITORY https://github.com/chriskohlhoff/asio.git
            GIT_TAG asio-1-32-0
            GIT_SHALLOW TRUE
    )

    FetchContent_GetProperties(asio)
    if (NOT asio_POPULATED)
        FetchContent_Populate(asio)

        # Apply vcpkg's exact source-code patch
        set(ASIO_CONFIG_HPP "${asio_SOURCE_DIR}/asio/include/asio/detail/config.hpp")
        file(READ "${ASIO_CONFIG_HPP}" ASIO_CONFIG_CONTENTS)
        string(REPLACE
                "defined(ASIO_STANDALONE)"
                "!defined(WAVEX_DISABLE_ASIO_STANDALONE)"
                ASIO_CONFIG_CONTENTS "${ASIO_CONFIG_CONTENTS}")
        file(WRITE "${ASIO_CONFIG_HPP}" "${ASIO_CONFIG_CONTENTS}")

        # Recreate vcpkg's exact CMake target
        add_library(asio::asio INTERFACE IMPORTED GLOBAL)
        target_include_directories(asio::asio INTERFACE "${asio_SOURCE_DIR}/asio/include")

        find_package(Threads REQUIRED)
        target_link_libraries(asio::asio INTERFACE Threads::Threads)
    endif ()
endif ()

# ---------------------------------------------------------------------------
# nlohmann-json
# ---------------------------------------------------------------------------
find_package(nlohmann_json CONFIG QUIET)
if (NOT nlohmann_json_FOUND)
    message(STATUS "nlohmann_json not found via find_package — fetching from GitHub")
    FetchContent_Declare(nlohmann_json GIT_REPOSITORY https://github.com/nlohmann/json.git GIT_TAG v3.11.3 GIT_SHALLOW TRUE)
    set(JSON_BuildTests OFF CACHE INTERNAL "")
    set(JSON_Install ON CACHE INTERNAL "")
    FetchContent_MakeAvailable(nlohmann_json)
endif ()

# ---------------------------------------------------------------------------
# Google RE2 & Abseil (RE2 strictly requires Abseil)
# ---------------------------------------------------------------------------
find_package(re2 CONFIG QUIET)

if (NOT re2_FOUND)
    message(STATUS "re2 not found via find_package — fetching from GitHub")

    # 1. Fetch Abseil first if we don't have it
    find_package(absl CONFIG QUIET)
    if (NOT absl_FOUND)
        message(STATUS "absl not found — fetching from GitHub (Required by RE2)")
        set(ABSL_PROPAGATE_CXX_STD ON CACHE BOOL "" FORCE)
        set(ABSL_ENABLE_INSTALL ON CACHE BOOL "" FORCE)
        FetchContent_Declare(
                absl
                GIT_REPOSITORY https://github.com/abseil/abseil-cpp.git
                GIT_TAG 20240722.0 # Stable LTS
                GIT_SHALLOW TRUE
        )
        set(ABSL_BUILD_TESTING OFF CACHE INTERNAL "")
        set(ABSL_USE_GOOGLETEST_HEAD OFF CACHE INTERNAL "")
        FetchContent_MakeAvailable(absl)
    endif ()

    # 2. Fetch RE2
    set(RE2_BUILD_TESTING OFF CACHE INTERNAL "")
    FetchContent_Declare(
            re2
            GIT_REPOSITORY https://github.com/google/re2.git
            GIT_TAG 2024-07-02
            GIT_SHALLOW TRUE
    )
    FetchContent_MakeAvailable(re2)
endif ()

# ---------------------------------------------------------------------------
# OpenSSL (TLS 1.3 Support)
# ---------------------------------------------------------------------------
option(WAVEX_ENABLE_TLS "Enable TLS 1.3 support via OpenSSL" ON)

if (WAVEX_ENABLE_TLS)
    find_package(OpenSSL QUIET)
    if (OpenSSL_FOUND)
        message(STATUS "OpenSSL found: ${OPENSSL_VERSION}")
        set(WAVEX_HAS_SSL ON)
    else ()
        message(WARNING "OpenSSL requested but not found — TLS features will be compiled out.")
        set(WAVEX_HAS_SSL OFF)
    endif ()
else ()
    message(STATUS "WAVEX_ENABLE_TLS is OFF — compiling without TLS support.")
    set(WAVEX_HAS_SSL OFF)
endif ()

# ===========================================================================
#  Library Target
# ===========================================================================
add_library(wavex
        src/wavex.cpp
        src/protos/protos.cpp
        src/Base/Logger.cpp
        src/Base/Uri.cpp
        src/Base/Url.cpp
        src/Engine/Router.cpp
        src/Client/HttpClient.cpp
)

target_include_directories(wavex PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

# Link Dependencies
target_link_libraries(wavex PUBLIC
        asio::asio
        nlohmann_json::nlohmann_json
        re2::re2
)

target_compile_definitions(wavex PUBLIC ASIO_HAS_CO_AWAIT=1 ASIO_STANDALONE=1)

if (WIN32)
    target_compile_definitions(wavex PUBLIC _WIN32_WINNT=0x0A00)
endif ()

if (WAVEX_HAS_SSL)
    target_link_libraries(wavex PUBLIC OpenSSL::SSL OpenSSL::Crypto)
    target_compile_definitions(wavex PUBLIC WAVEX_HAS_SSL=1)
else ()
    target_compile_definitions(wavex PUBLIC WAVEX_HAS_SSL=0)
endif ()

# ===========================================================================
#  Clangd Header Registration
# ===========================================================================
# NOTE: Add any new headers here so Clangd correctly parses them!
target_sources(wavex
        PUBLIC FILE_SET public_headers TYPE HEADERS
        BASE_DIRS include
        FILES
        include/wavex/Base/Logger.hpp
        include/wavex/Base/Chainable.hpp
        include/wavex/Base/MiddleWare.hpp
        include/wavex/Base/MimeTypes.hpp
        include/wavex/Engine/Router.hpp
        include/wavex/Engine/HttpRouter.hpp
        include/wavex/protos/http/Methods.hpp
        include/wavex/protos/http/http.hpp
        include/wavex/protos/http/http1codec.hpp
        include/wavex/protos/http/http2codec.hpp
        include/wavex/protos/http/HttpRequest.hpp
        include/wavex/protos/http/HttpResponse.hpp
        include/wavex/Server/WorkStealingQueue.hpp
        include/wavex/Server/ThreadPool.hpp
        include/wavex/Server/TlsConfig.hpp
        include/wavex/Server/Server.hpp
        include/wavex/Client/HttpClient.hpp
        include/wavex/Cli/Cli.hpp
)

# C++ Modules
target_sources(wavex
        PUBLIC FILE_SET wavex_modules TYPE CXX_MODULES
        BASE_DIRS src
        FILES
        src/wavex.ixx
        src/Base/Logger.ixx
        src/Base/Chainable.ixx
        src/protos/protos.ixx
        src/protos/http/http.ixx
        src/protos/http/Methods.ixx
        src/protos/http/http1codec.ixx
        src/protos/http/http2codec.ixx
        src/protos/http/HttpRequest.ixx
        src/protos/http/HttpResponse.ixx
        src/Engine/Router.ixx
        src/Engine/HttpRouter.ixx
        src/Server/Server.ixx
        src/Server/WorkStealingQueue.ixx
        src/Server/ThreadPool.ixx
        src/Base/MiddleWare.ixx
        src/Client/HttpClient.ixx
        src/CLI/CLI.ixx
)

# ===========================================================================
#  Install Rules
# ===========================================================================
install(TARGETS wavex EXPORT WaveXTargets
        FILE_SET wavex_modules DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/wavex/modules"
        FILE_SET public_headers DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
        RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
        LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
        ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
)

# Install the configured wavex.hpp from the build directory
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/include/wavex/wavex.hpp" DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/wavex")

# If we used the Git fallback, we must ship the Asio headers to downstream consumers
if (NOT asio_FOUND)
    install(DIRECTORY "${asio_SOURCE_DIR}/asio/include/asio" DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}" FILES_MATCHING PATTERN "*.hpp" PATTERN "*.ipp")
    install(FILES "${asio_SOURCE_DIR}/asio/include/asio.hpp" DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}")
endif ()

install(EXPORT WaveXTargets FILE WaveXTargets.cmake NAMESPACE wavex:: DESTINATION "${CMAKE_INSTALL_DATADIR}/cmake/wavex")

include(CMakePackageConfigHelpers)
configure_package_config_file("${CMAKE_CURRENT_SOURCE_DIR}/cmake/WaveXConfig.cmake.in" "${CMAKE_CURRENT_BINARY_DIR}/WaveXConfig.cmake" INSTALL_DESTINATION "${CMAKE_INSTALL_DATADIR}/cmake/wavex")
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/WaveXConfig.cmake" DESTINATION "${CMAKE_INSTALL_DATADIR}/cmake/wavex")

# ===========================================================================
#  Quality of Life
# ===========================================================================
# Auto-copy compile_commands.json to project root for Clangd
#add_custom_target(clangd_sync ALL COMMAND ${CMAKE_COMMAND} -E copy_if_different "${CMAKE_BINARY_DIR}/compile_commands.json" "${CMAKE_SOURCE_DIR}/compile_commands.json" COMMENT "Syncing compile_commands.json for Clangd")

if (WAVEX_TEST)
    enable_testing()

    # -----------------------------------------------------------------------
    # Sanitizer flags — compiler-sensitive.
    # MSVC:       supports ASan only (/fsanitize=address). TSan is unavailable.
    # GCC/Clang:  full -fsanitize=thread | address,undefined,leak support.
    # Each sanitizer variant is a separate cmake configure (separate build dir)
    # so there is no need for duplicate library targets.
    # -----------------------------------------------------------------------
    if (WAVEX_TEST_TSAN)
        if (MSVC)
            message(FATAL_ERROR
                "[WaveX] WAVEX_TEST_TSAN is not supported with MSVC. "
                "Thread Sanitizer is only available with GCC or Clang."
            )
        endif ()
        message(STATUS "[WaveX] TSan build enabled (GCC/Clang)")
        set(WAVEX_SAN_COMPILE_FLAGS -fsanitize=thread -fno-omit-frame-pointer -g)
        set(WAVEX_SAN_LINK_FLAGS    -fsanitize=thread)
        set(WAVEX_SAN_ENV           "TSAN_OPTIONS=halt_on_error=1:second_deadlock_stack=1")
        set(WAVEX_SAN_LABEL         tsan)

    elseif (WAVEX_TEST_ASAN)
        if (MSVC)
            # MSVC ASan: no UBSan or LSan — address sanitizer only.
            # The runtime is linked automatically; no linker flag needed.
            message(STATUS "[WaveX] ASan build enabled (MSVC — address sanitizer only)")
            set(WAVEX_SAN_COMPILE_FLAGS /fsanitize=address /Zi)
            set(WAVEX_SAN_LINK_FLAGS    "")  # MSVC injects the ASan runtime automatically
        else ()
            message(STATUS "[WaveX] ASan+UBSan+LSan build enabled (GCC/Clang)")
            set(WAVEX_SAN_COMPILE_FLAGS -fsanitize=address,undefined,leak -fno-omit-frame-pointer -g)
            set(WAVEX_SAN_LINK_FLAGS    -fsanitize=address,undefined,leak)
        endif ()
        if (MSVC)
            # MSVC ASan does not support leak detection (detect_leaks=1) or detect_stack_use_after_return=1.
            set(WAVEX_SAN_ENV   "ASAN_OPTIONS=halt_on_error=1")
        else ()
            set(WAVEX_SAN_ENV   "ASAN_OPTIONS=halt_on_error=1:detect_leaks=1:strict_string_checks=1:detect_stack_use_after_return=1")
        endif ()
        set(WAVEX_SAN_LABEL asan)
    endif ()

    if (WAVEX_SAN_COMPILE_FLAGS)
        # Apply to the library so instrumented code paths are covered too.
        target_compile_options(wavex PUBLIC ${WAVEX_SAN_COMPILE_FLAGS})
        if (WAVEX_SAN_LINK_FLAGS)
            target_link_options(wavex PUBLIC ${WAVEX_SAN_LINK_FLAGS})
        endif ()
    endif ()

    # -----------------------------------------------------------------------
    # Helper: register a test executable, linking against wavex.
    # Sanitizer flags are inherited transitively via PUBLIC on wavex above.
    # -----------------------------------------------------------------------
    function(wavex_add_test test_name source)
        cmake_parse_arguments(ARG "" "" "DEFINES" ${ARGN})
        add_executable(${test_name} ${source})
        target_link_libraries(${test_name} PRIVATE wavex)
        if (ARG_DEFINES)
            target_compile_definitions(${test_name} PRIVATE ${ARG_DEFINES})
        endif ()
        add_test(NAME ${test_name} COMMAND ${test_name})
        if (WAVEX_SAN_COMPILE_FLAGS)
            set_tests_properties(${test_name} PROPERTIES
                LABELS       "${WAVEX_SAN_LABEL}"
                ENVIRONMENT  "${WAVEX_SAN_ENV}"
            )
        endif ()
        endfunction()

    # -----------------------------------------------------------------------
    # Test registrations
    # -----------------------------------------------------------------------
    wavex_add_test(wavex_tests                 tests/test1.cpp)
    wavex_add_test(wavex_mw_tests              tests/test_MW.cpp)
    wavex_add_test(wavex_method_template_tests tests/test_method_template.cpp)
    wavex_add_test(wavex_server_tests          tests/test_server.cpp)
    wavex_add_test(wavex_client_tests          tests/test_client.cpp
        DEFINES PROJECT_DIR="${CMAKE_SOURCE_DIR}"
    )
    wavex_add_test(wavex_server_chunked_tests  tests/test_server_chunked.cpp)
    wavex_add_test(wavex_cli_tests             tests/test_cli.cpp)
    wavex_add_test(wavex_chainable_tests       tests/test_chainable.cpp)
    wavex_add_test(wavex_logger_tests          tests/test_logger_modern.cpp)
    wavex_add_test(wavex_server_keepalive_tests tests/test_server_keepalive.cpp)
    wavex_add_test(wavex_not_found_tests        tests/test_not_found.cpp)
    wavex_add_test(wavex_http2_codec_tests      tests/test_http2_codec.cpp)

    # Unified CLI-driven Postman Dev Servers (HTTP/1.1 and HTTP/2)
    add_executable(wavex_postman_http1_server tests/postman_demo_http1_server.cpp)
    target_link_libraries(wavex_postman_http1_server PRIVATE wavex)
    target_compile_definitions(wavex_postman_http1_server PRIVATE PROJECT_DIR="${CMAKE_SOURCE_DIR}")

    add_executable(wavex_postman_http2_server tests/postman_demo_http2_server.cpp)
    target_link_libraries(wavex_postman_http2_server PRIVATE wavex)
    target_compile_definitions(wavex_postman_http2_server PRIVATE PROJECT_DIR="${CMAKE_SOURCE_DIR}")
endif ()