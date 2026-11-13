# Copyright (c) 2026 Jyotipriya Mondal
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

# Test helper and registrations. Included from the root CMakeLists.txt (not add_subdirectory), so test targets and
# their working directory stay where they have always been. Needs the sanitizer variables set by the root file.
set(WAVEX_TESTS_DIR "${CMAKE_CURRENT_LIST_DIR}")

# -----------------------------------------------------------------------
# Helper: register a test executable, linking against wavex.
# Sanitizer flags are inherited transitively via PUBLIC on wavex above.
# -----------------------------------------------------------------------
# Every test includes <wavex/wavex.hpp>; parsing it dominates each test's compile time. One precompiled
# copy is built by wavex_test_pch and reused by every test whose compile flags match (no per-test DEFINES).
# Skipped for modules and MSVC, where the flags/PCH rules differ and the modules are imported instead.
if (WAVEX_TEST_PCH AND NOT WAVEX_USE_MODULE AND NOT MSVC)
    file(WRITE "${CMAKE_BINARY_DIR}/wavex_test_pch.cpp" "// precompiled header donor for the tests\n")
    add_library(wavex_test_pch STATIC "${CMAKE_BINARY_DIR}/wavex_test_pch.cpp")
    target_link_libraries(wavex_test_pch PRIVATE wavex)
    target_compile_options(wavex_test_pch PRIVATE -UNDEBUG)
    target_precompile_headers(wavex_test_pch PRIVATE <wavex/wavex.hpp>)
endif ()

# wavex_test_group(<name>): tests registered after this call get the ctest label <name>
# (`ctest -L routing`). Plain variable, so it applies to the rest of the including scope.
macro(wavex_test_group name)
    set(WAVEX_TEST_GROUP "${name}")
endmacro()

# wavex_add_test(<target> <source relative to tests/> [DEFINES <defs>...])
# The target name is also the ctest name; keep it stable (CI and `ctest -R` use it).
function(wavex_add_test test_name source)
    cmake_parse_arguments(ARG "" "" "DEFINES" ${ARGN})
    add_executable(${test_name} "${WAVEX_TESTS_DIR}/${source}")
    target_link_libraries(${test_name} PRIVATE wavex)
    if (TARGET wavex_test_pch AND NOT ARG_DEFINES)
        target_precompile_headers(${test_name} REUSE_FROM wavex_test_pch)
    endif ()
    # The tests are plain assert()-based and some asserts wrap the call under test, so they must never be
    # compiled out: undo the -DNDEBUG that Release/RelWithDebInfo add.
    target_compile_options(${test_name} PRIVATE $<IF:$<CXX_COMPILER_ID:MSVC>,/UNDEBUG,-UNDEBUG>)
    if (ARG_DEFINES)
        target_compile_definitions(${test_name} PRIVATE ${ARG_DEFINES})
    endif ()
    add_test(NAME ${test_name} COMMAND ${test_name})
    # Most tests bind fixed loopback ports; the lock makes `ctest -j N` safe without per-test ports.
    set_tests_properties(${test_name} PROPERTIES RESOURCE_LOCK wavex_loopback_ports TIMEOUT 120)
    if (WAVEX_SAN_COMPILE_FLAGS)
        set_tests_properties(${test_name} PROPERTIES
                LABELS "${WAVEX_SAN_LABEL}"
                ENVIRONMENT "${WAVEX_SAN_ENV}"
        )
    endif ()
    if (WAVEX_TEST_GROUP)
        set_property(TEST ${test_name} APPEND PROPERTY LABELS "${WAVEX_TEST_GROUP}")
    endif ()
endfunction()

# ---------------------------------------------------------------------------
# Test registrations, grouped like the directories. `ctest -L <group>` runs one group:
#   base  routing  protocols  server  client  content  checks
# (The last group is not called `build/` because the repository's .gitignore ignores any directory with that name.)
# ---------------------------------------------------------------------------
wavex_test_group(base)
wavex_add_test(wavex_flat_map_tests base/test_flat_map.cpp)
wavex_add_test(wavex_request_arena_tests base/test_request_arena.cpp)
wavex_add_test(wavex_executor_tests base/test_executor.cpp)
wavex_add_test(wavex_spawn_blocking_tests base/test_spawn_blocking.cpp)
wavex_add_test(wavex_async_fs_tests base/test_async_fs.cpp)
wavex_add_test(wavex_temp_file_tests base/test_temp_file.cpp)
wavex_add_test(wavex_cli_tests base/test_cli.cpp)
wavex_add_test(wavex_logger_tests base/test_logger_modern.cpp)
wavex_add_test(wavex_logger_async_tests base/test_logger_async.cpp)
wavex_add_test(wavex_dns_tests base/test_dns.cpp)

wavex_test_group(routing)
wavex_add_test(wavex_static_router_tests routing/test_static_router.cpp)
wavex_add_test(wavex_dynamic_router_cmp_tests routing/test_dynamic_router_cmp.cpp)
wavex_add_test(wavex_ctregex_tests routing/test_ctregex.cpp)
wavex_add_test(wavex_chainable_tests routing/test_chainable.cpp)
wavex_add_test(wavex_mw_tests routing/test_middleware.cpp)
wavex_add_test(wavex_method_template_tests routing/test_method_template.cpp)
wavex_add_test(wavex_not_found_tests routing/test_not_found.cpp)

wavex_test_group(protocols)
wavex_add_test(wavex_protocol_traits_tests protocols/test_protocol_traits.cpp)
wavex_add_test(wavex_http2_codec_tests protocols/test_http2_codec.cpp)
wavex_add_test(wavex_http2_session_tests protocols/test_http2_session.cpp)
wavex_add_test(wavex_websocket_tests protocols/test_websocket.cpp)
if (WAVEX_HAS_SSL)
    wavex_add_test(wavex_quic_tests protocols/test_quic.cpp)
    wavex_add_test(wavex_qpack_tests protocols/test_qpack.cpp)
    wavex_add_test(wavex_http3_tests protocols/test_http3.cpp)
    wavex_add_test(wavex_webtransport_tests protocols/test_webtransport.cpp)
endif ()

wavex_test_group(server)
wavex_add_test(wavex_server_tests server/test_server.cpp)
wavex_add_test(wavex_server_chunked_tests server/test_server_chunked.cpp)
wavex_add_test(wavex_server_keepalive_tests server/test_server_keepalive.cpp)
wavex_add_test(wavex_request_limits_tests server/test_request_limits.cpp)
wavex_add_test(wavex_connection_tracker_tests server/test_connection_tracker.cpp)
if (WAVEX_HAS_SSL)
    wavex_add_test(wavex_composed_static_tests server/test_composed_static.cpp)
endif ()

wavex_test_group(client)
wavex_add_test(wavex_client_tests client/test_client.cpp
        DEFINES PROJECT_DIR="${CMAKE_SOURCE_DIR}"
)
wavex_add_test(wavex_client_file_upload_tests client/test_client_file_upload.cpp)
if (WAVEX_HAS_SSL)
    wavex_add_test(wavex_http3_client_tests client/test_http3_client.cpp)
    wavex_add_test(wavex_client_streaming_tests client/test_client_streaming.cpp)
endif ()

wavex_test_group(content)
wavex_add_test(wavex_compression_tests content/test_compression.cpp)
wavex_add_test(wavex_multipart_tests content/test_multipart.cpp)

wavex_test_group(checks)
if (WAVEX_USE_MODULE)
    wavex_add_test(wavex_tests checks/test_module_smoke.cpp)
endif ()
# DEFINES keeps this test off the shared precompiled <wavex/wavex.hpp>, which would defeat the check.
wavex_add_test(wavex_include_hygiene_tests checks/test_include_hygiene.cpp DEFINES WAVEX_INCLUDE_HYGIENE_TEST=1)
