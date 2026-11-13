# Copyright (c) 2026 Jyotipriya Mondal
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

# Interactive Postman dev servers (see docs/dev-servers.md). Built together with the tests; not registered with ctest.

add_executable(wavex_postman_http1_server ${CMAKE_CURRENT_LIST_DIR}/postman_demo_http1_server.cpp)
target_link_libraries(wavex_postman_http1_server PRIVATE wavex)
target_compile_definitions(wavex_postman_http1_server PRIVATE PROJECT_DIR="${CMAKE_SOURCE_DIR}")

add_executable(wavex_postman_http2_server ${CMAKE_CURRENT_LIST_DIR}/postman_demo_http2_server.cpp)
target_link_libraries(wavex_postman_http2_server PRIVATE wavex)
target_compile_definitions(wavex_postman_http2_server PRIVATE PROJECT_DIR="${CMAKE_SOURCE_DIR}")

if (WAVEX_HAS_SSL)
    add_executable(wavex_postman_quic_server ${CMAKE_CURRENT_LIST_DIR}/postman_demo_quic_server.cpp)
    target_link_libraries(wavex_postman_quic_server PRIVATE wavex)
    target_compile_definitions(wavex_postman_quic_server PRIVATE PROJECT_DIR="${CMAKE_SOURCE_DIR}")

    add_executable(wavex_postman_http3_server ${CMAKE_CURRENT_LIST_DIR}/postman_demo_http3_server.cpp)
    target_link_libraries(wavex_postman_http3_server PRIVATE wavex)
    target_compile_definitions(wavex_postman_http3_server PRIVATE PROJECT_DIR="${CMAKE_SOURCE_DIR}")
endif ()
