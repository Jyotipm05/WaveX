---
trigger: always_on
---

# WaveX Toolchain, Compiler & Build Invariants

This rule governs compiler baselines, CMake target linkage, compiler-specific workarounds, and build/test execution across WaveX.

---

## 1. Baseline Supported Toolchains
- WaveX requires C++23 features (explicit object parameter / deducing-this P0847R7 and formatted output `<print>` P2093R14) that define the supported compiler floor:
  - **GCC 16+**: Official GCC baseline supporting modern C++23 features and codegen optimizations.
  - **Clang 18.1+**: Strictly required for P0847R7 and `libc++` `<print>`. Never configure or support older Clang releases (Clang 16/17 lack deducing-this and `<print>`).
  - **MSVC 19.44+** (Visual Studio 2022 v17.10+ / Visual Studio 2026): The official MSVC toolset baseline supporting stable deducing-this and C++20 module partition aggregation.

---

## 2. Windows Winsock Linkage Invariant (MinGW ld vs. MSVC Pragmas)
- Asio's networking implementation relies on the Windows Sockets 2 API (`ws2_32.dll`, `mswsock.dll`).
- While MSVC auto-links these libraries via embedded `#pragma comment(lib, ...)` directives, MinGW GCC (GNU `ld`) **strictly ignores** them.
- Any CMake target linking or consuming WaveX networking on Windows MUST explicitly link `ws2_32` and `mswsock` under `if (WIN32)`:
  ```cmake
  if (WIN32)
      target_link_libraries(wavex PUBLIC ws2_32 mswsock)
  endif ()
  ```
- Specifying `PUBLIC` ensures all tests (`wavex_add_test`) and downstream executables transitively inherit Winsock flags without manual per-target specification.

---

## 3. Asio Completion Executor Purity & TS Deprecation
- NEVER define `ASIO_USE_TS_EXECUTOR_AS_DEFAULT=1` in any WaveX header file or CMake compile definition.
- Defining this macro switches `asio::any_completion_executor` from a modern C++20 polymorphic class into a legacy Networking TS `typedef executor any_completion_executor`.
- When mixed across translation units or placed after forward declarations in `handler_work.hpp`, it causes fatal compiler errors (`error C2371: 'asio::any_completion_executor': redefinition; different basic types` on MSVC) and ABI breakage on GCC.
- All WaveX components use native C++20 Asio completion handlers and executors exclusively.

---

## 4. Cross-Compiler C++20 Module Guarding (`WAVEX_USE_MODULE`)
- C++20 module interface targets (`FILE_SET wavex_modules TYPE CXX_MODULES`) and module tests must always be guarded behind `if (WAVEX_USE_MODULE)` in `CMakeLists.txt`.
- Due to upstream GCC compiler and assembler defects on Windows PE/COFF targets (GCC Bugzilla PR 98718, PR 99242, PR 105440, and ISO C++ paper P2808R0) where internal-linkage entities in Global Module Fragments duplicate across partitions:
  - `WAVEX_USE_MODULE` defaults to `ON` under MSVC.
  - `WAVEX_USE_MODULE` defaults to `OFF` under MinGW GCC / Clang until upstream toolchains stabilize.
- When `WAVEX_USE_MODULE` is `OFF`, WaveX compiles as a traditional header-based C++23 library with 100% feature parity.

---

## 5. Header AST Leanliness & Out-of-Line Non-Template Implementations (MSVC C1001 Mitigation)
- Non-template utility methods, file operations, parser helper functions, and complex member methods MUST be implemented out-of-line in separate `.cpp` translation units (e.g., `src/Utils/Multipart.cpp`, `src/Utils/AsyncFs.cpp`, `src/Utils/BinaryFile.cpp`, `src/Utils/TempFile.cpp`, `src/Client/HttpClient.cpp`).
- Avoid defining large non-template, procedural algorithms completely inline in header files (`.hpp`).
- In complex C++23 codebases, header-only implementation bloating triggers internal AST buffer exhaustion in the MSVC Front-End (`fatal error C1001: Internal compiler error in ParseTree`, VS Developer Community #11155591).
- Keeping headers lean guarantees fast compile times, prevents circular include bloat, and safeguards against MSVC C++23 front-end crashes.

---

## 6. Build & Test Invariants
- **Allowed**: Compile and run tests (`cmake --build --preset fast-dev`, `cmake --build --preset fast-dev-mingw`, `ctest --preset run-tests --output-on-failure`).
- **Prohibited**: NEVER run CMake configuration commands (`cmake --preset ...`, `cmake -B ...`). Only the user is allowed to configure the project. See [never-config-cmake.md](file:///d:/programming/Cpp-files/Projects/WaveX/.agents/rules/never-config-cmake.md).
