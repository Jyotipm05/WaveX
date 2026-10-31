# Building & Testing

## Requirements

| Tool         | Minimum                                                                                    |
|:-------------|:-------------------------------------------------------------------------------------------|
| Compiler     | GCC 16+, Clang 18.1+, or MSVC 19.44+ (C++23 with explicit object parameters and `<print>`) |
| CMake        | 4.0+ with the Ninja generator                                                              |
| Dependencies | Asio, nlohmann/json, RE2, OpenSSL (OpenSSL 3.5+ for QUIC/HTTP3); zlib is optional          |

Dependencies come from [vcpkg](https://vcpkg.io/) (`VCPKG_ROOT` set) or, if a package is not found, CMake fetches Asio, nlohmann/json and RE2 itself.

## Dependencies

| Library                                           | Purpose                                   | License      |
|:--------------------------------------------------|:------------------------------------------|:-------------|
| [Asio](https://think-async.com/Asio/)             | Async I/O and C++ coroutines (standalone) | BSL-1.0      |
| [nlohmann/json](https://github.com/nlohmann/json) | JSON parsing and serialization            | MIT          |
| [Google RE2](https://github.com/google/re2)       | Linear-time regex for route constraints   | BSD-3-Clause |
| [OpenSSL](https://www.openssl.org/)               | TLS 1.3, ALPN, QUIC TLS callbacks (3.5+)  | Apache-2.0   |
| [zlib](https://zlib.net/) *(optional)*            | Gzip / Deflate compression                | zlib         |

Full notices: [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md).

## CMake presets

```bash
git clone https://github.com/Jyotipm05/WaveX.git
cd WaveX
git checkout dev

# configure
cmake --preset test-profile        # Debug + tests
cmake --preset release             # Release, no tests
cmake --preset asan                # ASan + UBSan + LSan
cmake --preset tsan                # ThreadSanitizer (GCC/Clang only)

# build
cmake --build --preset fast-dev        # 10 parallel jobs
cmake --build --preset max-dev         # all cores
cmake --build --preset fast-release

# test
ctest --preset run-tests --output-on-failure
ctest --preset run-tests -R test_server_keepalive --output-on-failure
ctest --preset asan
ctest --preset tsan
```

MinGW GCC on Windows uses the `-mingw` variants: `cmake --preset test-profile-mingw`, `cmake --build --preset fast-dev-mingw`, `ctest --preset run-tests-mingw`.

## CMake options

| Option                                | Default                            | Meaning                                                   |
|:--------------------------------------|:-----------------------------------|:----------------------------------------------------------|
| `WAVEX_TEST`                          | `OFF`                              | Build the test and dev-server executables                 |
| `WAVEX_TEST_ASAN` / `WAVEX_TEST_TSAN` | `OFF`                              | Sanitizer builds (mutually exclusive; imply `WAVEX_TEST`) |
| `WAVEX_ENABLE_TLS`                    | `ON`                               | TLS 1.3 via OpenSSL (`WAVEX_HAS_SSL`)                     |
| `WAVEX_USE_MODULE`                    | `ON` with MSVC, otherwise `OFF`    | Build and export the C++ modules (`import wavex;`)        |
| `WAVEX_USE_LLD`                       | `OFF` (the dev presets turn it on) | Use `lld` / `lld-link`                                    |
| `WAVEX_WIN32_WINNT`                   | auto                               | Windows target version for Asio                           |

Zlib is detected automatically; without it the compression helpers are compiled out (`WAVEX_HAS_ZLIB=0`).

## Using WaveX from your project

```cmake
include(FetchContent)
FetchContent_Declare(wavex GIT_REPOSITORY https://github.com/Jyotipm05/WaveX.git GIT_TAG dev)
FetchContent_MakeAvailable(wavex)
target_link_libraries(my_app PRIVATE wavex)
```

```c++
#include <wavex/wavex.hpp>   // headers
// or
import wavex;                // modules (WAVEX_USE_MODULE=ON)
```

## Supported toolchains

WaveX is a pure C++23 framework requiring a conforming modern C++23 compiler and CMake 4.0+.

| Compiler / Toolchain                         | Minimum Version    |  C++20 Modules (`WAVEX_USE_MODULE`)  | Header Usage (`#include <wavex/wavex.hpp>`) |
|:---------------------------------------------|:-------------------|:------------------------------------:|:-------------------------------------------:|
| **MSVC** (Visual Studio 2022 / 2026)         | 19.44+ (VS 17.10+) |    ✅ Supported (`ON` by default)    |                ✅ Supported                 |
| **MinGW GCC** (MSYS2 / winlibs UCRT / POSIX) | 16+                | ⚠️ Recommended `OFF` (compiler bugs) |    ✅ Fully Supported (`OFF` by default)    |
| **Clang** / **Apple Clang**                  | 18.1+              |             Experimental             |                ✅ Supported                 |

---

## Build speed

- `WAVEX_TEST_PCH` (default `ON`, GCC/Clang without modules): the tests share one precompiled `<wavex/wavex.hpp>`. Turn it off if a sanitizer or compiler flag change makes the precompiled header fail to load (`-Winvalid-pch`).
- Without `WAVEX_USE_MODULE`, CMake's module dependency scan is skipped (`CMAKE_CXX_SCAN_FOR_MODULES OFF`), so no scan step runs per source file and Clang does not need `clang-scan-deps`.
- Keep heavy code out of headers: anything non-template in a header is compiled again by every translation unit that includes it. `ComposedHttpServer::run()` is defined in `src/Server/ComposedHttpServer.cpp` for this reason.
- Use `ccache` (`-DCMAKE_CXX_COMPILER_LAUNCHER=ccache`) and, for local builds, a fast linker (`-DCMAKE_EXE_LINKER_FLAGS=-fuse-ld=mold` or `lld`). Without a system RE2 the first configure also builds Abseil and RE2 (about 270 build steps); a warm ccache removes that cost.
- CI Debug jobs build with `-g1` (`-DCMAKE_CXX_FLAGS_DEBUG=-g1`): line tables are kept for backtraces and sanitizer reports, but local-variable debug info is dropped. Measured on two test targets, this cut compile time by about 11% and test binaries by about 36%. Use plain `-g` locally when stepping through code in a debugger.
- Install the distro RE2 to skip those steps: `sudo apt install libre2-dev` (Ubuntu 24.04 ships RE2 2023-03-01, which does not need Abseil). CMake finds it through pkg-config when there is no CMake package, and a clean build drops from 369 to 101 steps. The GCC and Clang CI jobs do this. Sanitizer builds should keep building RE2 from source so it is instrumented too.

### Portability workflow

`.github/workflows/portability.yml` builds and tests on Windows (MSVC, vcpkg) and macOS (Homebrew LLVM) when started manually and once a week. It is informational: the jobs use `continue-on-error`, so they never block a pull request, and they have not been run yet, so expect to adjust them on first use. Move a job into `ci.yml` once it passes reliably.

---

## Compiler-specific notes

### Clang

Clang is verified in CI as **Clang 20 with libstdc++** (header usage). Clang 18 and 19 on Linux fail against libstdc++ because they report `__cpp_concepts` as `201907`, which makes libstdc++ hide `std::expected` (WaveX uses it). With those versions, build against libc++ instead (`-stdlib=libc++`, not covered by CI), or use Clang 20+.

### MinGW GCC (Windows)

When compiling WaveX under MinGW GCC on Windows, please observe the following compiler-specific behaviors and known upstream GCC/GNU issues:

#### C++20 Module Assembly Collision on PE/COFF (ISO P2808R0)

- **Compiler Bug**: GCC's `-fmodules-ts` on Windows (PE/COFF targets) exhibits a known defect when aggregating multiple module partitions (`export import :partition;`) that include third-party headers in their Global Module Fragment (`module;`). Internal-linkage entities (such as Asio customization point objects `query`, `prefer`, and `require` in unnamed namespaces) are duplicated across partition assembly outputs, causing the GNU assembler (`as`) to fail with:

  ```text
  Error: symbol `_ZN4asio12_GLOBAL__N_1L5queryE' is already defined
  ```

- **Upstream Bugzilla References**:
  - **[GCC Bugzilla PR 98718](https://gcc.gnu.org/bugzilla/show_bug.cgi?id=98718)**: *Internal linkage in the global module fragment causes multiple definition errors.*
  - **[GCC Bugzilla PR 99242](https://gcc.gnu.org/bugzilla/show_bug.cgi?id=99242)**: *Duplicate symbols emitted for unnamed-namespace entities across module partitions on PE/COFF.*
  - **[GCC Bugzilla PR 105440](https://gcc.gnu.org/bugzilla/show_bug.cgi?id=105440)**: *Multiple definition of symbols with internal linkage from module partitions on Windows.*
  - **ISO C++ Standards Proposal**: [P2808R0: "Internal linkage in the global module"](https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2023/p2808r0.html).

- **Guideline & Mitigation**:
  - WaveX introduces the CMake option `-DWAVEX_USE_MODULE=OFF` (enabled by default in `fast-dev-mingw`).
  - When targeting MinGW GCC, compile with `WAVEX_USE_MODULE=OFF` and consume WaveX via `#include <wavex/wavex.hpp>`. The traditional header-based library is 100% feature-complete with identical performance.

#### Winsock Socket Library Linkage

- **Compiler Difference**: MSVC automatically resolves Winsock functions (`WSAStartup`, `WSACleanup`, `WSASend`, `WSARecv`, `closesocket`, etc.) via `#pragma comment(lib, "ws2_32.lib")` embedded in Asio's headers. **MinGW's GNU `ld` ignores `#pragma comment(lib, ...)` directives.**

- **WaveX Solution**: WaveX's `CMakeLists.txt` automatically links `ws2_32` and `mswsock` to `wavex PUBLIC` on all Windows platforms, ensuring that all consumer binaries and test suites link without unresolved symbol errors.

#### Pthreads Support for Asio

- **Requirement**: MinGW GCC builds with POSIX threading require `-DASIO_HAS_PTHREADS=1` to enable thread synchronization in Asio. WaveX's `CMakeLists.txt` automatically injects this definition when `MINGW` is detected.

#### Asio C++20 Completion Executors

- **Invariant**: Never define `-DASIO_USE_TS_EXECUTOR_AS_DEFAULT=1`. Defining this macro forces Asio to revert `any_completion_executor` to a Networking TS typedef, causing type redefinition conflicts (`error C2371` under MSVC and ABI mismatches under GCC) with C++20 coroutine awaitables.

---

### MSVC / Visual Studio (Windows)

#### Rare Internal Compiler Error C1001 in Header-Heavy ASTs ([VS Developer Community #11155591](https://developercommunity.visualstudio.com/t/MSVC-1444-compiler-error-regarding-C100/11155591))

- **Rare Compiler Defect**: In rare scenarios when compiling complex, header-heavy C++23 template codebases (particularly involving deducing-this and extensive template metaprogramming) using MSVC toolsets 14.44 (VS 17.10+) through 19.51 previews, MSVC's C++ front-end parser can encounter an internal AST parse-tree buffer exhaustion:

  ```text
  fatal error C1001: Internal compiler error. (compiler file '...\CxxFE\sl\p1\c\ParseTree...')
  ```

- **Tracked Issue**: [Developer Community #11155591: MSVC 14.44 compiler error regarding C1001](https://developercommunity.visualstudio.com/t/MSVC-1444-compiler-error-regarding-C100/11155591).
- **Status**: Confirmed and marked as **Fixed - Pending Release** by Microsoft compiler engineers.
- **Architectural Safeguard in WaveX**: While this bug only surfaces in edge cases, WaveX proactively avoids it by keeping non-template member function and method implementations out of header files and placing them into dedicated `.cpp` translation units (such as [`src/Utils/Multipart.cpp`](../src/Utils/Multipart.cpp), [`src/Utils/AsyncFs.cpp`](../src/Utils/AsyncFs.cpp), [`src/Utils/BinaryFile.cpp`](../src/Utils/BinaryFile.cpp), and [`src/Client/HttpClient.cpp`](../src/Client/HttpClient.cpp)), ensuring header ASTs remain shallow and compiler memory stays well within bounds.

---

---

**See also:** [Dev servers & cURL](dev-servers.md) · [Contributing](../CONTRIBUTING.md)
