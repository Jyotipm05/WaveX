# Contributing to WaveX

First off, thank you for considering contributing to **WaveX**! Contributions from the community help make WaveX a faster, safer, and more robust C++23 coroutine backend framework.

This document provides guidelines, architectural principles, and instructions for building, testing, and submitting code to the repository.

---

## 📜 Table of Contents

- [Code of Conduct](#-code-of-conduct)
- [Architectural Principles](#-architectural-principles)
- [Getting Started](#-getting-started)
- [Documentation](#-documentation)
- [Build Presets & Sanitizers](#-build-presets--sanitizers)
- [Testing Guidelines](#-testing-guidelines)
- [Coding & Design Standards](#-coding--design-standards)
- [Submitting Pull Requests](#-submitting-pull-requests)
- [License](#-license)

---

## 🤝 Code of Conduct

We aim to foster an open, welcoming, and inclusive community. Please maintain respectful, constructive, and professional communication in all issues, pull requests, and discussions.

---

## 🏗 Architectural Principles

When contributing code to WaveX, please strictly adhere to the framework's core design rules:

### 1. C++23 "Deducing This" Zero-VTable Architecture

- Base abstractions in `wavex::base` (`Request`, `Response`) use C++23 explicit object parameters (`this Self&& self`) instead of template inheritance or CRTP to achieve compile-time static polymorphism.
- **Do not introduce virtual functions or v-tables** in request/response base classes. Keep objects lightweight without 64-bit `vptr` pointer overhead.

### 2. Base Class Layer Independence Rule

- Base abstractions in `wavex::base` (`Request`, `Response`, `MiddleWare`) **must remain protocol-agnostic**.
- Base classes **must never depend on, forward declare, or include derived protocol implementations** (such as `wavex::protos::http::HttpRequest` or `HttpResponse`).
- Generic engine components (`Server`, `Router`) use template parameters (`ReqT`, `ResT`, `Proto`) to operate on request/response types without hardcoding derived protocol details.

### 3. Coroutine-Native Pipeline

- All asynchronous pipeline logic must be coroutine-aware using Asio C++23 awaitables (`asio::awaitable<void>`, `co_await`, `co_return`).
- Middleware runners (`run_chain`) are linear and non-recursive to prevent stack overflow under deep middleware chains.

---

## 🚀 Getting Started

### Prerequisites

- **C++ Compiler**: GCC 16+, Clang 18.1+, or MSVC 19.44+ (needs C++23 explicit object parameters and `<print>`).
- **Build System**: CMake 4.0+ with Ninja.
- **Dependencies**: Asio (standalone), Google RE2, nlohmann/json, OpenSSL (3.5+ for QUIC/HTTP3); zlib is optional. Install through [vcpkg](https://vcpkg.io/) or let CMake fetch what is missing. See [docs/building.md](docs/building.md).

### Cloning & Building

```bash
# Clone the repository
git clone https://github.com/Jyotipm05/WaveX.git
cd WaveX

# Switch to the dev branch (all active development MUST happen on dev)
git checkout dev

# Configure a Debug build with tests enabled
cmake --preset test-profile

# Build the library, tests and dev servers
cmake --build --preset fast-dev

# Run the test suite
ctest --preset run-tests --output-on-failure
```

#### Sample TLS certificate and key

TLS and HTTP/3 tests expect `ssl/test.crt` and `ssl/test.key` (git-ignored). Generate them once:

```bash
mkdir -p ssl
openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 365 -subj "/CN=localhost" -keyout ssl/test.key -out ssl/test.crt
```

---

## 🧪 Build Presets & Sanitizers

WaveX provides pre-configured [`CMakePresets.json`](CMakePresets.json) targets for testing, code sanitization, and verification.

### Recommended CMake Presets

| Preset Name    | Purpose                                     | Command                                                             |
|:---------------|:--------------------------------------------|:--------------------------------------------------------------------|
| `test-profile` | Debug build with unit and integration tests | `cmake --preset test-profile`<br/>`cmake --build --preset fast-dev` |
| `asan`         | AddressSanitizer + UBSan + LSan             | `cmake --preset asan`<br/>`cmake --build build/asan`                |
| `tsan`         | ThreadSanitizer (GCC/Clang only)            | `cmake --preset tsan`<br/>`cmake --build build/tsan`                |

MinGW GCC on Windows: use the `-mingw` variants (`test-profile-mingw`, `fast-dev-mingw`, `run-tests-mingw`).

### Running Sanitizer Presets

> [!NOTE]
> **Sanitizer Compatibility Note**:
>
> - **AddressSanitizer (ASan)** and **ThreadSanitizer (TSan)** runtimes are mutually exclusive; run them in separate build configurations.
> - **TSan** is supported on GCC and Clang (not MSVC).
> - On MSVC, MSVC ASan flags are auto-injected (`/fsanitize=address /Zi`). Ensure `ASAN_OPTIONS` does not include unsupported platform flags like `detect_leaks=1` or `detect_stack_use_after_return=1` on MSVC.

```bash
# AddressSanitizer run
cmake --preset asan
cmake --build build/asan
ctest --preset asan

# ThreadSanitizer run (GCC/Clang)
cmake --preset tsan
cmake --build build/tsan
ctest --preset tsan
```

---

## 📋 Testing Guidelines

Every new feature, bug fix, or refactoring must be accompanied by relevant unit or integration tests.

### Running Test Suites

Execute all automated tests via CTest:

```bash
ctest --test-dir build --output-on-failure
```

Or via presets:

```bash
ctest --preset run-tests
```

### Interactive Manual Testing

For HTTP protocol testing or Postman verification, launch the interactive demo server:

```bash
./build/test-profile/wavex_postman_http1_server        # add .exe on Windows
# Or with TLS:
./build/test-profile/wavex_postman_http1_server --tls
```

Test endpoints against `http://127.0.0.1:8080`. All four dev servers and their flags are described in [docs/dev-servers.md](docs/dev-servers.md).

---

## 📚 Documentation

User-facing documentation lives in [`docs/`](docs/README.md); the root `README.md` is a short landing page and should stay that way.

- New or changed public API: update the matching guide in `docs/guides/` and, if maturity changes, [`docs/components.md`](docs/components.md).
- New file or directory: update [`docs/project-structure.md`](docs/project-structure.md).
- User-visible change: add a line under **Unreleased** in [`CHANGELOG.md`](CHANGELOG.md).
- Code samples in docs must compile against the current headers; prefer copying from a passing test or dev server.

### AI-assisted contributions

[`.agents/rules/`](.agents/rules) and [`.agents/skills/wavex-development/`](.agents/skills/wavex-development/SKILL.md) hold the project's conventions, QUIC and test invariants, and architecture references. Read them (or point your coding agent at them) before changing the transport, codecs or memory model. The rules there are authoritative for coding conventions; this file is authoritative for process.

---

## 🎨 Coding & Design Standards

1. **Modern C++23**: Leverage modern features (`std::string_view`, concepts, coroutines, `[[nodiscard]]`, `[[unlikely]]`).
2. **Explicit Signatures**: Verify exact function signatures and template parameters before modifying APIs.
3. **No Unintended Side Effects**: Ensure public API changes are reflected across all call sites and test suites.
4. **Documentation Integrity**: Maintain existing docstrings and comments. Add Doxygen-style `@brief` comments for new public interfaces.

---

## 📤 Submitting Pull Requests

> [!IMPORTANT]
> **Target Branch Rule**: All contributions, feature branches, and Pull Requests **MUST target the `dev` branch** (`git checkout dev`). Do not branch off or submit PRs directly against `main`.

1. **Fork & Branch**: Checkout `dev` and create your feature branch:

   ```bash
   git checkout dev
   git pull origin dev
   git checkout -b feature/your-feature-name
   ```

2. **Commit Guidelines**: Write clear, descriptive commit messages describing the *why* behind changes.
3. **Pre-PR Checklist**:
   - [ ] Project compiles cleanly without warnings or errors. (Asio platform-specific warnings may arise and can be ignored, but mention them in the PR beforehand.)
   - [ ] Automated tests pass (`ctest --preset run-tests`).
   - [ ] Sanitizers (ASan/TSan) run clean without leaks or race conditions.
   - [ ] Code adheres to C++23 deducing this zero-vtable and base-class layer independence rules.
   - [ ] Documentation updated: docstrings, the relevant page in `docs/`, and `CHANGELOG.md` (see [Documentation](#-documentation)).
4. **Submit PR**: Open a Pull Request targeting the **`dev`** branch with a summary of changes and testing performed.

---

## ⚖️ License

By contributing to WaveX, you agree that your contributions will be licensed under the project's [Mozilla Public License Version 2.0 (MPL-2.0)](LICENSE).
