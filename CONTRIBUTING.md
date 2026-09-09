# Contributing to WaveX

First off, thank you for considering contributing to **WaveX**! Contributions from the community help make WaveX a faster, safer, and more robust C++23 coroutine backend framework.

This document provides guidelines, architectural principles, and instructions for building, testing, and submitting code to the repository.

---

## 📜 Table of Contents

- [Code of Conduct](#-code-of-conduct)
- [Architectural Principles](#-architectural-principles)
- [Getting Started](#-getting-started)
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

### 1. CRTP Zero-VTable Architecture

- Base abstractions in `wavex::base` (`Request`, `Response`) use the **Curiously Recurring Template Pattern (CRTP)** (`Request<Derived>`, `Response<Derived>`) to achieve compile-time static polymorphism.
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

- **C++ Compiler**: C++23 compliant compiler (GCC 13+, Clang 16+, or MSVC 19.36+).
- **Build System**: CMake 3.20 or newer.
- **Package Manager / Dependencies**: Asio (standalone), Google RE2, nlohmann/json, OpenSSL (optional for TLS).

### Cloning & Building

```bash
# Clone the repository
git clone https://github.com/Jyotipm05/WaveX.git
cd WaveX

# Switch to the dev branch (all active development MUST happen on dev)
git checkout dev

# Configure with default build profile
cmake -B build -DWAVEX_TEST=ON

# Build the project and test binaries
cmake --build build
```

#### Sample TLS cert - key pair generation

```powershell
openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 365  -subj "/C=IN/ST=WB/L=Kharagpur/O=IIT_Kharagpur/CN=localhost"  -keyout test.key -out test.crt
```

---

## 🧪 Build Presets & Sanitizers

WaveX provides pre-configured [`CMakePresets.json`](CMakePresets.json) targets for testing, code sanitization, and verification.

### Recommended CMake Presets

| Preset Name | Purpose | Command |
| :--- | :--- | :--- |
| `test-profile` | Standard build preset for unit & integration tests | `cmake --preset test-profile`<br/>`cmake --build --preset test-profile` |
| `asan` | AddressSanitizer (ASan) build profile | `cmake --preset asan`<br/>`cmake --build --preset asan` |
| `tsan` | ThreadSanitizer (TSan) build profile (GCC/Clang only) | `cmake --preset tsan`<br/>`cmake --build --preset tsan` |

### Running Sanitizer Presets

> [!NOTE]
> **Sanitizer Compatibility Note**:
>
> - **AddressSanitizer (ASan)** and **ThreadSanitizer (TSan)** runtimes are mutually exclusive; run them in separate build configurations.
> - **TSan** is supported on GCC and Clang (not MSVC).
> - On MSVC, MSVC ASan flags are auto-injected (`/fsanitize=address /Zi`). Ensure `ASAN_OPTIONS` does not include unsupported platform flags like `detect_leaks=1` or `detect_stack_use_after_return=1` on MSVC.

```bash
# AddressSanitizer Run
cmake --preset asan
cmake --build --preset asan
ctest --preset run-tests

# ThreadSanitizer Run (GCC/Clang)
cmake --preset tsan
cmake --build --preset tsan
ctest --preset run-tests
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
./build/test-profile/wavex_postman_http1_server.exe
# Or with TLS:
./build/test-profile/wavex_postman_http1_server.exe --tls
```

Test endpoints against `http://127.0.0.1:8080`.

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
   - [ ] Code adheres to CRTP zero-vtable and base-class layer independence rules.
   - [ ] Documentation (`README.md`, docstrings) updated where appropriate.
4. **Submit PR**: Open a Pull Request targeting the **`dev`** branch with a summary of changes and testing performed.

---

## ⚖️ License

By contributing to WaveX, you agree that your contributions will be licensed under the project's [Mozilla Public License Version 2.0 (MPL-2.0)](LICENSE).
