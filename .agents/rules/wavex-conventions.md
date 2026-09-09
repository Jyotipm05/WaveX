# WaveX Architectural & Development Invariants

1. **C++20 Module Interface Synchronization**:
   - Whenever any new public class, struct, function, type alias, or template is added or modified in `include/wavex/`, you MUST update the corresponding C++20 module partition in `src/` (`.ixx` files).
   - Ensure all public symbols are explicitly exported via `export namespace wavex::... { using ...; }`.

2. **Zero-VTable & Modern C++ Invariants**:
   - Never introduce virtual functions (`virtual`) in `Request` or `Response` base classes. Use CRTP and C++23 explicit object parameter ("deducing this": `this Self&& self`).
   - Responses must support in-place mutation and zero-copy string views (`std::string_view`) referencing owned buffers where appropriate.
   - Status code mutations must ensure `status_text_` synchronizes with standard RFC reason phrases (`Codec::status_text_for(code)`).

3. **Build & Test Invariants**:
   - **Allowed**: You ARE allowed to compile/build and run tests for the project:
     - Build: `cmake --build --preset fast-dev` (or `cmake --build build/test-profile -j 10`)
     - Test: `ctest --preset run-tests --output-on-failure` (or `ctest --test-dir build/test-profile --output-on-failure`)
   - **Prohibited (No CMake Configure)**: NEVER run CMake configuration commands directly (e.g. `cmake --preset test-profile`, `cmake -B ...`, or changing generator/toolchain cache). The configuration step must ONLY be performed by the user.
