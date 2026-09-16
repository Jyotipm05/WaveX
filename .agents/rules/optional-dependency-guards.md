---
trigger: always_on
---

# Optional Dependency Header Guards in WaveX

## Rule

When guarding the `#include` of an **optional dependency header** (e.g., `<zlib.h>`, `<openssl/ssl.h>`, or any vcpkg package), ALWAYS use the CMake-injected compile definition EXCLUSIVELY.

**NEVER** combine it with `__has_include()` using `||`.

## Correct Pattern

```cpp
#if defined(WAVEX_HAS_ZLIB) && WAVEX_HAS_ZLIB
#define WAVEX_ZLIB_AVAILABLE 1
#include <zlib.h>
#else
#define WAVEX_ZLIB_AVAILABLE 0
#endif
```

## Anti-Pattern (PROHIBITED)

```cpp
// NEVER DO THIS:
#if defined(WAVEX_HAS_ZLIB) || __has_include(<zlib.h>)
#include <zlib.h>
#endif
```

## Rationale

`__has_include()` resolves at preprocessor time against system search paths, bypassing CMake cache definitions. If `WAVEX_HAS_ZLIB=0` was chosen by CMake because zlib is not configured, using `|| __has_include(<zlib.h>)` will evaluate to true if any header exists on disk, forcing a compile against non-linked symbols and breaking the build.
