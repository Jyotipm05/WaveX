# wavex::rx: compile-time regular expressions

`wavex::rx` (`<wavex/Base/CtRegex.hpp>`, header only, no dependencies) compiles a regular expression into an NFA
program at compile time and matches it without backtracking. `StaticRouter` uses it for `{id:regex}` constraints; it
is also usable on its own.

```cpp
static_assert(wavex::rx::matches<"[0-9]{4}-[0-9]{2}">("2026-11"));

constexpr auto uuid = wavex::rx::compile("[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}");
static_assert(uuid.ok());
bool a = uuid.match(segment);                 // constexpr and noexcept, no allocation
```

`compile()` never throws: check `ok()` / `err` (a failed program matches nothing). `matches<"...">` and the router
turn a bad pattern into a compile error.

## Semantics

* The whole input must match (`std::regex_match`, not `regex_search`), byte by byte; ECMAScript flavour.
* `.` matches any byte except `\n` and `\r`.
* Case-insensitive matching with a `(?i)` prefix.
* Matching is one pass over the input with a bit-set of NFA states (epsilon closures are precomputed): O(input x
  program size), no backtracking, so `(a+)+$` on a long run of `a` is as cheap as any other pattern.

## Syntax

| Form | Notes |
|------|-------|
| literals, `.` | escapes for punctuation (`\.`, `\/`, `\\`), `\t \n \r \f \v \0 \xHH` |
| `[abc]`, `[a-z0-9_-]`, `[^...]` | `\d \w \s` allowed inside |
| `\d \D \w \W \s \S` | shorthands |
| `( )`, `(?: )`, `\|` | groups never capture |
| `* + ? {n} {n,} {n,m}` | a trailing `?` (lazy form) is accepted and ignored |
| `^` first, `$` last, `(?i)` first | the anchors are no-ops under full-match semantics |

Not supported (compile error): lookahead/lookbehind, backreferences, `\b`, named groups, captures, anchors elsewhere.

## Limits

128 instructions and 16 distinct character sets per program, 32 nesting levels, 16 alternatives per group, repeat
counts up to 1000 (each copy of a repeated atom counts toward the instruction limit, so `(a{100}){100}` is rejected
with `too_complex`). `compile_with<MaxInsn, MaxSets>()` builds bigger programs.

## Cost

A 36-byte UUID check takes about 200 ns and a 7-digit number about 90 ns (GCC 14 `-O2`), roughly 3x faster than
`std::regex_match` on the same UUID. A program is about 3.4 KB. Converting the NFA to a DFA at compile time would be
faster still and is possible later; the interface would not change.

## Testing

`test_ctregex` checks the engine at compile time, against a table of expectations and error codes, against
`std::regex` on thousands of generated patterns and inputs, and with random garbage patterns.
