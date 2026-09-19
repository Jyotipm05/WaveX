---
trigger: always_on
---

# Class and Struct Layout Ordering & Packing Invariant in WaveX

## Rule

All `class` and `struct` definitions across the WaveX codebase MUST adhere strictly to the following member declaration order and memory packing rules.

### 1. Mandatory Declaration Order

Within every `class` or `struct` definition, declarations must be sequenced in this exact top-to-bottom order:

1. **Nested Types & Definitions (Top)**:
   - Nested `enum` and `enum class`
   - Type aliases (`using`, `typedef`)
   - Nested `struct` and `class` definitions
   - Associated static type constants / compile-time traits

2. **Member Variables (Second)**:
   - Static and non-static data members
   - Arranged strictly for **minimum padding** (see Section 2)

3. **Constructors, Destructor & Special Member Functions (Middle)**:
   - Default constructors
   - Parameterized constructors
   - Copy & move constructors
   - Copy & move assignment operators (`operator=`)
   - Destructor (`~ClassName()`)

4. **Member Functions & Friend Declarations (Last)**:
   - Static member functions
   - Public / protected / private member methods
   - Operator overloads
   - `friend` functions and friend class declarations

---

### 2. Variable Alignment & Minimum Padding Invariant

Data members must always be arranged such that compiler-inserted alignment padding is **minimized**:

- Order member variables by descending size/alignment requirements:
  1. `alignas(...)` types / 128-bit types / cache-line aligned members
  2. **64-bit types (8 bytes)**: pointers (`T*`), references, 64-bit integers (`uint64_t`, `int64_t`, `size_t`, `std::uintptr_t`), `double`, `std::chrono` 64-bit durations, atomic 64-bit types
  3. **Complex types**: Standard objects with 8-byte dominant alignment (`std::string`, `std::string_view`, `FlatMap`, `std::vector`, `std::function`, etc.)
  4. **32-bit types (4 bytes)**: 32-bit integers (`uint32_t`, `int32_t`, `int`), `float`, 32-bit enums
  5. **16-bit types (2 bytes)**: `uint16_t`, `int16_t`, `short`, 16-bit enums
  6. **8-bit types (1 byte)**: `char`, `uint8_t`, `int8_t`, `bool`, 8-bit enums (`enum class E : uint8_t`)
  7. Sub-byte / bitfields and trailing byte arrays
- Pack boolean flags and smaller enum types together at the end of the alignment block to avoid trailing and intermediate alignment holes.
- Keep constructor member initializer lists strictly synchronized with the declaration order of member variables to prevent MSVC `C5038` / Clang `-Wreorder-ctor` warnings.

---

### Example Template

```cpp
class MyComponent {
public:
    // ─── 1. Nested Types & Definitions (TOP) ───────────────────────────
    enum class State : uint8_t { Idle, Running, Stopped };
    using Callback = std::function<void(State)>;

    struct Metrics {
        uint64_t requests;
        uint32_t errors;
    };

private:
    // ─── 2. Member Variables (SECOND - Ordered for Minimal Padding) ────
    void* buffer_{nullptr};             // 8 bytes (align 8)
    uint64_t capacity_{0};              // 8 bytes (align 8)
    uint32_t size_{0};                  // 4 bytes (align 4)
    uint16_t port_{0};                  // 2 bytes (align 2)
    State state_{State::Idle};          // 1 byte  (align 1)
    bool enabled_{false};               // 1 byte  (align 1)
    // Total: 24 bytes (0 bytes padding!)

public:
    // ─── 3. Constructors & Destructor (MIDDLE) ─────────────────────────
    MyComponent() = default;
    explicit MyComponent(void* buf, uint64_t cap, uint16_t port)
        : buffer_(buf), capacity_(cap), size_(0), port_(port),
          state_(State::Idle), enabled_(true) {}
    ~MyComponent() = default;

    MyComponent(const MyComponent&) = delete;
    MyComponent& operator=(const MyComponent&) = delete;
    MyComponent(MyComponent&&) noexcept = default;
    MyComponent& operator=(MyComponent&&) noexcept = default;

    // ─── 4. Member Functions & Friend Declarations (LAST) ──────────────
    [[nodiscard]] State state() const noexcept { return state_; }
    void start();
    void stop();

    friend bool operator==(const MyComponent& lhs, const MyComponent& rhs) noexcept;
};
```
