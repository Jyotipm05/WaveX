---
trigger: always_on
---

Never run CMake configuration commands (`cmake --preset <configure-preset>`, `cmake -B ...`) by yourself.
Only the user is allowed to configure the project.
You ARE allowed to compile/build (`cmake --build --preset fast-dev`) and run tests (`ctest --preset run-tests`).
