// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Test support: locate the repository root (for ssl/test.crt and friends) from the test's own source file, so a
// test keeps working wherever it sits under tests/.
//
//     const auto root = wavex_test::project_root();            // call from the test .cpp itself
//     const std::string cert = (root / "ssl" / "test.crt").string();

#ifndef WAVEX_TESTS_SUPPORT_PROJECT_ROOT_HPP
#define WAVEX_TESTS_SUPPORT_PROJECT_ROOT_HPP

#include <filesystem>
#include <source_location>

namespace wavex_test {

    /// The first ancestor of the calling source file that holds both CMakeLists.txt and include/wavex.
    /// Falls back to the process working directory if the sources are not on disk (e.g. a relocated build).
    /// The default argument makes `file_name()` the caller's file, not this header.
    [[nodiscard]] inline std::filesystem::path project_root(
        const std::source_location loc = std::source_location::current()) {
        namespace fs = std::filesystem;
        std::error_code ec;
        fs::path dir = fs::absolute(fs::path(loc.file_name()), ec).parent_path();
        for (; !dir.empty(); dir = dir.parent_path()) {
            if (fs::exists(dir / "CMakeLists.txt", ec) && fs::exists(dir / "include" / "wavex", ec)) return dir;
            if (dir == dir.parent_path()) break;
        }
        return fs::current_path(ec);
    }

} // namespace wavex_test

#endif // WAVEX_TESTS_SUPPORT_PROJECT_ROOT_HPP
