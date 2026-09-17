#include <cassert>
#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

#include <asio/awaitable.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/io_context.hpp>

#include <wavex/Utils/AsyncFs.hpp>

void test_async_fs_operations() {
    std::cout << "[Test AsyncFs] Non-blocking file operations...\n";

    asio::io_context io;
    const auto temp_dir = std::filesystem::temp_directory_path();
    const auto test_file = temp_dir / "wavex_async_fs_test.txt";
    const auto copy_file = temp_dir / "wavex_async_fs_copy.txt";

    // Clean up if existing
    std::error_code ec;
    std::filesystem::remove(test_file, ec);
    std::filesystem::remove(copy_file, ec);

    bool all_passed = false;

    auto test_coro = [&]() -> asio::awaitable<void> {
        // 1. write_file
        const std::string original_data = "WaveX AsyncFs High-Performance File I/O\nLine 2";
        auto write_res = co_await wavex::fs::write_file(test_file, original_data);
        assert(write_res.has_value());

        // 2. read_file
        auto read_res = co_await wavex::fs::read_file(test_file);
        assert(read_res.has_value());
        assert(*read_res == original_data);

        // 3. append_file
        const std::string extra_data = "\nAppended Line 3";
        auto append_res = co_await wavex::fs::append_file(test_file, extra_data);
        assert(append_res.has_value());

        auto read_after_append = co_await wavex::fs::read_file(test_file);
        assert(read_after_append.has_value());
        assert(*read_after_append == (original_data + extra_data));

        // 4. read_bytes
        auto bytes_res = co_await wavex::fs::read_bytes(test_file);
        assert(bytes_res.has_value());
        assert(bytes_res->size() == (original_data.size() + extra_data.size()));

        // 5. copy_file
        auto copy_res = co_await wavex::fs::copy_file(test_file, copy_file);
        assert(copy_res.has_value());
        auto copy_read = co_await wavex::fs::read_file(copy_file);
        assert(copy_read.has_value());
        assert(*copy_read == *read_after_append);

        // 6. remove
        auto remove_res1 = co_await wavex::fs::remove(test_file);
        assert(remove_res1.has_value() && *remove_res1 == true);
        assert(!std::filesystem::exists(test_file));

        auto remove_res2 = co_await wavex::fs::remove(copy_file);
        assert(remove_res2.has_value() && *remove_res2 == true);
        assert(!std::filesystem::exists(copy_file));

        // 7. Error handling (reading non-existent file)
        auto missing_read = co_await wavex::fs::read_file(temp_dir / "non_existent_wavex_file.txt");
        assert(!missing_read.has_value());
        assert(missing_read.error() == std::errc::no_such_file_or_directory);

        all_passed = true;
        co_return;
    };

    asio::co_spawn(io, test_coro(), asio::detached);
    io.run();

    assert(all_passed);
    std::cout << "  [PASS] Async write, read, append, copy, remove, and error handling passed.\n";
}

int main() {
    std::cout << "=== Running WaveX AsyncFs Tests ===\n";
    try {
        test_async_fs_operations();
        std::cout << "=== All AsyncFs Tests PASSED ===\n";
        return 0;
    } catch (const std::exception &ex) {
        std::cerr << "[FAIL] Unexpected exception: " << ex.what() << "\n";
        return 1;
    }
}
