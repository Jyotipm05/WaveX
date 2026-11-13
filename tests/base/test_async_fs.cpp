#include <cassert>
#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

#include <asio/awaitable.hpp>
#include <wavex/Base/Task.hpp>
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

    auto test_coro = [&]() -> wavex::task<void> {
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

void test_async_fs_utf8_operations() {
    std::cout << "[Test AsyncFs] UTF-8 Unicode filename operations...\n";

    asio::io_context io;
    std::error_code ec;
    const std::string temp_dir_u8 = wavex::utils::fs_utils::temp_directory_path(ec);
    assert(!temp_dir_u8.empty());

    // Construct paths with Cyrillic, Japanese, and emoji UTF-8 characters
    const std::string u8_file = temp_dir_u8 + "/wavex_тест_日本語_📁.txt";
    const std::string u8_copy = temp_dir_u8 + "/wavex_копия_コピー_🚀.txt";

    // Clean up if existing
    wavex::utils::fs_utils::remove(u8_file, ec);
    wavex::utils::fs_utils::remove(u8_copy, ec);

    bool all_passed = false;

    auto test_coro = [&]() -> wavex::task<void> {
        // 1. write_file with UTF-8 path string
        const std::string original_data = "WaveX AsyncFs UTF-8 Payload: こんにちは世界 🚀";
        auto write_res = co_await wavex::fs::write_file(u8_file, original_data);
        assert(write_res.has_value());
        assert(wavex::utils::fs_utils::exists(u8_file, ec));

        // 2. read_file with UTF-8 path
        auto read_res = co_await wavex::fs::read_file(u8_file);
        assert(read_res.has_value());
        assert(*read_res == original_data);

        // 3. append_file
        const std::string extra_data = "\nAppended Unicode: Привет, мир!";
        auto append_res = co_await wavex::fs::append_file(u8_file, extra_data);
        assert(append_res.has_value());

        auto read_after = co_await wavex::fs::read_file(u8_file);
        assert(read_after.has_value());
        assert(*read_after == (original_data + extra_data));

        // 4. copy_file
        auto copy_res = co_await wavex::fs::copy_file(u8_file, u8_copy);
        assert(copy_res.has_value());
        assert(wavex::utils::fs_utils::exists(u8_copy, ec));

        auto copy_read = co_await wavex::fs::read_file(u8_copy);
        assert(copy_read.has_value());
        assert(*copy_read == *read_after);

        // 5. Test with std::filesystem::path constructed via to_path
        std::filesystem::path fs_u8_file = wavex::utils::fs_utils::to_path(u8_file);
        auto fs_read = co_await wavex::fs::read_file(fs_u8_file);
        assert(fs_read.has_value());
        assert(*fs_read == *read_after);

        // 6. remove both files
        auto rem1 = co_await wavex::fs::remove(u8_file);
        assert(rem1.has_value() && *rem1 == true);
        assert(!wavex::utils::fs_utils::exists(u8_file, ec));

        auto rem2 = co_await wavex::fs::remove(u8_copy);
        assert(rem2.has_value() && *rem2 == true);
        assert(!wavex::utils::fs_utils::exists(u8_copy, ec));

        all_passed = true;
        co_return;
    };

    asio::co_spawn(io, test_coro(), asio::detached);
    io.run();

    assert(all_passed);
    std::cout << "  [PASS] Async UTF-8 Unicode operations passed.\n";
}

// Runs the read/write checks once per I/O mode. `native` is exercised for real only in builds that have native file
// I/O (Windows IOCP, Linux with -DWAVEX_IO_URING=ON); elsewhere set_io_mode(native) must leave the blocking pool in
// effect and every result must be identical.
void test_async_fs_io_modes() {
    std::cout << "[Test AsyncFs] I/O modes (blocking pool / native small-file reads)...\n";
    std::cout << "  native_io_available() = " << (wavex::fs::native_io_available() ? "yes" : "no") << "\n";

    const auto dir = std::filesystem::temp_directory_path() / "wavex_async_fs_modes";
    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
    std::filesystem::create_directories(dir, ec);

    // Payloads around the native/pool boundary, plus bytes that text-mode I/O would mangle.
    std::string binary;
    for (int i = 0; i < 4096; ++i) binary.push_back(static_cast<char>(i % 256)); // NULs, \r, \n, 0xFF ...
    const std::string empty;
    const std::string at_limit(wavex::fs::native_read_max_bytes, 'a');
    const std::string over_limit(wavex::fs::native_read_max_bytes + 1, 'b');
    const std::string big(300 * 1024, 'c');

    for (const auto requested: {wavex::fs::io_mode::blocking_pool, wavex::fs::io_mode::native}) {
        const auto effective = wavex::fs::set_io_mode(requested);
        assert(effective == wavex::fs::get_io_mode());
        if (requested == wavex::fs::io_mode::native && !wavex::fs::native_io_available()) {
            assert(effective == wavex::fs::io_mode::blocking_pool);
        }
        std::cout << "  mode requested=" << (requested == wavex::fs::io_mode::native ? "native" : "blocking_pool")
                << " effective=" << (effective == wavex::fs::io_mode::native ? "native" : "blocking_pool") << "\n";

        asio::io_context io;
        bool done = false;
        auto coro = [&]() -> wavex::task<void> {
            int n = 0;
            for (const std::string *payload: std::initializer_list<const std::string *>{&binary, &empty, &at_limit, &over_limit, &big}) {
                const auto path = (dir / ("f" + std::to_string(n++))).string();
                auto w = co_await wavex::fs::write_file(path, *payload);
                assert(w.has_value());

                auto text = co_await wavex::fs::read_file(path);
                assert(text.has_value());
                assert(*text == *payload);

                auto bytes = co_await wavex::fs::read_bytes(path);
                assert(bytes.has_value());
                assert(bytes->size() == payload->size());
                assert(std::string(bytes->begin(), bytes->end()) == *payload);
            }

            // Missing file: the real reason, not a generic error.
            auto missing = co_await wavex::fs::read_file((dir / "missing").string());
            assert(!missing.has_value() && missing.error() == std::errc::no_such_file_or_directory);
            auto missing_bytes = co_await wavex::fs::read_bytes((dir / "missing").string());
            assert(!missing_bytes.has_value() && missing_bytes.error() == std::errc::no_such_file_or_directory);

            // write_file creates missing parent directories (existing behaviour) ...
            auto nested = co_await wavex::fs::write_file((dir / "a" / "b" / "c.txt").string(), "nested");
            assert(nested.has_value());
            // ... and a path below a regular file fails with an error instead of pretending success.
            auto below_file = co_await wavex::fs::write_file((dir / "f0" / "x.txt").string(), "nope");
            assert(!below_file.has_value());
            done = true;
        };
        asio::co_spawn(io, coro(), asio::detached);
        io.run();
        assert(done);
    }
    wavex::fs::set_io_mode(wavex::fs::io_mode::blocking_pool);
    std::filesystem::remove_all(dir, ec);
    std::cout << "  [PASS] Both I/O modes return identical results (binary, empty, boundary, large, errors).\n";
}

int main() {
    std::cout << "=== Running WaveX AsyncFs Tests ===\n";
    try {
        test_async_fs_operations();
        test_async_fs_utf8_operations();
        test_async_fs_io_modes();
        std::cout << "=== All AsyncFs Tests PASSED ===\n";
        return 0;
    } catch (const std::exception &ex) {
        std::cerr << "[FAIL] Unexpected exception: " << ex.what() << "\n";
        return 1;
    }
}
