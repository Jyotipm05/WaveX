#include <iostream>
#include <cassert>
#include <string>
#include <filesystem>
#include <fstream>
#include <wavex/Utils/TempFile.hpp>

int main() {
    std::cout << "[Test TempFileGuard] Starting...\n";

    std::filesystem::path created_path;

    // Test 1: Auto-purge on destruction
    {
        auto temp = wavex::utils::TempFileGuard::create_with_prefix("test_prefix_");
        assert(!temp.empty());
        created_path = temp.path();
        assert(std::filesystem::exists(created_path));

        // Write some bytes
        {
            std::ofstream out(created_path, std::ios::binary);
            out << "Hello Temporary File Guard!";
        }
        assert(temp.size() == 27);
        // temp goes out of scope here
    }

    // After destruction, file MUST be purged
    assert(!std::filesystem::exists(created_path));
    std::cout << "  [PASS] Auto-purge on destruction verified.\n";

    // Test 2: move_to keeps destination and purges temporary handle
    std::filesystem::path dest_path = std::filesystem::temp_directory_path() / "wavex_test_dest.txt";
    if (std::filesystem::exists(dest_path)) {
        std::filesystem::remove(dest_path);
    }

    {
        auto temp = wavex::utils::TempFileGuard::create();
        assert(!temp.empty());
        created_path = temp.path();
        {
            std::ofstream out(created_path, std::ios::binary);
            out << "Persist this content!";
        }

        bool moved = temp.move_to(dest_path);
        assert(moved);
        assert(std::filesystem::exists(dest_path));
        assert(!std::filesystem::exists(created_path));
    }

    // Verify content at dest_path
    {
        std::ifstream in(dest_path);
        std::string content;
        std::getline(in, content);
        assert(content == "Persist this content!");
    }
    std::filesystem::remove(dest_path);
    std::cout << "  [PASS] move_to verified.\n";

    // Test 3: Move semantics of TempFileGuard
    {
        auto temp1 = wavex::utils::TempFileGuard::create();
        assert(!temp1.empty());
        created_path = temp1.path();

        wavex::utils::TempFileGuard temp2 = std::move(temp1);
        assert(temp1.path().empty());
        assert(temp2.path() == created_path);
        assert(std::filesystem::exists(created_path));
    }
    assert(!std::filesystem::exists(created_path));
    std::cout << "  [PASS] Move semantics verified.\n";

    std::cout << "[Test TempFileGuard] All tests passed!\n";
    return 0;
}
