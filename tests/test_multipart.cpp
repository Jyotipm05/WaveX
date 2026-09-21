#include <iostream>
#include <cassert>
#include <string>
#include <vector>
#include <filesystem>
#include <asio/io_context.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/use_awaitable.hpp>
#include <wavex/Utils/Multipart.hpp>
#include <wavex/protos/http/HttpRequest.hpp>

int main() {
    std::cout << "[Test Multipart] Starting...\n";

    // 1. Compose multipart form data
    wavex::utils::MultipartFormData form("---TestBoundary12345");
    form.add_field("username", "alice");
    form.add_field("description", "A developer building WaveX");
    form.add_file("avatar", "profile.png", "\x89PNG\r\n\x1a\nfakeimagebytes", "image/png");

    std::string composed = form.compose();
    std::string content_type = form.content_type_header();

    assert(composed.find("name=\"username\"") != std::string::npos);
    assert(composed.find("alice") != std::string::npos);
    assert(composed.find("filename=\"profile.png\"") != std::string::npos);
    assert(composed.find("image/png") != std::string::npos);
    assert(content_type.find("multipart/form-data") != std::string::npos);
    assert(content_type.find("boundary=---TestBoundary12345") != std::string::npos);
    std::cout << "  [PASS] Form composition verified.\n";

    // 2. Parse composed multipart form data (In-memory)
    wavex::utils::MultipartLimits in_mem_limits;
    in_mem_limits.max_memory_buffer = 1024 * 1024; // 1MB

    auto parsed = wavex::utils::MultipartFormData::parse(composed, content_type, in_mem_limits);
    assert(parsed.field("username") == "alice");
    assert(parsed.field("description") == "A developer building WaveX");

    auto avatar = parsed.file("avatar");
    assert(avatar.has_value());
    assert(avatar->filename == "profile.png");
    assert(avatar->content_type == "image/png");
    assert(avatar->is_in_memory());
    assert(!avatar->is_on_disk());
    assert(avatar->data == "\x89PNG\r\n\x1a\nfakeimagebytes");
    assert(avatar->size() == 22);
    std::cout << "  [PASS] In-memory parsing verified.\n";

    // 3. Save uploaded file to disk
    std::filesystem::path dest_file = std::filesystem::temp_directory_path() / "wavex_avatar_out.png";
    if (std::filesystem::exists(dest_file)) {
        std::filesystem::remove(dest_file);
    }
    assert(avatar->save_to(dest_file));
    assert(std::filesystem::exists(dest_file));
    assert(std::filesystem::file_size(dest_file) == 22);
    std::filesystem::remove(dest_file);
    std::cout << "  [PASS] In-memory file save_to verified.\n";

    // 4. Disk spooling when file exceeds max_memory_buffer
    wavex::utils::MultipartFormData large_form("---LargeBoundary12345");
    std::string large_payload(5000, 'X');
    large_form.add_file("large_doc", "document.pdf", large_payload, "application/pdf");
    std::string large_composed = large_form.compose();
    std::string large_ct = large_form.content_type_header();

    wavex::utils::MultipartLimits spool_limits;
    spool_limits.max_memory_buffer = 1000; // Small threshold to force spooling

    auto spooled_form = wavex::utils::MultipartFormData::parse(large_composed, large_ct, spool_limits);
    auto doc = spooled_form.file("large_doc");
    assert(doc.has_value());
    assert(doc->filename == "document.pdf");
    assert(doc->is_on_disk());
    assert(!doc->is_in_memory());
    assert(doc->size() == 5000);
    assert(doc->temp_file != nullptr);
    assert(std::filesystem::exists(doc->temp_file->path()));

    // Verify saving spooled file moves the temp file
    std::filesystem::path spooled_dest = std::filesystem::temp_directory_path() / "wavex_doc_out.pdf";
    if (std::filesystem::exists(spooled_dest)) {
        std::filesystem::remove(spooled_dest);
    }
    assert(doc->save_to(spooled_dest));
    assert(std::filesystem::exists(spooled_dest));
    assert(std::filesystem::file_size(spooled_dest) == 5000);
    std::filesystem::remove(spooled_dest);
    std::cout << "  [PASS] Disk spooling & atomic move save_to verified.\n";

    // 5. Verification through HttpRequest methods
    wavex::protos::http::Http1Request req;
    req.set_header("Content-Type", content_type);
    req.set_body(composed);

    assert(req.is_multipart());
    auto req_multipart = req.multipart();
    assert(req_multipart.field("username") == "alice");

    auto req_file = req.file("avatar");
    assert(req_file.has_value());
    assert(req_file->filename == "profile.png");

    auto all_files = req.files();
    assert(all_files.size() == 1);
    assert(all_files[0].name == "avatar");
    std::cout << "  [PASS] HttpRequest multipart methods verified.\n";

    // 6. Resource protection: Part and file count limits (DoS mitigation)
    {
        wavex::utils::MultipartFormData multi_part_form("---BoundaryCountLimits");
        for (int i = 0; i < 5; ++i) {
            multi_part_form.add_file("file" + std::to_string(i), "test" + std::to_string(i) + ".txt", "data");
        }
        std::string count_composed = multi_part_form.compose();
        std::string count_ct = multi_part_form.content_type_header();

        // Limit max_files = 3
        wavex::utils::MultipartLimits file_limited;
        file_limited.max_files = 3;
        auto rejected_files = wavex::utils::MultipartFormData::parse(count_composed, count_ct, file_limited);
        assert(!rejected_files.is_valid());

        // Limit max_parts = 4
        wavex::utils::MultipartLimits parts_limited;
        parts_limited.max_parts = 4;
        auto rejected_parts = wavex::utils::MultipartFormData::parse(count_composed, count_ct, parts_limited);
        assert(!rejected_parts.is_valid());

        // Limits generous -> accepted
        wavex::utils::MultipartLimits ok_limits;
        ok_limits.max_files = 10;
        ok_limits.max_parts = 10;
        auto accepted = wavex::utils::MultipartFormData::parse(count_composed, count_ct, ok_limits);
        assert(accepted.is_valid());
        assert(accepted.files().size() == 5);
        std::cout << "  [PASS] Resource protection: max_files and max_parts ceilings verified.\n";
    }

    // 7. Async coroutine verification: parse_async, parallel spooling, HttpRequest async & save_to_async
    {
        asio::io_context io;
        bool async_tests_passed = false;

        asio::co_spawn(io, [&]() -> asio::awaitable<void> {
            // A. parse_async in-memory
            auto async_parsed = co_await wavex::utils::MultipartFormData::parse_async(composed, content_type, in_mem_limits);
            assert(async_parsed.is_valid());
            assert(async_parsed.field("username") == "alice");
            auto async_avatar = async_parsed.file("avatar");
            assert(async_avatar.has_value());
            assert(async_avatar->is_in_memory());
            assert(async_avatar->size() == 22);

            // B. save_to_async for in-memory file
            std::filesystem::path in_mem_dest = std::filesystem::temp_directory_path() / "wavex_async_avatar_out.png";
            if (std::filesystem::exists(in_mem_dest)) std::filesystem::remove(in_mem_dest);
            bool in_mem_save_ok = co_await async_avatar->save_to_async(in_mem_dest);
            assert(in_mem_save_ok);
            assert(std::filesystem::exists(in_mem_dest));
            assert(std::filesystem::file_size(in_mem_dest) == 22);
            std::filesystem::remove(in_mem_dest);

            // C. Multi-file parallel spooling via parse_async
            wavex::utils::MultipartFormData multi_upload("---ParallelSpoolBoundary");
            std::string payload1(3000, 'A');
            std::string payload2(4000, 'B');
            std::string payload3(5000, 'C');
            multi_upload.add_file("photo1", "pic1.jpg", payload1, "image/jpeg");
            multi_upload.add_file("photo2", "pic2.jpg", payload2, "image/jpeg");
            multi_upload.add_file("photo3", "pic3.jpg", payload3, "image/jpeg");
            multi_upload.add_field("album", "Summer 2026");

            std::string multi_composed = multi_upload.compose();
            std::string multi_ct = multi_upload.content_type_header();

            wavex::utils::MultipartLimits parallel_limits;
            parallel_limits.max_memory_buffer = 1000; // Force all 3 files to spool to disk in parallel

            auto spooled_multi = co_await wavex::utils::MultipartFormData::parse_async(multi_composed, multi_ct, parallel_limits);
            assert(spooled_multi.is_valid());
            assert(spooled_multi.field("album") == "Summer 2026");
            assert(spooled_multi.files().size() == 3);

            auto f1 = spooled_multi.file("photo1");
            auto f2 = spooled_multi.file("photo2");
            auto f3 = spooled_multi.file("photo3");
            assert(f1 && f1->is_on_disk() && f1->size() == 3000);
            assert(f2 && f2->is_on_disk() && f2->size() == 4000);
            assert(f3 && f3->is_on_disk() && f3->size() == 5000);

            // D. save_to_async for disk-spooled file (atomic move)
            std::filesystem::path spooled_async_dest = std::filesystem::temp_directory_path() / "wavex_async_spooled.bin";
            if (std::filesystem::exists(spooled_async_dest)) std::filesystem::remove(spooled_async_dest);
            bool spooled_save_ok = co_await f1->save_to_async(spooled_async_dest);
            assert(spooled_save_ok);
            assert(std::filesystem::exists(spooled_async_dest));
            assert(std::filesystem::file_size(spooled_async_dest) == 3000);
            std::filesystem::remove(spooled_async_dest);

            // E. HttpRequest async methods
            wavex::protos::http::Http1Request async_req;
            async_req.set_header("Content-Type", multi_ct);
            async_req.set_body(multi_composed);

            auto req_form = co_await async_req.multipart_async(parallel_limits);
            assert(req_form.is_valid());
            assert(req_form.field("album") == "Summer 2026");

            auto async_f2 = req_form.file("photo2");
            assert(async_f2.has_value());
            assert(async_f2->size() == 4000);

            auto async_all = req_form.files();
            assert(async_all.size() == 3);

            async_tests_passed = true;
            co_return;
        }, asio::detached);

        io.run();
        assert(async_tests_passed);
        std::cout << "  [PASS] Async parsing, parallel spooling, save_to_async, and HttpRequest async APIs verified.\n";
    }

    std::cout << "[Test Multipart] All tests passed!\n";
    return 0;
}
