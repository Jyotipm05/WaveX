#include <iostream>
#include <cassert>
#include <string>
#include <vector>
#include <filesystem>
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

    std::cout << "[Test Multipart] All tests passed!\n";
    return 0;
}
