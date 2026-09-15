#include <iostream>
#include <cassert>
#include <string>
#include <filesystem>
#include <fstream>
#include <wavex/Client/HttpClient.hpp>

int main() {
    std::cout << "[Test Client File Upload] Starting...\n";

    // 1. ClientRequest with multipart fields and files
    wavex::client::ClientRequest req(wavex::protos::http::method::POST, "/upload");
    req.add_field("user_id", "42");
    req.add_file("document", "report.txt", "This is an important report.", "text/plain");

    assert(req.header("Content-Type").has_value());
    assert(req.header("Content-Type")->find("multipart/form-data") != std::string_view::npos);
    assert(req.body().find("name=\"user_id\"") != std::string::npos);
    assert(req.body().find("42") != std::string::npos);
    assert(req.body().find("filename=\"report.txt\"") != std::string::npos);
    assert(req.body().find("This is an important report.") != std::string::npos);
    std::cout << "  [PASS] ClientRequest multipart fluent methods verified.\n";

    // 2. ClientRequest add_file_from_path
    std::filesystem::path temp_src = std::filesystem::temp_directory_path() / "wavex_test_upload_src.bin";
    {
        std::ofstream out(temp_src, std::ios::binary);
        out << "Raw Binary Payload 0x123456";
    }

    wavex::client::ClientRequest req2(wavex::protos::http::method::POST, "/upload-binary");
    req2.add_file_from_path("attachment", temp_src);
    assert(req2.body().find("filename=\"wavex_test_upload_src.bin\"") != std::string::npos);
    assert(req2.body().find("Raw Binary Payload 0x123456") != std::string::npos);
    std::cout << "  [PASS] ClientRequest add_file_from_path verified.\n";

    // 3. ClientRequest file_body (raw upload)
    wavex::client::ClientRequest req3(wavex::protos::http::method::PUT, "/raw-upload");
    req3.file_body(temp_src, "application/octet-stream");
    assert(req3.header("Content-Type") == "application/octet-stream");
    assert(req3.body() == "Raw Binary Payload 0x123456");
    std::cout << "  [PASS] ClientRequest file_body verified.\n";

    std::filesystem::remove(temp_src);

    // 4. ClientResponse save_to_file
    wavex::client::ClientResponse res;
    res.status_code(200);
    res.body("Response file content from server");

    std::filesystem::path temp_dest = std::filesystem::temp_directory_path() / "wavex_client_res_dest.txt";
    if (std::filesystem::exists(temp_dest)) {
        std::filesystem::remove(temp_dest);
    }
    assert(res.save_to_file(temp_dest));
    assert(std::filesystem::exists(temp_dest));
    {
        std::ifstream in(temp_dest);
        std::string content;
        std::getline(in, content);
        assert(content == "Response file content from server");
    }
    std::filesystem::remove(temp_dest);
    std::cout << "  [PASS] ClientResponse save_to_file verified.\n";

    std::cout << "[Test Client File Upload] All tests passed!\n";
    return 0;
}
