#include <iostream>
#include <cassert>
#include <string>
#include <wavex/Utils/Compression.hpp>

int main() {
    std::cout << "[Test Compression] Starting...\n";

    std::string original = "The quick brown fox jumps over the lazy dog. 1234567890! Repeated payload to ensure compressibility: ";
    for (int i = 0; i < 20; ++i) {
        original += "WaveX high-performance C++23 framework. ";
    }

#if defined(WAVEX_HAS_ZLIB) && WAVEX_HAS_ZLIB
    std::cout << "  [INFO] WAVEX_HAS_ZLIB is enabled. Testing full deflate/inflate...\n";

    // Test Gzip
    auto compressed_gz = wavex::utils::Compressor::compress(original, wavex::utils::CompressionFormat::Gzip);
    assert(compressed_gz.has_value());
    assert(!compressed_gz->empty());
    assert(compressed_gz->size() < original.size());

    auto decompressed_gz = wavex::utils::Compressor::decompress(*compressed_gz, wavex::utils::CompressionFormat::Gzip);
    assert(decompressed_gz.has_value());
    assert(*decompressed_gz == original);
    std::cout << "  [PASS] Gzip round-trip verified.\n";

    // Test Deflate
    auto compressed_df = wavex::utils::Compressor::compress(original, wavex::utils::CompressionFormat::Deflate);
    assert(compressed_df.has_value());
    assert(!compressed_df->empty());
    assert(compressed_df->size() < original.size());

    auto decompressed_df = wavex::utils::Compressor::decompress(*compressed_df, wavex::utils::CompressionFormat::Deflate);
    assert(decompressed_df.has_value());
    assert(*decompressed_df == original);
    std::cout << "  [PASS] Deflate round-trip verified.\n";

    // Test empty input
    auto empty_comp = wavex::utils::Compressor::compress("", wavex::utils::CompressionFormat::Gzip);
    assert(empty_comp.has_value());
    auto empty_decomp = wavex::utils::Compressor::decompress(*empty_comp, wavex::utils::CompressionFormat::Gzip);
    assert(empty_decomp.has_value());
    assert(empty_decomp->empty());
    std::cout << "  [PASS] Empty payload handling verified.\n";

    // Test corrupted input decompression
    std::string corrupt = "this is not a valid gzip stream";
    auto corrupt_decomp = wavex::utils::Compressor::decompress(corrupt, wavex::utils::CompressionFormat::Gzip);
    assert(!corrupt_decomp.has_value());
    std::cout << "  [PASS] Corrupted input rejection verified.\n";
#else
    std::cout << "  [INFO] WAVEX_HAS_ZLIB is disabled. Testing fallback behavior...\n";
    auto compressed = wavex::utils::Compressor::compress(original);
    assert(!compressed.has_value());
    auto decompressed = wavex::utils::Compressor::decompress(original);
    assert(!decompressed.has_value());
    std::cout << "  [PASS] Graceful disabled fallback verified.\n";
#endif

    std::cout << "[Test Compression] All tests passed!\n";
    return 0;
}
