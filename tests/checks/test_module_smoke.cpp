#include <print>
import wavex;

int main() {
    auto p = wavex::protocol::http;
    const int val = static_cast<int>(p);
    std::println("{}", val);
    return 0;
}
