#include "test_suite.hpp"

#include <exception>
#include <iostream>

int main() {
    using namespace winemu::tests;
    try {
        test_memory();
        test_cpu_loop();
        test_cpu_32bit_mode();
        test_pshufd();
        test_pshufb();
        test_packed_absolute_values();
        test_bit_count_instructions();
        test_extended_ssse3();
        test_sse3_float_operations();
        test_sign_extend_accumulator();
        test_apps();
        test_logging();
        test_paint_selftest();
        test_winrt_activation();
        std::cout << "all tests passed\n";
        return 0;
    } catch (const std::exception &error) {
        std::cerr << "test failure: " << error.what() << '\n';
        return 1;
    }
}
