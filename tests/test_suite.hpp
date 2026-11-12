#pragma once

#include <string>

namespace winemu::tests {

void require(bool condition, const std::string &message);
void test_memory();
void test_cpu_loop();
void test_cpu_32bit_mode();
void test_pshufd();
void test_pshufb();
void test_packed_absolute_values();
void test_bit_count_instructions();
void test_extended_ssse3();
void test_sse3_float_operations();
void test_sign_extend_accumulator();
void test_apps();
void test_logging();
void test_paint_selftest();
void test_winrt_activation();
void test_schedule_chore();
void test_get_error_info();
void test_property_value();
void test_fail_fast_isolation();
void test_mime_type_marshaling();

} // namespace winemu::tests
