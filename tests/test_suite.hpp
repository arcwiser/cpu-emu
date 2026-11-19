#pragma once

#include <string>

namespace winemu::tests {

void require(bool condition, const std::string &message);
void test_memory();
void test_cpu_loop();
void test_cpu_32bit_mode();
void test_double_shifts();
void test_x87_pop_arithmetic();
void test_x87_sign_operations();
void test_x87_stack_exchange();
void test_x87_double_arithmetic();
void test_x87_square_root();
void test_x87_comparison_status();
void test_x87_rounding();
void test_x87_register_arithmetic();
void test_x87_integer_arithmetic();
void test_packed_float_conversions();
void test_sse_square_roots();
void test_packed_logical_operations();
void test_pshufd();
void test_pshufb();
void test_packed_absolute_values();
void test_bit_count_instructions();
void test_crc32_instruction();
void test_movbe_instruction();
void test_extended_ssse3();
void test_sse3_float_operations();
void test_sign_extend_accumulator();
void test_apps();
void test_logging();
void test_paint_selftest();
void test_timer_callback_lifetime();
void test_winrt_activation();
void test_schedule_chore();
void test_get_error_info();
void test_property_value();
void test_fail_fast_isolation();
void test_mime_type_marshaling();
void test_guest_thread_scheduling();

} // namespace winemu::tests
