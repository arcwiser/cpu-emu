#pragma once

#include <filesystem>

namespace cpuemu::fixtures {

void make_hello(const std::filesystem::path &path);
void make_winrt_activation(const std::filesystem::path &path);
void make_schedule_chore(const std::filesystem::path &path);
void make_get_error_info(const std::filesystem::path &path);
void make_property_value(const std::filesystem::path &path);
void make_fail_fast(const std::filesystem::path &path);

} // namespace cpuemu::fixtures
