#pragma once

#include <filesystem>

namespace cpuemu::fixtures {

void make_hello(const std::filesystem::path &path);
void make_winrt_activation(const std::filesystem::path &path);

} // namespace cpuemu::fixtures
