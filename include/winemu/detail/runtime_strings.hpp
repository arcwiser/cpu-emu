#pragma once

#include <string>

namespace winemu::detail {

[[nodiscard]] std::string lowercase(std::string value);
[[nodiscard]] std::string narrow_string(const std::wstring &value);

} // namespace winemu::detail
