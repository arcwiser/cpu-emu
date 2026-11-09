#include "winemu/detail/runtime_strings.hpp"

#include <algorithm>
#include <cctype>

namespace winemu::detail {

std::string lowercase(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char character) {
        return static_cast<char>(std::tolower(character));
    });
    return value;
}

std::string narrow_string(const std::wstring &value) {
    std::string result;
    result.reserve(value.size());
    for (const wchar_t character : value) {
        result.push_back(character >= 0 && character < 0x80 ? static_cast<char>(character) : '?');
    }
    return result;
}

} // namespace winemu::detail
