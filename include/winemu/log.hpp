#pragma once

#include <cstdint>
#include <sstream>
#include <string>
#include <string_view>

namespace winemu::log {

enum class Level : int {
    Error = 0,
    Warn = 1,
    Info = 2,
    Api = 3,
    Trace = 4,
};

// The default stream is stderr; set_file mirrors every written line into a file.
void set_level(Level level);
void set_file(const std::string &path);
[[nodiscard]] Level level();
[[nodiscard]] bool enabled(Level level);
[[nodiscard]] std::string_view level_name(Level level);
[[nodiscard]] bool parse_level(std::string_view text, Level &result);

void write(Level level, std::string_view component, const std::string &message);

inline void error(std::string_view component, const std::string &message) {
    write(Level::Error, component, message);
}

inline void warn(std::string_view component, const std::string &message) {
    write(Level::Warn, component, message);
}

inline void info(std::string_view component, const std::string &message) {
    write(Level::Info, component, message);
}

inline void api(std::string_view component, const std::string &message) {
    write(Level::Api, component, message);
}

inline void trace(std::string_view component, const std::string &message) {
    write(Level::Trace, component, message);
}

[[nodiscard]] inline std::string hex(std::uint64_t value) {
    std::ostringstream stream;
    stream << "0x" << std::hex << value;
    return stream.str();
}

} // namespace winemu::log
