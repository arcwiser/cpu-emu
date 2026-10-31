#include "winemu/log.hpp"

#include "winemu/error.hpp"

#include <chrono>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <mutex>

namespace winemu::log {

namespace {

std::mutex mutex;
Level active_level = Level::Info;
std::ofstream file_stream;

void write_timestamp(std::ostream &stream) {
    const auto now = std::chrono::system_clock::now();
    const auto seconds = std::chrono::system_clock::to_time_t(now);
    const auto millisecond =
        std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;
    std::tm local{};
    localtime_s(&local, &seconds);
    char buffer[16];
    std::strftime(buffer, sizeof(buffer), "%H:%M:%S", &local);
    stream << '[' << buffer << '.' << std::setw(3) << std::setfill('0') << millisecond.count()
           << std::setfill(' ') << ']';
}

} // namespace

void set_level(const Level level) {
    const std::lock_guard lock(mutex);
    active_level = level;
}

void set_file(const std::string &path) {
    const std::lock_guard lock(mutex);
    std::ofstream stream(path, std::ios::app);
    if (!stream) {
        throw Error("cannot open log file: " + path);
    }
    file_stream = std::move(stream);
}

Level level() {
    const std::lock_guard lock(mutex);
    return active_level;
}

bool enabled(const Level level) {
    const std::lock_guard lock(mutex);
    return static_cast<int>(level) <= static_cast<int>(active_level);
}

std::string_view level_name(const Level level) {
    switch (level) {
    case Level::Error:
        return "error";
    case Level::Warn:
        return "warn";
    case Level::Info:
        return "info";
    case Level::Api:
        return "api";
    case Level::Trace:
        return "trace";
    }
    return "unknown";
}

bool parse_level(const std::string_view text, Level &result) {
    if (text == "error") {
        result = Level::Error;
    } else if (text == "warn" || text == "warning") {
        result = Level::Warn;
    } else if (text == "info") {
        result = Level::Info;
    } else if (text == "api" || text == "verbose") {
        result = Level::Api;
    } else if (text == "trace" || text == "debug") {
        result = Level::Trace;
    } else {
        return false;
    }
    return true;
}

void write(const Level level, const std::string_view component, const std::string &message) {
    const std::lock_guard lock(mutex);
    if (static_cast<int>(level) > static_cast<int>(active_level)) {
        return;
    }
    std::ostringstream line;
    write_timestamp(line);
    line << " [" << level_name(level) << "] " << component << ": " << message << '\n';
    const auto text_line = line.str();
    std::cerr << text_line;
    std::cerr.flush();
    if (file_stream.is_open()) {
        file_stream << text_line;
        file_stream.flush();
    }
}

} // namespace winemu::log
