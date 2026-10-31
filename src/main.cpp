#include "winemu/error.hpp"
#include "winemu/log.hpp"
#include "winemu/runtime.hpp"

#include <charconv>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <limits>
#include <string>
#include <string_view>

namespace {

namespace logging = winemu::log;

void print_usage() {
    std::cerr << "usage: cpuemu <program.exe> [options] [-- <guest arguments>]\n"
                 "\n"
                 "options:\n"
                 "  --limit <count>      stop after <count> guest instructions (0 = no limit)\n"
                 "  -v, --verbose        log every guest API call and notable window message\n"
                 "  --log-level <level>  error, warn, info (default), api, or trace\n"
                 "  --log-file <path>    also write all log lines to <path>\n"
                 "  -h, --help           show this help\n"
                 "\n"
                 "Everything after -- is passed to the guest program as its command line.\n";
}

bool parse_limit(const std::string_view text, std::uint64_t &result) {
    if (text.empty()) {
        return false;
    }
    std::uint64_t parsed = 0;
    const auto converted = std::from_chars(text.data(), text.data() + text.size(), parsed);
    if (converted.ec != std::errc{} || converted.ptr != text.data() + text.size()) {
        return false;
    }
    result = parsed;
    return true;
}

} // namespace

int main(int argc, char **argv) {
    logging::set_level(logging::Level::Info);
    std::filesystem::path program;
    std::uint64_t limit = 100'000'000;
    bool guest_arguments_mode = false;
    std::wstring guest_arguments;
    for (int index = 1; index < argc; ++index) {
        const std::string_view argument = argv[index];
        const auto value = [&]() -> std::string_view {
            if (index + 1 >= argc) {
                return {};
            }
            return argv[++index];
        };
        if (guest_arguments_mode) {
            if (!guest_arguments.empty()) {
                guest_arguments += L' ';
            }
            guest_arguments += std::wstring(argument.begin(), argument.end());
        } else if (argument == "--") {
            guest_arguments_mode = true;
        } else if (argument == "-h" || argument == "--help") {
            print_usage();
            return 0;
        } else if (argument == "--limit") {
            if (!parse_limit(value(), limit)) {
                std::cerr << "cpuemu: invalid instruction limit\n";
                return 2;
            }
        } else if (argument == "-v" || argument == "--verbose") {
            logging::set_level(logging::Level::Api);
        } else if (argument == "-vv") {
            logging::set_level(logging::Level::Trace);
        } else if (argument == "--log-level") {
            logging::Level parsed = logging::Level::Info;
            if (!logging::parse_level(value(), parsed)) {
                std::cerr << "cpuemu: unknown log level (use error, warn, info, api, trace)\n";
                return 2;
            }
            logging::set_level(parsed);
        } else if (argument == "--log-file") {
            try {
                logging::set_file(std::string(value()));
            } catch (const std::exception &error) {
                std::cerr << "cpuemu: " << error.what() << '\n';
                return 2;
            }
        } else if (!argument.empty() && argument.front() == '-') {
            std::cerr << "cpuemu: unknown option '" << argument << "'\n";
            print_usage();
            return 2;
        } else if (program.empty()) {
            program = argument;
        } else {
            std::cerr << "cpuemu: unexpected extra argument '" << argument << "'\n";
            return 2;
        }
    }
    if (program.empty()) {
        print_usage();
        return 2;
    }
    try {
        logging::info("main", "starting guest '" + program.string() + "' with instruction limit " +
                                  (limit == 0 ? std::string("none") : std::to_string(limit)));
        winemu::Runtime runtime(std::cout);
        const auto result =
            runtime.run(program, limit == 0 ? std::numeric_limits<std::uint64_t>::max() : limit,
                        guest_arguments);
        logging::info("main", "guest exited with code " + std::to_string(result.exit_code) +
                                  " after " + std::to_string(result.instructions) +
                                  " instructions");
        return static_cast<int>(result.exit_code);
    } catch (const std::exception &error) {
        logging::error("main", error.what());
        return 1;
    }
}
