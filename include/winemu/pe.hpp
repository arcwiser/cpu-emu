#pragma once

#include "winemu/memory.hpp"

#include <cstdint>
#include <filesystem>
#include <functional>
#include <string>
#include <vector>

namespace winemu {

struct LoadedImage {
    std::uint64_t base;
    std::uint64_t size;
    std::uint64_t entry;
    std::uint64_t stack_reserve;
    std::uint64_t tls_start;
    std::uint64_t tls_end;
    std::uint64_t tls_index;
    std::vector<std::uint64_t> tls_callbacks;
};

using ImportResolver = std::function<std::uint64_t(const std::string &, const std::string &)>;

class PeLoader {
  public:
    static LoadedImage load(const std::filesystem::path &path, Memory &memory,
                            const ImportResolver &resolver);
};

} // namespace winemu
