#pragma once

#include <stdexcept>
#include <string>

namespace winemu {

class Error : public std::runtime_error {
  public:
    explicit Error(const std::string &message) : std::runtime_error(message) {}
};

} // namespace winemu
