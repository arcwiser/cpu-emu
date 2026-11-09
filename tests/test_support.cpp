#include "test_suite.hpp"

#include <stdexcept>

namespace winemu::tests {

void require(bool condition, const std::string &message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

} // namespace winemu::tests
