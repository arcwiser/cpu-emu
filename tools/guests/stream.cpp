#include <fstream>

int main() {
    std::fstream input(L"test-apps/stream-data.bin", std::ios::in | std::ios::binary);
    input.exceptions(std::ios::failbit | std::ios::badbit);
    input.clear();
    if (!input.good()) {
        return 2;
    }
    input.seekg(4);
    char value = 0;
    input.read(&value, 1);
    if (value != '4' || input.tellg() != 5) {
        return 1;
    }
    input.exceptions(std::ios::goodbit);
    input.seekg(10);
    input.read(&value, 1);
    return input.fail() ? 0 : 3;
}
