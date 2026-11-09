#include <fstream>

int main() {
    std::fstream input(L"test-apps/stream-data.bin", std::ios::in | std::ios::binary);
    input.seekg(4);
    char value = 0;
    input.read(&value, 1);
    return value == '4' ? 0 : 1;
}
