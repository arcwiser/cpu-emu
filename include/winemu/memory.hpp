#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace winemu {

enum Permission : std::uint8_t {
    Read = 1,
    Write = 2,
    Execute = 4,
};

struct VirtualMemoryInfo {
    std::uint64_t base;
    std::uint64_t allocation_base;
    std::uint64_t size;
    std::uint8_t permissions;
    bool committed;
};

class Memory {
  public:
    Memory() = default;
    ~Memory();
    Memory(const Memory &) = delete;
    Memory &operator=(const Memory &) = delete;
    void map(std::uint64_t base, std::uint64_t size, std::uint8_t permissions, std::string name);
    // Registers an externally-owned mapping (for example the host's own KUSER_SHARED_DATA
    // page); Memory does not allocate or free it.
    void map_existing(std::uint64_t base, std::uint64_t size, std::uint8_t permissions,
                      std::string name, std::uint8_t *data);
    void track_allocation(std::uint64_t base, std::uint64_t size, std::string name);
    void commit(std::uint64_t base, std::uint64_t size, std::uint8_t permissions, std::string name);
    [[nodiscard]] bool decommit(std::uint64_t base, std::uint64_t size);
    [[nodiscard]] bool release(std::uint64_t base);
    [[nodiscard]] bool protect(std::uint64_t base, std::uint64_t size, std::uint8_t permissions);
    [[nodiscard]] bool permissions(std::uint64_t address, std::uint8_t &result) const;
    [[nodiscard]] bool query(std::uint64_t address, VirtualMemoryInfo &result) const;
    [[nodiscard]] bool contains(std::uint64_t address, std::uint64_t size = 1) const;
    [[nodiscard]] std::uint8_t read8(std::uint64_t address) const;
    [[nodiscard]] std::uint16_t read16(std::uint64_t address) const;
    [[nodiscard]] std::uint32_t read32(std::uint64_t address) const;
    [[nodiscard]] std::uint64_t read64(std::uint64_t address) const;
    [[nodiscard]] std::vector<std::uint8_t> read(std::uint64_t address, std::size_t size) const;
    [[nodiscard]] std::string read_c_string(std::uint64_t address, std::size_t limit = 32768) const;
    void write8(std::uint64_t address, std::uint8_t value);
    void write16(std::uint64_t address, std::uint16_t value);
    void write32(std::uint64_t address, std::uint32_t value);
    void write64(std::uint64_t address, std::uint64_t value);
    void write(std::uint64_t address, std::span<const std::uint8_t> bytes);

  private:
    struct Region {
        std::uint64_t base;
        std::uint64_t size;
        std::uint8_t permissions;
        std::string name;
        std::uint8_t *data;
    };

    struct Allocation {
        std::uint64_t base;
        std::uint64_t size;
        std::string name;
        bool releasable;
    };

    void remove_mappings(std::uint64_t base, std::uint64_t size);

    [[nodiscard]] const Region &region_for(std::uint64_t address, std::uint64_t size,
                                           std::uint8_t permission) const;
    [[nodiscard]] Region &region_for(std::uint64_t address, std::uint64_t size,
                                     std::uint8_t permission);
    std::vector<Region> regions_;
    std::vector<Allocation> allocations_;
};

} // namespace winemu
