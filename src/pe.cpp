#include "winemu/pe.hpp"

#include "winemu/error.hpp"
#include "winemu/log.hpp"

#include <algorithm>
#include <array>
#include <fstream>
#include <limits>
#include <span>
#include <vector>

namespace winemu {

namespace {

template <typename T> T read_value(std::span<const std::uint8_t> bytes, std::size_t offset) {
    if (offset > bytes.size() || sizeof(T) > bytes.size() - offset) {
        throw Error("truncated PE file");
    }
    T value = 0;
    for (std::size_t index = 0; index < sizeof(T); ++index) {
        value |= static_cast<T>(bytes[offset + index]) << (index * 8);
    }
    return value;
}

std::vector<std::uint8_t> read_file(const std::filesystem::path &path) {
    std::ifstream stream(path, std::ios::binary | std::ios::ate);
    if (!stream) {
        throw Error("cannot open executable: " + path.string());
    }
    const auto end = stream.tellg();
    if (end < 0 || static_cast<std::uint64_t>(end) > std::numeric_limits<std::size_t>::max()) {
        throw Error("invalid executable size");
    }
    std::vector<std::uint8_t> bytes(static_cast<std::size_t>(end));
    stream.seekg(0);
    if (!bytes.empty() && !stream.read(reinterpret_cast<char *>(bytes.data()), end)) {
        throw Error("cannot read executable: " + path.string());
    }
    return bytes;
}

} // namespace

LoadedImage PeLoader::load(const std::filesystem::path &path, Memory &memory,
                           const ImportResolver &resolver) {
    const auto file = read_file(path);
    const std::span<const std::uint8_t> bytes(file);
    if (read_value<std::uint16_t>(bytes, 0) != 0x5a4d) {
        throw Error("not a DOS/PE executable");
    }
    const auto pe_offset = read_value<std::uint32_t>(bytes, 0x3c);
    const auto pe = static_cast<std::size_t>(pe_offset);
    if (read_value<std::uint32_t>(bytes, pe) != 0x00004550) {
        throw Error("missing PE signature");
    }
    if (read_value<std::uint16_t>(bytes, pe + 4) != 0x8664) {
        throw Error("only x86-64 PE images are supported");
    }
    const auto section_count = read_value<std::uint16_t>(bytes, pe + 6);
    const auto optional_size = read_value<std::uint16_t>(bytes, pe + 20);
    if (pe > std::numeric_limits<std::size_t>::max() - 24) {
        throw Error("invalid PE header offset");
    }
    const auto optional = pe + 24;
    if (optional_size < 0xf0 || optional > bytes.size() ||
        optional_size > bytes.size() - optional ||
        read_value<std::uint16_t>(bytes, optional) != 0x20b) {
        throw Error("only PE32+ images are supported");
    }
    const auto entry_rva = read_value<std::uint32_t>(bytes, optional + 16);
    const auto image_base = read_value<std::uint64_t>(bytes, optional + 24);
    const auto image_size = read_value<std::uint32_t>(bytes, optional + 56);
    const auto header_size = read_value<std::uint32_t>(bytes, optional + 60);
    const auto stack_reserve = read_value<std::uint64_t>(bytes, optional + 72);
    if (image_size == 0 || header_size > file.size() || header_size > image_size ||
        entry_rva >= image_size) {
        throw Error("invalid PE image layout");
    }

    memory.map(image_base, image_size, Read | Write | Execute, path.filename().string());
    memory.write(image_base, std::span<const std::uint8_t>(file.data(), header_size));

    const auto section_table = optional + optional_size;
    if (section_table > bytes.size() ||
        static_cast<std::size_t>(section_count) > (bytes.size() - section_table) / 40) {
        throw Error("truncated PE section table");
    }
    for (std::uint16_t index = 0; index < section_count; ++index) {
        const auto section = section_table + static_cast<std::size_t>(index) * 40;
        const auto virtual_size = read_value<std::uint32_t>(bytes, section + 8);
        const auto virtual_address = read_value<std::uint32_t>(bytes, section + 12);
        const auto raw_size = read_value<std::uint32_t>(bytes, section + 16);
        const auto raw_offset = read_value<std::uint32_t>(bytes, section + 20);
        if (log::enabled(log::Level::Trace)) {
            std::array<char, 9> name{};
            for (std::size_t offset = 0; offset < 8; ++offset) {
                const auto character = bytes[section + offset];
                name[offset] = character == 0 ? '\0' : static_cast<char>(character);
            }
            log::trace("pe",
                       "section " + std::string(name.data()) + " rva=" + log::hex(virtual_address) +
                           " virtual=" + log::hex(virtual_size) + " raw=" + log::hex(raw_size));
        }
        const auto copy_size = std::min(raw_size, virtual_size == 0 ? raw_size : virtual_size);
        if (static_cast<std::uint64_t>(virtual_address) + copy_size > image_size ||
            static_cast<std::uint64_t>(raw_offset) + copy_size > file.size()) {
            throw Error("invalid PE section bounds");
        }
        if (copy_size != 0) {
            memory.write(image_base + virtual_address,
                         std::span<const std::uint8_t>(file.data() + raw_offset, copy_size));
        }
    }

    const auto directory_count = read_value<std::uint32_t>(bytes, optional + 108);
    if (directory_count > (optional_size - 112) / 8) {
        throw Error("invalid PE data-directory count");
    }
    if (directory_count > 1) {
        const auto import_rva = read_value<std::uint32_t>(bytes, optional + 112 + 8);
        const auto import_size = read_value<std::uint32_t>(bytes, optional + 112 + 12);
        if (import_rva != 0 && import_size != 0) {
            if (static_cast<std::uint64_t>(import_rva) + import_size > image_size) {
                throw Error("invalid import directory");
            }
            std::size_t import_count = 0;
            for (std::uint64_t descriptor = image_base + import_rva;; descriptor += 20) {
                const auto original_thunk = memory.read32(descriptor);
                const auto name_rva = memory.read32(descriptor + 12);
                const auto first_thunk = memory.read32(descriptor + 16);
                if (original_thunk == 0 && name_rva == 0 && first_thunk == 0) {
                    break;
                }
                if (name_rva >= image_size || first_thunk >= image_size) {
                    throw Error("invalid import descriptor");
                }
                const auto module = memory.read_c_string(image_base + name_rva);
                const auto lookup_rva = original_thunk == 0 ? first_thunk : original_thunk;
                for (std::uint64_t entry = 0;; ++entry) {
                    const auto lookup_address = image_base + lookup_rva + entry * 8;
                    const auto value = memory.read64(lookup_address);
                    if (value == 0) {
                        break;
                    }
                    std::string name;
                    if ((value & (1ULL << 63)) != 0) {
                        name = "#" + std::to_string(value & 0xffff);
                    } else {
                        if (value + 2 >= image_size) {
                            throw Error("invalid import name");
                        }
                        name = memory.read_c_string(image_base + value + 2);
                    }
                    memory.write64(image_base + first_thunk + entry * 8, resolver(module, name));
                    ++import_count;
                    if (log::enabled(log::Level::Trace)) {
                        log::trace("pe", "import " + module + "!" + name + " -> " +
                                             log::hex(memory.read64(image_base + first_thunk +
                                                                    entry * 8)));
                    }
                }
            }
            log::info("pe", "resolved " + std::to_string(import_count) + " imports");
        }
    }
    std::uint64_t tls_start = 0;
    std::uint64_t tls_end = 0;
    std::uint64_t tls_index = 0;
    std::vector<std::uint64_t> tls_callbacks;
    if (directory_count > 9) {
        const auto tls_rva = read_value<std::uint32_t>(bytes, optional + 112 + 9 * 8);
        const auto tls_size = read_value<std::uint32_t>(bytes, optional + 116 + 9 * 8);
        if (tls_rva != 0) {
            if (tls_size < 40 || static_cast<std::uint64_t>(tls_rva) + 40 > image_size) {
                throw Error("invalid TLS directory");
            }
            const auto directory = image_base + tls_rva;
            tls_start = memory.read64(directory);
            tls_end = memory.read64(directory + 8);
            tls_index = memory.read64(directory + 16);
            const auto callback_array = memory.read64(directory + 24);
            const auto in_image = [&](std::uint64_t address, std::uint64_t size) {
                return address >= image_base && size <= image_size &&
                       address - image_base <= image_size - size;
            };
            if (tls_end < tls_start ||
                (tls_start != 0 && !in_image(tls_start, tls_end - tls_start)) ||
                (tls_index != 0 && !in_image(tls_index, sizeof(std::uint32_t)))) {
                throw Error("invalid TLS data range");
            }
            if (callback_array != 0) {
                if (!in_image(callback_array, sizeof(std::uint64_t))) {
                    throw Error("invalid TLS callback array");
                }
                bool terminated = false;
                for (std::size_t index = 0; index < 1024; ++index) {
                    const auto entry = callback_array + index * sizeof(std::uint64_t);
                    if (!in_image(entry, sizeof(std::uint64_t))) {
                        throw Error("unterminated TLS callback array");
                    }
                    const auto callback = memory.read64(entry);
                    if (callback == 0) {
                        terminated = true;
                        break;
                    }
                    if (!in_image(callback, 1)) {
                        throw Error("TLS callback outside image");
                    }
                    tls_callbacks.push_back(callback);
                }
                if (!terminated) {
                    throw Error("unterminated TLS callback array");
                }
            }
            log::info("pe", "TLS template=" + std::to_string(tls_end - tls_start) +
                                " bytes callbacks=" + std::to_string(tls_callbacks.size()));
        }
    }
    log::info("pe", "loaded '" + path.filename().string() + "' base=" + log::hex(image_base) +
                        " entry=" + log::hex(image_base + entry_rva) +
                        " size=" + log::hex(image_size));
    return {image_base, image_size, image_base + entry_rva,  stack_reserve, tls_start,
            tls_end,    tls_index,  std::move(tls_callbacks)};
}

} // namespace winemu
