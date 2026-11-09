#include "guest_fixture_builders.hpp"

#include "pe_fixture_writer.hpp"

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

namespace cpuemu::fixtures {

namespace {

void append32(std::vector<std::uint8_t> &code, std::uint32_t value) {
    for (unsigned index = 0; index < 4; ++index) {
        code.push_back(static_cast<std::uint8_t>(value >> (index * 8)));
    }
}

} // namespace

void make_hello(const std::filesystem::path &path) {
    constexpr std::uint32_t message_rva = 0x1080;
    constexpr std::uint32_t imports_rva = 0x1100;
    constexpr std::uint32_t dll_rva = 0x1140;
    constexpr std::uint32_t int_rva = 0x1160;
    constexpr std::uint32_t iat_rva = 0x1190;
    constexpr std::uint32_t names_rva = 0x11c0;
    const std::string message = "Hello from an emulated Windows PE app!\r\n";
    const std::vector<std::string> imports{"GetStdHandle", "WriteFile", "ExitProcess"};
    std::vector<std::uint8_t> section(0x400);
    std::vector<std::uint8_t> code;
    const auto emit = [&](std::initializer_list<std::uint8_t> values) {
        code.insert(code.end(), values.begin(), values.end());
    };
    const auto emit_rip_relative = [&](std::initializer_list<std::uint8_t> prefix,
                                       std::uint32_t target) {
        code.insert(code.end(), prefix.begin(), prefix.end());
        const auto next = section_rva + static_cast<std::uint32_t>(code.size()) + 4;
        append32(code, target - next);
    };
    emit({0x48, 0x83, 0xec, 0x38});
    emit({0xb9, 0xf5, 0xff, 0xff, 0xff});
    emit_rip_relative({0xff, 0x15}, iat_rva);
    emit({0x48, 0x89, 0xc1});
    emit_rip_relative({0x48, 0x8d, 0x15}, message_rva);
    emit({0x41, 0xb8});
    append32(code, static_cast<std::uint32_t>(message.size()));
    emit({0x4c, 0x8d, 0x4c, 0x24, 0x30});
    emit({0x48, 0xc7, 0x44, 0x24, 0x20, 0, 0, 0, 0});
    emit_rip_relative({0xff, 0x15}, iat_rva + 8);
    emit({0x31, 0xc9});
    emit_rip_relative({0xff, 0x15}, iat_rva + 16);
    emit({0x48, 0x83, 0xc4, 0x38, 0xc3});
    std::copy(code.begin(), code.end(), section.begin());
    std::copy(message.begin(), message.end(), section.begin() + (message_rva - section_rva));

    const auto section_offset = [](std::uint32_t rva) { return rva - section_rva; };
    put32(section, section_offset(imports_rva), int_rva);
    put32(section, section_offset(imports_rva) + 12, dll_rva);
    put32(section, section_offset(imports_rva) + 16, iat_rva);
    const std::string dll = "KERNEL32.dll";
    std::copy(dll.begin(), dll.end(), section.begin() + section_offset(dll_rva));

    auto current_name_rva = names_rva;
    for (std::size_t index = 0; index < imports.size(); ++index) {
        put64(section, section_offset(int_rva) + index * 8, current_name_rva);
        put64(section, section_offset(iat_rva) + index * 8, current_name_rva);
        const auto destination = section.begin() + section_offset(current_name_rva) + 2;
        std::copy(imports[index].begin(), imports[index].end(), destination);
        current_name_rva += align_up(static_cast<std::uint32_t>(imports[index].size() + 3), 2);
    }
    write_pe(path, section, imports_rva, 40, iat_rva, 32);
}

// Builds a guest that activates a WinRT class with no dedicated adapter and then calls
// IActivationFactory::ActivateInstance. The emulator must hand back a guest-owned instance
// instead of reporting success with an untouched out parameter.
void make_winrt_activation(const std::filesystem::path &path) {
    constexpr std::uint32_t class_name_rva = 0x1080;
    constexpr std::uint32_t chars_rva = 0x10e0;
    constexpr std::uint32_t hstring_rva = 0x10c0;
    constexpr std::uint32_t iid_rva = 0x1100;
    constexpr std::uint32_t factory_rva = 0x1120;
    constexpr std::uint32_t instance_rva = 0x1128;
    constexpr std::uint32_t imports_rva = 0x1140;
    constexpr std::uint32_t dll_rva = 0x1180;
    constexpr std::uint32_t int_rva = 0x11a0;
    constexpr std::uint32_t iat_rva = 0x11c0;
    constexpr std::uint32_t names_rva = 0x11f0;
    const std::u16string class_name = u"CPUEmu.Test";
    constexpr std::uint32_t fail_offset = 103;

    std::vector<std::uint8_t> section(0x400);
    std::vector<std::uint8_t> code;
    const auto emit = [&](std::initializer_list<std::uint8_t> values) {
        code.insert(code.end(), values.begin(), values.end());
    };
    const auto emit_rip_relative = [&](std::initializer_list<std::uint8_t> prefix,
                                       std::uint32_t target) {
        code.insert(code.end(), prefix.begin(), prefix.end());
        const auto next = section_rva + static_cast<std::uint32_t>(code.size()) + 4;
        append32(code, target - next);
    };
    const auto emit_jump = [&](std::uint8_t opcode, std::uint32_t at) {
        emit({0x0f, opcode});
        append32(code, fail_offset - (at + 6));
    };

    emit({0x48, 0x83, 0xec, 0x28});                      // sub rsp, 0x28
    emit_rip_relative({0x48, 0x8d, 0x0d}, hstring_rva);  // lea rcx, [class handle]
    emit_rip_relative({0x48, 0x8d, 0x15}, iid_rva);      // lea rdx, [IActivationFactory]
    emit_rip_relative({0x4c, 0x8d, 0x05}, factory_rva);  // lea r8, [&factory]
    emit_rip_relative({0xff, 0x15}, iat_rva);            // call RoGetActivationFactory
    emit({0x85, 0xc0});                                  // test eax, eax
    emit_jump(0x85, 33);                                 // jne fail
    emit_rip_relative({0x48, 0x8b, 0x0d}, factory_rva);  // mov rcx, [factory]
    emit({0x48, 0x85, 0xc9});                            // test rcx, rcx
    emit_jump(0x84, 49);                                 // je fail
    emit_rip_relative({0x48, 0x8d, 0x15}, instance_rva); // lea rdx, [&instance]
    emit({0x48, 0x8b, 0x01});                            // mov rax, [rcx]
    emit({0x48, 0x8b, 0x40, 0x30});                      // mov rax, [rax+0x30] slot 6
    emit({0xff, 0xd0});                                  // call rax
    emit({0x85, 0xc0});                                  // test eax, eax
    emit_jump(0x85, 74);                                 // jne fail
    emit_rip_relative({0x48, 0x8b, 0x05}, instance_rva); // mov rax, [instance]
    emit({0x48, 0x85, 0xc0});                            // test rax, rax
    emit_jump(0x84, 90);                                 // je fail
    emit({0x31, 0xc0});                                  // xor eax, eax
    emit({0x48, 0x83, 0xc4, 0x28, 0xc3});                // add rsp, 0x28; ret
    emit({0xb8, 0x01, 0x00, 0x00, 0x00});                // fail: mov eax, 1
    emit({0x48, 0x83, 0xc4, 0x28, 0xc3});                // add rsp, 0x28; ret
    std::copy(code.begin(), code.end(), section.begin());

    const auto offset = [](std::uint32_t rva) { return rva - section_rva; };
    for (std::size_t index = 0; index < class_name.size(); ++index) {
        put16(section, offset(chars_rva) + index * 2, class_name[index]);
    }
    put16(section, offset(chars_rva) + class_name.size() * 2, 0);
    put32(section, offset(hstring_rva) + 4, static_cast<std::uint32_t>(class_name.size()));
    put64(section, offset(hstring_rva) + 16, image_base + chars_rva);
    put32(section, offset(hstring_rva) + 24, 1);
    put32(section, offset(iid_rva), 0x35);
    section[offset(iid_rva) + 8] = 0xc0;
    section[offset(iid_rva) + 15] = 0x46;

    put32(section, offset(imports_rva), int_rva);
    put32(section, offset(imports_rva) + 12, dll_rva);
    put32(section, offset(imports_rva) + 16, iat_rva);
    const std::string dll = "combase.dll";
    std::copy(dll.begin(), dll.end(), section.begin() + offset(dll_rva));
    const std::string import = "RoGetActivationFactory";
    put64(section, offset(int_rva), names_rva);
    put64(section, offset(iat_rva), names_rva);
    std::copy(import.begin(), import.end(), section.begin() + offset(names_rva) + 2);
    write_pe(path, section, imports_rva, 40, iat_rva, 16);
}

// Builds a guest that schedules an MSVC PPL chore. The callback increments guest memory, proving
// that CPUEmu re-entered the interpreter instead of handing a guest address to the host thread
// pool.
void make_schedule_chore(const std::filesystem::path &path) {
    constexpr std::uint32_t callback_rva = 0x1080;
    constexpr std::uint32_t chore_rva = 0x10a0;
    constexpr std::uint32_t callback_value_rva = 0x10c0;
    constexpr std::uint32_t imports_rva = 0x1100;
    constexpr std::uint32_t dll_rva = 0x1140;
    constexpr std::uint32_t int_rva = 0x1160;
    constexpr std::uint32_t iat_rva = 0x1170;
    constexpr std::uint32_t name_rva = 0x1180;

    std::vector<std::uint8_t> section(0x400);
    std::vector<std::uint8_t> code;
    const auto emit = [&](std::initializer_list<std::uint8_t> values) {
        code.insert(code.end(), values.begin(), values.end());
    };
    const auto emit_rip_relative = [&](std::initializer_list<std::uint8_t> prefix,
                                       std::uint32_t target) {
        code.insert(code.end(), prefix.begin(), prefix.end());
        const auto next = section_rva + static_cast<std::uint32_t>(code.size()) + 4;
        append32(code, target - next);
    };

    emit({0x48, 0x83, 0xec, 0x28});                      // sub rsp, 0x28
    emit_rip_relative({0x48, 0x8d, 0x0d}, chore_rva);    // lea rcx, [chore]
    emit_rip_relative({0xff, 0x15}, iat_rva);            // call _Schedule_chore
    emit({0x85, 0xc0, 0x75, 0x12});                      // test eax,eax; jne fail
    emit_rip_relative({0x8b, 0x05}, callback_value_rva); // mov eax, [callback value]
    emit({0x83, 0xf8, 0x01, 0x75, 0x07});                // cmp eax,1; jne fail
    emit({0x31, 0xc0});                                  // xor eax,eax
    emit({0x48, 0x83, 0xc4, 0x28, 0xc3});                // add rsp,0x28; ret
    emit({0xb8, 0x01, 0x00, 0x00, 0x00});                // fail: mov eax,1
    emit({0x48, 0x83, 0xc4, 0x28, 0xc3});                // add rsp,0x28; ret
    std::copy(code.begin(), code.end(), section.begin());

    const auto offset = [](std::uint32_t rva) { return rva - section_rva; };
    const std::initializer_list<std::uint8_t> callback{0x83, 0x01, 0x01, 0xc3};
    std::copy(callback.begin(), callback.end(), section.begin() + offset(callback_rva));
    put64(section, offset(chore_rva) + 8, image_base + callback_rva);
    put64(section, offset(chore_rva) + 16, image_base + callback_value_rva);

    put32(section, offset(imports_rva), int_rva);
    put32(section, offset(imports_rva) + 12, dll_rva);
    put32(section, offset(imports_rva) + 16, iat_rva);
    const std::string dll = "MSVCP140.dll";
    std::copy(dll.begin(), dll.end(), section.begin() + offset(dll_rva));
    const std::string import =
        "?_Schedule_chore@details@Concurrency@@YAHPEAU_Threadpool_chore@12@@Z";
    put64(section, offset(int_rva), name_rva);
    put64(section, offset(iat_rva), name_rva);
    std::copy(import.begin(), import.end(), section.begin() + offset(name_rva) + 2);
    write_pe(path, section, imports_rva, 40, iat_rva, 16);
}

// Imports GetErrorInfo by its documented OLEAUT32 ordinal and verifies that the no-error result
// clears the guest output pointer instead of exposing a native COM object.
void make_get_error_info(const std::filesystem::path &path) {
    constexpr std::uint32_t output_rva = 0x1080;
    constexpr std::uint32_t imports_rva = 0x1100;
    constexpr std::uint32_t dll_rva = 0x1140;
    constexpr std::uint32_t int_rva = 0x1160;
    constexpr std::uint32_t iat_rva = 0x1170;

    std::vector<std::uint8_t> section(0x300);
    std::vector<std::uint8_t> code;
    const auto emit = [&](std::initializer_list<std::uint8_t> values) {
        code.insert(code.end(), values.begin(), values.end());
    };
    const auto emit_rip_relative = [&](std::initializer_list<std::uint8_t> prefix,
                                       std::uint32_t target) {
        code.insert(code.end(), prefix.begin(), prefix.end());
        const auto next = section_rva + static_cast<std::uint32_t>(code.size()) + 4;
        append32(code, target - next);
    };

    emit({0x48, 0x83, 0xec, 0x28});                    // sub rsp, 0x28
    emit({0x31, 0xc9});                                // xor ecx, ecx
    emit_rip_relative({0x48, 0x8d, 0x15}, output_rva); // lea rdx, [output]
    emit_rip_relative({0xff, 0x15}, iat_rva);          // call GetErrorInfo
    emit({0x83, 0xf8, 0x01, 0x75, 0x13});              // cmp eax,1; jne fail
    emit_rip_relative({0x48, 0x8b, 0x05}, output_rva); // mov rax, [output]
    emit({0x48, 0x85, 0xc0, 0x75, 0x07});              // test rax,rax; jne fail
    emit({0x31, 0xc0});                                // xor eax,eax
    emit({0x48, 0x83, 0xc4, 0x28, 0xc3});              // add rsp,0x28; ret
    emit({0xb8, 0x01, 0x00, 0x00, 0x00});              // fail: mov eax,1
    emit({0x48, 0x83, 0xc4, 0x28, 0xc3});              // add rsp,0x28; ret
    std::copy(code.begin(), code.end(), section.begin());

    const auto offset = [](std::uint32_t rva) { return rva - section_rva; };
    put64(section, offset(output_rva), 0x12345678);
    put32(section, offset(imports_rva), int_rva);
    put32(section, offset(imports_rva) + 12, dll_rva);
    put32(section, offset(imports_rva) + 16, iat_rva);
    const std::string dll = "OLEAUT32.dll";
    std::copy(dll.begin(), dll.end(), section.begin() + offset(dll_rva));
    constexpr std::uint64_t ordinal_import = 0x8000000000000000ULL | 200;
    put64(section, offset(int_rva), ordinal_import);
    put64(section, offset(iat_rva), ordinal_import);
    write_pe(path, section, imports_rva, 40, iat_rva, 16);
}

// Creates a UInt32 through Windows.Foundation.PropertyValue and reads it back through
// IPropertyValue, covering both the factory slot and the per-object scalar state.
void make_property_value(const std::filesystem::path &path) {
    constexpr std::uint32_t hstring_rva = 0x1100;
    constexpr std::uint32_t chars_rva = 0x1120;
    constexpr std::uint32_t iid_rva = 0x1180;
    constexpr std::uint32_t factory_rva = 0x11a0;
    constexpr std::uint32_t value_rva = 0x11a8;
    constexpr std::uint32_t output_rva = 0x11b0;
    constexpr std::uint32_t imports_rva = 0x11c0;
    constexpr std::uint32_t dll_rva = 0x1200;
    constexpr std::uint32_t int_rva = 0x1220;
    constexpr std::uint32_t iat_rva = 0x1230;
    constexpr std::uint32_t name_rva = 0x1240;
    const std::u16string class_name = u"Windows.Foundation.PropertyValue";

    std::vector<std::uint8_t> section(0x500);
    std::vector<std::uint8_t> code;
    std::vector<std::size_t> failure_jumps;
    const auto emit = [&](std::initializer_list<std::uint8_t> values) {
        code.insert(code.end(), values.begin(), values.end());
    };
    const auto emit_rip_relative = [&](std::initializer_list<std::uint8_t> prefix,
                                       std::uint32_t target) {
        code.insert(code.end(), prefix.begin(), prefix.end());
        const auto next = section_rva + static_cast<std::uint32_t>(code.size()) + 4;
        append32(code, target - next);
    };
    const auto emit_failure_jump = [&](bool equal = false) {
        failure_jumps.push_back(code.size());
        emit({0x0f, static_cast<std::uint8_t>(equal ? 0x84 : 0x85), 0, 0, 0, 0});
    };

    emit({0x48, 0x83, 0xec, 0x28});                     // sub rsp,0x28
    emit_rip_relative({0x48, 0x8d, 0x0d}, hstring_rva); // lea rcx,[class]
    emit_rip_relative({0x48, 0x8d, 0x15}, iid_rva);     // lea rdx,[iid]
    emit_rip_relative({0x4c, 0x8d, 0x05}, factory_rva); // lea r8,[factory]
    emit_rip_relative({0xff, 0x15}, iat_rva);           // call RoGetActivationFactory
    emit({0x85, 0xc0});
    emit_failure_jump();
    emit_rip_relative({0x48, 0x8b, 0x0d}, factory_rva); // mov rcx,[factory]
    emit({0x48, 0x85, 0xc9});
    emit_failure_jump(true);                          // je fail
    emit({0xba, 0x03, 0, 0, 0});                      // mov edx,3
    emit_rip_relative({0x4c, 0x8d, 0x05}, value_rva); // lea r8,[value]
    emit({0x48, 0x8b, 0x01, 0xff, 0x50, 0x58});       // call vtable slot 11
    emit({0x85, 0xc0});
    emit_failure_jump();
    emit_rip_relative({0x48, 0x8b, 0x0d}, value_rva);  // mov rcx,[value]
    emit_rip_relative({0x48, 0x8d, 0x15}, output_rva); // lea rdx,[output]
    emit({0x48, 0x8b, 0x01, 0xff, 0x50, 0x60});        // call vtable slot 12
    emit({0x85, 0xc0});
    emit_failure_jump();
    emit_rip_relative({0x8b, 0x05}, output_rva); // mov eax,[output]
    emit({0x83, 0xf8, 0x03});                    // cmp eax,3
    emit_failure_jump();
    emit({0x31, 0xc0, 0x48, 0x83, 0xc4, 0x28, 0xc3}); // return 0
    const auto failure_offset = static_cast<std::uint32_t>(code.size());
    emit({0xb8, 0x01, 0, 0, 0, 0x48, 0x83, 0xc4, 0x28, 0xc3}); // return 1
    for (const auto jump : failure_jumps) {
        put32(code, jump + 2, failure_offset - static_cast<std::uint32_t>(jump + 6));
    }
    std::copy(code.begin(), code.end(), section.begin());

    const auto offset = [](std::uint32_t rva) { return rva - section_rva; };
    for (std::size_t index = 0; index < class_name.size(); ++index) {
        put16(section, offset(chars_rva) + index * 2, class_name[index]);
    }
    put32(section, offset(hstring_rva) + 4, static_cast<std::uint32_t>(class_name.size()));
    put64(section, offset(hstring_rva) + 16, image_base + chars_rva);
    put32(section, offset(hstring_rva) + 24, 1);
    put32(section, offset(iid_rva), 0x35);
    put32(section, offset(imports_rva), int_rva);
    put32(section, offset(imports_rva) + 12, dll_rva);
    put32(section, offset(imports_rva) + 16, iat_rva);
    const std::string dll = "combase.dll";
    std::copy(dll.begin(), dll.end(), section.begin() + offset(dll_rva));
    const std::string import = "RoGetActivationFactory";
    put64(section, offset(int_rva), name_rva);
    put64(section, offset(iat_rva), name_rva);
    std::copy(import.begin(), import.end(), section.begin() + offset(name_rva) + 2);
    write_pe(path, section, imports_rva, 40, iat_rva, 16);
}

} // namespace cpuemu::fixtures
