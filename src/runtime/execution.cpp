#include "winemu/runtime.hpp"

#include "callbacks.hpp"
#include "winemu/detail/runtime_layout.hpp"
#include "winemu/detail/runtime_strings.hpp"
#include "winemu/error.hpp"
#include "winemu/log.hpp"

#include <algorithm>
#include <cstdio>
#include <limits>
#include <sstream>

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <shellapi.h>
#include <windows.h>

namespace winemu {

using detail::command_line_address;
using detail::crt_argc;
using detail::crt_argv;
using detail::crt_wargv;
using detail::environment_base;
using detail::environment_size;
using detail::minimum_stack_size;
using detail::narrow_string;
using detail::peb_base;
using detail::return_thunk32;
using detail::return_thunk64;
using detail::stack_top;
using detail::teb_base;
using detail::tls_base;
using detail::tls_size;
using detail::winmain_command_line_address;

namespace {

std::string cpu_state_dump(const Cpu &cpu) {
    static constexpr const char *register_names[16] = {"rax", "rcx", "rdx", "rbx", "rsp", "rbp",
                                                       "rsi", "rdi", "r8",  "r9",  "r10", "r11",
                                                       "r12", "r13", "r14", "r15"};
    std::ostringstream stream;
    for (std::size_t index = 0; index < 16; ++index) {
        stream << register_names[index] << '=' << log::hex(cpu.reg(static_cast<Register>(index)))
               << ((index % 4) == 3 ? '\n' : ' ');
    }
    stream << "rip history:";
    for (const auto address : cpu.recent_instructions()) {
        stream << ' ' << log::hex(address);
    }
    return stream.str();
}

} // namespace

RunResult Runtime::run(const std::filesystem::path &executable, std::uint64_t instruction_limit,
                       const std::wstring &arguments) {
    log::info("runtime", "loading guest '" + executable.string() + "'");
    Memory memory;
    thunks_.clear();
    thunk_names_.clear();
    native_functions_.clear();
    bool format_initialized = false;
    const auto configure_format = [&](bool is_64_bit) {
        if (!format_initialized) {
            guest_is_64_bit_ = is_64_bit;
            const auto return_thunk = is_64_bit ? return_thunk64 : return_thunk32;
            thunks_.emplace(return_thunk, Api::ProcessReturn);
            next_thunk_ = return_thunk + 0x100;
            format_initialized = true;
        } else if (guest_is_64_bit_ != is_64_bit) {
            throw Error("PE architecture changed while resolving imports");
        }
    };
    data_import_next_ = 0;
    data_import_slots_.clear();
    last_error_ = 0;
    guest_exception_filter_ = 0;
    heap_next_ = 0x0000'0006'0000'0000ULL;
    heap_sizes_.clear();
    next_module_handle_ = 0x7fe0'0000ULL;
    guest_modules_.clear();
    for (const auto &[guest_handle, host_handle] : find_handles_) {
        static_cast<void>(guest_handle);
        ::FindClose(static_cast<HANDLE>(host_handle));
    }
    find_handles_.clear();
    next_find_handle_ = 0x300;
    for (const auto &[guest_handle, host_handle] : file_handles_) {
        static_cast<void>(guest_handle);
        ::CloseHandle(static_cast<HANDLE>(host_handle));
    }
    file_handles_.clear();
    next_file_handle_ = 0x400;
    for (const auto &[guest_handle, host_handle] : sync_handles_) {
        static_cast<void>(guest_handle);
        ::CloseHandle(static_cast<HANDLE>(host_handle));
    }
    sync_handles_.clear();
    next_sync_handle_ = 0x600;
    class_window_procedures_.clear();
    atom_window_procedures_.clear();
    window_procedures_.clear();
    creating_window_procedure_ = 0;
    quit_message_pending_ = false;
    quit_message_code_ = 0;
    callback_long_parameters_.clear();
    callback_depth_ = 0;
    direct_input_proxy_ = 0;
    direct_input_device_proxy_ = 0;
    direct_input_methods_.clear();
    acc_prop_services_proxy_ = 0;
    acc_prop_services_methods_.clear();
    application_document_lists_proxy_ = 0;
    empty_object_array_proxy_ = 0;
    application_document_lists_methods_.clear();
    object_array_methods_.clear();
    protection_policy_proxy_ = 0;
    protection_policy_methods_.clear();
    winrt_activation_factory_proxy_ = 0;
    geographic_region_proxy_ = 0;
    winrt_activation_factory_methods_.clear();
    geographic_region_methods_.clear();
    application_data_statics_proxy_ = 0;
    application_data_proxy_ = 0;
    application_data_statics_methods_.clear();
    application_data_methods_.clear();
    application_data_container_proxy_ = 0;
    property_set_proxy_ = 0;
    application_data_container_methods_.clear();
    property_set_methods_.clear();
    app_data_paths_statics_proxy_ = 0;
    app_data_paths_proxy_ = 0;
    app_data_path_strings_.fill(0);
    app_data_paths_statics_methods_.clear();
    app_data_paths_methods_.clear();
    xaml_resource_factory_proxy_ = 0;
    xaml_resource_proxy_ = 0;
    xaml_resource_factory_methods_.clear();
    xaml_resource_methods_.clear();
    xaml_application_statics_proxy_ = 0;
    xaml_application_statics_methods_.clear();
    xaml_app_factory_proxy_ = 0;
    xaml_app_proxy_ = 0;
    xaml_app_drag_verifier_ = 0;
    xaml_app_localized_key_storage_ = 0;
    xaml_app_factory_methods_.clear();
    xaml_app_methods_.clear();
    dispatcher_queue_controller_statics_proxy_ = 0;
    dispatcher_queue_controller_proxy_ = 0;
    dispatcher_queue_controller_statics_methods_.clear();
    dispatcher_queue_controller_methods_.clear();
    resource_manager_statics_proxy_ = 0;
    resource_manager_proxy_ = 0;
    resource_map_proxy_ = 0;
    resource_context_statics_proxy_ = 0;
    resource_context_proxy_ = 0;
    resource_candidate_proxy_ = 0;
    resource_candidate_value_ = 0;
    resource_candidate_language_ = 0;
    resource_manager_statics_methods_.clear();
    resource_manager_methods_.clear();
    resource_map_methods_.clear();
    resource_context_statics_methods_.clear();
    resource_context_methods_.clear();
    resource_candidate_methods_.clear();
    ui_settings_factory_proxy_ = 0;
    ui_settings_proxy_ = 0;
    ui_settings3_proxy_ = 0;
    ui_settings_factory_methods_.clear();
    ui_settings_methods_.clear();
    ui_settings3_methods_.clear();
    property_value_statics_proxy_ = 0;
    property_value_proxy_ = 0;
    property_value_boolean_ = false;
    property_value_statics_methods_.clear();
    property_value_methods_.clear();
    locale_proxy_ = 0;
    locale_facet_vtable_ = 0;
    locale_facet_methods_.clear();
    locale_facets_.clear();
    output_stream_buffers_.clear();
    stream_buffer_storage_.clear();
    stream_buffer_lengths_.clear();
    stream_buffer_files_.clear();
    input_stream_buffers_.clear();
    pending_guest_file_stream_ = 0;
    for (const auto &[guest_stream, host_stream] : guest_file_streams_) {
        static_cast<void>(guest_stream);
        std::fclose(static_cast<FILE *>(host_stream));
    }
    guest_file_streams_.clear();
    next_tls_index_ = 1;
    next_fls_index_ = 1;
    tls_values_.clear();
    fls_values_.clear();
    const auto image = PeLoader::load(executable, memory,
                                      [&](const auto &module, const auto &name, bool is_64_bit) {
                                          configure_format(is_64_bit);
                                          return resolve_import(module, name);
                                      });
    configure_format(image.is_64_bit);
    heap_next_ = image.is_64_bit ? 0x0000'0006'0000'0000ULL : 0x1000'0000ULL;
    guest_image_base_ = image.base;
    guest_executable_ = std::filesystem::absolute(executable);
    if (resource_module_ != nullptr) {
        FreeLibrary(static_cast<HMODULE>(resource_module_));
    }
    resource_module_ =
        LoadLibraryExW(guest_executable_.c_str(), nullptr,
                       LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE | LOAD_LIBRARY_AS_IMAGE_RESOURCE);
    const auto requested_stack = std::max(image.stack_reserve, minimum_stack_size);
    if (requested_stack > std::numeric_limits<std::uint64_t>::max() - 0xffff) {
        throw Error("guest stack reserve is too large");
    }
    const auto stack_size = (requested_stack + 0xffff) & ~0xffffULL;
    if (stack_size >= stack_top) {
        throw Error("guest stack reserve is too large");
    }
    const auto stack_base = stack_top - stack_size;
    memory.map(stack_base, stack_size, Read | Write, "main stack");
    memory.map(environment_base, environment_size, Read | Write, "process environment");
    // KUSER_SHARED_DATA is mapped read-only into every Windows process; alias the host's own
    // page so guest code reading tick counts and system time sees real values.
    memory.map_existing(
        0x7ffe0000ULL, 0x1000, Read, "kuser shared data",
        reinterpret_cast<std::uint8_t *>(static_cast<std::uintptr_t>(0x7ffe0000ULL)));
    const auto stack_entry_size = image.is_64_bit ? 8U : 4U;
    const auto initial_rsp = stack_base + stack_size - 0x1000 - stack_entry_size;
    const auto return_thunk = image.is_64_bit ? return_thunk64 : return_thunk32;
    if (image.is_64_bit) {
        memory.write64(initial_rsp, return_thunk);
    } else {
        memory.write32(initial_rsp, static_cast<std::uint32_t>(return_thunk));
    }
    if (image.is_64_bit) {
        memory.write64(teb_base + 0x08, stack_base + stack_size);
        memory.write64(teb_base + 0x10, stack_base);
        memory.write64(teb_base + 0x30, teb_base);
        memory.write64(teb_base + 0x40, 1);
        memory.write64(teb_base + 0x48, 1);
        memory.write64(teb_base + 0x60, peb_base);
    } else {
        memory.write32(teb_base + 0x04, static_cast<std::uint32_t>(stack_base + stack_size));
        memory.write32(teb_base + 0x08, static_cast<std::uint32_t>(stack_base));
        memory.write32(teb_base + 0x18, static_cast<std::uint32_t>(teb_base));
        memory.write32(teb_base + 0x20, 1);
        memory.write32(teb_base + 0x24, 1);
        memory.write32(teb_base + 0x30, static_cast<std::uint32_t>(peb_base));
    }
    if (image.tls_start != 0 || image.tls_index != 0 || !image.tls_callbacks.empty()) {
        const auto template_size = image.tls_end - image.tls_start;
        if (template_size > tls_size - 0x1000) {
            throw Error("guest TLS template is too large");
        }
        memory.map(tls_base, tls_size, Read | Write, "main thread TLS");
        const auto tls_block = tls_base + 0x1000;
        if (image.is_64_bit) {
            memory.write64(teb_base + 0x58, tls_base);
            memory.write64(tls_base, tls_block);
        } else {
            memory.write32(teb_base + 0x2c, static_cast<std::uint32_t>(tls_base));
            memory.write32(tls_base, static_cast<std::uint32_t>(tls_block));
        }
        if (template_size != 0) {
            memory.write(tls_block,
                         memory.read(image.tls_start, static_cast<std::size_t>(template_size)));
        }
        if (image.tls_index != 0) {
            memory.write32(image.tls_index, 0);
        }
    }
    if (arguments.size() > 1000) {
        throw Error("guest command line arguments too long");
    }
    std::wstring full_command_line = L"\"" + executable.wstring() + L"\"";
    if (!arguments.empty()) {
        full_command_line += L' ';
        full_command_line += arguments;
    }
    if (full_command_line.size() > 2047) {
        throw Error("guest command line too long");
    }
    const auto write_guest_pointer = [&](std::uint64_t address, std::uint64_t value) {
        if (image.is_64_bit) {
            memory.write64(address, value);
        } else {
            memory.write32(address, static_cast<std::uint32_t>(value));
        }
    };

    int host_argc = 0;
    auto **host_argv = ::CommandLineToArgvW(full_command_line.c_str(), &host_argc);
    if (host_argv == nullptr || host_argc < 1 || host_argc > 128) {
        if (host_argv != nullptr) {
            ::LocalFree(host_argv);
        }
        throw Error("cannot construct guest argv");
    }
    constexpr std::uint64_t argv_allocation_size = 0x10000;
    const auto argv_storage = heap_next_;
    heap_next_ += argv_allocation_size;
    memory.map(argv_storage, argv_allocation_size, Read | Write, "guest argv");
    heap_sizes_.emplace(argv_storage, argv_allocation_size);
    const auto wide_pointer_array = argv_storage;
    const auto narrow_pointer_array = argv_storage + 0x800;
    auto narrow_string_next = argv_storage + 0x1000;
    auto wide_string_next = argv_storage + 0x8000;
    for (int index = 0; index < host_argc; ++index) {
        const std::wstring wide_argument(host_argv[index]);
        std::string narrow_argument;
        narrow_argument.reserve(wide_argument.size());
        for (const wchar_t character : wide_argument) {
            narrow_argument.push_back(
                character >= 0 && character < 0x80 ? static_cast<char>(character) : '_');
        }
        if (narrow_string_next + narrow_argument.size() + 1 > argv_storage + 0x8000 ||
            wide_string_next + (wide_argument.size() + 1) * 2 >
                argv_storage + argv_allocation_size) {
            ::LocalFree(host_argv);
            throw Error("guest argv storage exhausted");
        }
        write_guest_pointer(narrow_pointer_array + index * (image.is_64_bit ? 8 : 4),
                            narrow_string_next);
        write_guest_pointer(wide_pointer_array + index * (image.is_64_bit ? 8 : 4),
                            wide_string_next);
        for (const char character : narrow_argument) {
            memory.write8(narrow_string_next++, static_cast<std::uint8_t>(character));
        }
        memory.write8(narrow_string_next++, 0);
        for (const wchar_t character : wide_argument) {
            memory.write16(wide_string_next, static_cast<std::uint16_t>(character));
            wide_string_next += 2;
        }
        memory.write16(wide_string_next, 0);
        wide_string_next += 2;
    }
    ::LocalFree(host_argv);
    write_guest_pointer(narrow_pointer_array + host_argc * (image.is_64_bit ? 8 : 4), 0);
    write_guest_pointer(wide_pointer_array + host_argc * (image.is_64_bit ? 8 : 4), 0);
    memory.write32(crt_argc, static_cast<std::uint32_t>(host_argc));
    write_guest_pointer(crt_argv, narrow_pointer_array);
    write_guest_pointer(crt_wargv, wide_pointer_array);

    for (std::size_t index = 0; index < full_command_line.size(); ++index) {
        memory.write16(command_line_address + index * 2,
                       static_cast<std::uint16_t>(full_command_line[index]));
    }
    memory.write16(command_line_address + full_command_line.size() * 2, 0);
    for (std::size_t index = 0; index < arguments.size(); ++index) {
        memory.write16(winmain_command_line_address + index * 2,
                       static_cast<std::uint16_t>(arguments[index]));
    }
    memory.write16(winmain_command_line_address + arguments.size() * 2, 0);
    guest_command_line_ = command_line_address;
    guest_winmain_command_line_ = winmain_command_line_address;
    std::string narrow_command_line;
    narrow_command_line.reserve(full_command_line.size());
    for (const wchar_t character : full_command_line) {
        narrow_command_line.push_back(character < 0x80 ? static_cast<char>(character) : '_');
    }
    for (std::size_t index = 0; index < narrow_command_line.size(); ++index) {
        memory.write8(environment_base + 0x3800 + index,
                      static_cast<std::uint8_t>(narrow_command_line[index]));
    }
    memory.write8(environment_base + 0x3800 + narrow_command_line.size(), 0);
    guest_command_line_a_ = environment_base + 0x3800;
    const auto data_slot = [&](const char *name) {
        const auto found = data_import_slots_.find(name);
        return found == data_import_slots_.end() ? 0 : found->second;
    };
    if (const auto slot = data_slot("_wcmdln"); slot != 0) {
        write_guest_pointer(slot, command_line_address);
    }
    if (const auto slot = data_slot("_acmdln"); slot != 0) {
        write_guest_pointer(slot, environment_base + 0x3800);
    }
    // An empty environment is a single NULL pointer entry.
    if (const auto slot = data_slot("_environ"); slot != 0) {
        const auto pointer_size = image.is_64_bit ? 8U : 4U;
        write_guest_pointer(slot, slot + pointer_size);
    }
    if (const auto slot = data_slot("_wenviron"); slot != 0) {
        const auto pointer_size = image.is_64_bit ? 8U : 4U;
        write_guest_pointer(slot, slot + pointer_size);
    }
    if (const auto slot = data_slot("_winmajor"); slot != 0) {
        memory.write32(slot, 10);
    }
    if (const auto slot = data_slot("_winminor"); slot != 0) {
        memory.write32(slot, 0);
    }
    if (const auto slot = data_slot("_osver"); slot != 0) {
        memory.write32(slot, 0);
    }
    if (const auto slot = data_slot("_winver"); slot != 0) {
        memory.write32(slot, 0x0A00);
    }
    log::info("runtime", "guest command line: " + narrow_string(full_command_line));

    Cpu cpu(memory);
    cpu.reset(image.entry, initial_rsp, image.is_64_bit);
    if (image.is_64_bit) {
        cpu.set_gs_base(teb_base);
    } else {
        cpu.set_fs_base(teb_base);
    }
    std::uint32_t exit_code = 0;
    bool exited = false;
    detail::set_callback_context(*this, cpu, exit_code, exited);
    log::info("runtime", "starting guest at entry " + log::hex(image.entry));
    try {
        for (const auto callback : image.tls_callbacks) {
            log::trace("runtime", "calling TLS callback " + log::hex(callback));
            static_cast<void>(invoke_guest(cpu, callback, {image.base, DLL_PROCESS_ATTACH, 0, 0},
                                           exit_code, exited));
            if (exited) {
                break;
            }
        }
        while (!exited) {
            if (cpu.instructions() >= instruction_limit) {
                throw Error("instruction limit exceeded");
            }
            if (!dispatch(cpu, exit_code, exited)) {
                cpu.step();
            }
        }
    } catch (const std::exception &) {
        log::error("cpu",
                   "guest stopped after " + std::to_string(cpu.instructions()) + " instructions");
        log::error("cpu", cpu_state_dump(cpu));
        detail::clear_callback_context();
        throw;
    }
    detail::clear_callback_context();
    log::info("runtime", "guest finished cleanly");
    return {exit_code, cpu.instructions()};
}

} // namespace winemu
