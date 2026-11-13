#pragma once

#include "winemu/cpu.hpp"
#include "winemu/detail/runtime_api.hpp"
#include "winemu/pe.hpp"

#include <array>
#include <cstdint>
#include <filesystem>
#include <iosfwd>
#include <span>
#include <string>
#include <unordered_map>
#include <vector>

namespace winemu {

struct RunResult {
    std::uint32_t exit_code;
    std::uint64_t instructions;
};

class Runtime {
  public:
    explicit Runtime(std::ostream &output);
    ~Runtime();
    RunResult run(const std::filesystem::path &executable,
                  std::uint64_t instruction_limit = 10'000'000,
                  const std::wstring &arguments = std::wstring());
    std::intptr_t invoke_window_proc(Cpu &cpu, std::uint64_t window, std::uint32_t message,
                                     std::uint64_t word_parameter, std::int64_t long_parameter,
                                     std::uint32_t &exit_code, bool &exited);
    std::intptr_t invoke_window_subclass(Cpu &cpu, std::uint64_t token, std::uint64_t window,
                                         std::uint32_t message, std::uint64_t word_parameter,
                                         std::int64_t long_parameter, std::uint32_t &exit_code,
                                         bool &exited);
    std::intptr_t invoke_dialog_proc(Cpu &cpu, std::uint64_t window, std::uint32_t message,
                                     std::uint64_t word_parameter, std::int64_t long_parameter,
                                     std::uint32_t &exit_code, bool &exited);
    bool invoke_window_enum(Cpu &cpu, std::uint64_t window, std::uint32_t &exit_code, bool &exited);

  private:
    using Api = detail::RuntimeApi;

    [[nodiscard]] std::uint64_t resolve_import(const std::string &module, const std::string &name);
    [[nodiscard]] std::uint64_t allocate_data_import(const std::string &module,
                                                     const std::string &name);
    // Guest imports must bind under the guest's own activation context. Without it, a manifest
    // that requests Side-by-Side assemblies such as Common-Controls v6 silently binds to the
    // older system DLL, whose export table can be missing the ordinals the guest imports.
    [[nodiscard]] bool ensure_guest_activation_context();
    [[nodiscard]] std::uintptr_t activate_guest_context() const;
    void deactivate_guest_context(std::uintptr_t cookie) const;
    [[nodiscard]] bool dispatch(Cpu &cpu, std::uint32_t &exit_code, bool &exited);
    [[nodiscard]] std::uint64_t invoke_guest(Cpu &cpu, std::uint64_t target,
                                             const std::array<std::uint64_t, 4> &arguments,
                                             std::uint32_t &exit_code, bool &exited);
    [[nodiscard]] std::uint64_t invoke_guest(Cpu &cpu, std::uint64_t target,
                                             std::span<const std::uint64_t> arguments,
                                             std::uint32_t &exit_code, bool &exited);
    [[nodiscard]] std::intptr_t invoke_window_callback(
        Cpu &cpu, std::uint64_t target, std::uint64_t window, std::uint32_t message,
        std::uint64_t word_parameter, std::int64_t long_parameter, std::uint64_t subclass_id,
        std::uint64_t reference_data, bool subclass, std::uint32_t &exit_code, bool &exited);

    // Import thunks are guest-callable addresses. The maps below keep their behavior and any
    // explicitly approved native target separate so an untrusted guest address is never cast and
    // called directly.
    std::ostream &output_;
    std::unordered_map<std::uint64_t, Api> thunks_;
    std::unordered_map<std::uint64_t, std::string> thunk_names_;
    std::unordered_map<std::uint64_t, void *> native_functions_;
    std::uint64_t next_thunk_ = 0xffff'0000'0000'0100ULL;
    bool guest_is_64_bit_ = true;
    std::uint64_t data_import_next_ = 0;
    std::unordered_map<std::string, std::uint64_t> data_import_slots_;
    std::uint32_t last_error_ = 0;
    std::uint32_t common_dialog_error_ = 0;
    std::uint64_t guest_exception_filter_ = 0;
    std::uint64_t guest_command_line_ = 0;
    std::uint64_t guest_command_line_a_ = 0;
    std::uint64_t guest_winmain_command_line_ = 0;

    // Handles exposed to the guest are small opaque tokens, never raw host HANDLE or FILE values.
    // Every adapter must validate a token through its owning table before touching host state.
    std::uint64_t heap_next_ = 0x0000'0006'0000'0000ULL;
    std::unordered_map<std::uint64_t, std::uint64_t> heap_sizes_;
    std::uint64_t guest_image_base_ = 0;
    std::uint64_t next_module_handle_ = 0x7fe0'0000ULL;
    std::unordered_map<std::uint64_t, std::string> guest_modules_;
    std::uint64_t next_find_handle_ = 0x300;
    std::unordered_map<std::uint64_t, void *> find_handles_;
    std::uint64_t next_file_handle_ = 0x400;
    std::unordered_map<std::uint64_t, void *> file_handles_;
    std::uint64_t next_mapping_handle_ = 0x500;
    std::unordered_map<std::uint64_t, void *> mapping_handles_;
    std::unordered_map<std::uint64_t, std::uint64_t> mapped_views_;
    std::uint64_t next_sync_handle_ = 0x600;
    std::unordered_map<std::uint64_t, void *> sync_handles_;
    std::wstring synchronization_namespace_;
    std::uint64_t host_gdiplus_token_ = 0;
    std::filesystem::path guest_executable_;
    void *resource_module_ = nullptr;
    void *guest_activation_context_ = nullptr;

    // Host windows call back through a bridge. These tables retain the corresponding guest
    // procedure and callback arguments while the interpreter is re-entered.
    std::unordered_map<std::wstring, std::uint64_t> class_window_procedures_;
    std::unordered_map<std::uint16_t, std::uint64_t> atom_window_procedures_;
    std::unordered_map<std::uint64_t, std::uint64_t> window_procedures_;
    std::uint64_t creating_window_procedure_ = 0;
    struct PendingDialog {
        std::uint64_t procedure;
        std::uint64_t init_parameter;
    };
    std::vector<PendingDialog> pending_dialogs_;
    std::unordered_map<std::uint64_t, std::uint64_t> dialog_procedures_;
    struct PendingWindowEnumeration {
        std::uint64_t procedure;
        std::uint64_t parameter;
        bool current_process_only;
    };
    std::vector<PendingWindowEnumeration> pending_window_enumerations_;
    bool quit_message_pending_ = false;
    std::uint32_t quit_message_code_ = 0;
    std::unordered_map<std::uint64_t, std::int64_t> callback_long_parameters_;
    std::unordered_map<std::uint64_t, std::uint64_t> edit_memory_handles_;
    std::uint32_t callback_depth_ = 0;
    std::uint64_t direct_input_proxy_ = 0;
    std::uint64_t direct_input_device_proxy_ = 0;
    std::unordered_map<std::uint64_t, std::uint32_t> direct_input_methods_;

    // COM and WinRT objects below are guest-owned proxy objects. Method maps translate each
    // guest vtable thunk back to its slot number; no host vtable pointer crosses the ABI boundary.
    std::uint64_t acc_prop_services_proxy_ = 0;
    std::unordered_map<std::uint64_t, std::uint32_t> acc_prop_services_methods_;
    std::uint64_t application_document_lists_proxy_ = 0;
    std::uint64_t empty_object_array_proxy_ = 0;
    std::unordered_map<std::uint64_t, std::uint32_t> application_document_lists_methods_;
    std::unordered_map<std::uint64_t, std::uint32_t> object_array_methods_;
    std::uint64_t protection_policy_proxy_ = 0;
    std::unordered_map<std::uint64_t, std::uint32_t> protection_policy_methods_;
    // Guest feature-state-change callbacks, retained so they are never executed as host code.
    std::unordered_map<std::uint64_t, std::uint64_t> feature_state_callbacks_;
    struct WindowSubclass {
        std::uint64_t window;
        std::uint64_t procedure;
        std::uint64_t id;
        std::uint64_t reference_data;
    };
    // Common Controls receives only a host bridge and an opaque token. Guest procedures and
    // reference data remain here and are invoked through the interpreter.
    std::uint64_t next_window_subclass_token_ = 1;
    std::unordered_map<std::uint64_t, WindowSubclass> window_subclasses_;
    std::uint64_t winrt_activation_factory_proxy_ = 0;
    std::uint64_t geographic_region_proxy_ = 0;
    std::unordered_map<std::uint64_t, std::uint32_t> winrt_activation_factory_methods_;
    std::unordered_map<std::uint64_t, std::uint32_t> geographic_region_methods_;
    // Activation factories for classes without a dedicated adapter, keyed by WinRT class name, and
    // the guest-owned instance each factory's ActivateInstance returns, keyed by factory object.
    std::unordered_map<std::wstring, std::uint64_t> winrt_generic_factories_;
    std::unordered_map<std::uint64_t, std::uint64_t> winrt_factory_instances_;
    std::unordered_map<std::uint64_t, std::uint32_t> winrt_generic_factory_methods_;
    std::unordered_map<std::uint64_t, std::uint32_t> winrt_inspectable_methods_;
    std::uint64_t application_data_statics_proxy_ = 0;
    std::uint64_t application_data_proxy_ = 0;
    std::unordered_map<std::uint64_t, std::uint32_t> application_data_statics_methods_;
    std::unordered_map<std::uint64_t, std::uint32_t> application_data_methods_;
    std::uint64_t application_data_container_proxy_ = 0;
    std::uint64_t property_set_proxy_ = 0;
    std::unordered_map<std::uint64_t, std::uint32_t> application_data_container_methods_;
    std::unordered_map<std::uint64_t, std::uint32_t> property_set_methods_;
    std::uint64_t app_data_paths_statics_proxy_ = 0;
    std::uint64_t app_data_paths_proxy_ = 0;
    std::array<std::uint64_t, 9> app_data_path_strings_{};
    std::unordered_map<std::uint64_t, std::uint32_t> app_data_paths_statics_methods_;
    std::unordered_map<std::uint64_t, std::uint32_t> app_data_paths_methods_;
    std::uint64_t xaml_resource_factory_proxy_ = 0;
    std::uint64_t xaml_resource_proxy_ = 0;
    std::unordered_map<std::uint64_t, std::uint32_t> xaml_resource_factory_methods_;
    std::unordered_map<std::uint64_t, std::uint32_t> xaml_resource_methods_;
    std::uint64_t xaml_application_statics_proxy_ = 0;
    std::unordered_map<std::uint64_t, std::uint32_t> xaml_application_statics_methods_;
    std::uint64_t xaml_app_factory_proxy_ = 0;
    std::uint64_t xaml_app_proxy_ = 0;
    std::uint64_t xaml_app_drag_verifier_ = 0;
    std::uint64_t xaml_app_localized_key_storage_ = 0;
    std::unordered_map<std::uint64_t, std::uint32_t> xaml_app_factory_methods_;
    std::unordered_map<std::uint64_t, std::uint32_t> xaml_app_methods_;
    std::uint64_t dispatcher_queue_controller_statics_proxy_ = 0;
    std::uint64_t dispatcher_queue_controller_proxy_ = 0;
    std::unordered_map<std::uint64_t, std::uint32_t> dispatcher_queue_controller_statics_methods_;
    std::unordered_map<std::uint64_t, std::uint32_t> dispatcher_queue_controller_methods_;
    std::uint64_t resource_manager_statics_proxy_ = 0;
    std::uint64_t resource_manager_proxy_ = 0;
    std::uint64_t resource_map_proxy_ = 0;
    std::uint64_t resource_context_statics_proxy_ = 0;
    std::uint64_t resource_context_proxy_ = 0;
    std::uint64_t resource_candidate_proxy_ = 0;
    std::uint64_t resource_candidate_value_ = 0;
    std::uint64_t resource_candidate_language_ = 0;
    std::unordered_map<std::uint64_t, std::uint32_t> resource_manager_statics_methods_;
    std::unordered_map<std::uint64_t, std::uint32_t> resource_manager_methods_;
    std::unordered_map<std::uint64_t, std::uint32_t> resource_map_methods_;
    std::unordered_map<std::uint64_t, std::uint32_t> resource_context_statics_methods_;
    std::unordered_map<std::uint64_t, std::uint32_t> resource_context_methods_;
    std::unordered_map<std::uint64_t, std::uint32_t> resource_candidate_methods_;
    std::uint64_t ui_settings_factory_proxy_ = 0;
    std::uint64_t ui_settings_proxy_ = 0;
    std::uint64_t ui_settings3_proxy_ = 0;
    std::unordered_map<std::uint64_t, std::uint32_t> ui_settings_factory_methods_;
    std::unordered_map<std::uint64_t, std::uint32_t> ui_settings_methods_;
    std::unordered_map<std::uint64_t, std::uint32_t> ui_settings3_methods_;
    std::uint64_t property_value_statics_proxy_ = 0;
    std::uint64_t property_value_vtable_ = 0;
    std::unordered_map<std::uint64_t, std::uint32_t> property_value_types_;
    std::unordered_map<std::uint64_t, std::uint64_t> property_value_data_;
    std::unordered_map<std::uint64_t, std::uint32_t> property_value_statics_methods_;
    std::unordered_map<std::uint64_t, std::uint32_t> property_value_methods_;

    // MSVC runtime objects use adapters because native C++ object layouts and stream pointers are
    // not ABI-safe guest data. Host FILE pointers remain private in guest_file_streams_.
    std::uint64_t locale_proxy_ = 0;
    std::uint64_t locale_facet_vtable_ = 0;
    std::unordered_map<std::uint64_t, std::uint32_t> locale_facet_methods_;
    std::unordered_map<std::uint64_t, std::uint64_t> locale_facets_;
    std::unordered_map<std::uint64_t, std::uint64_t> output_stream_buffers_;
    std::unordered_map<std::uint64_t, std::uint64_t> stream_buffer_storage_;
    std::unordered_map<std::uint64_t, std::uint64_t> stream_buffer_lengths_;
    std::unordered_map<std::uint64_t, std::uint64_t> stream_buffer_files_;
    std::unordered_map<std::uint64_t, std::uint64_t> input_stream_buffers_;
    std::unordered_map<std::uint64_t, std::uint64_t> input_stream_ios_;
    std::unordered_map<std::uint64_t, std::uint32_t> ios_states_;
    std::unordered_map<std::uint64_t, std::uint32_t> ios_exception_masks_;
    std::uint64_t pending_ios_object_ = 0;
    std::unordered_map<std::uint64_t, void *> guest_file_streams_;
    std::uint64_t pending_guest_file_stream_ = 0;

    // CPUEmu currently schedules one guest thread cooperatively, so TLS/FLS values are process-
    // local until the scheduler gains distinct per-thread execution contexts.
    std::uint32_t next_tls_index_ = 1;
    std::uint32_t next_fls_index_ = 1;
    std::unordered_map<std::uint32_t, std::uint64_t> tls_values_;
    std::unordered_map<std::uint32_t, std::uint64_t> fls_values_;
};

} // namespace winemu
