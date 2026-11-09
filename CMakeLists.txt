cmake_minimum_required(VERSION 3.24)
project(CPUEmu VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(winemu_core
    src/core/cpu_execute.cpp
    src/core/cpu_decode.cpp
    src/core/cpu_flags.cpp
    src/core/cpu_state.cpp
    src/core/log.cpp
    src/core/memory.cpp
    src/core/memory_access.cpp
    src/core/memory_virtual.cpp
    src/loader/pe.cpp
    src/runtime/imports.cpp
    src/runtime/callbacks.cpp
    src/runtime/execution.cpp
    src/runtime/lifecycle.cpp
    src/runtime/dispatch.cpp
    src/runtime/strings.cpp
)
target_include_directories(winemu_core PUBLIC include)
target_link_libraries(winemu_core PUBLIC advapi32 shell32 winmm)
target_compile_options(winemu_core PRIVATE
    $<$<CXX_COMPILER_ID:Clang>:-Wall -Wextra -Wpedantic -Werror>
)

add_executable(cpuemu src/cli/main.cpp)
target_link_libraries(cpuemu PRIVATE winemu_core)
target_compile_definitions(cpuemu PRIVATE CPUEMU_VERSION="${PROJECT_VERSION}")
target_link_options(cpuemu PRIVATE $<$<CXX_COMPILER_ID:Clang>:-Wl,/base:0x10000000000,/dynamicbase:no>)

enable_testing()
add_executable(cpuemu_tests
    tests/cpu_tests.cpp
    tests/memory_tests.cpp
    tests/runtime_case_tests.cpp
    tests/test_main.cpp
    tests/test_support.cpp
)
target_link_libraries(cpuemu_tests PRIVATE winemu_core)
target_link_options(cpuemu_tests PRIVATE $<$<CXX_COMPILER_ID:Clang>:-Wl,/base:0x10000000000,/dynamicbase:no>)
target_compile_definitions(cpuemu_tests PRIVATE WINEMU_TEST_APPS_DIR="${CMAKE_BINARY_DIR}/test-apps")
add_test(NAME cpuemu_tests COMMAND cpuemu_tests)

add_executable(make_test_apps
    tools/generators/guest_fixture_builders.cpp
    tools/generators/make_test_apps.cpp
    tools/generators/pe_fixture_writer.cpp
)
add_custom_command(
    OUTPUT
        ${CMAKE_BINARY_DIR}/test-apps/exit42.exe
        ${CMAKE_BINARY_DIR}/test-apps/exit32.exe
        ${CMAKE_BINARY_DIR}/test-apps/sum.exe
        ${CMAKE_BINARY_DIR}/test-apps/hello.exe
        ${CMAKE_BINARY_DIR}/test-apps/winrt.exe
        ${CMAKE_BINARY_DIR}/test-apps/schedule.exe
        ${CMAKE_BINARY_DIR}/test-apps/errorinfo.exe
        ${CMAKE_BINARY_DIR}/test-apps/propertyvalue.exe
    COMMAND make_test_apps ${CMAKE_BINARY_DIR}/test-apps
    DEPENDS make_test_apps
    VERBATIM
)
add_custom_target(generate_test_apps ALL DEPENDS
    ${CMAKE_BINARY_DIR}/test-apps/exit42.exe
    ${CMAKE_BINARY_DIR}/test-apps/exit32.exe
    ${CMAKE_BINARY_DIR}/test-apps/sum.exe
    ${CMAKE_BINARY_DIR}/test-apps/hello.exe
    ${CMAKE_BINARY_DIR}/test-apps/winrt.exe
    ${CMAKE_BINARY_DIR}/test-apps/schedule.exe
    ${CMAKE_BINARY_DIR}/test-apps/errorinfo.exe
    ${CMAKE_BINARY_DIR}/test-apps/propertyvalue.exe
)
add_dependencies(cpuemu_tests generate_test_apps)

# Guest painting application, compiled with the host toolchain and executed by CPUEmu.
add_custom_command(
    OUTPUT ${CMAKE_BINARY_DIR}/test-apps/paint.exe
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_BINARY_DIR}/test-apps
    COMMAND ${CMAKE_CXX_COMPILER} ${CMAKE_SOURCE_DIR}/tools/guests/paint.cpp -std=c++20 -O2
            -municode -D_DLL -D_MT -Xclang --dependent-lib=msvcrt
            -o ${CMAKE_BINARY_DIR}/test-apps/paint.exe -luser32 -lgdi32 -Wl,-subsystem:windows
    DEPENDS tools/guests/paint.cpp
    VERBATIM
)
add_custom_target(guest_paint ALL DEPENDS ${CMAKE_BINARY_DIR}/test-apps/paint.exe)
add_dependencies(cpuemu_tests guest_paint)

# Guest MSVC stream fixture. It exercises guest-owned file/iostream adapters without exposing a
# host FILE pointer to the guest C++ object layout.
file(GENERATE OUTPUT ${CMAKE_BINARY_DIR}/test-apps/stream-data.bin CONTENT "0123456789")
add_custom_command(
    OUTPUT ${CMAKE_BINARY_DIR}/test-apps/stream.exe
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_BINARY_DIR}/test-apps
    COMMAND ${CMAKE_CXX_COMPILER} ${CMAKE_SOURCE_DIR}/tools/guests/stream.cpp -std=c++20 -O0
            -D_DLL -D_MT -Xclang --dependent-lib=msvcrt
            -o ${CMAKE_BINARY_DIR}/test-apps/stream.exe
    DEPENDS tools/guests/stream.cpp
    VERBATIM
)
add_custom_target(guest_stream ALL DEPENDS ${CMAKE_BINARY_DIR}/test-apps/stream.exe)
add_dependencies(cpuemu_tests guest_stream)
add_test(NAME guest_stream_adapter COMMAND cpuemu ${CMAKE_BINARY_DIR}/test-apps/stream.exe)
set_tests_properties(guest_stream_adapter PROPERTIES TIMEOUT 10)

add_test(
    NAME paint_message_loop
    COMMAND cpuemu ${CMAKE_BINARY_DIR}/test-apps/paint.exe -- --message-selftest
)
set_tests_properties(paint_message_loop PROPERTIES TIMEOUT 10)
add_test(
    NAME guest_synchronization
    COMMAND cpuemu ${CMAKE_BINARY_DIR}/test-apps/paint.exe -- --sync-selftest
)
set_tests_properties(guest_synchronization PROPERTIES TIMEOUT 10)
