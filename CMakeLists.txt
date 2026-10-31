cmake_minimum_required(VERSION 3.24)
project(CPUEmu VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(winemu_core
    src/cpu.cpp
    src/log.cpp
    src/memory.cpp
    src/pe.cpp
    src/runtime.cpp
)
target_include_directories(winemu_core PUBLIC include)
target_link_libraries(winemu_core PUBLIC advapi32 shell32)
target_compile_options(winemu_core PRIVATE
    $<$<CXX_COMPILER_ID:Clang>:-Wall -Wextra -Wpedantic -Werror>
)

add_executable(cpuemu src/main.cpp)
target_link_libraries(cpuemu PRIVATE winemu_core)
target_compile_definitions(cpuemu PRIVATE CPUEMU_VERSION="${PROJECT_VERSION}")
target_link_options(cpuemu PRIVATE $<$<CXX_COMPILER_ID:Clang>:-Wl,/base:0x10000000000,/dynamicbase:no>)

enable_testing()
add_executable(cpuemu_tests tests/tests.cpp)
target_link_libraries(cpuemu_tests PRIVATE winemu_core)
target_link_options(cpuemu_tests PRIVATE $<$<CXX_COMPILER_ID:Clang>:-Wl,/base:0x10000000000,/dynamicbase:no>)
target_compile_definitions(cpuemu_tests PRIVATE WINEMU_TEST_APPS_DIR="${CMAKE_BINARY_DIR}/test-apps")
add_test(NAME cpuemu_tests COMMAND cpuemu_tests)

add_executable(make_test_apps tools/make_test_apps.cpp)
add_custom_command(
    OUTPUT
        ${CMAKE_BINARY_DIR}/test-apps/exit42.exe
        ${CMAKE_BINARY_DIR}/test-apps/sum.exe
        ${CMAKE_BINARY_DIR}/test-apps/hello.exe
    COMMAND make_test_apps ${CMAKE_BINARY_DIR}/test-apps
    DEPENDS make_test_apps
    VERBATIM
)
add_custom_target(generate_test_apps ALL DEPENDS
    ${CMAKE_BINARY_DIR}/test-apps/exit42.exe
    ${CMAKE_BINARY_DIR}/test-apps/sum.exe
    ${CMAKE_BINARY_DIR}/test-apps/hello.exe
)
add_dependencies(cpuemu_tests generate_test_apps)

# Guest painting application, compiled with the host toolchain and executed by CPUEmu.
add_custom_command(
    OUTPUT ${CMAKE_BINARY_DIR}/test-apps/paint.exe
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_BINARY_DIR}/test-apps
    COMMAND ${CMAKE_CXX_COMPILER} ${CMAKE_SOURCE_DIR}/tools/guest/paint.cpp -std=c++20 -O2
            -municode -D_DLL -D_MT -Xclang --dependent-lib=msvcrt
            -o ${CMAKE_BINARY_DIR}/test-apps/paint.exe -luser32 -lgdi32 -Wl,-subsystem:windows
    DEPENDS tools/guest/paint.cpp
    VERBATIM
)
add_custom_target(guest_paint ALL DEPENDS ${CMAKE_BINARY_DIR}/test-apps/paint.exe)
add_dependencies(cpuemu_tests guest_paint)
