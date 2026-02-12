cmake_minimum_required(VERSION 3.20)
project(EXHTTP VERSION 1.5.2 LANGUAGES CXX C)

# ============================================================================
# Налаштування опцій
# ============================================================================
option(USE_UCRT "Use UCRT runtime" ON)

# Архітектура (визначається автоматично або через -DARCH_SUFFIX)
if(NOT DEFINED ARCH_SUFFIX)
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "AMD64|x86_64")
        set(ARCH_SUFFIX "x64")
    elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "ARM64|aarch64")
        set(ARCH_SUFFIX "arm64")
    elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "X86|i686")
        set(ARCH_SUFFIX "x32")
    else()
        set(ARCH_SUFFIX "x64")
    endif()
endif()

# Визначення рантайму
if(NOT DEFINED RUNTIME_DIR)
    set(RUNTIME_DIR "ucrt")
endif()

message(STATUS "========================================")
message(STATUS "Build configuration:")
message(STATUS "  Project:      EXHTTP (WinHTTP Emulator)")
message(STATUS "  Architecture: ${ARCH_SUFFIX}")
message(STATUS "  Runtime:      ${RUNTIME_DIR}")
message(STATUS "========================================")

# ============================================================================
# Налаштування компілятора
# ============================================================================
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Вихідна директорія для DLL та LIB
set(OUTPUT_DIR "${CMAKE_SOURCE_DIR}/${RUNTIME_DIR}/${ARCH_SUFFIX}")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${OUTPUT_DIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${OUTPUT_DIR})
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${OUTPUT_DIR})

# Прапорці оптимізації та лінкування
if(CMAKE_C_COMPILER_ID MATCHES "Clang")
    add_compile_options(
        -O3
        -flto
        -ffunction-sections
        -fdata-sections
        -fms-extensions
        -Wno-inconsistent-dllimport
        -Wno-microsoft-anon-tag
    )

    add_link_options(
        -flto
        -fuse-ld=lld
        -Wl,/OPT:REF
        -Wl,/OPT:ICF
        -Wl,/DYNAMICBASE
        -Wl,/NXCOMPAT
    )
endif()

# ============================================================================
# Компіляція ресурсів
# ============================================================================
find_program(RC_COMPILER
    NAMES llvm-rc llvm-windres windres
    HINTS
        "${CMAKE_C_COMPILER_TARGET}"
        "$ENV{LLVM_PATH}/bin"
        "$ENV{PATH}"
)

if(NOT RC_COMPILER)
    message(WARNING "Resource compiler (llvm-rc or windres) not found! Building without resources.")
    set(RC_OBJECT "")
else()
    message(STATUS "Using resource compiler: ${RC_COMPILER}")

    set(RC_SOURCE "${CMAKE_SOURCE_DIR}/version.rc")
    set(RC_OBJECT "${CMAKE_BINARY_DIR}/version.res")

    add_custom_command(
        OUTPUT ${RC_OBJECT}
        COMMAND ${RC_COMPILER} /fo ${RC_OBJECT} ${RC_SOURCE}
        DEPENDS ${RC_SOURCE}
        COMMENT "Compiling resources: ${RC_SOURCE}"
        VERBATIM
    )
endif()

# ============================================================================
# Створення DLL
# ============================================================================
add_library(EXHTTP SHARED
    dllmain.c
    winhttp.def
    ${RC_OBJECT}
)

set_target_properties(EXHTTP PROPERTIES
    OUTPUT_NAME "EXHTTP"
    PREFIX ""
    SUFFIX ".dll"
    IMPORT_PREFIX ""
    IMPORT_SUFFIX ".lib"
    ENABLE_EXPORTS ON
)

target_link_libraries(EXHTTP PRIVATE
    kernel32
    user32
)

target_link_options(EXHTTP PRIVATE
    "LINKER:/DEF:${CMAKE_SOURCE_DIR}/winhttp.def"
)

if(RC_OBJECT)
    target_link_options(EXHTTP PRIVATE "${RC_OBJECT}")
endif()

# ============================================================================
# Обов'язкове лінкування з exws2.lib
# ============================================================================
# exws2.lib знаходиться в include/<arch>/, а НЕ в ucrt/<arch>/
set(EXWS2_LIB "${CMAKE_SOURCE_DIR}/include/${ARCH_SUFFIX}/exws2.lib")

if(NOT EXISTS "${EXWS2_LIB}")
    message(FATAL_ERROR
        "========================================\n"
        "ERROR: exws2.lib not found!\n"
        "Path: ${EXWS2_LIB}\n"
        "\n"
        "EXHTTP requires exws2.lib to function.\n"
        "Please build EXWS2 first or place exws2.lib\n"
        "in the include/${ARCH_SUFFIX} directory.\n"
        "========================================\n"
    )
endif()

message(STATUS "Found exws2.lib: ${EXWS2_LIB}")
target_link_libraries(EXHTTP PRIVATE "${EXWS2_LIB}")
message(STATUS "Linking with exws2.lib: ENABLED")

# ============================================================================
# Інформація про збірку
# ============================================================================
add_custom_command(TARGET EXHTTP POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E echo "=========================================="
    COMMAND ${CMAKE_COMMAND} -E echo "Build successful!"
    COMMAND ${CMAKE_COMMAND} -E echo "Output: ${OUTPUT_DIR}/EXHTTP.dll"
    COMMAND ${CMAKE_COMMAND} -E echo "Import lib: ${OUTPUT_DIR}/EXHTTP.lib"
    COMMAND ${CMAKE_COMMAND} -E echo "Linked with: ${EXWS2_LIB}"
    COMMAND ${CMAKE_COMMAND} -E echo "=========================================="
    VERBATIM
)