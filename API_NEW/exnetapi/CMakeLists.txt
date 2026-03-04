cmake_minimum_required(VERSION 3.20)
project(EXNETAPI VERSION 1.0.5 LANGUAGES C)

# ============================================================================
# Налаштування опцій
# ============================================================================
set(NETWORK_MODE "WORKGROUP" CACHE STRING "Network mode: WORKGROUP, DOMAIN, STANDALONE")

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

message(STATUS "========================================")
message(STATUS "EXNETAPI.dll (NETAPI32 Emulator) Build")
message(STATUS "========================================")
message(STATUS "  Architecture: ${ARCH_SUFFIX}")
message(STATUS "  Runtime:      ucrt")
message(STATUS "  Network Mode: ${NETWORK_MODE}")
message(STATUS "========================================")

# ============================================================================
# Налаштування компілятора
# ============================================================================
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Вихідна директорія для DLL та LIB
set(OUTPUT_DIR "${CMAKE_SOURCE_DIR}/ucrt/${ARCH_SUFFIX}")
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
    )
    
    add_link_options(
        -flto
        -fuse-ld=lld
        -Wl,/OPT:REF
        -Wl,/OPT:ICF
    )
endif()

# ============================================================================
# Конфігурація NETWORK_MODE (передаємо як макрос)
# ============================================================================
add_compile_definitions(NETWORK_MODE="${NETWORK_MODE}")

# ============================================================================
# Компіляція ресурсів
# ============================================================================
# Знаходимо llvm-rc або windres
find_program(RC_COMPILER
    NAMES llvm-rc llvm-windres windres
    HINTS
        "${CMAKE_C_COMPILER_TARGET}"
        "$ENV{LLVM_PATH}/bin"
        "$ENV{PATH}"
)

if(NOT RC_COMPILER)
    message(FATAL_ERROR "Resource compiler (llvm-rc or windres) not found!")
endif()

message(STATUS "Using resource compiler: ${RC_COMPILER}")

# Компіляція version.rc
set(RC_SOURCE "${CMAKE_SOURCE_DIR}/version.rc")
set(RC_OBJECT "${CMAKE_BINARY_DIR}/version.res")

# llvm-rc компілює .rc в .res формат
add_custom_command(
    OUTPUT ${RC_OBJECT}
    COMMAND ${RC_COMPILER} /fo ${RC_OBJECT} ${RC_SOURCE}
    DEPENDS ${RC_SOURCE}
    COMMENT "Compiling resources: ${RC_SOURCE}"
    VERBATIM
)

# ============================================================================
# Створення DLL
# ============================================================================
add_library(EXNETAPI SHARED
    netapi32_core.c
    exnetapi.def
    ${RC_OBJECT}
)

# Назва вихідного файлу - EXNETAPI.dll
set_target_properties(EXNETAPI PROPERTIES
    OUTPUT_NAME "EXNETAPI"
    PREFIX ""
    SUFFIX ".dll"
    IMPORT_PREFIX ""
    IMPORT_SUFFIX ".lib"
    ENABLE_EXPORTS ON
)

# Лінкування з DEF файлом (exnetapi.def - для експорту функцій netapi32)
target_link_options(EXNETAPI PRIVATE
    "LINKER:/DEF:${CMAKE_SOURCE_DIR}/exnetapi.def"
    "${RC_OBJECT}"  # Додаємо .res файл напряму в лінкер
)

# ============================================================================
# Інформація про збірку
# ============================================================================
add_custom_command(TARGET EXNETAPI POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E echo "=========================================="
    COMMAND ${CMAKE_COMMAND} -E echo "Build successful!"
    COMMAND ${CMAKE_COMMAND} -E echo "Output: ${OUTPUT_DIR}/EXNETAPI.dll"
    COMMAND ${CMAKE_COMMAND} -E echo "Import lib: ${OUTPUT_DIR}/EXNETAPI.lib"
    COMMAND ${CMAKE_COMMAND} -E echo "=========================================="
    VERBATIM
)