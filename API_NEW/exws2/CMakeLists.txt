cmake_minimum_required(VERSION 3.20)
project(EXWS2 VERSION 2.1.2 LANGUAGES CXX C)

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
message(STATUS "  Architecture: ${ARCH_SUFFIX}")
message(STATUS "  Runtime:      ${RUNTIME_DIR}")
message(STATUS "========================================")

# ============================================================================
# Налаштування компілятора
# ============================================================================
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Вихідна директорія для DLL та LIB
set(OUTPUT_DIR "${CMAKE_SOURCE_DIR}/${RUNTIME_DIR}/${ARCH_SUFFIX}")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${OUTPUT_DIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${OUTPUT_DIR})
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${OUTPUT_DIR})

# Прапорці оптимізації та лінкування
if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    add_compile_options(
        -O3
        -flto
        -ffunction-sections
        -fdata-sections
        -Wno-inconsistent-dllimport
    )
    
    add_link_options(
        -flto
        -fuse-ld=lld
        -Wl,/OPT:REF
        -Wl,/OPT:ICF
    )
endif()

# ============================================================================
# Компіляція ресурсів
# ============================================================================
# Знаходимо llvm-rc
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
add_library(EXWS2 SHARED
    ws2_emu.cpp
    ws2_32.def
    ${RC_OBJECT}
)

# Назва вихідного файлу
set_target_properties(EXWS2 PROPERTIES
    OUTPUT_NAME "EXWS2"
    PREFIX ""
    SUFFIX ".dll"
    IMPORT_PREFIX ""
    IMPORT_SUFFIX ".lib"
    ENABLE_EXPORTS ON
)

# ============================================================================
# Лінкування з системними бібліотеками
# ============================================================================
# ОНОВЛЕНО: Додано advapi32 для роботи з реєстром
# ВИДАЛЕНО: exiphl.lib - більше не потрібен!
target_link_libraries(EXWS2 PRIVATE
    kernel32    # Windows API basics
    user32      # User interface
    ws2_32      # Real Winsock2 for fallback
    advapi32    # Registry API (RegOpenKeyEx, RegQueryValueEx)
)

message(STATUS "EXWS2: Fully autonomous - no EXIPHL dependency!")

# Лінкування з DEF файлом
target_link_options(EXWS2 PRIVATE
    "LINKER:/DEF:${CMAKE_SOURCE_DIR}/ws2_32.def"
    "${RC_OBJECT}"  # Додаємо .res файл напряму в лінкер
)

# ============================================================================
# Інформація про збірку
# ============================================================================
add_custom_command(TARGET EXWS2 POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E echo "=========================================="
    COMMAND ${CMAKE_COMMAND} -E echo "Build successful!"
    COMMAND ${CMAKE_COMMAND} -E echo "Output: ${OUTPUT_DIR}/EXWS2.dll"
    COMMAND ${CMAKE_COMMAND} -E echo "Import lib: ${OUTPUT_DIR}/EXWS2.lib"
    COMMAND ${CMAKE_COMMAND} -E echo "=========================================="
    COMMAND ${CMAKE_COMMAND} -E echo "EXWS2 v2.1.2 - Fully autonomous!"
    COMMAND ${CMAKE_COMMAND} -E echo "No EXIPHL dependency"
    COMMAND ${CMAKE_COMMAND} -E echo "Reads config from: HKCU\\Software\\EXLOUD\\Config"
    COMMAND ${CMAKE_COMMAND} -E echo "Run add_to_reg.bat to configure"
    COMMAND ${CMAKE_COMMAND} -E echo "=========================================="
    VERBATIM
)