cmake_minimum_required(VERSION 3.20)
project(EXURLM VERSION 1.0.0 LANGUAGES C)

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
message(STATUS "  Project:      EXURLM")
message(STATUS "  Architecture: ${ARCH_SUFFIX}")
message(STATUS "  Runtime:      ${RUNTIME_DIR}")
message(STATUS "  Compiler:     ${CMAKE_C_COMPILER_ID}")
message(STATUS "========================================")

# ============================================================================
# Налаштування компілятора
# ============================================================================
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Вихідна директорія для DLL
set(OUTPUT_DIR "${CMAKE_SOURCE_DIR}/${RUNTIME_DIR}/${ARCH_SUFFIX}")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${OUTPUT_DIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${OUTPUT_DIR})

# Прапорці оптимізації (clang-cl specific)
if(CMAKE_C_COMPILER_ID MATCHES "Clang" AND CMAKE_C_COMPILER_FRONTEND_VARIANT MATCHES "MSVC")
    # clang-cl (MSVC-compatible mode)
    add_compile_options(
        /O2                    # Оптимізація
        /Oi                    # Intrinsics
        /GL                    # Whole program optimization
        /GS-                   # Disable security checks
    )
    
    add_link_options(
        /LTCG                  # Link-time code generation
        /OPT:REF               # Remove unreferenced functions
        /OPT:ICF               # Identical COMDAT folding
    )
elseif(CMAKE_C_COMPILER_ID MATCHES "Clang")
    # clang (GCC-compatible mode)
    add_compile_options(
        -O3
        -flto
        -ffunction-sections
        -fdata-sections
    )
    
    add_link_options(
        -flto
        -Wl,--gc-sections
    )
endif()

# ============================================================================
# Компіляція ресурсів
# ============================================================================
# Знаходимо llvm-rc
find_program(RC_COMPILER
    NAMES llvm-rc rc
    HINTS
        "$ENV{LLVM_PATH}/bin"
        "$ENV{PATH}"
)

if(NOT RC_COMPILER)
    message(FATAL_ERROR "Resource compiler (llvm-rc) not found!")
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
add_library(EXURLM SHARED
    dllmain.c
    urlmon.def
    ${RC_OBJECT}
)

# Назва вихідного файлу
set_target_properties(EXURLM PROPERTIES
    OUTPUT_NAME "EXURLM"
    PREFIX ""
    SUFFIX ".dll"
    ENABLE_EXPORTS ON
)

# Лінкування з необхідними бібліотеками
target_link_libraries(EXURLM PRIVATE
    kernel32
    user32
)

# Лінкування з DEF файлом
if(CMAKE_C_COMPILER_FRONTEND_VARIANT MATCHES "MSVC")
    # clang-cl uses /DEF:
    target_link_options(EXURLM PRIVATE
        /DEF:${CMAKE_SOURCE_DIR}/urlmon.def
    )
else()
    # clang uses --def-file
    target_link_options(EXURLM PRIVATE
        -Wl,--def-file,${CMAKE_SOURCE_DIR}/urlmon.def
    )
endif()

# Додати .res файл до лінкера
set_target_properties(EXURLM PROPERTIES
    LINK_FLAGS "${RC_OBJECT}"
)

# ============================================================================
# Інформація про збірку
# ============================================================================
add_custom_command(TARGET EXURLM POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E echo "=========================================="
    COMMAND ${CMAKE_COMMAND} -E echo "Build successful!"
    COMMAND ${CMAKE_COMMAND} -E echo "Output: ${OUTPUT_DIR}/EXURLM.dll"
    COMMAND ${CMAKE_COMMAND} -E echo "Toolchain: ${CMAKE_C_COMPILER_ID} (${CMAKE_C_COMPILER_FRONTEND_VARIANT})"
    COMMAND ${CMAKE_COMMAND} -E echo "=========================================="
    VERBATIM
)