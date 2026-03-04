cmake_minimum_required(VERSION 3.20)
project(EXWS VERSION 1.0.0 LANGUAGES C RC)

# ============================================================================
# Project Description
# ============================================================================
# EXWS - wsock32.dll Proxy Emulator
# Pure proxy DLL that forwards all calls to:
# - exws2.dll (standard Winsock functions)
# - EXMSW.dll (MSWSOCK emulation)
# ============================================================================

option(USE_UCRT "Use UCRT runtime" ON)

# Architecture detection
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

# Runtime directory
if(NOT DEFINED RUNTIME_DIR)
    set(RUNTIME_DIR "ucrt")
endif()

message(STATUS "========================================")
message(STATUS "Build configuration:")
message(STATUS "  Project:      EXWS (wsock32.dll proxy)")
message(STATUS "  Architecture: ${ARCH_SUFFIX}")
message(STATUS "  Runtime:      ${RUNTIME_DIR}")
message(STATUS "  Compiler:     ${CMAKE_C_COMPILER_ID}")
message(STATUS "========================================")

# ============================================================================
# Compiler Settings
# ============================================================================
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Output directory
set(OUTPUT_DIR "${CMAKE_SOURCE_DIR}/${RUNTIME_DIR}/${ARCH_SUFFIX}")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${OUTPUT_DIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${OUTPUT_DIR})

# Optimization flags
if(CMAKE_C_COMPILER_ID MATCHES "Clang" AND CMAKE_C_COMPILER_FRONTEND_VARIANT MATCHES "MSVC")
    # clang-cl (MSVC-compatible mode)
    add_compile_options(
        /O2                    # Optimize
        /Oi                    # Intrinsics
        /GL                    # Whole program optimization
        /GS-                   # Disable security checks (smaller DLL)
    )
    
    add_link_options(
        /LTCG                  # Link-time code generation
        /OPT:REF               # Remove unreferenced
        /OPT:ICF               # COMDAT folding
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
# Resource Compilation
# ============================================================================
find_program(RC_COMPILER
    NAMES llvm-rc rc windres
    HINTS
        "$ENV{LLVM_PATH}/bin"
        "$ENV{PATH}"
)

if(NOT RC_COMPILER)
    message(FATAL_ERROR "Resource compiler (llvm-rc/windres) not found!")
endif()

message(STATUS "Using resource compiler: ${RC_COMPILER}")

set(RC_SOURCE "${CMAKE_SOURCE_DIR}/version.rc")
set(RC_OBJECT "${CMAKE_BINARY_DIR}/version.res")

# Determine RC compiler type and set appropriate flags
get_filename_component(RC_NAME "${RC_COMPILER}" NAME_WE)

if(RC_NAME MATCHES "llvm-rc")
    # llvm-rc uses /fo flag
    add_custom_command(
        OUTPUT ${RC_OBJECT}
        COMMAND ${RC_COMPILER} /fo ${RC_OBJECT} ${RC_SOURCE}
        DEPENDS ${RC_SOURCE}
        COMMENT "Compiling resources with llvm-rc: ${RC_SOURCE}"
        VERBATIM
    )
elseif(RC_NAME MATCHES "windres")
    # windres uses -o flag
    add_custom_command(
        OUTPUT ${RC_OBJECT}
        COMMAND ${RC_COMPILER} ${RC_SOURCE} -O coff -o ${RC_OBJECT}
        DEPENDS ${RC_SOURCE}
        COMMENT "Compiling resources with windres: ${RC_SOURCE}"
        VERBATIM
    )
else()
    # Fallback to llvm-rc style
    add_custom_command(
        OUTPUT ${RC_OBJECT}
        COMMAND ${RC_COMPILER} /fo ${RC_OBJECT} ${RC_SOURCE}
        DEPENDS ${RC_SOURCE}
        COMMENT "Compiling resources: ${RC_SOURCE}"
        VERBATIM
    )
endif()

# ============================================================================
# Create DLL
# ============================================================================
add_library(EXWS SHARED
    dllmain.c
    ws_32.def
    ${RC_OBJECT}
)

# Output name
set_target_properties(EXWS PROPERTIES
    OUTPUT_NAME "EXWS"
    PREFIX ""
    SUFFIX ".dll"
    ENABLE_EXPORTS ON
)

# Link with necessary libraries
target_link_libraries(EXWS PRIVATE
    kernel32
)

# Link with DEF file
if(CMAKE_C_COMPILER_FRONTEND_VARIANT MATCHES "MSVC")
    # clang-cl uses /DEF:
    target_link_options(EXWS PRIVATE
        /DEF:${CMAKE_SOURCE_DIR}/ws_32.def
    )
else()
    # clang/gcc uses --def-file or -Wl,--output-def
    target_link_options(EXWS PRIVATE
        LINKER:--def-file,${CMAKE_SOURCE_DIR}/ws_32.def
    )
endif()

# Add resource object to linker
set_target_properties(EXWS PROPERTIES
    LINK_FLAGS "${RC_OBJECT}"
)

# ============================================================================
# Post-build Information
# ============================================================================
add_custom_command(TARGET EXWS POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E echo "=========================================="
    COMMAND ${CMAKE_COMMAND} -E echo "Build successful!"
    COMMAND ${CMAKE_COMMAND} -E echo "Output: ${OUTPUT_DIR}/EXWS.dll"
    COMMAND ${CMAKE_COMMAND} -E echo "Type: Pure Proxy (forwards to exws2.dll + EXMSW.dll)"
    COMMAND ${CMAKE_COMMAND} -E echo "=========================================="
    VERBATIM
)
