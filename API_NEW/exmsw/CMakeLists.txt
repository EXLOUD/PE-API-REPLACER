cmake_minimum_required(VERSION 3.20)
project(EXMSW VERSION 1.0.1 LANGUAGES C RC)

# ============================================================================
# Project Description
# ============================================================================
# EXMSW - mswsock.dll Emulator
# Stub implementation of Microsoft Winsock Extensions
# Links with exws2.lib for basic Winsock functions
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
message(STATUS "  Project:      EXMSW (mswsock.dll emulator)")
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
        /O2
        /Oi
        /GL
        /GS-
    )
    
    add_link_options(
        /LTCG
        /OPT:REF
        /OPT:ICF
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
# Find exws2.lib
# ============================================================================
# Library is located in include/{arch}/ directory
set(EXWS2_LIB "${CMAKE_SOURCE_DIR}/include/${ARCH_SUFFIX}/exws2.lib")

if(EXISTS "${EXWS2_LIB}")
    message(STATUS "Found exws2.lib: ${EXWS2_LIB}")
    set(HAVE_EXWS2_LIB TRUE)
else()
    message(WARNING "exws2.lib not found at: ${EXWS2_LIB}")
    message(WARNING "Building without exws2.lib - some functions may not link!")
    message(WARNING "Expected location: include/${ARCH_SUFFIX}/exws2.lib")
    set(HAVE_EXWS2_LIB FALSE)
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

get_filename_component(RC_NAME "${RC_COMPILER}" NAME_WE)

if(RC_NAME MATCHES "llvm-rc")
    add_custom_command(
        OUTPUT ${RC_OBJECT}
        COMMAND ${RC_COMPILER} /fo ${RC_OBJECT} ${RC_SOURCE}
        DEPENDS ${RC_SOURCE}
        COMMENT "Compiling resources with llvm-rc"
        VERBATIM
    )
elseif(RC_NAME MATCHES "windres")
    add_custom_command(
        OUTPUT ${RC_OBJECT}
        COMMAND ${RC_COMPILER} ${RC_SOURCE} -O coff -o ${RC_OBJECT}
        DEPENDS ${RC_SOURCE}
        COMMENT "Compiling resources with windres"
        VERBATIM
    )
else()
    add_custom_command(
        OUTPUT ${RC_OBJECT}
        COMMAND ${RC_COMPILER} /fo ${RC_OBJECT} ${RC_SOURCE}
        DEPENDS ${RC_SOURCE}
        COMMENT "Compiling resources"
        VERBATIM
    )
endif()

# ============================================================================
# Create DLL
# ============================================================================
add_library(EXMSW SHARED
    dllmain.c
    exmsw.def
    ${RC_OBJECT}
)

# Output name
set_target_properties(EXMSW PROPERTIES
    OUTPUT_NAME "EXMSW"
    PREFIX ""
    SUFFIX ".dll"
    ENABLE_EXPORTS ON
)

# Link with necessary libraries
target_link_libraries(EXMSW PRIVATE
    kernel32
    ws2_32
)

# Link with exws2.lib if found
if(HAVE_EXWS2_LIB)
    target_link_libraries(EXMSW PRIVATE "${EXWS2_LIB}")
    message(STATUS "Linking with exws2.lib")
endif()

# Link with DEF file
if(CMAKE_C_COMPILER_FRONTEND_VARIANT MATCHES "MSVC")
    # clang-cl uses /DEF:
    target_link_options(EXMSW PRIVATE
        /DEF:${CMAKE_SOURCE_DIR}/exmsw.def
    )
else()
    # clang/gcc uses --def-file
    target_link_options(EXMSW PRIVATE
        LINKER:--def-file,${CMAKE_SOURCE_DIR}/exmsw.def
    )
endif()

# Add resource object to linker
set_target_properties(EXMSW PROPERTIES
    LINK_FLAGS "${RC_OBJECT}"
)

# ============================================================================
# Post-build Cleanup (remove EXWS2 files)
# ============================================================================
add_custom_command(TARGET EXMSW POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E echo "=========================================="
    COMMAND ${CMAKE_COMMAND} -E echo "Build successful!"
    COMMAND ${CMAKE_COMMAND} -E echo "Output: ${OUTPUT_DIR}/EXMSW.dll"
    COMMAND ${CMAKE_COMMAND} -E echo "=========================================="
    VERBATIM
)

# Optional: Clean up EXWS2.dll from output directory
# Note: exws2.lib stays in include/{arch}/ and is not cleaned
add_custom_command(TARGET EXMSW POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E echo "Cleaning up EXWS2.dll..."
    COMMAND ${CMAKE_COMMAND} -E remove -f "${OUTPUT_DIR}/EXWS2.dll"
    COMMENT "Removing EXWS2.dll from output directory"
    VERBATIM
)