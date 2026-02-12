cmake_minimum_required(VERSION 3.20)

project(EXINET VERSION 1.0.2 LANGUAGES C)

# ============================================================================
# Опції
# ============================================================================
option(EXINET_WITH_RESOURCES "Embed version resources (version.rc)" ON)
option(EXINET_ENABLE_LTO     "Enable LTO for Clang" ON)

# ============================================================================
# Архітектура / runtime (використовуються для вихідних папок)
# ============================================================================
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

if(NOT DEFINED RUNTIME_DIR)
    set(RUNTIME_DIR "ucrt")
endif()

message(STATUS "========================================")
message(STATUS "Build configuration:")
message(STATUS "  Project:      EXINET (WinINet Emulator)")
message(STATUS "  Architecture: ${ARCH_SUFFIX}")
message(STATUS "  Runtime:      ${RUNTIME_DIR}")
message(STATUS "========================================")

# ============================================================================
# Мова/стандарт
# ============================================================================
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# ============================================================================
# Вихідні директорії
# ============================================================================
set(OUTPUT_DIR "${CMAKE_SOURCE_DIR}/${RUNTIME_DIR}/${ARCH_SUFFIX}")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${OUTPUT_DIR}")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${OUTPUT_DIR}")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${OUTPUT_DIR}")

# ============================================================================
# Resources (RC) — правильний спосіб: RC як мова і version.rc як source
# ============================================================================
set(EXINET_HAVE_RC FALSE)

if(EXINET_WITH_RESOURCES)
    # Prefer llvm-rc if available (можна також задати -DCMAKE_RC_COMPILER=llvm-rc)
    if(NOT DEFINED CMAKE_RC_COMPILER OR CMAKE_RC_COMPILER STREQUAL "")
        find_program(EXINET_LLVM_RC
            NAMES llvm-rc
            HINTS
                "$ENV{LLVM_PATH}/bin"
                "$ENV{ProgramFiles}/LLVM/bin"
            PATHS
                $ENV{PATH}
        )
        if(EXINET_LLVM_RC)
            set(CMAKE_RC_COMPILER "${EXINET_LLVM_RC}" CACHE FILEPATH "Resource compiler" FORCE)
        endif()
    endif()

    enable_language(RC OPTIONAL)

    if(DEFINED CMAKE_RC_COMPILER AND NOT CMAKE_RC_COMPILER STREQUAL "" AND
       DEFINED CMAKE_RC_COMPILER_WORKS AND CMAKE_RC_COMPILER_WORKS)
        set(EXINET_HAVE_RC TRUE)
        message(STATUS "Resources: ENABLED (RC compiler: ${CMAKE_RC_COMPILER})")
    else()
        message(WARNING "Resources: DISABLED (RC compiler not available/working)")
    endif()
else()
    message(STATUS "Resources: DISABLED (by option)")
endif()

# ============================================================================
# DLL EXINET
# ============================================================================
add_library(EXINET SHARED
    main.c
    http.c
    ftp.c
    cache.c
    stubs.c
)

# Додаємо version.rc тільки якщо RC реально увімкнувся
if(EXINET_HAVE_RC)
    target_sources(EXINET PRIVATE "${CMAKE_SOURCE_DIR}/version.rc")
endif()

set_target_properties(EXINET PROPERTIES
    OUTPUT_NAME "exinet"
    PREFIX ""
    SUFFIX ".dll"
    IMPORT_PREFIX ""
    IMPORT_SUFFIX ".lib"
    ENABLE_EXPORTS ON
)

# ============================================================================
# Опції компіляції/л��нкування (Clang)
# ============================================================================
if(CMAKE_C_COMPILER_ID MATCHES "Clang")
    target_compile_options(EXINET PRIVATE
        -O3
        -ffunction-sections
        -fdata-sections
        -fms-extensions
        -Wno-inconsistent-dllimport
        -Wno-microsoft-anon-tag
    )

    if(EXINET_ENABLE_LTO)
        target_compile_options(EXINET PRIVATE -flto)
        target_link_options(EXINET PRIVATE -flto)
    endif()

    target_link_options(EXINET PRIVATE
        -fuse-ld=lld
        -Wl,/OPT:REF
        -Wl,/OPT:ICF
        -Wl,/DYNAMICBASE
        -Wl,/NXCOMPAT
    )
endif()

# ============================================================================
# .def файл (експорти як у wininet)
# ============================================================================
target_link_options(EXINET PRIVATE
    "LINKER:/DEF:${CMAKE_SOURCE_DIR}/wininet.def"
)

# ============================================================================
# Лінкування з системними бібліотеками
# ============================================================================
target_link_libraries(EXINET PRIVATE
    kernel32
    user32
)

# ============================================================================
# exws2.lib / exiphl.lib (залежні від архітектури)
# ============================================================================
set(EXWS2_LIB  "${CMAKE_SOURCE_DIR}/include/${ARCH_SUFFIX}/exws2.lib")
set(EXIPHL_LIB "${CMAKE_SOURCE_DIR}/include/${ARCH_SUFFIX}/exiphl.lib")

if(NOT EXISTS "${EXWS2_LIB}")
    message(FATAL_ERROR "ERROR: exws2.lib not found: ${EXWS2_LIB}")
endif()
if(NOT EXISTS "${EXIPHL_LIB}")
    message(FATAL_ERROR "ERROR: exiphl.lib not found: ${EXIPHL_LIB}")
endif()

message(STATUS "Found exws2.lib:  ${EXWS2_LIB}")
message(STATUS "Found exiphl.lib: ${EXIPHL_LIB}")

target_link_libraries(EXINET PRIVATE
    "${EXWS2_LIB}"
    "${EXIPHL_LIB}"
)

# ============================================================================
# Інформація про збірку
# ============================================================================
add_custom_command(TARGET EXINET POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E echo "=========================================="
    COMMAND ${CMAKE_COMMAND} -E echo "Build successful!"
    COMMAND ${CMAKE_COMMAND} -E echo "Output: ${OUTPUT_DIR}/exinet.dll"
    COMMAND ${CMAKE_COMMAND} -E echo "Import lib: ${OUTPUT_DIR}/exinet.lib"
    COMMAND ${CMAKE_COMMAND} -E echo "=========================================="
    VERBATIM
)