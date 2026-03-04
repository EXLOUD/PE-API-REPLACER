cmake_minimum_required(VERSION 3.20)
project(EXIPHL VERSION 1.5.4 LANGUAGES C)

# ============================================================================
# Налаштування опцій
# ============================================================================
option(USE_EXWS2 "Link with exws2.lib" OFF)
option(USE_OLE32 "Link with ole32.lib" OFF)
option(USE_UCRT "Use UCRT runtime (default is MSVCRT)" ON)

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
    if(USE_UCRT)
        set(RUNTIME_DIR "ucrt")
    else()
        set(RUNTIME_DIR "msvcrt")
    endif()
endif()

message(STATUS "========================================")
message(STATUS "Build configuration:")
message(STATUS "  Architecture: ${ARCH_SUFFIX}")
message(STATUS "  Runtime:      ${RUNTIME_DIR}")
message(STATUS "  USE_EXWS2:    ${USE_EXWS2}")
message(STATUS "  USE_OLE32:    ${USE_OLE32}")
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
add_library(EXIPHL SHARED
    dllmain.c
    iphlpapi_stub.def
    ${RC_OBJECT}
)

# Назва вихідного файлу
set_target_properties(EXIPHL PROPERTIES
    OUTPUT_NAME "EXIPHL"
    PREFIX ""
    SUFFIX ".dll"
    IMPORT_PREFIX ""
    IMPORT_SUFFIX ".lib"
    ENABLE_EXPORTS ON
)

# ============================================================================
# Лінкування з бібліотеками
# ============================================================================

# СИСТЕМНІ бібліотеки Windows (тільки для Winsock функцій)
target_link_libraries(EXIPHL PRIVATE
    ws2_32      # Winsock2 API (inet_pton, ntohl, htonl, socket functions)
)

message(STATUS "Linking with system library: ws2_32")

# ОПЦІОНАЛЬНІ бібліотеки (ваші власні)
set(OPTIONAL_LIBS "")

# exws2.lib - ВАША бібліотека з include/${ARCH_SUFFIX}/
if(USE_EXWS2)
    set(EXWS2_LIB "${CMAKE_SOURCE_DIR}/include/${ARCH_SUFFIX}/exws2.lib")
    if(EXISTS ${EXWS2_LIB})
        list(APPEND OPTIONAL_LIBS ${EXWS2_LIB})
        message(STATUS "Linking with custom library: ${EXWS2_LIB}")
    else()
        message(WARNING "exws2.lib not found at: ${EXWS2_LIB}")
        message(WARNING "Place exws2.lib in include/${ARCH_SUFFIX}/ or set -DUSE_EXWS2=OFF")
        message(FATAL_ERROR "exws2.lib is required when USE_EXWS2=ON")
    endif()
endif()

# ole32.lib - якщо потрібна
if(USE_OLE32)
    set(OLE32_LIB "${CMAKE_SOURCE_DIR}/${RUNTIME_DIR}/${ARCH_SUFFIX}/ole32.lib")
    if(EXISTS ${OLE32_LIB})
        list(APPEND OPTIONAL_LIBS ${OLE32_LIB})
        message(STATUS "Linking with: ${OLE32_LIB}")
    else()
        message(FATAL_ERROR "ole32.lib not found at: ${OLE32_LIB} (set -DUSE_OLE32=OFF to skip)")
    endif()
endif()

# Додаємо опціональні бібліотеки якщо є
if(OPTIONAL_LIBS)
    target_link_libraries(EXIPHL PRIVATE ${OPTIONAL_LIBS})
    message(STATUS "Added optional libraries: ${OPTIONAL_LIBS}")
endif()

# Лінкування з DEF файлом
target_link_options(EXIPHL PRIVATE
    "LINKER:/DEF:${CMAKE_SOURCE_DIR}/iphlpapi_stub.def"
    "${RC_OBJECT}"
)

# ============================================================================
# Інформація про збірку
# ============================================================================
add_custom_command(TARGET EXIPHL POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E echo "=========================================="
    COMMAND ${CMAKE_COMMAND} -E echo "Build successful!"
    COMMAND ${CMAKE_COMMAND} -E echo "Output: ${OUTPUT_DIR}/EXIPHL.dll"
    COMMAND ${CMAKE_COMMAND} -E echo "Import lib: ${OUTPUT_DIR}/EXIPHL.lib"
    COMMAND ${CMAKE_COMMAND} -E echo "=========================================="
    VERBATIM
)

# ============================================================================
# Додаткові цілі для очистки
# ============================================================================
# Очищення EXWS2.dll/lib файлів після збірки (як в оригінальному build.bat)
if(USE_EXWS2)
    add_custom_command(TARGET EXIPHL POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E remove -f "${OUTPUT_DIR}/EXWS2.dll"
        COMMAND ${CMAKE_COMMAND} -E remove -f "${OUTPUT_DIR}/EXWS2.lib"
        COMMENT "Cleaning up EXWS2 files..."
        VERBATIM
    )
    
    # Показати важливе попередження
    add_custom_command(TARGET EXIPHL POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E echo "=========================================="
        COMMAND ${CMAKE_COMMAND} -E echo "ВАЖЛИВО: exws2.dll має бути поруч з EXIPHL.dll!"
        COMMAND ${CMAKE_COMMAND} -E echo "=========================================="
        VERBATIM
    )
endif()