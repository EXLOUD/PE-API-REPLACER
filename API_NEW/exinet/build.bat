@echo off
cd /d "%~dp0"
set "LLVM_UCRT=C:\llvm-mingw-ucrt\bin"
set "LLVM_MSVCRT=C:\llvm-mingw-msvcrt\bin"
set "DLL=exinet.dll"
set "SOURCES=main.c http.c ftp.c cache.c stubs.c"
set "FLAGS=-shared -O3 -flto -ffunction-sections -fdata-sections -s -static-libgcc -Wl,--enable-stdcall-fixup -Wl,--gc-sections -Wl,--strip-all"

REM Перевірка файлів
for %%f in (
    "%LLVM_UCRT%\x86_64-w64-mingw32-clang.exe"
    "%~dp0main.c"
    "%~dp0http.c"
    "%~dp0ftp.c"
    "%~dp0cache.c"
    "%~dp0stubs.c"
    "%~dp0wininet_internal.h"
    "%~dp0version.rc"
    "%~dp0wininet.def"
) do (
    if not exist %%f (
        echo ERROR: File not found - %%f
        pause
        exit /b 1
    )
)

echo Starting build...
echo Source files: %SOURCES%
echo.

REM Збірка UCRT
echo === Building UCRT versions ===
set "LLVM=%LLVM_UCRT%"
set "RUNTIME=ucrt"
call :build_all

REM Збірка MSVCRT
if exist "%LLVM_MSVCRT%\x86_64-w64-mingw32-clang.exe" (
    echo.
    echo === Building MSVCRT versions ===
    set "LLVM=%LLVM_MSVCRT%"
    set "RUNTIME=msvcrt"
    call :build_all
) else (
    echo.
    echo WARNING: MSVCRT compiler not found, skipping...
)

echo.
echo Build complete!
pause
exit /b

:build_all
call :build x86_64-w64-mingw32 x64 -m64
call :build aarch64-w64-mingw32 arm64
call :build i686-w64-mingw32 x32 -m32
exit /b

:build
echo Building %RUNTIME%\%2...
if not exist "%~dp0%RUNTIME%\%2" mkdir "%~dp0%RUNTIME%\%2"

REM === exws2.lib лежить в тій самій папці ===
set "EXWS2_LIB=%~dp0%RUNTIME%\%2\exws2.lib"

if not exist "%EXWS2_LIB%" (
    echo ERROR: exws2.lib not found at %EXWS2_LIB%
    pause
    exit /b 1
)

set "RES=version-%2.res"
"%LLVM%\%1-windres" "%~dp0version.rc" -O coff -o "%~dp0%RES%" 2>nul
if errorlevel 1 echo WARNING: windres failed for %2

REM Компіляція з exws2.lib
"%LLVM%\%1-gcc" %FLAGS% %3 -o "%~dp0%DLL%" %SOURCES% "%~dp0%RES%" "%~dp0wininet.def" "%EXWS2_LIB%"
if errorlevel 1 (
    echo ERROR: Compilation failed for %RUNTIME%\%2
    del "%~dp0%RES%" 2>nul
    pause
    exit /b 1
)

if not exist "%~dp0%DLL%" (
    echo ERROR: DLL file was not created for %RUNTIME%\%2
    del "%~dp0%RES%" 2>nul
    pause
    exit /b 1
)

copy /Y "%~dp0%DLL%" "%~dp0%RUNTIME%\%2\" >nul 2>nul
if errorlevel 1 (
    echo ERROR: Failed to copy DLL to %RUNTIME%\%2
    pause
    exit /b 1
)

del "%~dp0%DLL%" 2>nul
del "%~dp0%RES%" 2>nul
echo %RUNTIME%\%2 - OK
exit /b