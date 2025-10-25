@echo off
cd /d "%~dp0"
set "LLVM_UCRT=C:\llvm-mingw-ucrt\bin"
set "LLVM_MSVCRT=C:\llvm-mingw-msvcrt\bin"
set "DLL=EXIPHL.dll"
set "FLAGS=-shared -O3 -flto -ffunction-sections -fdata-sections -s -static-libgcc -Wl,--enable-stdcall-fixup -Wl,--gc-sections -Wl,--strip-all"
REM Перевірка файлів
for %%f in (
    "%LLVM_UCRT%\x86_64-w64-mingw32-gcc.exe"
    "%~dp0dllmain.c"
    "%~dp0version.rc"
    "%~dp0iphlpapi_stub.def"
) do (
    if not exist %%f (
        echo ERROR: File not found - %%f
        pause
        exit /b 1
    )
)
echo Starting build...
echo.
REM Збірка UCRT
echo === Building UCRT versions ===
set "LLVM=%LLVM_UCRT%"
set "RUNTIME=ucrt"
call :build_all
REM Збірка MSVCRT
if exist "%LLVM_MSVCRT%\x86_64-w64-mingw32-gcc.exe" (
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
echo.
echo === Cleaning up EXWS2.dll files ===
call :cleanup_files
pause
exit /b
:build_all
call :build x86_64-w64-mingw32 x64
call :build aarch64-w64-mingw32 arm64
call :build i686-w64-mingw32 x32
exit /b
:build
echo Building %RUNTIME%\%2...
if not exist "%~dp0%RUNTIME%\%2" mkdir "%~dp0%RUNTIME%\%2"
set "RES=version-%2.res"
set "EXWS2_LIB=%~dp0%RUNTIME%\%2\exws2.lib"
if not exist "%EXWS2_LIB%" (
    echo ERROR: Library not found - %EXWS2_LIB%
    pause
    exit /b 1
)
"%LLVM%\%1-windres" "%~dp0version.rc" -O coff -o "%~dp0%RES%"
if errorlevel 1 (
    echo ERROR: windres failed for %RUNTIME%\%2
    pause
    exit /b 1
)
"%LLVM%\%1-gcc" %FLAGS% -o "%~dp0%DLL%" "%~dp0dllmain.c" "%~dp0%RES%" "%~dp0iphlpapi_stub.def" "%EXWS2_LIB%"
if errorlevel 1 (
    echo ERROR: Compilation failed for %RUNTIME%\%2
    del "%~dp0%RES%" 2>nul
    pause
    exit /b 1
)
copy /Y "%~dp0%DLL%" "%~dp0%RUNTIME%\%2\" >nul 2>nul
del "%~dp0%DLL%" 2>nul
del "%~dp0%RES%" 2>nul
echo %RUNTIME%\%2 - OK
exit /b
:cleanup_files
setlocal enabledelayedexpansion
REM Перевірка і видалення EXWS2.dll та EXWS2.lib з папок UCRT
for %%d in (x64 arm64 x32) do (
    set "filepath_dll=%~dp0ucrt\%%d\EXWS2.dll"
    set "filepath_lib=%~dp0ucrt\%%d\EXWS2.lib"
    if exist "!filepath_dll!" (
        echo Deleting: !filepath_dll!
        del "!filepath_dll!"
    )
    if exist "!filepath_lib!" (
        echo Deleting: !filepath_lib!
        del "!filepath_lib!"
    )
)
REM Перевірка і видалення EXWS2.dll та EXWS2.lib з папок MSVCRT
for %%d in (x64 arm64 x32) do (
    set "filepath_dll=%~dp0msvcrt\%%d\EXWS2.dll"
    set "filepath_lib=%~dp0msvcrt\%%d\EXWS2.lib"
    if exist "!filepath_dll!" (
        echo Deleting: !filepath_dll!
        del "!filepath_dll!"
    )
    if exist "!filepath_lib!" (
        echo Deleting: !filepath_lib!
        del "!filepath_lib!"
    )
)
endlocal
echo Cleanup complete!
exit /b