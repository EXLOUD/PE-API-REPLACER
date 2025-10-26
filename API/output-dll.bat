@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion

REM Get the script directory path
set "SCRIPT_DIR=%~dp0"
set "OUTPUT_DIR=%SCRIPT_DIR%OUTPUT"

REM Create OUTPUT folder if it doesn't exist
if not exist "!OUTPUT_DIR!" (
    echo OUTPUT folder not found. Creating it...
    mkdir "!OUTPUT_DIR!"
    if !errorlevel! equ 0 (
        echo OUTPUT folder created successfully.
    ) else (
        echo Error creating OUTPUT folder!
        pause
        exit /b 1
    )
)

echo.
echo ===============================================
echo Script to copy UCRT and MSVCRT folders
echo ===============================================
echo OUTPUT folder: !OUTPUT_DIR!
echo.

REM Counter for statistics
set "TOTAL_COPIED=0"

REM Loop through all folders in the current directory
for /d %%D in ("!SCRIPT_DIR!*") do (
    set "FOLDER_NAME=%%~nxD"
    
    REM Skip OUTPUT folder
    if /i not "!FOLDER_NAME!"=="OUTPUT" (
        echo Processing folder: !FOLDER_NAME!
        
        REM Check for UCRT folder
        if exist "%%D\UCRT" (
            echo   - UCRT folder found
            
            REM Copy all subfolders from UCRT
            for /d %%S in ("%%D\UCRT\*") do (
                set "SUBFOLDER=%%~nxS"
                set "SRC=%%D\UCRT\!SUBFOLDER!"
                set "DEST=!OUTPUT_DIR!\UCRT\!SUBFOLDER!"
                
                if not exist "!DEST!" (
                    mkdir "!DEST!"
                )
                
                xcopy "!SRC!\*" "!DEST!\" /e /i /y >nul 2>&1
                if !errorlevel! equ 0 (
                    echo     + Copied UCRT\!SUBFOLDER!
                    set /a TOTAL_COPIED+=1
                ) else (
                    echo     - Error copying UCRT\!SUBFOLDER!
                )
            )
        ) else (
            echo   - UCRT folder not found, skipping
        )
        
        REM Check for MSVCRT folder
        if exist "%%D\MSVCRT" (
            echo   - MSVCRT folder found
            
            REM Copy all subfolders from MSVCRT
            for /d %%S in ("%%D\MSVCRT\*") do (
                set "SUBFOLDER=%%~nxS"
                set "SRC=%%D\MSVCRT\!SUBFOLDER!"
                set "DEST=!OUTPUT_DIR!\MSVCRT\!SUBFOLDER!"
                
                if not exist "!DEST!" (
                    mkdir "!DEST!"
                )
                
                xcopy "!SRC!\*" "!DEST!\" /e /i /y >nul 2>&1
                if !errorlevel! equ 0 (
                    echo     + Copied MSVCRT\!SUBFOLDER!
                    set /a TOTAL_COPIED+=1
                ) else (
                    echo     - Error copying MSVCRT\!SUBFOLDER!
                )
            )
        ) else (
            echo   - MSVCRT folder not found, skipping
        )
        
        echo.
    )
)

echo ===============================================
echo Total subfolders processed: !TOTAL_COPIED!
echo ===============================================
echo.

REM Ask if user wants to delete .lib files in architecture folders
echo.
timeout /t 2 /nobreak >nul
echo Searching for .lib files in architecture folders...

set "LIB_FOUND=0"

dir /s /b "!OUTPUT_DIR!\UCRT\*.lib" >nul 2>&1
if !errorlevel! equ 0 (
    set "LIB_FOUND=1"
)

dir /s /b "!OUTPUT_DIR!\MSVCRT\*.lib" >nul 2>&1
if !errorlevel! equ 0 (
    set "LIB_FOUND=1"
)

if !LIB_FOUND! equ 1 (
    echo.
    echo .lib files found in architecture folders!
    echo.
    echo Do you want to delete all .lib files?
    echo 1 - YES, delete
    echo 2 - NO, keep them
    echo.
    set /p CHOICE="Enter your choice (1 or 2): "
    
    if "!CHOICE!"=="1" (
        echo.
        echo Deleting .lib files...
        
        REM Delete from UCRT
        for /f "delims=" %%F in ('dir /s /b "!OUTPUT_DIR!\UCRT\*.lib" 2^>nul') do (
            del "%%F" >nul 2>&1
            echo Deleted: %%F
        )
        
        REM Delete from MSVCRT
        for /f "delims=" %%F in ('dir /s /b "!OUTPUT_DIR!\MSVCRT\*.lib" 2^>nul') do (
            del "%%F" >nul 2>&1
            echo Deleted: %%F
        )
        
        echo All .lib files deleted!
    ) else if "!CHOICE!"=="2" (
        echo .lib files kept.
    ) else (
        echo Invalid choice!
    )
) else (
    echo No .lib files found.
)

echo.
pause