@echo off
setlocal

REM --- CONFIGURATION ---
set VENV_DIR=venv
set REQUIREMENTS_FILE=requirements.txt
set MAIN_SCRIPT=main.py
set APP_NAME="PE-API-REPLACER"
set ICON_FILE="app.ico"

REM --- SCRIPT LOGIC ---
echo [BUILD SCRIPT STARTED]
echo.

REM 1. Ensure virtual environment exists and dependencies are installed
echo [1/3] Setting up virtual environment and dependencies...
if not exist "%VENV_DIR%" (
    echo    - Creating new virtual environment in '%VENV_DIR%'...
    python -m venv %VENV_DIR%
)
call "%VENV_DIR%\Scripts\activate.bat"
echo    - Installing/updating build dependencies (PyInstaller)...
pip install -r %REQUIREMENTS_FILE%
pip install pyinstaller
echo    + Environment is ready.
echo.

REM 2. Clean up previous build artifacts
echo [2/3] Cleaning up previous build artifacts...
if exist "dist" rmdir /s /q "dist"
if exist "build" rmdir /s /q "build"
if exist "%APP_NAME%.spec" del "%APP_NAME%.spec"
echo    + Cleanup complete.
echo.

REM 3. Run PyInstaller to build the executable
echo [3/3] Building the executable with PyInstaller...
pyinstaller --onefile ^
            --windowed ^
            --uac-admin ^
            --name=%APP_NAME% ^
            --add-data "languages;languages" ^
            --add-data "config.py;." ^
            --hidden-import "pefile" ^
            --icon=%ICON_FILE% ^
            %MAIN_SCRIPT%

REM Check if the build was successful
if %errorlevel% neq 0 (
    echo.
    echo [ERROR] PyInstaller failed to build the application.
    pause
    exit /b 1
)

echo.
echo [BUILD COMPLETE]
echo The executable can be found in the 'dist' folder.
echo.
pause
endlocal