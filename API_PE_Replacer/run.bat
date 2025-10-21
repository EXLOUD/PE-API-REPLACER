@echo off
setlocal

REM --- CONFIGURATION ---
REM Name of the virtual environment directory
set VENV_DIR=venv

REM File with dependencies. Create this file if you don't have one.
set REQUIREMENTS_FILE=requirements.txt

REM The main script of your application
set MAIN_SCRIPT=main.py

REM --- SCRIPT LOGIC ---
echo [1/4] Checking for virtual environment...

REM Check if the venv directory exists
if not exist "%VENV_DIR%" (
    echo    - Directory '%VENV_DIR%' not found. Creating a new environment...
    python -m venv %VENV_DIR%
    if %errorlevel% neq 0 (
        echo [ERROR] Failed to create the virtual environment. Please check if Python is installed and in your PATH.
        pause
        exit /b 1
    )
    echo    + Virtual environment created successfully.
) else (
    echo    + Virtual environment found.
)

REM Activate the virtual environment
echo [2/4] Activating environment...
call "%VENV_DIR%\Scripts\activate.bat"
echo    + Environment activated.

REM Install dependencies from requirements.txt
echo [3/4] Installing/checking dependencies...
pip install -r %REQUIREMENTS_FILE%
if %errorlevel% neq 0 (
    echo [ERROR] Failed to install dependencies from %REQUIREMENTS_FILE%.
    pause
    exit /b 1
)
echo    + Dependencies are up to date.

REM Run the main script
echo [4/4] Starting the application...
echo.
python %MAIN_SCRIPT%

echo.
echo Application finished.
endlocal