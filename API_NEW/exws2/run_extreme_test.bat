@echo off
REM ============================================================================
REM EXTREME ZeroMQ Stress Test Runner
REM ============================================================================
REM This script runs HARDCORE stress tests comparing exws2.dll vs ws2_32.dll
REM 
REM WARNING: These tests are VERY intensive:
REM   - Uses significant CPU and memory  
REM   - May take 10-30 minutes (full mode)
REM   - Generates 100MB+ network traffic
REM   - Tests system limits
REM
REM Use --quick for faster (but less thorough) testing
REM ============================================================================

setlocal enabledelayedexpansion

echo.
echo ========================================================================
echo   EXTREME ZEROMQ STRESS TEST - EMULATOR VS SYSTEM
echo ========================================================================
echo.
echo WARNING: This test is VERY intensive and may take 10-30 minutes!
echo.

REM Parse command line arguments
set QUICK_MODE=0
if "%1"=="--quick" set QUICK_MODE=1
if "%1"=="-q" set QUICK_MODE=1

REM Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python not found!
    echo Please install Python 3.x
    pause
    exit /b 1
)

REM Check pyzmq
echo Checking dependencies...
python -c "import zmq" >nul 2>&1
if errorlevel 1 (
    echo.
    echo pyzmq not installed. Installing...
    pip install pyzmq
    if errorlevel 1 (
        echo Failed to install pyzmq
        pause
        exit /b 1
    )
)

REM Check psutil (optional but recommended)
python -c "import psutil" >nul 2>&1
if errorlevel 1 (
    echo.
    echo psutil not installed (optional - for memory tracking)
    echo Installing psutil...
    pip install psutil
    if errorlevel 1 (
        echo Warning: psutil install failed - memory tracking disabled
        echo Continuing anyway...
    )
)

REM Check for exws2.dll
if not exist "exws2.dll" (
    if not exist "ucrt\x64\EXWS2.dll" (
        echo.
        echo WARNING: exws2.dll not found!
        echo Please ensure exws2.dll is in:
        echo   - Current directory, OR
        echo   - ucrt\x64\ directory, OR
        echo   - System PATH
        echo.
        pause
    )
)

echo.
echo ========================================================================
echo   READY TO START
echo ========================================================================
echo.

if !QUICK_MODE!==1 (
    echo MODE: QUICK ^(reduced intensity, ~2-5 minutes^)
    echo.
    set QUICK_ARG=--quick
) else (
    echo MODE: FULL ^(maximum stress, 10-30 minutes^)
    echo.
    echo Press Ctrl+C now to cancel, or
    pause
    set QUICK_ARG=
)

echo.
echo Starting extreme stress tests...
echo.

REM Run the tests
python test_zeromq_extreme.py --compare !QUICK_ARG!

if errorlevel 1 (
    echo.
    echo ========================================================================
    echo   TESTS COMPLETED WITH ERRORS
    echo ========================================================================
    echo.
    pause
    exit /b 1
)

echo.
echo ========================================================================
echo   ALL TESTS COMPLETED SUCCESSFULLY!
echo ========================================================================
echo.

pause
exit /b 0
