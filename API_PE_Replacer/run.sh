#!/usr/bin/env bash
set -e

# Change to the directory where the script is located
cd "$(dirname "$0")"

# --- CONFIGURATION ---
VENV_DIR="venv"
REQUIREMENTS_FILE="requirements.txt"
MAIN_SCRIPT="main.py"

# --- SCRIPT LOGIC ---
echo "[1/4] Checking for virtual environment..."

if [ ! -d "$VENV_DIR" ]; then
    echo "   - Directory '$VENV_DIR' not found. Creating a new environment..."
    python3 -m venv "$VENV_DIR" || { echo "[ERROR] Failed to create virtual environment. Is Python 3 installed?"; exit 1; }
    echo "   + Virtual environment created successfully."
else
    echo "   + Virtual environment found."
fi

echo "[2/4] Activating environment..."
source "$VENV_DIR/bin/activate"
echo "   + Environment activated."

echo "[3/4] Installing/checking dependencies..."
if [ ! -f "$REQUIREMENTS_FILE" ]; then
    echo "   - $REQUIREMENTS_FILE not found. Skipping dependency installation."
else
    pip install -r "$REQUIREMENTS_FILE" || { echo "[ERROR] Failed to install dependencies from $REQUIREMENTS_FILE."; exit 1; }
    echo "   + Dependencies are up to date."
fi

echo "[4/4] Starting the application..."
echo ""
python "$MAIN_SCRIPT"

echo ""
echo "Application finished."