#!/usr/bin/env bash
# ============================================================
# Run script for Look-Alike Website Detector backend
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# Create .env from example if it doesn't exist
if [ ! -f .env ]; then
    cp .env.example .env
    echo "[+] Created .env from .env.example — edit it with your API keys."
fi

# Detect Python 3.11+ executable
PYTHON_BIN=""
if command -v python3 &>/dev/null && [ "$(python3 -c 'import sys; print(int(sys.version_info >= (3, 11)))')" = "1" ]; then
    PYTHON_BIN="python3"
elif [ -x "/Library/Frameworks/Python.framework/Versions/3.14/bin/python3.14" ]; then
    PYTHON_BIN="/Library/Frameworks/Python.framework/Versions/3.14/bin/python3.14"
elif command -v python3.12 &>/dev/null; then
    PYTHON_BIN="python3.12"
elif command -v python3.11 &>/dev/null; then
    PYTHON_BIN="python3.11"
fi

# Virtual environment handling
if [ ! -d ".venv" ]; then
    if [ -n "$PYTHON_BIN" ]; then
        echo "[+] Creating virtual environment using $PYTHON_BIN..."
        "$PYTHON_BIN" -m venv .venv
    else
        echo "[!] Python 3.11+ not found in PATH."
    fi
fi

if [ -f ".venv/bin/activate" ]; then
    source .venv/bin/activate
fi

# Ensure requirements are installed
echo "[+] Checking/installing dependencies..."
pip install -q -r requirements.txt

# Run the server
echo ""
echo "============================================================"
echo " Starting Look-Alike Website Detector Backend"
echo "============================================================"
echo "  API Docs:     http://localhost:8000/docs"
echo "  Health:       http://localhost:8000/health"
echo "  Active Model: http://localhost:8000/models"
echo "  Registry:     http://localhost:8000/registry/brands"
echo "============================================================"
echo ""

uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
