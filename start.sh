#!/usr/bin/env bash
# ExfilTrace Security Monitor — One-command launcher for Linux / macOS
set -euo pipefail

BOLD="\033[1m"
GREEN="\033[0;32m"
YELLOW="\033[0;33m"
RED="\033[0;31m"
RESET="\033[0m"

ok()   { echo -e "${GREEN}[OK]${RESET} $*"; }
warn() { echo -e "${YELLOW}[WARNING]${RESET} $*"; }
err()  { echo -e "${RED}[ERROR]${RESET} $*"; }
info() { echo -e "[*] $*"; }

# Resolve script directory so the launcher works from any working directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo ""
echo -e "${BOLD} ======================================================"
echo -e "  ExfilTrace Security Monitor — Application Launcher"
echo -e " ======================================================${RESET}"
echo ""

# ── 1. Prerequisite checks ──────────────────────────────────────────────────

if ! command -v python3 &>/dev/null; then
    err "Python 3 is not installed or not on PATH."
    echo "    Install Python 3.10+ from https://www.python.org/ or your system package manager."
    exit 1
fi
PYTHON_VER=$(python3 --version 2>&1)
ok "Found $PYTHON_VER"

if ! command -v node &>/dev/null; then
    err "Node.js is not installed or not on PATH."
    echo "    Install Node.js 18 LTS or later from https://nodejs.org/"
    exit 1
fi
NODE_VER=$(node --version 2>&1)
ok "Found Node.js $NODE_VER"

if ! command -v npm &>/dev/null; then
    err "npm is not available. Please reinstall Node.js."
    exit 1
fi

# ── 2. Backend — Python virtual environment ─────────────────────────────────

echo ""
info "Setting up Python backend..."

VENV_DIR=".venv"

if [ ! -f "$VENV_DIR/bin/python" ]; then
    info "Creating Python virtual environment in .venv/ ..."
    python3 -m venv "$VENV_DIR"
    ok "Virtual environment created."
else
    ok "Virtual environment already exists."
fi

PIP="$VENV_DIR/bin/pip"
PYTHON_VENV="$VENV_DIR/bin/python"

SENTINEL="$VENV_DIR/.deps_installed"

if [ ! -f "$SENTINEL" ] || [ "backend/requirements.txt" -nt "$SENTINEL" ]; then
    info "Installing backend dependencies..."
    "$PIP" install -q -r backend/requirements.txt
    touch "$SENTINEL"
    ok "Backend dependencies installed."
else
    ok "Backend dependencies up to date."
fi

# ── 3. Frontend — Node dependencies ─────────────────────────────────────────

echo ""
info "Setting up React frontend..."

if [ ! -d "node_modules" ] || [ ! -f "node_modules/.package-lock.json" ]; then
    info "Installing frontend dependencies (this may take a moment)..."
    if npm ci --silent 2>/dev/null; then
        ok "Frontend dependencies installed (npm ci)."
    else
        warn "npm ci failed, falling back to npm install..."
        npm install --silent
        ok "Frontend dependencies installed (npm install)."
    fi
else
    ok "Frontend dependencies already installed."
fi

# ── 4. Port availability check ──────────────────────────────────────────────

echo ""
info "Checking port availability..."

if lsof -iTCP:5000 -sTCP:LISTEN &>/dev/null 2>&1; then
    warn "Port 5000 is already in use. The backend may fail to start."
    warn "Stop the existing process or change api.port in backend/config.json."
fi

if lsof -iTCP:5173 -sTCP:LISTEN &>/dev/null 2>&1; then
    warn "Port 5173 is already in use. Vite will auto-select a different port."
fi

# ── 5. macOS AirPlay conflict check ─────────────────────────────────────────

if [[ "$OSTYPE" == "darwin"* ]]; then
    if lsof -iTCP:5000 -sTCP:LISTEN &>/dev/null 2>&1; then
        warn "On macOS, port 5000 may be held by AirPlay Receiver."
        warn "Disable it: System Settings → General → AirDrop & Handoff → AirPlay Receiver"
        warn "Or change api.port in backend/config.json and set VITE_API_URL accordingly."
    fi
fi

# ── 6. PID tracking for clean shutdown ──────────────────────────────────────

BACKEND_PID=""
FRONTEND_PID=""

cleanup() {
    echo ""
    info "Shutting down ExfilTrace services..."
    if [ -n "$BACKEND_PID" ] && kill -0 "$BACKEND_PID" 2>/dev/null; then
        kill "$BACKEND_PID"
        ok "Backend stopped (PID $BACKEND_PID)."
    fi
    if [ -n "$FRONTEND_PID" ] && kill -0 "$FRONTEND_PID" 2>/dev/null; then
        kill "$FRONTEND_PID"
        ok "Frontend stopped (PID $FRONTEND_PID)."
    fi
    echo ""
}
trap cleanup EXIT INT TERM

# ── 7. Start the backend ─────────────────────────────────────────────────────

echo ""
info "Starting Python backend on http://127.0.0.1:5000/api ..."
"$PYTHON_VENV" backend/run.py &
BACKEND_PID=$!

# Wait for backend to come up (up to 8 seconds)
ATTEMPTS=0
until "$PYTHON_VENV" -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/api/status', timeout=2)" &>/dev/null || [ $ATTEMPTS -ge 8 ]; do
    sleep 1
    ATTEMPTS=$((ATTEMPTS + 1))
done

if [ $ATTEMPTS -ge 8 ]; then
    warn "Backend did not respond in time. The frontend will use mock data as fallback."
else
    ok "Backend is live at http://127.0.0.1:5000/api"
fi

# ── 8. Start the frontend ────────────────────────────────────────────────────

info "Starting React frontend..."
npm run dev &
FRONTEND_PID=$!

sleep 2

echo ""
echo -e "${BOLD} ======================================================"
echo -e "  ExfilTrace is running!"
echo ""
echo -e "  Frontend  :  http://localhost:5173"
echo -e "  Backend   :  http://127.0.0.1:5000/api"
echo -e "  API Status:  http://127.0.0.1:5000/api/status"
echo ""
echo -e "  Press Ctrl+C to stop both services."
echo -e " ======================================================${RESET}"
echo ""

# Open browser if possible
if command -v xdg-open &>/dev/null; then
    sleep 2 && xdg-open "http://localhost:5173" &
elif command -v open &>/dev/null; then
    sleep 2 && open "http://localhost:5173" &
fi

# ── 9. Wait for child processes ──────────────────────────────────────────────

wait "$BACKEND_PID" "$FRONTEND_PID"
