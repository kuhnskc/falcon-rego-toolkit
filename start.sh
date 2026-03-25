#!/usr/bin/env bash
set -e

# Falcon Rego Toolkit — Start Script
# Starts both the backend (FastAPI) and frontend (Vite) servers.

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
BACKEND_DIR="$ROOT_DIR/backend"
FRONTEND_DIR="$ROOT_DIR/frontend"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

cleanup() {
    echo ""
    echo -e "${YELLOW}Shutting down...${NC}"
    if [ -n "$BACKEND_PID" ]; then
        kill "$BACKEND_PID" 2>/dev/null || true
    fi
    if [ -n "$FRONTEND_PID" ]; then
        kill "$FRONTEND_PID" 2>/dev/null || true
    fi
    wait 2>/dev/null
    echo -e "${GREEN}Stopped.${NC}"
    exit 0
}

trap cleanup SIGINT SIGTERM

# --- Check prerequisites ---

echo -e "${CYAN}Falcon Rego Toolkit${NC}"
echo ""

# Python
if command -v python3 &>/dev/null; then
    PYTHON=python3
elif command -v python &>/dev/null; then
    PYTHON=python
else
    echo -e "${RED}Error: Python 3 is required but not found.${NC}"
    echo "Install Python 3.10+ from https://www.python.org/downloads/"
    exit 1
fi

PY_VERSION=$($PYTHON --version 2>&1 | grep -oE '[0-9]+\.[0-9]+')
echo -e "  Python:  ${GREEN}$($PYTHON --version 2>&1)${NC}"

# Node
if ! command -v node &>/dev/null; then
    echo -e "${RED}Error: Node.js is required but not found.${NC}"
    echo "Install Node.js 18+ from https://nodejs.org/"
    exit 1
fi
echo -e "  Node:    ${GREEN}$(node --version)${NC}"

# npm
if ! command -v npm &>/dev/null; then
    echo -e "${RED}Error: npm is required but not found.${NC}"
    exit 1
fi
echo -e "  npm:     ${GREEN}$(npm --version)${NC}"

# OPA (optional — needed for local KAC rule testing)
if command -v opa &>/dev/null; then
    echo -e "  OPA:     ${GREEN}$(opa version 2>&1 | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')${NC}"
else
    echo -e "  OPA:     ${YELLOW}not found (optional — needed for local KAC rule testing)${NC}"
    echo -e "           Install with: ${CYAN}brew install opa${NC}"
fi
echo ""

# --- Backend setup ---

echo -e "${CYAN}Setting up backend...${NC}"

if [ ! -d "$BACKEND_DIR/.venv" ]; then
    echo "  Creating Python virtual environment..."
    $PYTHON -m venv "$BACKEND_DIR/.venv"
fi

# Activate venv and install deps
source "$BACKEND_DIR/.venv/bin/activate"

# Check if deps need installing (fast check: see if fastapi is importable)
if ! "$BACKEND_DIR/.venv/bin/python" -c "import fastapi" 2>/dev/null; then
    echo "  Installing Python dependencies..."
    pip install -q -r "$BACKEND_DIR/requirements.txt"
else
    echo "  Python dependencies already installed."
fi

# --- Frontend setup ---

echo -e "${CYAN}Setting up frontend...${NC}"

if [ ! -d "$FRONTEND_DIR/node_modules" ]; then
    echo "  Installing Node dependencies..."
    (cd "$FRONTEND_DIR" && npm install --silent)
else
    echo "  Node dependencies already installed."
fi

echo ""

# --- Start services ---

echo -e "${CYAN}Starting services...${NC}"

# Backend
(cd "$BACKEND_DIR" && "$BACKEND_DIR/.venv/bin/python" run.py) &
BACKEND_PID=$!
echo -e "  Backend:  ${GREEN}http://localhost:8000${NC}  (PID $BACKEND_PID)"

# Frontend
(cd "$FRONTEND_DIR" && npm run dev -- --host 2>/dev/null || npm run dev) &
FRONTEND_PID=$!
echo -e "  Frontend: ${GREEN}http://localhost:5173${NC}  (PID $FRONTEND_PID)"

echo ""
echo -e "${GREEN}Ready!${NC} Open ${CYAN}http://localhost:5173${NC} in your browser."
echo -e "Press ${YELLOW}Ctrl+C${NC} to stop both servers."
echo ""

# Wait for either process to exit
wait -n "$BACKEND_PID" "$FRONTEND_PID" 2>/dev/null || true
cleanup
