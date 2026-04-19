#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

REACT_UI_DIR="$PROJECT_DIR/react-ui"
REACT_DIST_DIR="$REACT_UI_DIR/dist"

PYTHON_BIN="${PYTHON_BIN:-python3}"
VENV_DIR="${VENV_DIR:-.venv-linux}"
BUILD_TAG="$(date +%Y%m%d-%H%M%S)"
GUI_APP_NAME="${GUI_APP_NAME:-VulnMngSysDesktop-linux-$BUILD_TAG}"
CLI_APP_NAME="${CLI_APP_NAME:-VulnMngSysDesktop-CLI-linux-$BUILD_TAG}"

if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  echo "[ERROR] Python binary not found: $PYTHON_BIN"
  exit 1
fi

if [ ! -d "$VENV_DIR" ]; then
  "$PYTHON_BIN" -m venv "$VENV_DIR"
fi

# shellcheck disable=SC1090
source "$VENV_DIR/bin/activate"

python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install --upgrade pyinstaller

if command -v npm >/dev/null 2>&1; then
  echo "[1/4] Building React frontend..."
  (cd "$REACT_UI_DIR" && npm install && npm run build)
else
  echo "[WARN] npm not found; using existing react-ui/dist if available."
fi

if ! command -v firefox >/dev/null 2>&1; then
  echo "[WARN] firefox is not installed. Linux frozen app defaults to Firefox web-view mode."
  echo "[WARN] Install Firefox or run with --legacy-ui at runtime."
fi

if ! python -c "import tkinter" >/dev/null 2>&1; then
  echo "[ERROR] tkinter is missing in this Python environment."
  echo "Install it on Ubuntu: sudo apt install -y python3-tk"
  echo "Then recreate venv and rerun this script."
  exit 1
fi

rm -rf build dist

if [ ! -f "$REACT_DIST_DIR/index.html" ]; then
  echo "[ERROR] React build output not found at $REACT_DIST_DIR/index.html"
  echo "Run: cd react-ui && npm install && npm run build"
  exit 1
fi

echo "[2/4] Building Linux GUI executable..."
python -m PyInstaller \
  --noconfirm \
  --clean \
  --onefile \
  --windowed \
  --name "$GUI_APP_NAME" \
  --hidden-import tkinter \
  --hidden-import _tkinter \
  --hidden-import webview \
  --add-data "rules:rules" \
  --add-data "react-ui/dist:react-ui/dist" \
  main.py

echo "[3/4] Building Linux CLI executable..."
python -m PyInstaller \
  --noconfirm \
  --clean \
  --onefile \
  --console \
  --name "$CLI_APP_NAME" \
  --hidden-import tkinter \
  --hidden-import _tkinter \
  --hidden-import webview \
  --add-data "rules:rules" \
  --add-data "react-ui/dist:react-ui/dist" \
  main.py

echo "[4/4] Done. Outputs:"
echo " - $PROJECT_DIR/dist/$GUI_APP_NAME"
echo " - $PROJECT_DIR/dist/$CLI_APP_NAME"
