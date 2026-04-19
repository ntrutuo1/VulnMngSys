#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

PYTHON_BIN="${PYTHON_BIN:-python3}"
VENV_DIR="${VENV_DIR:-.venv-linux}"
APP_NAME="${APP_NAME:-VulnMngSysDesktop-linux}"

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
python -m pip install --upgrade pyinstaller

if ! python -c "import tkinter" >/dev/null 2>&1; then
  echo "[ERROR] tkinter is missing in this Python environment."
  echo "Install it on Ubuntu: sudo apt install -y python3-tk"
  echo "Then recreate venv and rerun this script."
  exit 1
fi

rm -rf build dist

python -m PyInstaller \
  --noconfirm \
  --clean \
  --onefile \
  --name "$APP_NAME" \
  --hidden-import tkinter \
  --hidden-import _tkinter \
  --add-data "rules:rules" \
  main.py

echo "[OK] Linux binary created at: $PROJECT_DIR/dist/$APP_NAME"
