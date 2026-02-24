#!/usr/bin/env bash
# ==========================================================================
# install.sh - WebInspector Install Script for Linux, macOS, WSL, Git Bash
#
# This script automates the full setup of the webinspector development
# environment. It performs the following steps:
#
#   1. Verifies that Python 3.10 or newer is available on the system
#   2. Creates a Python virtual environment (venv) if one does not exist
#   3. Installs all dependencies from requirements.txt
#   4. Installs the webinspector package itself in editable/development mode
#   5. Downloads or updates the webtech technology fingerprint database
#   6. Runs the full test suite with pytest to confirm everything works
#   7. Prints a summary with usage instructions
#
# Usage:
#   chmod +x install.sh
#   ./install.sh
#
# Author: Red Siege Information Security
# ==========================================================================

# Exit immediately on any error (-e), treat unset variables as errors (-u),
# and ensure piped commands propagate failures (-o pipefail).
set -euo pipefail

# ---------------------------------------------------------------------------
# Resolve the directory where this script lives, regardless of where it was
# invoked from. This ensures all relative paths (venv, requirements.txt, etc.)
# are resolved correctly even if the user runs ./scripts/install.sh from a
# different working directory.
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------
echo "============================================"
echo "  WebInspector Installer"
echo "  Red Siege Information Security"
echo "============================================"
echo

# ===========================================================================
# Step 1: Check that Python 3.10+ is available
# ===========================================================================
# We try 'python3' first (standard on Linux/macOS) and fall back to 'python'
# (common on Windows Git Bash or some distributions). The first command that
# exists AND reports a version >= 3.10 wins.
# ---------------------------------------------------------------------------
echo "[*] Checking for Python 3.10+..."

PYTHON_CMD=""

for cmd in python3 python; do
    # Check if the command exists on the PATH
    if command -v "$cmd" &>/dev/null; then
        # Query the Python interpreter for its major and minor version numbers.
        # Using sys.version_info avoids fragile string parsing of --version output.
        version=$("$cmd" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
        major=$("$cmd" -c "import sys; print(sys.version_info.major)")
        minor=$("$cmd" -c "import sys; print(sys.version_info.minor)")

        # Require Python 3.10 or newer (matches python_requires in setup.py)
        if [ "$major" -ge 3 ] && [ "$minor" -ge 10 ]; then
            PYTHON_CMD="$cmd"
            echo "[+] Found Python $version at $(which "$cmd")"
            break
        else
            echo "[-] $cmd is version $version (need 3.10+), skipping"
        fi
    fi
done

# If no suitable Python was found, print a helpful error and exit.
if [ -z "$PYTHON_CMD" ]; then
    echo
    echo "[!] ERROR: Python 3.10 or newer is required but was not found."
    echo "[!] Please install Python from https://www.python.org/downloads/"
    echo "[!] On Ubuntu/Debian:  sudo apt install python3.10"
    echo "[!] On macOS (brew):   brew install python@3.12"
    exit 1
fi

echo

# ===========================================================================
# Step 2: Create a virtual environment (if it does not already exist)
# ===========================================================================
# A virtual environment isolates webinspector's dependencies from the system
# Python packages, preventing version conflicts with other projects.
# The venv is created in a directory called 'venv' at the project root.
# ---------------------------------------------------------------------------
if [ ! -d "venv" ]; then
    echo "[*] Creating virtual environment in ./venv ..."
    $PYTHON_CMD -m venv venv
    echo "[+] Virtual environment created."
else
    echo "[*] Virtual environment already exists at ./venv"
fi

# Activate the virtual environment so that pip and python resolve to the
# venv copies rather than the system-wide ones.
echo "[*] Activating virtual environment..."
# shellcheck disable=SC1091
source venv/bin/activate
echo "[+] Active Python: $(which python)"
echo

# ===========================================================================
# Step 3: Install dependencies from requirements.txt
# ===========================================================================
# Upgrade pip first to avoid warnings and ensure we have the latest resolver.
# Then install all runtime and development dependencies listed in
# requirements.txt (requests, sslyze, webtech, pytest, etc.).
# ---------------------------------------------------------------------------
echo "[*] Upgrading pip..."
pip install --upgrade pip --quiet

echo "[*] Installing dependencies from requirements.txt..."
pip install -r requirements.txt --quiet
echo "[+] Dependencies installed."
echo

# ===========================================================================
# Step 4: Install webinspector in editable (development) mode
# ===========================================================================
# 'pip install -e .' installs the package so that the 'webinspector' console
# command is available, AND changes to the source code take effect immediately
# without needing to re-install. This is the standard workflow for development.
# ---------------------------------------------------------------------------
echo "[*] Installing webinspector in development mode (pip install -e .) ..."
pip install -e . --quiet
echo "[+] webinspector installed. CLI command is now available."
echo

# ===========================================================================
# Step 5: Download / update the webtech technology database
# ===========================================================================
# The webtech library ships with a built-in fingerprint database but can
# also download the latest version from the upstream project. We import
# webtech and instantiate it, which triggers a database check. This step
# is non-critical -- if it fails (e.g., no internet), we continue anyway.
# ---------------------------------------------------------------------------
echo "[*] Updating webtech technology database..."
if python -c "
import webtech
# Instantiating WebTech triggers the database check/download
wt = webtech.WebTech()
print('[+] Technology database is ready')
" 2>/dev/null; then
    : # Success -- message already printed above
else
    echo "[!] Database update skipped (non-critical, may require internet)"
fi
echo

# ===========================================================================
# Step 6: Run the test suite
# ===========================================================================
# Execute all tests under the tests/ directory using pytest. The -v flag
# produces verbose output (one line per test), and --tb=short gives a
# condensed traceback on failures. If any test fails, the script will
# exit with a non-zero status (due to set -e).
# ---------------------------------------------------------------------------
echo "[*] Running test suite..."
echo "--------------------------------------------"
python -m pytest tests/ -v --tb=short
echo "--------------------------------------------"
echo

# ===========================================================================
# Step 7: Print summary with usage instructions
# ===========================================================================
echo "============================================"
echo "  Installation Complete!"
echo "============================================"
echo
echo "All tests passed. WebInspector is ready to use."
echo
echo "Quick Start:"
echo "  # Activate the virtual environment (if not already active)"
echo "  source venv/bin/activate"
echo
echo "  # Scan a single target"
echo "  webinspector -t example.com"
echo
echo "  # Scan targets from an Nmap XML file"
echo "  webinspector -x nmap_scan.xml"
echo
echo "  # Output results as JSON"
echo "  webinspector -t example.com -o json"
echo
echo "  # Show all available options"
echo "  webinspector --help"
echo
echo "For more information, see the project documentation."
echo "============================================"
