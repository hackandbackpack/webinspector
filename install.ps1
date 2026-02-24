# ==========================================================================
# install.ps1 - WebInspector Install Script for Windows (PowerShell)
#
# This script automates the full setup of the webinspector development
# environment on Windows. It performs the following steps:
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
#   Open PowerShell and run:
#     .\install.ps1
#
#   If you get a script execution policy error, run:
#     Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
#
# Author: Red Siege Information Security
# ==========================================================================

# ---------------------------------------------------------------------------
# Strict mode: stop on errors, treat uninitialized variables as errors, and
# halt on failed commands in pipelines. This is the PowerShell equivalent of
# bash's "set -euo pipefail".
# ---------------------------------------------------------------------------
$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

# ---------------------------------------------------------------------------
# Resolve the directory where this script lives, regardless of where it was
# invoked from. This ensures all relative paths (venv, requirements.txt, etc.)
# are resolved correctly.
# ---------------------------------------------------------------------------
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  WebInspector Installer"                     -ForegroundColor Cyan
Write-Host "  Red Siege Information Security"             -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# ===========================================================================
# Step 1: Check that Python 3.10+ is available
# ===========================================================================
# On Windows, the command is typically 'python' (not 'python3'). We also
# check 'python3' as a fallback in case it is available (e.g., Windows
# Store alias or custom setup). The first command that exists AND reports
# a version >= 3.10 wins.
# ---------------------------------------------------------------------------
Write-Host "[*] Checking for Python 3.10+..."

$PythonCmd = $null

# Try 'python' first (standard on Windows), then 'python3' as a fallback
foreach ($cmd in @("python", "python3")) {
    try {
        # Test if the command is available on the PATH
        $cmdPath = Get-Command $cmd -ErrorAction SilentlyContinue
        if ($null -eq $cmdPath) {
            continue
        }

        # Query Python for its version using sys.version_info to avoid
        # fragile string parsing of --version output.
        $version = & $cmd -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>$null
        $major   = & $cmd -c "import sys; print(sys.version_info.major)" 2>$null
        $minor   = & $cmd -c "import sys; print(sys.version_info.minor)" 2>$null

        # Require Python 3.10 or newer (matches python_requires in setup.py)
        if ([int]$major -ge 3 -and [int]$minor -ge 10) {
            $PythonCmd = $cmd
            Write-Host "[+] Found Python $version at $($cmdPath.Source)" -ForegroundColor Green
            break
        }
        else {
            Write-Host "[-] $cmd is version $version (need 3.10+), skipping" -ForegroundColor Yellow
        }
    }
    catch {
        # Command not found or failed -- try the next one
        continue
    }
}

# If no suitable Python was found, print a helpful error and exit.
if ($null -eq $PythonCmd) {
    Write-Host ""
    Write-Host "[!] ERROR: Python 3.10 or newer is required but was not found." -ForegroundColor Red
    Write-Host "[!] Please install Python from https://www.python.org/downloads/" -ForegroundColor Red
    Write-Host "[!] Make sure to check 'Add Python to PATH' during installation." -ForegroundColor Red
    exit 1
}

Write-Host ""

# ===========================================================================
# Step 2: Create a virtual environment (if it does not already exist)
# ===========================================================================
# A virtual environment isolates webinspector's dependencies from the system
# Python packages, preventing version conflicts with other projects.
# The venv is created in a directory called 'venv' at the project root.
# ---------------------------------------------------------------------------
if (-not (Test-Path "venv")) {
    Write-Host "[*] Creating virtual environment in .\venv ..."
    & $PythonCmd -m venv venv
    Write-Host "[+] Virtual environment created." -ForegroundColor Green
}
else {
    Write-Host "[*] Virtual environment already exists at .\venv"
}

# Activate the virtual environment so that pip and python resolve to the
# venv copies rather than the system-wide ones.
# On Windows, the activation script is in venv\Scripts\Activate.ps1.
Write-Host "[*] Activating virtual environment..."
& ".\venv\Scripts\Activate.ps1"
Write-Host "[+] Active Python: $(Get-Command python | Select-Object -ExpandProperty Source)" -ForegroundColor Green
Write-Host ""

# ===========================================================================
# Step 3: Install dependencies from requirements.txt
# ===========================================================================
# Upgrade pip first to avoid warnings and ensure we have the latest resolver.
# Then install all runtime and development dependencies listed in
# requirements.txt (requests, sslyze, webtech, pytest, etc.).
# ---------------------------------------------------------------------------
Write-Host "[*] Upgrading pip..."
python -m pip install --upgrade pip --quiet

Write-Host "[*] Installing dependencies from requirements.txt..."
pip install -r requirements.txt --quiet
Write-Host "[+] Dependencies installed." -ForegroundColor Green
Write-Host ""

# ===========================================================================
# Step 4: Install webinspector in editable (development) mode
# ===========================================================================
# 'pip install -e .' installs the package so that the 'webinspector' console
# command is available, AND changes to the source code take effect immediately
# without needing to re-install. This is the standard workflow for development.
# ---------------------------------------------------------------------------
Write-Host "[*] Installing webinspector in development mode (pip install -e .) ..."
pip install -e . --quiet
Write-Host "[+] webinspector installed. CLI command is now available." -ForegroundColor Green
Write-Host ""

# ===========================================================================
# Step 5: Download / update the webtech technology database
# ===========================================================================
# The webtech library ships with a built-in fingerprint database but can
# also download the latest version from the upstream project. We import
# webtech and instantiate it, which triggers a database check. This step
# is non-critical -- if it fails (e.g., no internet), we continue anyway.
# ---------------------------------------------------------------------------
Write-Host "[*] Updating webtech technology database..."
try {
    python -c "import webtech; wt = webtech.WebTech(); print('[+] Technology database is ready')"
}
catch {
    Write-Host "[!] Database update skipped (non-critical, may require internet)" -ForegroundColor Yellow
}
Write-Host ""

# ===========================================================================
# Step 6: Run the test suite
# ===========================================================================
# Execute all tests under the tests/ directory using pytest. The -v flag
# produces verbose output (one line per test), and --tb=short gives a
# condensed traceback on failures. If any test fails, the script will
# exit with a non-zero status (due to $ErrorActionPreference = "Stop").
# ---------------------------------------------------------------------------
Write-Host "[*] Running test suite..."
Write-Host "--------------------------------------------"
python -m pytest tests/ -v --tb=short
if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "[!] Some tests failed. Please review the output above." -ForegroundColor Red
    exit $LASTEXITCODE
}
Write-Host "--------------------------------------------"
Write-Host ""

# ===========================================================================
# Step 7: Print summary with usage instructions
# ===========================================================================
Write-Host "============================================" -ForegroundColor Green
Write-Host "  Installation Complete!"                     -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Green
Write-Host ""
Write-Host "All tests passed. WebInspector is ready to use."
Write-Host ""
Write-Host "Quick Start:"
Write-Host "  # Activate the virtual environment (if not already active)"
Write-Host "  .\venv\Scripts\Activate.ps1"
Write-Host ""
Write-Host "  # Scan a single target"
Write-Host "  webinspector -t example.com"
Write-Host ""
Write-Host "  # Scan targets from an Nmap XML file"
Write-Host "  webinspector -x nmap_scan.xml"
Write-Host ""
Write-Host "  # Output results as JSON"
Write-Host "  webinspector -t example.com -o json"
Write-Host ""
Write-Host "  # Show all available options"
Write-Host "  webinspector --help"
Write-Host ""
Write-Host "For more information, see the project documentation."
Write-Host "============================================" -ForegroundColor Green
