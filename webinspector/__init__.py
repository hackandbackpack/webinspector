"""
webinspector - A comprehensive web security inspection tool for penetration testing.

This package provides automated security analysis capabilities for web applications,
combining multiple inspection techniques into a single unified tool. It is designed
for use by Red Siege's penetration testing team during engagements.

Key capabilities include:
    - SSL/TLS configuration analysis (powered by sslyze)
    - HTTP security header evaluation
    - Cookie security attribute checking
    - CORS (Cross-Origin Resource Sharing) misconfiguration detection
    - Technology fingerprinting (powered by webtech)
    - Passive web security analysis and reporting

The tool is designed to be run from the command line and produces structured
output suitable for inclusion in penetration testing reports.

Usage:
    # Run as a module
    python -m webinspector <target>

    # Run as an installed console script
    webinspector <target>

Author: Red Siege Information Security
License: Proprietary
"""

# VERSION is the canonical single source of truth for the package version.
# All other references (setup.py, CLI output, etc.) should read from here.
# Follows semantic versioning: MAJOR.MINOR.PATCH
VERSION = "1.0.0"

# __version__ is the standard Python package version attribute that tools
# like pip and setuptools expect to find in the top-level __init__.py.
__version__ = VERSION

# __all__ defines the public API surface when someone does "from webinspector import *".
# For now it only exposes the version constants; modules will be added as they are built.
__all__ = ["VERSION", "__version__"]
