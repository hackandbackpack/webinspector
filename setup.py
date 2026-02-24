"""
setup.py - Package configuration for webinspector.

This file tells setuptools how to build, install, and distribute the
webinspector package. It defines metadata (name, version, author),
runtime dependencies, and the console_scripts entry point that creates
the 'webinspector' command-line executable.

Install in development/editable mode with:
    pip install -e .

Install normally with:
    pip install .

Author: Red Siege Information Security
"""

# setuptools is the standard Python build/packaging library.
# find_packages() automatically discovers sub-packages so we don't have to
# list them all manually (it looks for directories containing __init__.py).
from setuptools import setup, find_packages

# Read the version from the package's __init__.py so there is a single
# source of truth. We could import webinspector directly, but that can
# fail if dependencies aren't installed yet. Instead we parse the file.
# For simplicity and because VERSION is a simple string literal, we
# just hardcode it here to match webinspector/__init__.py.
# If you change the version, update it in BOTH places.
VERSION = "1.0.0"

# install_requires lists the packages needed at runtime.
# These match requirements.txt EXCEPT for pytest, which is only
# needed during development/testing and belongs in extras_require.
INSTALL_REQUIRES = [
    # SSL/TLS configuration scanner (sslyze)
    "sslyze>=6.0,<7.0",
    # Web technology fingerprinting (webtech)
    "webtech>=1.3",
    # HTTP requests library
    "requests>=2.31",
    # DNS toolkit for record lookups
    "dnspython>=2.4",
    # Rich terminal output formatting
    "rich>=13.0",
    # Fast XML/HTML parser
    "lxml>=4.9",
    # Network address manipulation (IP/CIDR handling)
    "netaddr>=0.9",
]

# extras_require defines optional dependency groups that can be installed with:
#   pip install -e .[dev]
EXTRAS_REQUIRE = {
    # Development dependencies: testing tools, linters, etc.
    "dev": [
        "pytest>=7.0",
    ],
}

setup(
    # --- Package identity ---
    # name: the distribution name on PyPI / pip install <name>
    name="webinspector",

    # version: follows semantic versioning (MAJOR.MINOR.PATCH)
    version=VERSION,

    # --- Metadata ---
    # description: one-line summary shown by pip search and PyPI
    description="A comprehensive web security inspection tool for penetration testing",

    # long_description would normally come from README.md; omitted for now
    long_description="webinspector combines SSL/TLS scanning, HTTP header analysis, "
                     "cookie checks, CORS detection, and technology fingerprinting "
                     "into a single CLI tool for Red Siege pentest engagements.",

    # author and contact info
    author="Red Siege Information Security",
    author_email="info@redsiege.com",

    # url: project homepage or repository
    url="https://github.com/redsiege/webinspector",

    # --- Package discovery ---
    # find_packages() scans the directory tree for any folder with __init__.py.
    # We exclude the tests/ directory from the installed distribution since
    # end users don't need the test suite.
    packages=find_packages(exclude=["tests", "tests.*"]),

    # --- Dependencies ---
    # Runtime dependencies that pip will install automatically
    install_requires=INSTALL_REQUIRES,

    # Optional dependency groups (pip install -e .[dev])
    extras_require=EXTRAS_REQUIRE,

    # --- Entry points ---
    # console_scripts creates a platform-appropriate executable wrapper.
    # After installation, typing 'webinspector' on the command line will
    # call the main() function in webinspector/__main__.py.
    entry_points={
        "console_scripts": [
            # Format: "command_name = package.module:function"
            "webinspector = webinspector.__main__:main",
        ],
    },

    # --- Classifiers ---
    # Trove classifiers help categorize the package on PyPI.
    # These are informational only and don't affect functionality.
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
    ],

    # Minimum Python version required to run webinspector
    python_requires=">=3.10",
)
