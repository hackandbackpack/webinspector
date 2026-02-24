"""
webinspector.__main__ - Entry point for running webinspector as a module or CLI command.

This module is invoked when the user runs:
    python -m webinspector
or when the installed console_scripts entry point calls main().

It parses command-line arguments via the CLI module, prints a configuration
summary, and exits. The scanner orchestrator (Task 6) will extend this to
actually run the scan modules against the parsed targets.

Author: Red Siege Information Security
"""

# Import the version string from the top-level package __init__.py so that
# the CLI output always stays in sync with the package metadata.
from webinspector import VERSION

# Import the CLI argument parser. parse_args() returns a ScanConfig dataclass
# with all user-supplied options validated and normalized.
from webinspector.cli import parse_args


def main():
    """
    Main entry point for the webinspector CLI tool.

    This function is referenced by setup.py's console_scripts entry point,
    which means pip will generate a wrapper script called 'webinspector'
    that calls this function when the package is installed.

    Current behavior:
        1. Parse command-line arguments into a ScanConfig dataclass.
        2. Print a configuration summary showing what will be scanned.
        3. Exit — actual scanning will be added in Task 6.
    """
    # Parse command-line arguments. This handles --help, --version, and
    # validation (at least one target source required, mutually exclusive
    # flags). If validation fails, parse_args() calls sys.exit().
    config = parse_args()

    # Print the tool banner with the current version.
    print(f"webinspector v{VERSION}")
    print("Red Siege Information Security - Web Security Inspector")
    print()

    # Print a configuration summary so the user can verify their options
    # before the scan starts. This is especially useful with -v (verbose).
    print("[*] Scan configuration:")

    # Show target sources — which of the three input methods were used.
    if config.targets:
        print(f"    Targets (-t):      {', '.join(config.targets)}")
    if config.target_file:
        print(f"    Target file (-iL): {config.target_file}")
    if config.nmap_files:
        print(f"    Nmap files (-x):   {', '.join(config.nmap_files)}")

    # Show port override if specified.
    if config.ports:
        print(f"    Ports (-p):        {', '.join(str(p) for p in config.ports)}")

    # Show module selection if specified.
    if config.only_modules:
        print(f"    Only modules:      {', '.join(config.only_modules)}")
    elif config.exclude_modules:
        print(f"    Excluded modules:  {', '.join(config.exclude_modules)}")
    else:
        print("    Modules:           all")

    # Show scan tuning settings.
    print(f"    Timeout:           {config.timeout}s")
    print(f"    Threads:           {config.threads}")
    if config.proxy:
        print(f"    Proxy:             {config.proxy}")

    # Show output destinations.
    if config.output_file:
        print(f"    Output file (-o):  {config.output_file}")
    if config.json_file:
        print(f"    JSON file:         {config.json_file}")

    # Show verbosity level.
    if config.verbose:
        print("    Verbosity:         verbose")
    elif config.quiet:
        print("    Verbosity:         quiet")

    print()
    print("[*] Scanner orchestration not yet implemented.")
    print("[*] Will be added in Task 6.")


# This block runs when the module is executed directly via:
#   python -m webinspector
# Python looks for __main__.py inside the package and executes it.
if __name__ == "__main__":
    main()
