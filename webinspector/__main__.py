"""
webinspector.__main__ - Entry point for running webinspector as a module or CLI command.

This module is invoked when the user runs:
    python -m webinspector
or when the installed console_scripts entry point calls main().

Currently this is a stub that prints the version and a placeholder message.
It will be replaced in a later task with the full CLI argument parser (argparse)
and the orchestration logic that calls each scanning module.

Author: Red Siege Information Security
"""

# Import the version string from the top-level package __init__.py so that
# the CLI output always stays in sync with the package metadata.
from webinspector import VERSION


def main():
    """
    Main entry point for the webinspector CLI tool.

    This function is referenced by setup.py's console_scripts entry point,
    which means pip will generate a wrapper script called 'webinspector'
    that calls this function when the package is installed.

    Currently prints a stub message with the version number.
    Will be replaced with full argparse-based CLI in a later task.
    """
    # Print the tool banner with the current version.
    # This confirms the package is installed and importable.
    print(f"webinspector v{VERSION}")
    print("Red Siege Information Security - Web Security Inspector")
    print()
    print("[*] CLI not yet implemented. This is a placeholder entry point.")
    print("[*] Full argument parsing and scan orchestration coming soon.")


# This block runs when the module is executed directly via:
#   python -m webinspector
# Python looks for __main__.py inside the package and executes it.
if __name__ == "__main__":
    main()
