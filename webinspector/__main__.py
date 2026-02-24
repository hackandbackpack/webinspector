"""
webinspector.__main__ - Entry point for running webinspector as a module or CLI command.

This module is invoked when the user runs:
    python -m webinspector
or when the installed console_scripts entry point calls main().

It orchestrates the full end-to-end scanning pipeline:
    1. Parse CLI args
    2. Resolve targets from all input sources (-t, -iL, -x)
    3. Select modules based on --only/--no
    4. Print banner (unless --quiet)
    5. Run scanner
    6. Render output (console, and optionally text/json)

Author: Red Siege Information Security
"""

from __future__ import annotations

import sys

# Import the version string from the top-level package __init__.py so that
# the CLI output always stays in sync with the package metadata.
from webinspector import VERSION

# Import the CLI argument parser. parse_args() returns a ScanConfig dataclass
# with all user-supplied options validated and normalized.
from webinspector.cli import parse_args

# Import target resolution functions.
# expand_targets() parses raw strings (hostnames, IPs, CIDRs) into Target objects.
# parse_target_file() reads a target file into raw strings for expand_targets().
from webinspector.core.target import expand_targets, parse_target_file

# Import the nmap XML parser that extracts web service targets from nmap output.
from webinspector.utils.nmap_parser import parse_nmap_xml

# Import the module registry function that applies --only/--no filtering.
from webinspector.modules import ALL_MODULE_NAMES, get_modules_for_selection

# Import the scanner orchestrator that coordinates DNS resolution, HTTP fetching,
# and module execution across all targets.
from webinspector.core.scanner import WebInspectorScanner


def main():
    """
    Main entry point for the webinspector CLI tool.

    This function is referenced by setup.py's console_scripts entry point,
    which means pip will generate a wrapper script called 'webinspector'
    that calls this function when the package is installed.

    Execution flow:
        1. CLI PARSING        - parse_args() validates and returns ScanConfig
        2. TARGET RESOLUTION  - Expand all inputs into Target objects
        3. MODULE SELECTION   - Filter modules based on --only/--no flags
        4. BANNER             - Print tool banner and scan info (unless -q)
        5. SCANNING           - WebInspectorScanner.run() does the actual work
        6. OUTPUT             - Print results to console (+ optional file/json)
    """
    # -----------------------------------------------------------------------
    # Step 1: Parse CLI args
    # -----------------------------------------------------------------------
    # This handles --help, --version, and validation (at least one target
    # source required, mutually exclusive flags, module name validation).
    # If validation fails, parse_args() calls sys.exit().
    config = parse_args()

    # -----------------------------------------------------------------------
    # Step 2: Resolve targets from all input sources
    # -----------------------------------------------------------------------
    # Targets can come from three sources that are merged together:
    #   -t HOST [HOST ...]  : Direct command-line targets
    #   -iL FILE            : Target list file (one per line)
    #   -x FILE [FILE ...]  : Nmap XML output files

    # Start with raw target strings from -t.
    all_raw_targets: list[str] = list(config.targets)

    # Add targets from target file (-iL) if specified.
    if config.target_file:
        try:
            file_targets = parse_target_file(config.target_file)
            all_raw_targets.extend(file_targets)
        except FileNotFoundError:
            print(
                f"[!] Target file not found: {config.target_file}",
                file=sys.stderr,
            )
            sys.exit(1)

    # Parse nmap XML files (-x) into Target objects.
    # These are already fully formed targets (with scheme, host, port),
    # so they bypass expand_targets() and go directly into the target list.
    nmap_targets = []
    for nmap_file in config.nmap_files:
        nmap_targets.extend(parse_nmap_xml(nmap_file))

    # Expand CLI/file targets into Target objects.
    # expand_targets() handles:
    #   - Bare hostnames -> both http + https on default/specified ports
    #   - IP addresses -> both http + https on default/specified ports
    #   - CIDR ranges -> all IPs * both schemes * all ports
    #   - Full URLs -> single target with explicit scheme/port
    #   - Deduplication by (scheme, host, port)
    targets = expand_targets(
        all_raw_targets,
        ports=config.ports if config.ports else None,
    )

    # Add nmap-sourced targets to the list.
    # These are already parsed Target objects, not raw strings.
    targets.extend(nmap_targets)

    # Deduplicate the combined list.
    # expand_targets() already deduplicates its own output, but we need
    # to deduplicate again after merging nmap targets because the same
    # host:port might appear in both -t and -x inputs.
    seen: set[tuple[str, str, int]] = set()
    unique_targets = []
    for t in targets:
        key = (t.scheme, t.host, t.port)
        if key not in seen:
            seen.add(key)
            unique_targets.append(t)
    targets = unique_targets

    # Validate that we have at least one target after all parsing.
    # This catches cases where all inputs were empty, commented out,
    # or nmap files contained no web services.
    if not targets:
        print(
            "[!] No valid targets found. Check your input.",
            file=sys.stderr,
        )
        sys.exit(1)

    # -----------------------------------------------------------------------
    # Step 3: Select modules based on --only/--no
    # -----------------------------------------------------------------------
    # get_modules_for_selection() returns the list of ScanModule instances
    # that should run based on the user's filtering preferences.
    modules = get_modules_for_selection(
        only=config.only_modules,
        exclude=config.exclude_modules,
    )

    # -----------------------------------------------------------------------
    # Step 4: Print banner (unless --quiet)
    # -----------------------------------------------------------------------
    if not config.quiet:
        print(f"[*] WebInspector v{VERSION}")
        print(f"[*] Targets: {len(targets)} URLs")

        # Show which modules will run.  If we have loaded module instances,
        # show their names; otherwise fall back to the canonical list.
        # In early development (before Task 19 wires up module imports),
        # modules will be an empty list, so we show ALL_MODULE_NAMES as
        # a preview of what will eventually run.
        module_names = (
            [m.name for m in modules] if modules else ALL_MODULE_NAMES
        )
        print(f"[*] Modules: {', '.join(module_names)}")
        print()

    # -----------------------------------------------------------------------
    # Step 5: Run scanner
    # -----------------------------------------------------------------------
    # The WebInspectorScanner handles the full scan pipeline:
    #   - DNS pre-resolution (batch)
    #   - HTTP-based module scanning (ThreadPoolExecutor)
    #   - sslyze SSL/cert scanning (separate phase, stubbed for now)
    #   - Result aggregation into ScanSummary
    scanner = WebInspectorScanner(config)
    findings, summary = scanner.run(targets, modules)

    # -----------------------------------------------------------------------
    # Step 6: Render output
    # -----------------------------------------------------------------------
    # Output rendering is handled here for now with basic console output.
    # Task 7 will add proper renderers for console (Rich tables), text
    # file (-o), and JSON (--json) output formats.

    if not config.quiet:
        if findings:
            print(f"\n[*] Found {len(findings)} findings")
        else:
            print("\n[*] No findings (no scanner modules loaded yet)")

        print(f"[*] Scan completed in {summary.duration_seconds:.1f}s")
        print(
            f"[*] Targets: {summary.successful} successful, "
            f"{summary.failed} failed"
        )

        # If there are failed targets, list them so the analyst knows
        # which hosts were unreachable.
        if summary.failed_targets:
            print("\n[!] Failed targets:")
            for target, error in summary.failed_targets:
                print(f"    {target.display}: {error}")

    # -----------------------------------------------------------------------
    # TODO (Task 7): Write output to files when -o or --json is specified.
    #
    #   if config.output_file:
    #       render_text_report(findings, summary, config.output_file)
    #
    #   if config.json_file:
    #       render_json_report(findings, summary, config.json_file)
    # -----------------------------------------------------------------------


# This block runs when the module is executed directly via:
#   python -m webinspector
# Python looks for __main__.py inside the package and executes it.
if __name__ == "__main__":
    main()
