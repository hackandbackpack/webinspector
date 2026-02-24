"""
webinspector.cli - Command-line argument parser for webinspector.

This module defines the CLI interface that pentesters interact with. It uses
argparse to parse command-line arguments and validates them before returning
a ScanConfig dataclass that the scanner orchestrator (Task 6) consumes.

The CLI supports three ways to provide targets:
    -t HOST [HOST ...]     Direct target specification (hostnames, IPs, CIDRs)
    -iL FILE               Target list file (one target per line)
    -x FILE [FILE ...]     Nmap XML output files (auto-extracts HTTPS services)

At least one of these three must be provided. They can also be combined —
targets from all sources are merged and deduplicated by the orchestrator.

Module selection uses two mutually exclusive flags:
    --only ssl,headers     Run ONLY the named modules
    --no tech,content      Run ALL modules EXCEPT the named ones

Other options control output format, timeouts, threading, proxies, and
verbosity level.

Key public API:
    ScanConfig   - Dataclass holding all parsed CLI options
    parse_args() - Parse sys.argv (or a provided list) into a ScanConfig

Usage examples:
    # Single target (defaults to port 443)
    webinspector -t example.com

    # Multiple targets with port override
    webinspector -t 10.0.0.1 10.0.0.2 -p 443 8443

    # Nmap XML input with module exclusion
    webinspector -x scan.xml --no dns --timeout 30

    # Full-featured invocation
    webinspector -x scan.xml -iL extras.txt -t 10.0.0.5 --no dns \
        --timeout 30 -o report.txt --json report.json -v

Author: Red Siege Information Security
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field

# Import the version string from the top-level package so that --version
# output always matches the installed package version.
from webinspector import VERSION

# Import the canonical list of module names so we can validate --only and --no
# arguments against it and include the list in --help output.
from webinspector.modules import ALL_MODULE_NAMES


# ---------------------------------------------------------------------------
# ScanConfig dataclass
# ---------------------------------------------------------------------------

@dataclass
class ScanConfig:
    """
    Holds all parsed CLI options for a single scan run.

    This is the output of parse_args() and the primary input to the scanner
    orchestrator. Every field maps directly to a CLI argument. Fields with
    None or empty-list defaults indicate "not specified by the user," which
    lets downstream code apply its own defaults.

    Attributes:
        targets         : Raw target strings from -t (hostnames, IPs, CIDRs).
                          Empty list if -t was not used.
        target_file     : Path to a target list file from -iL, or None.
        nmap_files      : Paths to Nmap XML files from -x.
                          Empty list if -x was not used.
        ports           : Port numbers from -p. Empty list means "use the
                          default port (443)" — the target parser handles this.
        only_modules    : Module names from --only (e.g. ["ssl", "headers"]).
                          None means "no inclusion filter — run all modules."
        exclude_modules : Module names from --no (e.g. ["tech", "content"]).
                          None means "no exclusion filter — run all modules."
        timeout         : HTTP request timeout in seconds (default 10).
        threads         : Maximum concurrent scan threads (default 10).
        proxy           : Proxy URL string (e.g. "socks5://127.0.0.1:9050"),
                          or None for direct connections.
        output_file     : Path for text output from -o, or None for stdout only.
        json_file       : Path for JSON output from --json, or None.
        verbose         : True if -v was specified (show extra diagnostic output).
        quiet           : True if -q was specified (suppress everything except findings).
    """

    targets: list[str] = field(default_factory=list)
    target_file: str | None = None
    nmap_files: list[str] = field(default_factory=list)
    ports: list[int] = field(default_factory=list)
    only_modules: list[str] | None = None
    exclude_modules: list[str] | None = None
    timeout: int = 10
    threads: int = 10
    proxy: str | None = None
    output_file: str | None = None
    json_file: str | None = None
    verbose: bool = False
    quiet: bool = False


# ---------------------------------------------------------------------------
# Argument parser construction
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    """
    Build and return the argparse.ArgumentParser for webinspector.

    The parser is organized into logical argument groups that mirror the
    sections in --help output. Each argument has a detailed help string
    explaining what it does and showing example usage.

    Returns:
        A fully configured ArgumentParser ready to parse sys.argv.
    """
    # Create the top-level parser with a description shown in --help output.
    # RawDescriptionHelpFormatter preserves our hand-formatted description
    # text instead of reflowing it.
    parser = argparse.ArgumentParser(
        prog="webinspector",
        description=(
            "webinspector - Web security inspection tool for penetration testing.\n"
            "\n"
            "Combines SSL/TLS scanning, HTTP header analysis, cookie checks,\n"
            "CORS detection, certificate validation, and technology fingerprinting\n"
            "into a single CLI tool.\n"
            "\n"
            "At least one target source (-t, -iL, or -x) is required."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        # Append examples to the end of --help output.
        epilog=(
            "examples:\n"
            "  webinspector -t example.com\n"
            "  webinspector -t 10.0.0.1 -p 443 8443\n"
            "  webinspector -x scan.xml --no dns --timeout 30\n"
            "  webinspector -iL targets.txt --only ssl,headers -o report.txt\n"
        ),
    )

    # --version: Print the version string and exit.
    # Uses the VERSION constant from webinspector/__init__.py.
    parser.add_argument(
        "--version",
        action="version",
        version=f"webinspector {VERSION}",
    )

    # -----------------------------------------------------------------------
    # Target input group
    # -----------------------------------------------------------------------
    # These arguments define WHERE to scan. At least one must be provided.
    # They can be combined — targets from all sources are merged.

    target_group = parser.add_argument_group(
        "target input",
        "Specify targets to scan. At least one of -t, -iL, or -x is required.",
    )

    # -t: Direct target specification.
    # Accepts one or more target strings: hostnames, IPs, CIDRs, or URLs.
    # nargs="*" means zero or more arguments — allows -t to be absent entirely
    # while still accepting multiple values when present.
    # Example: -t example.com 10.0.0.1 192.168.1.0/24
    target_group.add_argument(
        "-t",
        dest="targets",
        nargs="*",
        default=[],
        metavar="TARGET",
        help=(
            "Target hostname(s), IP(s), or CIDR range(s) to scan. "
            "Example: -t example.com 10.0.0.1"
        ),
    )

    # -iL: Target list file.
    # Reads one target per line from a text file. Comment lines (#) and
    # blank lines are skipped by the target parser downstream.
    # Example: -iL targets.txt
    target_group.add_argument(
        "-iL",
        dest="target_file",
        default=None,
        metavar="FILE",
        help="File containing targets, one per line. Example: -iL targets.txt",
    )

    # -x: Nmap XML output file(s).
    # Parses Nmap's XML output to extract hosts with HTTPS/SSL services.
    # nargs="*" supports multiple XML files.
    # Example: -x scan1.xml scan2.xml
    target_group.add_argument(
        "-x",
        dest="nmap_files",
        nargs="*",
        default=[],
        metavar="FILE",
        help=(
            "Nmap XML output file(s). HTTPS/SSL services are extracted "
            "automatically. Example: -x scan.xml"
        ),
    )

    # -----------------------------------------------------------------------
    # Port specification
    # -----------------------------------------------------------------------
    # -p overrides the default port (443) for targets that don't already
    # have a port specified. Targets given as host:port or full URLs
    # ignore this flag — their explicit port takes precedence.

    port_group = parser.add_argument_group(
        "port specification",
        "Override the default port (443) for bare hostname/IP targets.",
    )

    # -p: Port list.
    # nargs="*" allows multiple port numbers separated by spaces.
    # type=int ensures each value is converted to an integer.
    # Example: -p 443 8443 8080
    port_group.add_argument(
        "-p",
        dest="ports",
        nargs="*",
        type=int,
        default=[],
        metavar="PORT",
        help="Port(s) to scan. Example: -p 443 8443 8080",
    )

    # -----------------------------------------------------------------------
    # Module selection group
    # -----------------------------------------------------------------------
    # --only and --no are mutually exclusive — you either whitelist or
    # blacklist modules, not both. If neither is specified, all modules run.

    module_group = parser.add_argument_group(
        "module selection",
        (
            "Choose which scanner modules to run. Available modules: "
            + ", ".join(ALL_MODULE_NAMES)
            + ". --only and --no are mutually exclusive."
        ),
    )

    # argparse mutually exclusive group enforces that --only and --no
    # cannot both be specified on the same command line.
    module_exclusive = module_group.add_mutually_exclusive_group()

    # --only: Run ONLY the named modules. Accepts a comma-separated string.
    # Example: --only ssl,headers
    module_exclusive.add_argument(
        "--only",
        dest="only_modules",
        default=None,
        metavar="MODULES",
        help=(
            "Run ONLY these modules (comma-separated). "
            "Example: --only ssl,headers"
        ),
    )

    # --no: Exclude specific modules. Accepts a comma-separated string.
    # Example: --no tech,content
    module_exclusive.add_argument(
        "--no",
        dest="exclude_modules",
        default=None,
        metavar="MODULES",
        help=(
            "Exclude these modules (comma-separated). "
            "Example: --no tech,content"
        ),
    )

    # -----------------------------------------------------------------------
    # Scan tuning group
    # -----------------------------------------------------------------------
    # These arguments control how the scan behaves: timeouts, threading,
    # and proxy settings.

    tuning_group = parser.add_argument_group(
        "scan tuning",
        "Control timeouts, concurrency, and network settings.",
    )

    # --timeout: HTTP request timeout in seconds.
    # Default is 10 seconds — fast enough for most web servers on internal
    # networks, but long enough for slow external hosts. Can be increased
    # for targets behind VPNs or high-latency links.
    # Example: --timeout 30
    tuning_group.add_argument(
        "--timeout",
        dest="timeout",
        type=int,
        default=10,
        metavar="SECONDS",
        help="HTTP request timeout in seconds (default: 10). Example: --timeout 30",
    )

    # --threads: Maximum concurrent scan threads.
    # Default is 10 threads — balances speed vs. not overwhelming the target
    # or triggering rate limiters. For large scans, increase; for stealth, decrease.
    # Example: --threads 20
    tuning_group.add_argument(
        "--threads",
        dest="threads",
        type=int,
        default=10,
        metavar="N",
        help="Max concurrent scan threads (default: 10). Example: --threads 20",
    )

    # --proxy: Route all traffic through a proxy.
    # Supports HTTP, HTTPS, and SOCKS5 proxy URLs. Useful for routing
    # through Burp Suite or over a SOCKS tunnel during engagements.
    # Example: --proxy socks5://127.0.0.1:9050
    tuning_group.add_argument(
        "--proxy",
        dest="proxy",
        default=None,
        metavar="URL",
        help=(
            "Proxy URL for all HTTP requests. "
            "Example: --proxy socks5://127.0.0.1:9050"
        ),
    )

    # -----------------------------------------------------------------------
    # Output options group
    # -----------------------------------------------------------------------
    # These arguments control where scan results are written. By default,
    # output goes to stdout only. -o and --json are independent — you can
    # use both to get text AND JSON output from the same scan.

    output_group = parser.add_argument_group(
        "output options",
        "Control where results are saved. Both -o and --json can be used together.",
    )

    # -o: Write text output to a file (in addition to stdout).
    # Example: -o results.txt
    output_group.add_argument(
        "-o",
        dest="output_file",
        default=None,
        metavar="FILE",
        help="Write text output to FILE. Example: -o results.txt",
    )

    # --json: Write JSON output to a file.
    # Produces structured JSON suitable for post-processing, import into
    # reporting tools, or integration with other scripts.
    # Example: --json results.json
    output_group.add_argument(
        "--json",
        dest="json_file",
        default=None,
        metavar="FILE",
        help="Write JSON output to FILE. Example: --json results.json",
    )

    # -----------------------------------------------------------------------
    # Verbosity group
    # -----------------------------------------------------------------------
    # -v and -q are mutually exclusive. Default behavior (neither flag)
    # shows a progress banner, module names as they run, and all findings.

    verbosity_group = parser.add_argument_group(
        "verbosity",
        "Control output verbosity. -v and -q are mutually exclusive.",
    )

    # argparse mutually exclusive group enforces that -v and -q cannot
    # both be specified on the same command line.
    verbosity_exclusive = verbosity_group.add_mutually_exclusive_group()

    # -v: Verbose mode — show extra diagnostic output like DNS resolution
    # details, HTTP response codes, and per-module timing.
    verbosity_exclusive.add_argument(
        "-v", "--verbose",
        dest="verbose",
        action="store_true",
        default=False,
        help="Verbose output — show extra diagnostic information.",
    )

    # -q: Quiet mode — suppress everything except findings. No banner,
    # no progress indicators, no module names. Useful for scripting.
    verbosity_exclusive.add_argument(
        "-q", "--quiet",
        dest="quiet",
        action="store_true",
        default=False,
        help="Quiet output — suppress everything except findings.",
    )

    return parser


# ---------------------------------------------------------------------------
# Argument parsing and validation
# ---------------------------------------------------------------------------

def _split_module_list(raw: str) -> list[str]:
    """
    Split a comma-separated module name string into a list of names.

    Handles whitespace around commas gracefully. Used to process the
    --only and --no argument values.

    Args:
        raw: Comma-separated string like "ssl,headers" or "ssl, headers".

    Returns:
        List of stripped, non-empty module name strings.

    Examples:
        >>> _split_module_list("ssl,headers")
        ['ssl', 'headers']
        >>> _split_module_list("ssl, headers, cookies")
        ['ssl', 'headers', 'cookies']
    """
    # Split on commas, strip whitespace from each part, and filter out
    # any empty strings that result from trailing commas or double commas.
    return [name.strip() for name in raw.split(",") if name.strip()]


def parse_args(argv: list[str] | None = None) -> ScanConfig:
    """
    Parse command-line arguments and return a validated ScanConfig.

    This is the main public entry point for the CLI module. It builds the
    argparse parser, parses the provided argument list (or sys.argv if None),
    validates that at least one target source was provided, and converts
    --only/--no from comma-separated strings to lists.

    Args:
        argv: List of argument strings to parse. If None, argparse reads
              from sys.argv automatically. Passing an explicit list is
              used by tests to avoid touching sys.argv.

    Returns:
        A fully populated ScanConfig dataclass.

    Raises:
        SystemExit: If argument parsing fails (invalid args, --help, --version)
                    or if no target source is provided.

    Examples:
        # In production (reads sys.argv):
        config = parse_args()

        # In tests (explicit argument list):
        config = parse_args(["-t", "example.com", "-v"])
    """
    parser = _build_parser()

    # Parse the arguments. If argv is None, argparse reads sys.argv[1:].
    args = parser.parse_args(argv)

    # -----------------------------------------------------------------------
    # Validation: At least one target source required
    # -----------------------------------------------------------------------
    # The user must provide at least one of: -t (targets), -iL (target file),
    # or -x (nmap files). Without any targets, there's nothing to scan.
    has_targets = args.targets and len(args.targets) > 0
    has_target_file = args.target_file is not None
    has_nmap_files = args.nmap_files and len(args.nmap_files) > 0

    if not has_targets and not has_target_file and not has_nmap_files:
        parser.error(
            "No targets specified. Use -t, -iL, or -x to provide targets.\n"
            "  Example: webinspector -t example.com\n"
            "  Example: webinspector -iL targets.txt\n"
            "  Example: webinspector -x nmap_scan.xml\n"
            "  Run 'webinspector --help' for full usage information."
        )

    # -----------------------------------------------------------------------
    # Post-processing: Convert comma-separated module names to lists
    # -----------------------------------------------------------------------
    # argparse gives us raw strings for --only and --no. We split them into
    # lists here so the rest of the codebase works with list[str] consistently.

    only_modules = None
    if args.only_modules is not None:
        only_modules = _split_module_list(args.only_modules)

    exclude_modules = None
    if args.exclude_modules is not None:
        exclude_modules = _split_module_list(args.exclude_modules)

    # -----------------------------------------------------------------------
    # Build and return the ScanConfig
    # -----------------------------------------------------------------------
    # Convert the argparse Namespace into our typed dataclass. This gives
    # downstream code IDE autocompletion and type safety instead of stringly-
    # typed namespace attributes.
    return ScanConfig(
        targets=args.targets if args.targets else [],
        target_file=args.target_file,
        nmap_files=args.nmap_files if args.nmap_files else [],
        ports=args.ports if args.ports else [],
        only_modules=only_modules,
        exclude_modules=exclude_modules,
        timeout=args.timeout,
        threads=args.threads,
        proxy=args.proxy,
        output_file=args.output_file,
        json_file=args.json_file,
        verbose=args.verbose,
        quiet=args.quiet,
    )
