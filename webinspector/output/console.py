"""
webinspector.output.console - Rich-based terminal output renderer.

This module renders scan findings and summary statistics to the terminal
using the Rich library for colored, formatted output.  It is the primary
output mode when the user runs webinspector from the command line without
redirecting output to a file.

The console renderer produces output matching the design doc format:
    1. Banner    - Version, target count, module list
    2. Findings  - Grouped by (module, finding_type) with colored severity
    3. Summary   - Total targets, successes, failures, duration, severity breakdown

Special handling is provided for certain module types:
    - disclosure module: findings are grouped under categorized headers
      (e.g., "INFORMATION DISCLOSURE HEADERS")
    - tech module: findings are shown as single lines per target with
      comma-separated detected technologies

Severity colors follow a standard risk visualization convention:
    CRITICAL      -> bold red (demands immediate attention)
    HIGH          -> red
    MEDIUM        -> yellow
    LOW           -> blue (low risk but worth noting)
    INFORMATIONAL -> dim/grey (context, not a vulnerability)

Key public API:
    render_banner(targets, modules, quiet=False)   -> str
    render_findings(findings, summary, verbose=False, quiet=False) -> str
    render_summary(summary, findings, quiet=False) -> str

Author: Red Siege Information Security
"""

from __future__ import annotations

from io import StringIO
from typing import TYPE_CHECKING

# Rich is used for colored terminal output.  We guard the import so the
# module can still be imported (and return plain text) if Rich is missing.
try:
    from rich.console import Console
    from rich.text import Text
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

# Import the version string from the top-level package so the banner
# always reflects the installed version.
from webinspector import VERSION

# Import the core data structures that we consume.
from webinspector.core.result import (
    Finding,
    ScanSummary,
    Severity,
    group_findings,
    sort_findings_by_ip,
)

if TYPE_CHECKING:
    from webinspector.core.target import Target


# ---------------------------------------------------------------------------
# Severity color mapping
# ---------------------------------------------------------------------------
# Maps each Severity level to a Rich style string.  These colors follow
# standard security tooling conventions (red = bad, blue = informational).

SEVERITY_COLORS: dict[Severity, str] = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
    Severity.INFORMATIONAL: "dim",
}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _get_console(file: StringIO | None = None) -> "Console":
    """
    Create a Rich Console instance for rendering.

    When *file* is provided, output is captured to the StringIO buffer
    instead of being printed to the terminal.  This is used by the
    render_*() functions to return strings rather than printing directly.

    Args:
        file: Optional StringIO buffer to capture output into.

    Returns:
        A Rich Console configured for string capture (or terminal output).
    """
    if RICH_AVAILABLE:
        # highlight=False prevents Rich from auto-colorizing numbers, URLs,
        # and other patterns in our output strings.  Without this, Rich
        # injects ANSI codes into strings like "47.2" or "Count: 2", which
        # breaks substring matching in tests and produces inconsistent output.
        return Console(file=file, force_terminal=True, width=120, highlight=False)
    # Fallback if Rich is not available — return a basic Console-like object.
    # This path is unlikely in production (Rich is a dependency) but keeps
    # the module importable for testing without Rich.
    return Console(file=file, width=120, highlight=False)


def _severity_label(severity: Severity) -> str:
    """
    Format a severity level with Rich markup for colored display.

    Args:
        severity: The Severity enum value to format.

    Returns:
        A Rich markup string like "[red]High[/red]".
    """
    color = SEVERITY_COLORS.get(severity, "white")
    return f"[{color}]{severity.value}[/{color}]"


# ---------------------------------------------------------------------------
# Public API: render_banner
# ---------------------------------------------------------------------------

def render_banner(
    targets: list["Target"],
    modules: list[str],
    quiet: bool = False,
) -> str:
    """
    Render the tool banner with version, target count, and module list.

    The banner is the first thing printed when webinspector starts scanning.
    It gives the analyst an at-a-glance summary of what's about to happen:
    how many targets, which modules, and which version of the tool.

    Output format:
        [*] WebInspector v1.0.0
        [*] Targets: 5 URLs
        [*] Modules: ssl, certs, headers, cookies, cors, tech, disclosure

    Args:
        targets: List of Target objects that will be scanned.
        modules: List of module name strings that will be run.
        quiet:   If True, suppress all output and return an empty string.

    Returns:
        A string containing the rendered banner.  The string includes Rich
        markup for colored terminal display when printed via Rich.
    """
    # In quiet mode, produce no output.
    if quiet:
        return ""

    # Capture Rich output to a string buffer so we can return it.
    buf = StringIO()
    console = _get_console(file=buf)

    # Print the version banner.
    console.print(f"[bold cyan][*] WebInspector v{VERSION}[/bold cyan]")

    # Print the target count.
    console.print(f"[bold cyan][*] Targets: {len(targets)} URLs[/bold cyan]")

    # Print the module list.
    module_str = ", ".join(modules)
    console.print(f"[bold cyan][*] Modules: {module_str}[/bold cyan]")

    return buf.getvalue()


# ---------------------------------------------------------------------------
# Public API: render_findings
# ---------------------------------------------------------------------------

def render_findings(
    findings: list[Finding],
    summary: ScanSummary,
    verbose: bool = False,
    quiet: bool = False,
) -> str:
    """
    Render all findings to a string for console display.

    Groups findings by (module, finding_type) using the group_findings()
    helper from core.result.  Within each group, targets are sorted
    numerically by IP address using sort_findings_by_ip().

    Special handling is applied for certain module types:
    - "disclosure" module: grouped under an "INFORMATION DISCLOSURE HEADERS"
      banner with category sub-headings.
    - "tech" module: shown under a "TECHNOLOGY FINGERPRINTING" banner with
      one line per target showing comma-separated technologies.

    All other finding types use the standard format:
        Title - Finding Type:
        ------------------------------
        target:port    detail string
        Count: N

    Args:
        findings: List of all Finding objects from the scan.
        summary:  The ScanSummary (used for context but not directly rendered here).
        verbose:  If True, show additional detail (e.g., references).
        quiet:    If True, suppress all output and return an empty string.

    Returns:
        A string containing the rendered findings with Rich markup.
    """
    # In quiet mode, produce no output.
    if quiet:
        return ""

    # Capture Rich output to a string buffer.
    buf = StringIO()
    console = _get_console(file=buf)

    # Handle the case where there are no findings.
    if not findings:
        console.print("\n[dim]No findings to display.[/dim]")
        return buf.getvalue()

    # Print the RESULTS header.
    console.print()
    console.print("=" * 80)
    console.print("[bold]RESULTS[/bold]")
    console.print("=" * 80)

    # Group findings by (module, finding_type).
    grouped = group_findings(findings)

    # Separate findings into categories for special rendering:
    # - disclosure findings get their own section
    # - tech findings get their own section
    # - everything else uses the standard format
    standard_groups: dict[tuple[str, str], list[Finding]] = {}
    disclosure_groups: dict[tuple[str, str], list[Finding]] = {}
    tech_groups: dict[tuple[str, str], list[Finding]] = {}

    for key, group in grouped.items():
        module_name = key[0]
        if module_name == "disclosure":
            disclosure_groups[key] = group
        elif module_name == "tech":
            tech_groups[key] = group
        else:
            standard_groups[key] = group

    # --- Render standard findings ---
    # Each group gets a section header, then a list of affected targets
    # with their detail strings, then a count line.
    for (module, finding_type), group in standard_groups.items():
        # Use the title from the first finding in the group (they all share
        # the same title since they share the same finding_type).
        title = group[0].title
        severity = group[0].severity

        # Print the section header with severity color.
        severity_str = _severity_label(severity)
        console.print()
        console.print(f"{title}:  ({severity_str})")
        console.print("-" * 30)

        # Sort targets by IP for consistent, logical ordering.
        sorted_group = sort_findings_by_ip(group)

        # Print each affected target with its detail string.
        for finding in sorted_group:
            target_str = finding.target.hostport
            detail = finding.detail
            # Pad the target string for aligned columns.
            console.print(f"  {target_str:<20s} {detail}")

            # In verbose mode, show references (CWE, OWASP, etc.).
            if verbose and finding.references:
                refs = ", ".join(finding.references)
                console.print(f"  [dim]  References: {refs}[/dim]")

        # Print the count line.
        console.print(f"  Count: {len(group)}")

    # --- Render disclosure findings ---
    # Disclosure findings are grouped under a special section header.
    if disclosure_groups:
        console.print()
        console.print("[bold]INFORMATION DISCLOSURE HEADERS:[/bold]")
        console.print("=" * 40)

        for (module, finding_type), group in disclosure_groups.items():
            title = group[0].title
            severity = group[0].severity
            severity_str = _severity_label(severity)

            console.print()
            console.print(f"[{finding_type}]  ({severity_str})")

            # Sort and print each target with its detail.
            sorted_group = sort_findings_by_ip(group)
            for finding in sorted_group:
                # For disclosure, the detail is the value (e.g., "nginx/1.18.0").
                console.print(f"  {finding.detail}")
                console.print(f"    {finding.target.url}")

    # --- Render tech fingerprint findings ---
    # Tech findings show one line per target with comma-separated technologies.
    if tech_groups:
        console.print()
        console.print("[bold]TECHNOLOGY FINGERPRINTING:[/bold]")
        console.print("=" * 40)

        for (module, finding_type), group in tech_groups.items():
            sorted_group = sort_findings_by_ip(group)
            for finding in sorted_group:
                target_str = finding.target.hostport
                console.print(f"  {target_str:<20s} {finding.detail}")

    return buf.getvalue()


# ---------------------------------------------------------------------------
# Public API: render_summary
# ---------------------------------------------------------------------------

def render_summary(
    summary: ScanSummary,
    findings: list[Finding],
    quiet: bool = False,
) -> str:
    """
    Render the scan summary section.

    Displays aggregate statistics about the completed scan:
    - Total targets scanned
    - Successful vs. failed target counts
    - Failed target details (host, error message)
    - Scan duration
    - Severity breakdown of findings

    Output format:
        ================================================================================
        SCAN SUMMARY
        ================================================================================
        Total targets scanned: 5
        Successful checks:     4
        Failed connections:    1 (10.0.0.3:443 - Connection refused)
        Scan duration:         47.2s

        Findings by Severity:
          Critical:        0
          High:            1
          Medium:          4
          Low:             1
          Informational:   1

    Args:
        summary:  The ScanSummary dataclass with aggregate metrics.
        findings: The full list of findings (used to compute severity counts
                  independently, rather than relying solely on summary.findings_by_severity).
        quiet:    If True, suppress all output and return an empty string.

    Returns:
        A string containing the rendered summary with Rich markup.
    """
    # In quiet mode, produce no output.
    if quiet:
        return ""

    # Capture Rich output to a string buffer.
    buf = StringIO()
    console = _get_console(file=buf)

    # Print the SCAN SUMMARY header.
    console.print()
    console.print("=" * 80)
    console.print("[bold]SCAN SUMMARY[/bold]")
    console.print("=" * 80)

    # Print the target statistics.
    console.print(f"Total targets scanned: {summary.total_targets}")
    console.print(f"Successful checks:     {summary.successful}")
    console.print(f"Failed connections:    {summary.failed}", end="")

    # If there are failed targets, list them inline.
    if summary.failed_targets:
        # Show the first few failed targets inline for quick reference.
        failed_details = []
        for target, error in summary.failed_targets:
            failed_details.append(f"{target.hostport} - {error}")
        console.print(f" ({'; '.join(failed_details)})")
    else:
        console.print()

    # Print the scan duration.
    console.print(f"Scan duration:         {summary.duration_seconds}s")

    # --- Severity breakdown ---
    # Calculate severity counts from the actual findings list for accuracy.
    severity_counts: dict[str, int] = {}
    for sev in Severity:
        count = sum(1 for f in findings if f.severity == sev)
        severity_counts[sev.value] = count

    console.print()
    console.print("[bold]Findings by Severity:[/bold]")
    for sev in Severity:
        count = severity_counts.get(sev.value, 0)
        color = SEVERITY_COLORS.get(sev, "white")
        # Right-align the severity label and left-align the count for readability.
        console.print(f"  [{color}]{sev.value:<16s}[/{color}] {count}")

    return buf.getvalue()
