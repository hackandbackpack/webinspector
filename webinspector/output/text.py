"""
webinspector.output.text - Plain text file report renderer.

This module writes scan findings and summary statistics to a plain text file.
It produces the same logical layout as the Rich console renderer (console.py)
but without any ANSI escape codes or Rich markup.  The output is suitable for
inclusion in penetration testing reports, email attachments, and any other
context where colored terminal output would render as garbage characters.

The text renderer replicates the console output structure:
    1. Header    - Version, modules run
    2. Findings  - Grouped by (module, finding_type) with severity labels
    3. Summary   - Total targets, successes, failures, duration, severity breakdown

Special handling (matching console.py):
    - disclosure module: grouped under "INFORMATION DISCLOSURE HEADERS" banner
    - tech module: one line per target with comma-separated technologies

Why a separate module instead of stripping ANSI from console output?
    Relying on ANSI stripping is fragile — different Rich versions, terminal
    capabilities, and encoding settings can produce unexpected sequences.
    Building the plain-text output directly is more reliable and easier to test.

Key public API:
    write_text_report(filepath, findings, summary, modules_run) -> None

Author: Red Siege Information Security
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

# Import the version string from the top-level package so the report header
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
    pass  # No additional type-only imports needed for now.


# ---------------------------------------------------------------------------
# Module-level logger
# ---------------------------------------------------------------------------

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _severity_label_plain(severity: Severity) -> str:
    """
    Return a plain-text severity label suitable for file output.

    Unlike the console renderer which uses Rich markup for colour, this
    returns a bare string like ``"High"`` or ``"Medium"``.

    Args:
        severity: The Severity enum value to format.

    Returns:
        The severity's human-readable value string.
    """
    return severity.value


def _build_text_lines(
    findings: list[Finding],
    summary: ScanSummary,
    modules_run: list[str],
) -> list[str]:
    """
    Build the complete list of plain-text lines for the report.

    This is the core logic shared between write_text_report() and any future
    callers that need the text content as a string (e.g., for email body).

    The output follows the same structure as the console renderer:
        1. Header with version and module list
        2. Grouped findings with severity labels
        3. Scan summary with target counts and severity breakdown

    Args:
        findings:    List of all Finding objects from the scan.
        summary:     The ScanSummary dataclass with aggregate metrics.
        modules_run: List of module name strings that were executed.

    Returns:
        A list of plain-text lines (without trailing newlines).
    """
    lines: list[str] = []

    # -----------------------------------------------------------------
    # Header section
    # -----------------------------------------------------------------
    lines.append(f"[*] WebInspector v{VERSION}")
    lines.append(f"[*] Modules: {', '.join(modules_run)}")
    lines.append("")

    # -----------------------------------------------------------------
    # Findings section
    # -----------------------------------------------------------------
    if not findings:
        lines.append("No findings to display.")
        lines.append("")
    else:
        lines.append("=" * 80)
        lines.append("RESULTS")
        lines.append("=" * 80)

        # Group findings by (module, finding_type).
        grouped = group_findings(findings)

        # Separate findings into categories for special rendering,
        # matching the console renderer's logic.
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

        # --- Standard findings ---
        # Each group gets a title line, a separator, target lines, and a count.
        for (module, finding_type), group in standard_groups.items():
            title = group[0].title
            severity = group[0].severity
            severity_str = _severity_label_plain(severity)

            lines.append("")
            lines.append(f"{title}:  ({severity_str})")
            lines.append("-" * 30)

            # Sort targets by IP for consistent ordering.
            sorted_group = sort_findings_by_ip(group)

            for finding in sorted_group:
                target_str = finding.target.hostport
                detail = finding.detail
                # Pad the target string for aligned columns (20 chars wide).
                lines.append(f"  {target_str:<20s} {detail}")

            lines.append(f"  Count: {len(group)}")

        # --- Disclosure findings ---
        # Grouped under an "INFORMATION DISCLOSURE HEADERS" banner.
        if disclosure_groups:
            lines.append("")
            lines.append("INFORMATION DISCLOSURE HEADERS:")
            lines.append("=" * 40)

            for (module, finding_type), group in disclosure_groups.items():
                severity = group[0].severity
                severity_str = _severity_label_plain(severity)

                lines.append("")
                lines.append(f"[{finding_type}]  ({severity_str})")

                sorted_group = sort_findings_by_ip(group)
                for finding in sorted_group:
                    lines.append(f"  {finding.detail}")
                    lines.append(f"    {finding.target.url}")

        # --- Tech fingerprint findings ---
        # One line per target with comma-separated detected technologies.
        if tech_groups:
            lines.append("")
            lines.append("TECHNOLOGY FINGERPRINTING:")
            lines.append("=" * 40)

            for (module, finding_type), group in tech_groups.items():
                sorted_group = sort_findings_by_ip(group)
                for finding in sorted_group:
                    target_str = finding.target.hostport
                    lines.append(f"  {target_str:<20s} {finding.detail}")

    # -----------------------------------------------------------------
    # Summary section
    # -----------------------------------------------------------------
    lines.append("")
    lines.append("=" * 80)
    lines.append("SCAN SUMMARY")
    lines.append("=" * 80)

    lines.append(f"Total targets scanned: {summary.total_targets}")
    lines.append(f"Successful checks:     {summary.successful}")

    # Build the failed connections line with optional detail.
    failed_line = f"Failed connections:    {summary.failed}"
    if summary.failed_targets:
        failed_details = []
        for target, error in summary.failed_targets:
            failed_details.append(f"{target.hostport} - {error}")
        failed_line += f" ({'; '.join(failed_details)})"
    lines.append(failed_line)

    lines.append(f"Scan duration:         {summary.duration_seconds}s")

    # --- Severity breakdown ---
    # Calculate severity counts from the actual findings list for accuracy.
    lines.append("")
    lines.append("Findings by Severity:")
    for sev in Severity:
        count = sum(1 for f in findings if f.severity == sev)
        lines.append(f"  {sev.value:<16s} {count}")

    return lines


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def write_text_report(
    filepath: str,
    findings: list[Finding],
    summary: ScanSummary,
    modules_run: list[str],
) -> None:
    """
    Write the complete scan report as a plain text file.

    The output follows the same logical layout as the Rich console output
    but uses no ANSI escape codes or colour markup.  This makes the file
    suitable for inclusion in pentest reports, email attachments, or
    archival in ticketing systems.

    Args:
        filepath:    Absolute or relative path for the output text file.
                     The file will be created if it does not exist, or
                     overwritten if it does.
        findings:    List of all Finding objects from the scan.
        summary:     The ScanSummary dataclass with aggregate metrics.
        modules_run: List of module name strings that were executed.

    Raises:
        OSError: If the file cannot be written (permissions, disk full, etc.).
    """
    lines = _build_text_lines(findings, summary, modules_run)

    # Write the lines to the specified file with UTF-8 encoding.
    # UTF-8 is the default for modern systems and handles any Unicode
    # characters that might appear in hostnames, headers, or error messages.
    with open(filepath, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
        # Ensure the file ends with a trailing newline (POSIX convention).
        fh.write("\n")

    logger.info("Text report written to %s", filepath)
