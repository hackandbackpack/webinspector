"""
webinspector.output.json_output - Structured JSON report renderer.

This module writes scan findings and summary statistics to a JSON file
matching the schema defined in the webinspector design document.  The JSON
output is intended for machine consumption: integration with SIEM platforms,
automated report generation pipelines, and data analysis scripts.

JSON schema (top-level keys):
    scan_info      - Metadata about the scan run (version, timestamp, modules, duration)
    findings       - Array of grouped findings, each with affected targets
    failed_targets - Array of targets that could not be scanned
    summary        - Aggregate statistics (total findings, severity breakdown)

The ``findings`` array groups findings by (module, finding_type) — the same
grouping used by the console and text renderers.  Within each entry, an array
of ``targets`` lists every affected host with its target-specific detail string.

Example output::

    {
      "scan_info": {
        "version": "1.0.0",
        "timestamp": "2026-02-24T10:30:00Z",
        "targets_scanned": 5,
        "modules_run": ["ssl", "headers"],
        "duration_seconds": 47.2
      },
      "findings": [
        {
          "module": "ssl",
          "finding_type": "deprecated_protocols",
          "severity": "Medium",
          "targets": [
            {"host": "10.0.0.1", "port": 443, "ip": "10.0.0.1", "detail": "TLSv1.0, TLSv1.1"}
          ],
          "count": 1
        }
      ],
      "failed_targets": [],
      "summary": {
        "total_findings": 7,
        "by_severity": {"High": 1, "Medium": 4, "Low": 1, "Informational": 1}
      }
    }

Key public API:
    write_json_report(filepath, findings, summary, modules_run, version, targets_scanned) -> None

Author: Red Siege Information Security
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

# Import the core data structures that we consume.
from webinspector.core.result import (
    Finding,
    ScanSummary,
    Severity,
    group_findings,
)


# ---------------------------------------------------------------------------
# Module-level logger
# ---------------------------------------------------------------------------

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _build_scan_info(
    version: str,
    targets_scanned: int,
    modules_run: list[str],
    duration_seconds: float,
) -> dict[str, Any]:
    """
    Build the ``scan_info`` section of the JSON report.

    This section contains metadata about the scan run: when it happened,
    what version of the tool was used, how many targets were scanned,
    which modules were run, and how long the scan took.

    Args:
        version:          The webinspector version string (e.g., "1.0.0").
        targets_scanned:  Total number of targets that were queued for scanning.
        modules_run:      List of module name strings that were executed.
        duration_seconds: Wall-clock time the scan took, in seconds.

    Returns:
        A dict matching the ``scan_info`` schema from the design doc.
    """
    return {
        "version": version,
        # ISO 8601 timestamp in UTC — the standard format for machine-readable
        # timestamps.  The "Z" suffix indicates UTC timezone.
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "targets_scanned": targets_scanned,
        "modules_run": modules_run,
        "duration_seconds": duration_seconds,
    }


def _build_findings_array(findings: list[Finding]) -> list[dict[str, Any]]:
    """
    Build the ``findings`` array of the JSON report.

    Groups findings by (module, finding_type) using the same helper as the
    console renderer, then serializes each group into a dict with the affected
    targets listed under a ``targets`` key.

    Each entry in the output array has:
        - module       : str  (e.g., "ssl")
        - finding_type : str  (e.g., "deprecated_protocols")
        - severity     : str  (e.g., "Medium")
        - targets      : list of dicts, each with host, port, ip, detail
        - count        : int  (number of affected targets in this group)

    Args:
        findings: Flat list of all Finding objects from the scan.

    Returns:
        A list of dicts, one per unique (module, finding_type) group.
    """
    if not findings:
        return []

    # Group findings using the shared helper from core.result.
    grouped = group_findings(findings)

    result: list[dict[str, Any]] = []

    for (module, finding_type), group in grouped.items():
        # All findings in a group share the same severity and title (they
        # represent the same type of issue).  Use the first finding's values.
        severity = group[0].severity
        title = group[0].title

        # Collect the union of all references across findings in this group.
        # Different targets may contribute additional reference identifiers.
        all_references: set[str] = set()
        for finding in group:
            for ref in finding.references:
                all_references.add(ref)

        # Build the per-target entries within this group.
        targets_list: list[dict[str, Any]] = []
        for finding in group:
            target_entry: dict[str, Any] = {
                "host": finding.target.host,
                "port": finding.target.port,
                "scheme": finding.target.scheme,
                "ip": finding.target.ip,
                "detail": finding.detail,
            }
            targets_list.append(target_entry)

        entry: dict[str, Any] = {
            "module": module,
            "finding_type": finding_type,
            "title": title,
            "severity": severity.value,
            "references": sorted(all_references),
            "targets": targets_list,
            "count": len(targets_list),
        }
        result.append(entry)

    return result


def _build_failed_targets(summary: ScanSummary) -> list[dict[str, Any]]:
    """
    Build the ``failed_targets`` array of the JSON report.

    Each entry contains the host, port, and error message for a target that
    could not be scanned successfully (connection refused, timeout, DNS
    failure, etc.).

    Args:
        summary: The ScanSummary containing the failed_targets list.

    Returns:
        A list of dicts, one per failed target.
    """
    result: list[dict[str, Any]] = []

    for target, error in summary.failed_targets:
        result.append({
            "host": target.host,
            "port": target.port,
            "error": error,
        })

    return result


def _build_summary(findings: list[Finding]) -> dict[str, Any]:
    """
    Build the ``summary`` section of the JSON report.

    This section provides aggregate statistics that consumers can use for
    dashboards, trend analysis, and automated gating decisions (e.g.,
    "fail the build if there are any High-severity findings").

    The severity counts are calculated from the actual findings list rather
    than from the ScanSummary's ``findings_by_severity`` dict.  This ensures
    the JSON output is always consistent with the findings array, even if
    the summary was built with slightly different counting logic.

    Args:
        findings: Flat list of all Finding objects from the scan.

    Returns:
        A dict with ``total_findings`` and ``by_severity`` keys.
    """
    # Count findings by severity level.
    by_severity: dict[str, int] = {}
    for finding in findings:
        sev_name = finding.severity.value
        by_severity[sev_name] = by_severity.get(sev_name, 0) + 1

    return {
        "total_findings": len(findings),
        "by_severity": by_severity,
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def write_json_report(
    filepath: str,
    findings: list[Finding],
    summary: ScanSummary,
    modules_run: list[str],
    version: str,
    targets_scanned: int,
) -> None:
    """
    Write the complete scan report as a structured JSON file.

    The output matches the JSON schema defined in the webinspector design doc,
    with four top-level sections: scan_info, findings, failed_targets, summary.

    Findings are grouped by (module, finding_type) so that consumers can
    iterate over unique issue types and see all affected targets under each.

    Args:
        filepath:         Absolute or relative path for the output JSON file.
                          The file will be created if it does not exist, or
                          overwritten if it does.
        findings:         List of all Finding objects from the scan.
        summary:          The ScanSummary dataclass with aggregate metrics.
        modules_run:      List of module name strings that were executed.
        version:          The webinspector version string (e.g., "1.0.0").
        targets_scanned:  Total number of targets that were queued for scanning.

    Raises:
        OSError: If the file cannot be written (permissions, disk full, etc.).
    """
    # Build the four top-level sections.
    report: dict[str, Any] = {
        "scan_info": _build_scan_info(
            version=version,
            targets_scanned=targets_scanned,
            modules_run=modules_run,
            duration_seconds=summary.duration_seconds,
        ),
        "findings": _build_findings_array(findings),
        "failed_targets": _build_failed_targets(summary),
        "summary": _build_summary(findings),
    }

    # Write the JSON with pretty-printing (indent=2) for human readability.
    # While JSON output is primarily for machines, analysts frequently inspect
    # JSON reports manually during engagements.  The extra whitespace is a
    # negligible cost compared to the improved readability.
    with open(filepath, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
        # Trailing newline for POSIX compatibility.
        fh.write("\n")

    logger.info("JSON report written to %s", filepath)
