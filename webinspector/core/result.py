"""
webinspector.core.result - Security findings and scan result data structures.

This module defines the data structures that every scanner module *produces*
and every output renderer *consumes*:

    Severity     - Enum representing the severity level of a finding
    Finding      - A single security finding tied to a target
    ScanSummary  - Aggregate metrics for a completed scan run

It also provides helper functions for grouping and sorting findings, which
are used by the report generators to present results in a logical order.

Why this module matters:
    All scanner modules (SSL, headers, cookies, CORS, tech fingerprint) return
    lists of Finding objects.  The output layer groups and sorts those findings
    before rendering them to the console, CSV, or JSON.  Having a clear,
    shared data model here prevents ad-hoc dicts from leaking through the
    codebase and ensures every component speaks the same language.

Key public API:
    Severity              - Enum with CRITICAL / HIGH / MEDIUM / LOW / INFORMATIONAL
    Finding               - Dataclass for a single security finding
    ScanSummary           - Dataclass for aggregate scan metrics
    group_findings()      - Group findings by (module, finding_type)
    sort_findings_by_ip() - Sort findings by IP address numerically

Author: Red Siege Information Security
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING

# Avoid circular imports at runtime — we only need Target for type annotations.
# TYPE_CHECKING is True only when a static analyser (mypy, pyright) reads this
# file, so the import is invisible at runtime.
if TYPE_CHECKING:
    from webinspector.core.target import Target


# ---------------------------------------------------------------------------
# Severity enum
# ---------------------------------------------------------------------------

class Severity(Enum):
    """
    Severity level for a security finding.

    The values are human-readable strings that appear directly in reports.
    The ``weight`` property provides a numeric score used for sorting so that
    Critical findings always appear before Informational ones.

    Levels follow a standard risk-based model:
        CRITICAL      - Immediate exploitation risk, requires urgent remediation
        HIGH          - Significant vulnerability, high likelihood of exploitation
        MEDIUM        - Moderate risk, should be addressed in normal patch cycles
        LOW           - Minor issue with limited impact
        INFORMATIONAL - Not a vulnerability; useful context for the analyst
    """

    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFORMATIONAL = "Informational"

    @property
    def weight(self) -> int:
        """
        Numeric weight for sorting.  Higher = more severe.

        This allows us to sort findings using standard comparison operators
        without hard-coding the ordering logic everywhere::

            sorted(findings, key=lambda f: f.severity.weight, reverse=True)
        """
        # Map each human-readable value to a numeric weight.
        weights = {
            "Critical": 5,
            "High": 4,
            "Medium": 3,
            "Low": 2,
            "Informational": 1,
        }
        return weights[self.value]


# ---------------------------------------------------------------------------
# Finding dataclass
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    """
    A single security finding produced by a scanner module.

    Each Finding ties together:
    - **What** was found (module, finding_type, title, detail)
    - **How bad** it is (severity)
    - **Where** it was found (target)
    - **References** to standards / CWEs for the report

    Attributes:
        module       : Name of the scanner module that produced this finding
                       (e.g. "ssl", "headers", "cookies", "cors", "tech").
        finding_type : Subcategory within the module that identifies the specific
                       check (e.g. "deprecated_protocols", "missing_csp").
                       Together with ``module``, this forms the unique "kind" of
                       finding used for grouping.
        severity     : Severity level (Critical / High / Medium / Low / Informational).
        target       : The Target object this finding applies to.
        title        : Short, human-readable title for report headings
                       (e.g. "Deprecated TLS Protocols").
        detail       : Specific detail string with the evidence
                       (e.g. "TLSv1.0, TLSv1.1 supported").
        references   : Optional list of reference identifiers such as CWE numbers
                       or OWASP Top-10 entries (e.g. ["CWE-326", "OWASP-A02"]).
    """

    module: str              # Module that produced this ('ssl', 'headers', etc.)
    finding_type: str        # Category within module ('deprecated_protocols', 'missing_csp')
    severity: Severity       # Severity level
    target: "Target"         # Which target this applies to
    title: str               # Human-readable title ('Deprecated Protocols')
    detail: str              # Specific detail ('TLSv1.0, TLSv1.1')
    references: list[str] = field(default_factory=list)  # CWE/OWASP refs


# ---------------------------------------------------------------------------
# ScanSummary dataclass
# ---------------------------------------------------------------------------

@dataclass
class ScanSummary:
    """
    Aggregate metrics for a completed scan run.

    This is produced by the scanner orchestrator after all modules have
    finished and is consumed by the output renderers to print a summary
    banner at the end of the report.

    Attributes:
        total_targets        : Total number of targets that were queued for scanning.
        successful           : Number of targets that completed scanning without errors.
        failed               : Number of targets that errored out (connection refused,
                               timeout, DNS failure, etc.).
        duration_seconds     : Wall-clock time the scan took, in seconds.
        findings_by_severity : Mapping of severity name -> count, e.g.
                               {"Critical": 2, "High": 5, "Medium": 10}.
        failed_targets       : List of (Target, error_message) tuples for targets
                               that failed, so the report can list them at the end.
    """

    total_targets: int
    successful: int
    failed: int
    duration_seconds: float
    findings_by_severity: dict[str, int]
    failed_targets: list[tuple["Target", str]]  # (target, error_message)


# ---------------------------------------------------------------------------
# Aggregation / sorting helpers
# ---------------------------------------------------------------------------

def group_findings(
    findings: list[Finding],
) -> dict[tuple[str, str], list[Finding]]:
    """
    Group a flat list of findings by ``(module, finding_type)``.

    This is the primary aggregation step used by the output renderers.
    For example, if 50 targets all have the same "Deprecated TLS Protocols"
    finding, they should be grouped into a single section in the report
    rather than listed 50 separate times.

    Args:
        findings: Flat list of Finding objects from all modules and targets.

    Returns:
        A dict mapping ``(module, finding_type)`` tuples to lists of
        findings that share that key.  The lists preserve insertion order.

    Example::

        grouped = group_findings(all_findings)
        for (module, ftype), group in grouped.items():
            print(f"[{module}] {ftype}: {len(group)} affected targets")
    """
    # defaultdict(list) automatically creates an empty list for any new key,
    # so we don't need to check ``if key not in groups`` before appending.
    groups: dict[tuple[str, str], list[Finding]] = defaultdict(list)

    for finding in findings:
        # The grouping key is the combination of module name and finding type.
        # This ensures that findings from different modules with the same
        # finding_type name (unlikely but possible) are kept separate.
        key = (finding.module, finding.finding_type)
        groups[key].append(finding)

    # Convert from defaultdict back to a plain dict so callers don't
    # accidentally trigger auto-creation of empty groups.
    return dict(groups)


def _ip_sort_key(finding: Finding) -> tuple:
    """
    Produce a sort key for a Finding based on its target's IP address.

    IP addresses are sorted numerically by octet so that ``10.0.0.2`` comes
    before ``10.0.0.10`` (string sorting would get this wrong because
    ``"10" > "2"`` lexicographically).

    Non-IP targets (hostnames without a resolved IP) are given a sort key
    that pushes them after all numeric IPs, then sorts them alphabetically.

    Returns:
        A tuple suitable for use as a sort key.
        - For IP targets: ``(0, (octet1, octet2, octet3, octet4))``
        - For hostname targets: ``(1, hostname)``
        The leading 0/1 ensures IPs sort before hostnames.
    """
    ip = finding.target.ip

    if ip is not None:
        # Attempt to parse the IP string into a tuple of integers.
        # This handles standard dotted-quad IPv4 like "10.0.0.2".
        try:
            octets = tuple(int(octet) for octet in ip.split("."))
            # Prefix with 0 so all IP-based findings sort before hostnames.
            return (0, octets)
        except (ValueError, AttributeError):
            # If parsing fails (shouldn't happen for valid IPs), fall through
            # to the hostname sorting path below.
            pass

    # No IP or unparseable IP — sort by hostname alphabetically, after all IPs.
    # The prefix 1 pushes these after the IP group (prefix 0).
    return (1, (finding.target.host,))


def sort_findings_by_ip(findings: list[Finding]) -> list[Finding]:
    """
    Sort findings by target IP address in numeric order.

    This is used within a finding group (after ``group_findings``) to
    present affected targets in a logical order — numerically by IP when
    available, alphabetically by hostname otherwise.

    Numeric sorting matters because pentest reports are often reviewed
    alongside network diagrams where ``10.0.0.2`` and ``10.0.0.10`` are
    adjacent hosts.  Lexicographic sorting would scatter them.

    Args:
        findings: List of findings (typically sharing the same
                  ``(module, finding_type)`` grouping key).

    Returns:
        A new list sorted by IP address (numerically), with non-IP
        targets sorted alphabetically at the end.
    """
    return sorted(findings, key=_ip_sort_key)
