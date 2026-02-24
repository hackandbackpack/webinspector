"""
tests/test_result.py - Unit tests for the Finding/Result classes and aggregation helpers.

Tests the core security-finding data structures that every scanner module
produces and every output renderer consumes.  Covers:
    - Severity enum weight ordering
    - Finding dataclass creation with all fields
    - group_findings() grouping by (module, finding_type)
    - sort_findings_by_ip() numerical IP sorting
    - ScanSummary dataclass

Author: Red Siege Information Security
"""

import pytest

# Import the Target dataclass (needed to create Finding instances).
from webinspector.core.target import Target

# Import the classes and functions under test from the core result module.
from webinspector.core.result import (
    Severity,
    Finding,
    ScanSummary,
    group_findings,
    sort_findings_by_ip,
)


# ---------------------------------------------------------------------------
# Severity enum tests
# ---------------------------------------------------------------------------

class TestSeverity:
    """Test the Severity enum values and their weight ordering."""

    def test_weight_ordering(self):
        """
        CRITICAL should have the highest weight (5) and INFORMATIONAL the
        lowest (1).  This ordering is used to sort findings by severity in
        reports so the most important issues appear first.
        """
        assert Severity.CRITICAL.weight == 5
        assert Severity.HIGH.weight == 4
        assert Severity.MEDIUM.weight == 3
        assert Severity.LOW.weight == 2
        assert Severity.INFORMATIONAL.weight == 1

    def test_critical_greater_than_high(self):
        """Severity weights should support numeric comparison for sorting."""
        assert Severity.CRITICAL.weight > Severity.HIGH.weight

    def test_high_greater_than_medium(self):
        """HIGH weight should be greater than MEDIUM weight."""
        assert Severity.HIGH.weight > Severity.MEDIUM.weight

    def test_severity_values(self):
        """Enum values should be human-readable title-case strings."""
        assert Severity.CRITICAL.value == "Critical"
        assert Severity.HIGH.value == "High"
        assert Severity.MEDIUM.value == "Medium"
        assert Severity.LOW.value == "Low"
        assert Severity.INFORMATIONAL.value == "Informational"


# ---------------------------------------------------------------------------
# Finding dataclass tests
# ---------------------------------------------------------------------------

class TestFinding:
    """Test the Finding dataclass creation and field defaults."""

    def test_finding_creation_all_fields(self):
        """
        A Finding should be creatable with all fields, and each field
        should be accessible as an attribute.
        """
        target = Target(host="example.com", port=443, scheme="https")
        finding = Finding(
            module="ssl",
            finding_type="deprecated_protocols",
            severity=Severity.HIGH,
            target=target,
            title="Deprecated Protocols",
            detail="TLSv1.0, TLSv1.1",
            references=["CWE-326", "OWASP-A02"],
        )

        assert finding.module == "ssl"
        assert finding.finding_type == "deprecated_protocols"
        assert finding.severity == Severity.HIGH
        assert finding.target is target
        assert finding.title == "Deprecated Protocols"
        assert finding.detail == "TLSv1.0, TLSv1.1"
        assert finding.references == ["CWE-326", "OWASP-A02"]

    def test_finding_default_references(self):
        """
        The references field should default to an empty list when not provided.
        This avoids accidental sharing of a mutable default across instances.
        """
        target = Target(host="example.com", port=443, scheme="https")
        finding = Finding(
            module="headers",
            finding_type="missing_csp",
            severity=Severity.MEDIUM,
            target=target,
            title="Missing Content-Security-Policy",
            detail="No CSP header found",
        )

        assert finding.references == []

    def test_finding_references_not_shared(self):
        """
        Two Findings created without explicit references should have
        independent empty lists (not the same list object).
        """
        target = Target(host="example.com", port=443, scheme="https")
        f1 = Finding(
            module="a", finding_type="b", severity=Severity.LOW,
            target=target, title="T1", detail="D1",
        )
        f2 = Finding(
            module="a", finding_type="b", severity=Severity.LOW,
            target=target, title="T2", detail="D2",
        )
        # They should be equal in value but NOT the same object.
        assert f1.references is not f2.references


# ---------------------------------------------------------------------------
# group_findings tests
# ---------------------------------------------------------------------------

class TestGroupFindings:
    """Test the group_findings() aggregation function."""

    def test_groups_by_module_and_finding_type(self):
        """
        Findings from the same (module, finding_type) should be grouped together,
        even if they apply to different targets.  Findings with different
        (module, finding_type) pairs should be in separate groups.
        """
        t1 = Target(host="10.0.0.1", port=443, scheme="https", ip="10.0.0.1")
        t2 = Target(host="10.0.0.2", port=443, scheme="https", ip="10.0.0.2")
        t3 = Target(host="10.0.0.3", port=443, scheme="https", ip="10.0.0.3")

        findings = [
            # Two findings of the same type on different targets
            Finding(
                module="ssl", finding_type="deprecated_protocols",
                severity=Severity.HIGH, target=t1,
                title="Deprecated Protocols", detail="TLSv1.0",
            ),
            Finding(
                module="ssl", finding_type="deprecated_protocols",
                severity=Severity.HIGH, target=t2,
                title="Deprecated Protocols", detail="TLSv1.0",
            ),
            # One finding of a different type
            Finding(
                module="headers", finding_type="missing_csp",
                severity=Severity.MEDIUM, target=t3,
                title="Missing CSP", detail="No CSP header",
            ),
        ]

        grouped = group_findings(findings)

        # Should produce two groups
        assert len(grouped) == 2
        assert ("ssl", "deprecated_protocols") in grouped
        assert ("headers", "missing_csp") in grouped

        # The SSL group should have two findings
        assert len(grouped[("ssl", "deprecated_protocols")]) == 2

        # The headers group should have one finding
        assert len(grouped[("headers", "missing_csp")]) == 1

    def test_empty_findings(self):
        """group_findings with an empty list should return an empty dict."""
        assert group_findings([]) == {}


# ---------------------------------------------------------------------------
# sort_findings_by_ip tests
# ---------------------------------------------------------------------------

class TestSortFindingsByIp:
    """Test the sort_findings_by_ip() numerical sorting function."""

    def test_numerical_ip_sort(self):
        """
        10.0.0.2 should sort before 10.0.0.10 when sorting numerically
        by IP octets.  Naive string sorting would put "10.0.0.10" before
        "10.0.0.2" because '1' < '2' lexicographically.
        """
        t1 = Target(host="10.0.0.10", port=443, scheme="https", ip="10.0.0.10")
        t2 = Target(host="10.0.0.2", port=443, scheme="https", ip="10.0.0.2")
        t3 = Target(host="10.0.0.1", port=443, scheme="https", ip="10.0.0.1")

        findings = [
            Finding(
                module="ssl", finding_type="weak_cipher",
                severity=Severity.MEDIUM, target=t1,
                title="Weak Cipher", detail="RC4",
            ),
            Finding(
                module="ssl", finding_type="weak_cipher",
                severity=Severity.MEDIUM, target=t2,
                title="Weak Cipher", detail="RC4",
            ),
            Finding(
                module="ssl", finding_type="weak_cipher",
                severity=Severity.MEDIUM, target=t3,
                title="Weak Cipher", detail="RC4",
            ),
        ]

        sorted_findings = sort_findings_by_ip(findings)

        # Verify correct numerical order: .1, .2, .10
        assert sorted_findings[0].target.ip == "10.0.0.1"
        assert sorted_findings[1].target.ip == "10.0.0.2"
        assert sorted_findings[2].target.ip == "10.0.0.10"

    def test_handles_none_ip_gracefully(self):
        """
        When a finding's target has ip=None (e.g. unresolved hostname),
        sort_findings_by_ip should not crash.  Non-IP targets should sort
        after IP targets (or at least not cause an exception).
        """
        t_ip = Target(host="10.0.0.1", port=443, scheme="https", ip="10.0.0.1")
        t_no_ip = Target(host="example.com", port=443, scheme="https")

        findings = [
            Finding(
                module="ssl", finding_type="weak_cipher",
                severity=Severity.MEDIUM, target=t_no_ip,
                title="Weak Cipher", detail="RC4",
            ),
            Finding(
                module="ssl", finding_type="weak_cipher",
                severity=Severity.MEDIUM, target=t_ip,
                title="Weak Cipher", detail="RC4",
            ),
        ]

        # Should not raise an exception
        sorted_findings = sort_findings_by_ip(findings)
        assert len(sorted_findings) == 2

        # The IP-based target should sort first (IPs before hostnames).
        assert sorted_findings[0].target.ip == "10.0.0.1"
        assert sorted_findings[1].target.ip is None

    def test_hostname_targets_sort_alphabetically(self):
        """
        Targets without numeric IPs (plain hostnames) should be sorted
        alphabetically among themselves, after all IP-based targets.
        """
        t_alpha = Target(host="alpha.com", port=443, scheme="https")
        t_beta = Target(host="beta.com", port=443, scheme="https")

        findings = [
            Finding(
                module="headers", finding_type="missing_csp",
                severity=Severity.MEDIUM, target=t_beta,
                title="Missing CSP", detail="No CSP",
            ),
            Finding(
                module="headers", finding_type="missing_csp",
                severity=Severity.MEDIUM, target=t_alpha,
                title="Missing CSP", detail="No CSP",
            ),
        ]

        sorted_findings = sort_findings_by_ip(findings)
        assert sorted_findings[0].target.host == "alpha.com"
        assert sorted_findings[1].target.host == "beta.com"


# ---------------------------------------------------------------------------
# ScanSummary dataclass tests
# ---------------------------------------------------------------------------

class TestScanSummary:
    """Test the ScanSummary dataclass."""

    def test_scan_summary_creation(self):
        """
        ScanSummary should store all the aggregate metrics from a completed scan.
        """
        target = Target(host="example.com", port=443, scheme="https")
        summary = ScanSummary(
            total_targets=10,
            successful=8,
            failed=2,
            duration_seconds=45.7,
            findings_by_severity={"Critical": 1, "High": 3, "Medium": 5},
            failed_targets=[(target, "Connection refused")],
        )

        assert summary.total_targets == 10
        assert summary.successful == 8
        assert summary.failed == 2
        assert summary.duration_seconds == 45.7
        assert summary.findings_by_severity["Critical"] == 1
        assert len(summary.failed_targets) == 1
        assert summary.failed_targets[0][1] == "Connection refused"
