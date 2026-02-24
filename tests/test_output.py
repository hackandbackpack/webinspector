"""
tests/test_output.py - Unit tests for the output formatting renderers.

Tests the three output renderers that transform Finding and ScanSummary objects
into human-readable or machine-parseable output:

    - console.py  : Rich-based terminal output with colored severity indicators
    - text.py     : Plain text file output (no ANSI escape codes)
    - json_output.py : Structured JSON matching the design doc schema

Covers:
    - Console formatter groups findings by (module, finding_type)
    - Text output contains no ANSI escape codes
    - JSON output is valid JSON with the expected schema
    - Summary statistics are calculated correctly
    - Empty findings produce clean output without errors

Author: Red Siege Information Security
"""

import json
import os
import re
import tempfile

import pytest

# Import the Target dataclass (needed to create Finding instances for test fixtures).
from webinspector.core.target import Target

# Import the core data structures that the renderers consume.
from webinspector.core.result import (
    Severity,
    Finding,
    ScanSummary,
    group_findings,
)

# Import the renderers under test.
from webinspector.output.console import (
    render_banner,
    render_findings,
    render_summary,
)
from webinspector.output.text import write_text_report
from webinspector.output.json_output import write_json_report


# ---------------------------------------------------------------------------
# Shared test fixtures
# ---------------------------------------------------------------------------
# These fixtures create realistic Finding and ScanSummary objects that are
# reused across multiple test classes.  Using fixtures avoids duplicating
# the same setup code in every test method.

@pytest.fixture
def sample_targets():
    """
    Create a set of sample Target objects representing a realistic scan.

    Returns three targets: two IP-based and one hostname-based, with varying
    ports and schemes to exercise the renderers' formatting logic.
    """
    t1 = Target(host="10.0.0.1", port=443, scheme="https", ip="10.0.0.1")
    t2 = Target(host="10.0.0.5", port=8443, scheme="https", ip="10.0.0.5")
    t3 = Target(host="10.0.0.3", port=443, scheme="https", ip="10.0.0.3")
    return [t1, t2, t3]


@pytest.fixture
def sample_findings(sample_targets):
    """
    Create a list of sample Finding objects spanning multiple modules and severity levels.

    These findings represent realistic output from SSL, headers, disclosure,
    and tech modules, which the renderers need to group and format differently.
    """
    t1, t2, t3 = sample_targets

    return [
        # --- SSL findings (two targets with deprecated protocols) ---
        Finding(
            module="ssl",
            finding_type="deprecated_protocols",
            severity=Severity.MEDIUM,
            target=t1,
            title="Deprecated Protocols",
            detail="TLSv1.0, TLSv1.1",
            references=["CWE-326"],
        ),
        Finding(
            module="ssl",
            finding_type="deprecated_protocols",
            severity=Severity.MEDIUM,
            target=t2,
            title="Deprecated Protocols",
            detail="SSLv3, TLSv1.0",
            references=["CWE-326"],
        ),
        # --- SSL finding (weak cipher on one target) ---
        Finding(
            module="ssl",
            finding_type="weak_ciphers",
            severity=Severity.HIGH,
            target=t1,
            title="Weak Ciphers",
            detail="TLS_RSA_WITH_3DES_EDE_CBC_SHA",
        ),
        # --- Header finding (missing CSP on multiple targets) ---
        Finding(
            module="headers",
            finding_type="missing_csp",
            severity=Severity.MEDIUM,
            target=t1,
            title="Missing Content-Security-Policy",
            detail="No CSP header found",
        ),
        Finding(
            module="headers",
            finding_type="missing_csp",
            severity=Severity.MEDIUM,
            target=t2,
            title="Missing Content-Security-Policy",
            detail="No CSP header found",
        ),
        # --- Disclosure finding (server header leaking version) ---
        Finding(
            module="disclosure",
            finding_type="server_header",
            severity=Severity.LOW,
            target=t1,
            title="Server Header",
            detail="nginx/1.18.0",
        ),
        # --- Tech fingerprint finding ---
        Finding(
            module="tech",
            finding_type="technology",
            severity=Severity.INFORMATIONAL,
            target=t1,
            title="Technology Detected",
            detail="nginx, PHP, WordPress 6.4",
        ),
    ]


@pytest.fixture
def sample_summary(sample_targets):
    """
    Create a ScanSummary representing a completed scan with some failures.

    Uses realistic values: 3 targets, one failed, 47.2 second duration.
    """
    t3 = sample_targets[2]
    return ScanSummary(
        total_targets=3,
        successful=2,
        failed=1,
        duration_seconds=47.2,
        findings_by_severity={
            "High": 1,
            "Medium": 4,
            "Low": 1,
            "Informational": 1,
        },
        failed_targets=[(t3, "Connection refused")],
    )


@pytest.fixture
def empty_summary():
    """
    Create a ScanSummary with zero findings and zero failures.

    Used to test that the renderers handle the "clean scan" case gracefully
    without crashing or producing misleading output.
    """
    return ScanSummary(
        total_targets=2,
        successful=2,
        failed=0,
        duration_seconds=5.1,
        findings_by_severity={},
        failed_targets=[],
    )


# ---------------------------------------------------------------------------
# Console renderer tests
# ---------------------------------------------------------------------------

class TestConsoleRenderer:
    """Tests for the Rich-based console renderer (console.py)."""

    def test_render_banner_returns_string(self, sample_targets):
        """
        render_banner() should return a non-empty string containing the version,
        target count, and module list.
        """
        modules_list = ["ssl", "headers", "cookies"]
        output = render_banner(sample_targets, modules_list)

        # Should be a non-empty string.
        assert isinstance(output, str)
        assert len(output) > 0

    def test_render_banner_contains_version(self, sample_targets):
        """
        The banner should contain the webinspector version string so the analyst
        knows which version produced the output.
        """
        from webinspector import VERSION
        output = render_banner(sample_targets, ["ssl", "headers"])
        assert VERSION in output

    def test_render_banner_contains_target_count(self, sample_targets):
        """
        The banner should show how many targets are being scanned.
        """
        output = render_banner(sample_targets, ["ssl"])
        # The banner should contain the number 3 (we have 3 sample targets).
        assert "3" in output

    def test_render_banner_contains_module_names(self, sample_targets):
        """
        The banner should list the module names that are running so the analyst
        knows which checks are being performed.
        """
        modules_list = ["ssl", "headers", "cookies"]
        output = render_banner(sample_targets, modules_list)
        for mod_name in modules_list:
            assert mod_name in output

    def test_render_banner_quiet_mode_returns_empty(self, sample_targets):
        """
        In quiet mode, the banner should return an empty string — nothing
        should be printed to the console when -q is specified.
        """
        output = render_banner(sample_targets, ["ssl"], quiet=True)
        assert output == ""

    def test_render_findings_groups_by_type(self, sample_findings, sample_summary):
        """
        render_findings() should group findings by (module, finding_type).
        The output should contain section headers for each unique finding type.
        """
        output = render_findings(sample_findings, sample_summary)

        # Should contain section headers for each finding type.
        assert "Deprecated Protocols" in output
        assert "Weak Ciphers" in output
        assert "Missing Content-Security-Policy" in output

    def test_render_findings_contains_target_info(self, sample_findings, sample_summary):
        """
        render_findings() should include target IP addresses or hostports
        within each finding group so the analyst can see which hosts are affected.
        """
        output = render_findings(sample_findings, sample_summary)

        # Both SSL targets should appear in the output.
        assert "10.0.0.1" in output
        assert "10.0.0.5" in output

    def test_render_findings_contains_detail(self, sample_findings, sample_summary):
        """
        render_findings() should include the detail string for each finding
        so the analyst knows the specific evidence (protocols, ciphers, etc.).
        """
        output = render_findings(sample_findings, sample_summary)

        # SSL detail strings should appear.
        assert "TLSv1.0" in output
        assert "TLS_RSA_WITH_3DES_EDE_CBC_SHA" in output

    def test_render_findings_contains_count(self, sample_findings, sample_summary):
        """
        Each finding group should show the count of affected targets so
        the analyst can quickly gauge the scope of an issue.
        """
        output = render_findings(sample_findings, sample_summary)

        # "Deprecated Protocols" affects 2 targets.
        assert "Count: 2" in output

    def test_render_findings_quiet_returns_empty(self, sample_findings, sample_summary):
        """
        In quiet mode, render_findings() should return an empty string.
        """
        output = render_findings(sample_findings, sample_summary, quiet=True)
        assert output == ""

    def test_render_findings_empty_list(self, empty_summary):
        """
        render_findings() with an empty findings list should not crash and
        should produce a clean message or empty output.
        """
        output = render_findings([], empty_summary)
        # Should not raise an exception.
        assert isinstance(output, str)

    def test_render_summary_returns_string(self, sample_summary, sample_findings):
        """
        render_summary() should return a non-empty string containing
        the scan summary statistics.
        """
        output = render_summary(sample_summary, sample_findings)
        assert isinstance(output, str)
        assert len(output) > 0

    def test_render_summary_contains_totals(self, sample_summary, sample_findings):
        """
        The summary should contain total targets, successful count, and
        failed count.
        """
        output = render_summary(sample_summary, sample_findings)

        # Total targets scanned.
        assert "3" in output
        # Successful count.
        assert "2" in output
        # Duration.
        assert "47.2" in output

    def test_render_summary_contains_failed_targets(self, sample_summary, sample_findings):
        """
        When there are failed targets, the summary should list them
        along with the error message.
        """
        output = render_summary(sample_summary, sample_findings)

        assert "10.0.0.3" in output
        assert "Connection refused" in output

    def test_render_summary_quiet_returns_empty(self, sample_summary, sample_findings):
        """
        In quiet mode, render_summary() should return an empty string.
        """
        output = render_summary(sample_summary, sample_findings, quiet=True)
        assert output == ""

    def test_render_summary_no_failures(self, empty_summary):
        """
        When no targets failed, the summary should still render cleanly
        without crashing or showing confusing failure counts.
        """
        output = render_summary(empty_summary, [])
        assert isinstance(output, str)
        # Should show 0 failed or not mention failures.
        assert "0" in output or "failed" not in output.lower()


# ---------------------------------------------------------------------------
# Text renderer tests
# ---------------------------------------------------------------------------

class TestTextRenderer:
    """Tests for the plain-text file renderer (text.py)."""

    def test_write_text_report_creates_file(self, sample_findings, sample_summary):
        """
        write_text_report() should create the specified file on disk.
        """
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False
        ) as f:
            filepath = f.name

        try:
            write_text_report(
                filepath, sample_findings, sample_summary, modules_run=["ssl", "headers"]
            )
            assert os.path.exists(filepath)
        finally:
            os.unlink(filepath)

    def test_text_output_contains_no_ansi(self, sample_findings, sample_summary):
        """
        The text file output must contain ZERO ANSI escape codes.

        ANSI codes like \\x1b[31m (red text) render beautifully in terminals
        but produce garbage in text files.  The text renderer must strip all
        such sequences so the output is clean when included in pentest reports.
        """
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False
        ) as f:
            filepath = f.name

        try:
            write_text_report(
                filepath, sample_findings, sample_summary, modules_run=["ssl", "headers"]
            )
            with open(filepath, "r", encoding="utf-8") as fh:
                content = fh.read()

            # ANSI escape codes start with ESC (0x1b) followed by '['.
            # This regex matches any ANSI CSI sequence.
            ansi_pattern = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")
            matches = ansi_pattern.findall(content)
            assert matches == [], f"Found ANSI codes in text output: {matches}"
        finally:
            os.unlink(filepath)

    def test_text_output_contains_findings(self, sample_findings, sample_summary):
        """
        The text output should contain the same information as the console
        output: finding titles, target IPs, and detail strings.
        """
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False
        ) as f:
            filepath = f.name

        try:
            write_text_report(
                filepath, sample_findings, sample_summary, modules_run=["ssl", "headers"]
            )
            with open(filepath, "r", encoding="utf-8") as fh:
                content = fh.read()

            # Check for key content from the findings.
            assert "Deprecated Protocols" in content
            assert "10.0.0.1" in content
            assert "TLSv1.0" in content
        finally:
            os.unlink(filepath)

    def test_text_output_contains_summary(self, sample_findings, sample_summary):
        """
        The text output should include the scan summary section with
        target counts and duration.
        """
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False
        ) as f:
            filepath = f.name

        try:
            write_text_report(
                filepath, sample_findings, sample_summary, modules_run=["ssl", "headers"]
            )
            with open(filepath, "r", encoding="utf-8") as fh:
                content = fh.read()

            # Summary section should contain totals.
            assert "47.2" in content
            assert "Connection refused" in content
        finally:
            os.unlink(filepath)

    def test_text_output_empty_findings(self, empty_summary):
        """
        write_text_report() with empty findings should produce a valid file
        without crashing.
        """
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False
        ) as f:
            filepath = f.name

        try:
            write_text_report(
                filepath, [], empty_summary, modules_run=["ssl"]
            )
            assert os.path.exists(filepath)
            with open(filepath, "r", encoding="utf-8") as fh:
                content = fh.read()
            # File should have some content (at least the summary).
            assert len(content) > 0
        finally:
            os.unlink(filepath)


# ---------------------------------------------------------------------------
# JSON renderer tests
# ---------------------------------------------------------------------------

class TestJsonRenderer:
    """Tests for the structured JSON renderer (json_output.py)."""

    def test_write_json_creates_file(self, sample_findings, sample_summary):
        """
        write_json_report() should create the specified file on disk.
        """
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            filepath = f.name

        try:
            write_json_report(
                filepath,
                sample_findings,
                sample_summary,
                modules_run=["ssl", "headers"],
                version="1.0.0",
                targets_scanned=3,
            )
            assert os.path.exists(filepath)
        finally:
            os.unlink(filepath)

    def test_json_output_is_valid_json(self, sample_findings, sample_summary):
        """
        The output file must contain valid JSON that json.loads() can parse.
        """
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            filepath = f.name

        try:
            write_json_report(
                filepath,
                sample_findings,
                sample_summary,
                modules_run=["ssl", "headers"],
                version="1.0.0",
                targets_scanned=3,
            )
            with open(filepath, "r", encoding="utf-8") as fh:
                data = json.load(fh)

            # Should be a dict (JSON object at the top level).
            assert isinstance(data, dict)
        finally:
            os.unlink(filepath)

    def test_json_has_scan_info_section(self, sample_findings, sample_summary):
        """
        The JSON output should contain a 'scan_info' section with version,
        timestamp, targets_scanned, modules_run, and duration_seconds.
        """
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            filepath = f.name

        try:
            write_json_report(
                filepath,
                sample_findings,
                sample_summary,
                modules_run=["ssl", "headers"],
                version="1.0.0",
                targets_scanned=3,
            )
            with open(filepath, "r", encoding="utf-8") as fh:
                data = json.load(fh)

            # Verify scan_info section exists and has required fields.
            assert "scan_info" in data
            scan_info = data["scan_info"]
            assert scan_info["version"] == "1.0.0"
            assert scan_info["targets_scanned"] == 3
            assert scan_info["modules_run"] == ["ssl", "headers"]
            assert scan_info["duration_seconds"] == 47.2
            assert "timestamp" in scan_info
        finally:
            os.unlink(filepath)

    def test_json_has_findings_section(self, sample_findings, sample_summary):
        """
        The JSON output should contain a 'findings' array where each entry
        has module, finding_type, severity, targets, and count.
        """
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            filepath = f.name

        try:
            write_json_report(
                filepath,
                sample_findings,
                sample_summary,
                modules_run=["ssl", "headers"],
                version="1.0.0",
                targets_scanned=3,
            )
            with open(filepath, "r", encoding="utf-8") as fh:
                data = json.load(fh)

            # The findings section should be a list.
            assert "findings" in data
            assert isinstance(data["findings"], list)

            # There should be grouped findings (not one per individual Finding).
            # We have 5 unique (module, finding_type) groups.
            assert len(data["findings"]) > 0

            # Each finding entry should have the required schema fields.
            for entry in data["findings"]:
                assert "module" in entry
                assert "finding_type" in entry
                assert "title" in entry
                assert "severity" in entry
                assert "references" in entry
                assert "targets" in entry
                assert "count" in entry
                assert isinstance(entry["title"], str)
                assert isinstance(entry["references"], list)
                assert isinstance(entry["targets"], list)
                assert entry["count"] == len(entry["targets"])
        finally:
            os.unlink(filepath)

    def test_json_findings_grouped_correctly(self, sample_findings, sample_summary):
        """
        Findings with the same (module, finding_type) should be grouped into
        a single entry with multiple targets, not listed as separate entries.
        """
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            filepath = f.name

        try:
            write_json_report(
                filepath,
                sample_findings,
                sample_summary,
                modules_run=["ssl", "headers"],
                version="1.0.0",
                targets_scanned=3,
            )
            with open(filepath, "r", encoding="utf-8") as fh:
                data = json.load(fh)

            # Find the "deprecated_protocols" entry.
            deprecated = None
            for entry in data["findings"]:
                if entry["finding_type"] == "deprecated_protocols":
                    deprecated = entry
                    break

            assert deprecated is not None, "deprecated_protocols finding not found"
            # Should have 2 targets grouped under one entry.
            assert deprecated["count"] == 2
            assert len(deprecated["targets"]) == 2
        finally:
            os.unlink(filepath)

    def test_json_findings_have_title_and_references(self, sample_findings, sample_summary):
        """
        Each finding group should include a 'title' (human-readable name) and
        'references' (union of CWE/OWASP identifiers from all findings in the group).
        """
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            filepath = f.name

        try:
            write_json_report(
                filepath,
                sample_findings,
                sample_summary,
                modules_run=["ssl", "headers"],
                version="1.0.0",
                targets_scanned=3,
            )
            with open(filepath, "r", encoding="utf-8") as fh:
                data = json.load(fh)

            # Find the "deprecated_protocols" entry which has references=["CWE-326"].
            deprecated = None
            for entry in data["findings"]:
                if entry["finding_type"] == "deprecated_protocols":
                    deprecated = entry
                    break

            assert deprecated is not None, "deprecated_protocols finding not found"
            assert deprecated["title"] == "Deprecated Protocols"
            assert deprecated["references"] == ["CWE-326"]

            # Find the "weak_ciphers" entry which has no references.
            weak = None
            for entry in data["findings"]:
                if entry["finding_type"] == "weak_ciphers":
                    weak = entry
                    break

            assert weak is not None, "weak_ciphers finding not found"
            assert weak["title"] == "Weak Ciphers"
            assert weak["references"] == []
        finally:
            os.unlink(filepath)

    def test_json_finding_target_has_required_fields(self, sample_findings, sample_summary):
        """
        Each target within a finding group should have host, port, scheme, ip, and detail.
        """
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            filepath = f.name

        try:
            write_json_report(
                filepath,
                sample_findings,
                sample_summary,
                modules_run=["ssl", "headers"],
                version="1.0.0",
                targets_scanned=3,
            )
            with open(filepath, "r", encoding="utf-8") as fh:
                data = json.load(fh)

            # Check the first target in the first finding.
            first_finding = data["findings"][0]
            first_target = first_finding["targets"][0]

            assert "host" in first_target
            assert "port" in first_target
            assert "scheme" in first_target
            assert "detail" in first_target
            assert first_target["scheme"] in ("http", "https")
        finally:
            os.unlink(filepath)

    def test_json_has_failed_targets_section(self, sample_findings, sample_summary):
        """
        The JSON output should contain a 'failed_targets' array listing
        targets that failed during scanning, with host, port, and error.
        """
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            filepath = f.name

        try:
            write_json_report(
                filepath,
                sample_findings,
                sample_summary,
                modules_run=["ssl", "headers"],
                version="1.0.0",
                targets_scanned=3,
            )
            with open(filepath, "r", encoding="utf-8") as fh:
                data = json.load(fh)

            assert "failed_targets" in data
            assert isinstance(data["failed_targets"], list)
            assert len(data["failed_targets"]) == 1

            failed = data["failed_targets"][0]
            assert failed["host"] == "10.0.0.3"
            assert failed["port"] == 443
            assert failed["error"] == "Connection refused"
        finally:
            os.unlink(filepath)

    def test_json_has_summary_section(self, sample_findings, sample_summary):
        """
        The JSON output should contain a 'summary' section with total_findings
        and by_severity breakdown.
        """
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            filepath = f.name

        try:
            write_json_report(
                filepath,
                sample_findings,
                sample_summary,
                modules_run=["ssl", "headers"],
                version="1.0.0",
                targets_scanned=3,
            )
            with open(filepath, "r", encoding="utf-8") as fh:
                data = json.load(fh)

            assert "summary" in data
            summary = data["summary"]
            assert "total_findings" in summary
            assert "by_severity" in summary
            assert summary["total_findings"] == len(sample_findings)
        finally:
            os.unlink(filepath)

    def test_json_summary_severity_counts(self, sample_findings, sample_summary):
        """
        The by_severity breakdown should correctly count findings by severity level.
        """
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            filepath = f.name

        try:
            write_json_report(
                filepath,
                sample_findings,
                sample_summary,
                modules_run=["ssl", "headers"],
                version="1.0.0",
                targets_scanned=3,
            )
            with open(filepath, "r", encoding="utf-8") as fh:
                data = json.load(fh)

            by_severity = data["summary"]["by_severity"]

            # From sample_findings:
            #   1 HIGH (weak_ciphers)
            #   4 MEDIUM (2 deprecated_protocols + 2 missing_csp)
            #   1 LOW (server_header)
            #   1 INFORMATIONAL (technology)
            assert by_severity.get("High", 0) == 1
            assert by_severity.get("Medium", 0) == 4
            assert by_severity.get("Low", 0) == 1
            assert by_severity.get("Informational", 0) == 1
        finally:
            os.unlink(filepath)

    def test_json_empty_findings(self, empty_summary):
        """
        write_json_report() with empty findings should still produce valid
        JSON with all required sections.
        """
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            filepath = f.name

        try:
            write_json_report(
                filepath,
                [],
                empty_summary,
                modules_run=["ssl"],
                version="1.0.0",
                targets_scanned=2,
            )
            with open(filepath, "r", encoding="utf-8") as fh:
                data = json.load(fh)

            # All top-level sections should exist.
            assert "scan_info" in data
            assert "findings" in data
            assert "failed_targets" in data
            assert "summary" in data

            # Findings and failed_targets should be empty lists.
            assert data["findings"] == []
            assert data["failed_targets"] == []
            assert data["summary"]["total_findings"] == 0
        finally:
            os.unlink(filepath)


# ---------------------------------------------------------------------------
# Summary statistics tests
# ---------------------------------------------------------------------------

class TestSummaryStats:
    """Tests that summary statistics are calculated correctly by the renderers."""

    def test_severity_counts_match_findings(self, sample_findings, sample_summary):
        """
        The by_severity counts in the JSON output should match the actual
        number of findings at each severity level.
        """
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            filepath = f.name

        try:
            write_json_report(
                filepath,
                sample_findings,
                sample_summary,
                modules_run=["ssl", "headers"],
                version="1.0.0",
                targets_scanned=3,
            )
            with open(filepath, "r", encoding="utf-8") as fh:
                data = json.load(fh)

            # Count manually from sample_findings.
            manual_counts = {}
            for f_item in sample_findings:
                sev = f_item.severity.value
                manual_counts[sev] = manual_counts.get(sev, 0) + 1

            by_severity = data["summary"]["by_severity"]

            for sev, count in manual_counts.items():
                assert by_severity.get(sev, 0) == count, (
                    f"Severity {sev}: expected {count}, got {by_severity.get(sev, 0)}"
                )
        finally:
            os.unlink(filepath)

    def test_total_findings_matches_input_length(self, sample_findings, sample_summary):
        """
        The total_findings in the JSON summary should equal the number of
        Finding objects passed to the renderer.
        """
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            filepath = f.name

        try:
            write_json_report(
                filepath,
                sample_findings,
                sample_summary,
                modules_run=["ssl", "headers"],
                version="1.0.0",
                targets_scanned=3,
            )
            with open(filepath, "r", encoding="utf-8") as fh:
                data = json.load(fh)

            assert data["summary"]["total_findings"] == len(sample_findings)
        finally:
            os.unlink(filepath)

    def test_console_summary_includes_severity_breakdown(
        self, sample_summary, sample_findings
    ):
        """
        The console summary should include a severity breakdown showing
        the count of findings at each level.
        """
        output = render_summary(sample_summary, sample_findings)

        # The summary should mention at least one severity level.
        assert "High" in output or "Medium" in output
