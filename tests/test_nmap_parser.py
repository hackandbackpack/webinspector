"""
tests/test_nmap_parser.py - Unit tests for the nmap XML parser utility.

The nmap parser is critical for the pentest team's workflow: they run nmap first
to discover open web services across the target network, then feed that XML
output into webinspector.  These tests verify that we correctly extract web
service targets while filtering out non-web services and closed ports.

Test fixture: tests/fixtures/sample_nmap.xml
    - Host 10.0.0.1: port 443 open, service "https"           -> extracted
    - Host 10.0.0.2: port 80 open "http"; port 8443 "https"   -> both extracted
    - Host 10.0.0.3: port 22 open, service "ssh"              -> excluded
    - Host 10.0.0.4: port 443, state="closed"                 -> excluded

Covers:
    - Extracting HTTPS services on standard port 443
    - Extracting HTTP services on port 80
    - Extracting SSL tunnel services on non-standard ports (8443)
    - Excluding non-web services (SSH on port 22)
    - Excluding closed ports regardless of service name
    - Correct scheme assignment (https for SSL services, http for plain HTTP)
    - Source attribution ('nmap' for all parsed targets)
    - Graceful handling of missing or malformed input files

Author: Red Siege Information Security
"""

import os
import pytest

# Import the function under test.
from webinspector.utils.nmap_parser import parse_nmap_xml


# ---------------------------------------------------------------------------
# Helper — path to the sample nmap XML fixture
# ---------------------------------------------------------------------------

# Build the absolute path to the test fixture.  __file__ is the path to this
# test module, so we navigate up to find the fixtures directory.
FIXTURE_DIR = os.path.join(os.path.dirname(__file__), "fixtures")
SAMPLE_NMAP_XML = os.path.join(FIXTURE_DIR, "sample_nmap.xml")


# ---------------------------------------------------------------------------
# Nmap XML parser tests
# ---------------------------------------------------------------------------

class TestParseNmapXml:
    """Test the parse_nmap_xml() function against the sample fixture."""

    def test_extracts_https_on_443(self):
        """
        Host 10.0.0.1 has port 443 open with service name 'https'.
        The parser should extract this as a Target with scheme='https',
        host='10.0.0.1', and port=443.
        """
        targets = parse_nmap_xml(SAMPLE_NMAP_XML)

        # Find the specific target for 10.0.0.1:443
        match = [t for t in targets if t.host == "10.0.0.1" and t.port == 443]
        assert len(match) == 1, "Expected exactly one target for 10.0.0.1:443"
        assert match[0].scheme == "https"

    def test_extracts_http_on_80(self):
        """
        Host 10.0.0.2 has port 80 open with service name 'http'.
        The parser should extract this as a Target with scheme='http',
        host='10.0.0.2', and port=80.
        """
        targets = parse_nmap_xml(SAMPLE_NMAP_XML)

        # Find the specific target for 10.0.0.2:80
        match = [t for t in targets if t.host == "10.0.0.2" and t.port == 80]
        assert len(match) == 1, "Expected exactly one target for 10.0.0.2:80"
        assert match[0].scheme == "http"

    def test_extracts_ssl_tunnel_on_8443(self):
        """
        Host 10.0.0.2 has port 8443 open with service name 'https' and
        tunnel='ssl'.  The parser should extract this as a Target with
        scheme='https', host='10.0.0.2', and port=8443.

        The tunnel="ssl" attribute is an alternative way nmap indicates
        that a service uses SSL/TLS — common for non-standard HTTPS ports.
        """
        targets = parse_nmap_xml(SAMPLE_NMAP_XML)

        # Find the specific target for 10.0.0.2:8443
        match = [t for t in targets if t.host == "10.0.0.2" and t.port == 8443]
        assert len(match) == 1, "Expected exactly one target for 10.0.0.2:8443"
        assert match[0].scheme == "https"

    def test_excludes_non_web_services(self):
        """
        Host 10.0.0.3 has only SSH on port 22 — not a web service.
        The parser should NOT produce any Target for this host.
        """
        targets = parse_nmap_xml(SAMPLE_NMAP_XML)

        # No target should exist for host 10.0.0.3 at all.
        match = [t for t in targets if t.host == "10.0.0.3"]
        assert len(match) == 0, "SSH service should not be included in web targets"

    def test_excludes_closed_ports(self):
        """
        Host 10.0.0.4 has port 443 but the state is 'closed'.
        Closed ports should be excluded even if the service name is 'https'.
        """
        targets = parse_nmap_xml(SAMPLE_NMAP_XML)

        # No target should exist for host 10.0.0.4.
        match = [t for t in targets if t.host == "10.0.0.4"]
        assert len(match) == 0, "Closed ports should not be included in targets"

    def test_correct_scheme_https(self):
        """
        All SSL/HTTPS-related services should be assigned scheme='https'.
        This includes services named 'https', 'ssl', or with tunnel='ssl'.
        """
        targets = parse_nmap_xml(SAMPLE_NMAP_XML)

        # 10.0.0.1:443 is 'https' -> scheme should be 'https'
        https_targets = [t for t in targets if t.scheme == "https"]
        # We expect at least two HTTPS targets: 10.0.0.1:443 and 10.0.0.2:8443
        assert len(https_targets) >= 2

    def test_correct_scheme_http(self):
        """
        Plain HTTP services should be assigned scheme='http'.
        """
        targets = parse_nmap_xml(SAMPLE_NMAP_XML)

        # 10.0.0.2:80 is 'http' -> scheme should be 'http'
        http_targets = [t for t in targets if t.scheme == "http"]
        assert len(http_targets) >= 1

    def test_source_is_nmap(self):
        """
        All targets produced by the nmap parser should have source='nmap'
        so that the output renderers can show provenance information.
        """
        targets = parse_nmap_xml(SAMPLE_NMAP_XML)

        # Every single target from the parser should be tagged as 'nmap'.
        for target in targets:
            assert target.source == "nmap", (
                f"Target {target.hostport} should have source='nmap', "
                f"got source='{target.source}'"
            )

    def test_total_target_count(self):
        """
        From the fixture, we expect exactly 3 web targets:
        - 10.0.0.1:443 (https)
        - 10.0.0.2:80  (http)
        - 10.0.0.2:8443 (https, ssl tunnel)

        SSH (host 3) and closed port (host 4) should be excluded.
        """
        targets = parse_nmap_xml(SAMPLE_NMAP_XML)
        assert len(targets) == 3, (
            f"Expected 3 web targets from fixture, got {len(targets)}: "
            f"{[t.hostport for t in targets]}"
        )

    def test_handles_missing_file(self):
        """
        When given a path to a file that doesn't exist, parse_nmap_xml
        should return an empty list (not crash).  The pentest team may
        have typos in their file paths and the tool should handle it.
        """
        targets = parse_nmap_xml("/nonexistent/path/nmap.xml")
        assert targets == [], "Missing file should return empty list"

    def test_handles_malformed_xml(self, tmp_path):
        """
        When given a file that contains invalid XML (not well-formed),
        parse_nmap_xml should return an empty list rather than crashing
        with an unhandled exception.
        """
        # Create a temporary file with garbage content.
        bad_file = tmp_path / "bad_nmap.xml"
        bad_file.write_text("this is not valid xml <<<<>>>")

        targets = parse_nmap_xml(str(bad_file))
        assert targets == [], "Malformed XML should return empty list"

    def test_handles_empty_file(self, tmp_path):
        """
        An empty file should be handled gracefully — return empty list.
        """
        empty_file = tmp_path / "empty.xml"
        empty_file.write_text("")

        targets = parse_nmap_xml(str(empty_file))
        assert targets == [], "Empty file should return empty list"
