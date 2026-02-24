"""
tests/test_target.py - Unit tests for the Target dataclass and target parsing functions.

Tests the core target management functionality that every scanner module depends on.
Covers:
    - Target dataclass properties (url, hostport, display)
    - parse_target_string() with all supported input formats
    - expand_targets() deduplication and comment/blank line handling
    - parse_target_file() file reading

Author: Red Siege Information Security
"""

import pytest

# Import the classes and functions under test from the core target module.
from webinspector.core.target import (
    Target,
    parse_target_string,
    expand_targets,
)


# ---------------------------------------------------------------------------
# Target dataclass property tests
# ---------------------------------------------------------------------------

class TestTargetProperties:
    """Test the computed properties on the Target dataclass."""

    def test_url_https(self):
        """The url property should produce a full HTTPS URL with port."""
        target = Target(host="example.com", port=443, scheme="https")
        assert target.url == "https://example.com:443"

    def test_url_http(self):
        """The url property should produce a full HTTP URL with port."""
        target = Target(host="example.com", port=80, scheme="http")
        assert target.url == "http://example.com:80"

    def test_url_custom_port(self):
        """The url property should include non-standard ports correctly."""
        target = Target(host="10.0.0.1", port=8443, scheme="https")
        assert target.url == "https://10.0.0.1:8443"

    def test_hostport(self):
        """The hostport property should return 'host:port' for display in findings."""
        target = Target(host="example.com", port=443, scheme="https")
        assert target.hostport == "example.com:443"

    def test_hostport_ip(self):
        """The hostport property should work with IP addresses too."""
        target = Target(host="10.0.0.1", port=8080, scheme="http")
        assert target.hostport == "10.0.0.1:8080"

    def test_display_hostname_with_resolved_ip(self):
        """
        When the target is a hostname and has a resolved IP,
        display should show 'host:port (resolved_ip)'.
        """
        target = Target(
            host="example.com", port=443, scheme="https", ip="10.0.0.1"
        )
        assert target.display == "example.com:443 (10.0.0.1)"

    def test_display_ip_with_rdns(self):
        """
        When the target is an IP address and has reverse DNS,
        display should show 'ip:port (rdns_name)'.
        """
        target = Target(
            host="10.0.0.1", port=443, scheme="https", rdns="server.corp.com"
        )
        assert target.display == "10.0.0.1:443 (server.corp.com)"

    def test_display_no_extra_info(self):
        """
        When neither resolved IP nor reverse DNS is available,
        display should fall back to just 'host:port'.
        """
        target = Target(host="example.com", port=443, scheme="https")
        assert target.display == "example.com:443"

    def test_display_ip_target_with_resolved_ip_same(self):
        """
        When the target host IS an IP and ip is set to the same value (no rdns),
        display should not redundantly show the same IP twice — just 'ip:port'.
        """
        target = Target(
            host="10.0.0.1", port=443, scheme="https", ip="10.0.0.1"
        )
        assert target.display == "10.0.0.1:443"


# ---------------------------------------------------------------------------
# parse_target_string tests
# ---------------------------------------------------------------------------

class TestParseTargetString:
    """Test the parse_target_string function with various input formats."""

    def test_full_url_https(self):
        """
        A full URL like 'https://example.com:8443' should produce exactly one Target
        with the explicit scheme, host, and port extracted from the URL.
        """
        targets = parse_target_string("https://example.com:8443")
        assert len(targets) == 1
        t = targets[0]
        assert t.scheme == "https"
        assert t.host == "example.com"
        assert t.port == 8443

    def test_full_url_http(self):
        """
        A full URL like 'http://example.com' should produce one Target.
        When no port is given explicitly, http should default to port 80.
        """
        targets = parse_target_string("http://example.com")
        assert len(targets) == 1
        t = targets[0]
        assert t.scheme == "http"
        assert t.host == "example.com"
        assert t.port == 80

    def test_full_url_https_no_port(self):
        """
        A full URL like 'https://example.com' should produce one Target.
        When no port is given explicitly, https should default to port 443.
        """
        targets = parse_target_string("https://example.com")
        assert len(targets) == 1
        t = targets[0]
        assert t.scheme == "https"
        assert t.host == "example.com"
        assert t.port == 443

    def test_host_port_pair(self):
        """
        A host:port pair like '10.0.0.1:443' (no scheme) should expand
        to TWO targets — one http and one https on that port — because
        we don't know which protocol the server speaks.
        """
        targets = parse_target_string("10.0.0.1:443")
        assert len(targets) == 2
        schemes = {t.scheme for t in targets}
        assert schemes == {"http", "https"}
        # Both should have the same host and port
        for t in targets:
            assert t.host == "10.0.0.1"
            assert t.port == 443

    def test_bare_hostname(self):
        """
        A bare hostname like 'example.com' should expand to two targets:
        http and https, both on port 443 (the default).
        """
        targets = parse_target_string("example.com")
        assert len(targets) == 2
        schemes = {t.scheme for t in targets}
        assert schemes == {"http", "https"}
        for t in targets:
            assert t.host == "example.com"
            assert t.port == 443

    def test_bare_ip(self):
        """
        A bare IP address like '10.0.0.1' should expand to two targets:
        http and https, both on port 443 (the default).
        """
        targets = parse_target_string("10.0.0.1")
        assert len(targets) == 2
        schemes = {t.scheme for t in targets}
        assert schemes == {"http", "https"}
        for t in targets:
            assert t.host == "10.0.0.1"
            assert t.port == 443

    def test_explicit_http_no_expand(self):
        """
        When an explicit scheme is given (http://example.com),
        the parser should NOT expand to both schemes — only return the one
        explicitly requested.
        """
        targets = parse_target_string("http://example.com:8080")
        assert len(targets) == 1
        assert targets[0].scheme == "http"
        assert targets[0].port == 8080

    def test_explicit_https_no_expand(self):
        """
        When an explicit https:// scheme is given, only one target is returned.
        """
        targets = parse_target_string("https://secure.example.com")
        assert len(targets) == 1
        assert targets[0].scheme == "https"
        assert targets[0].host == "secure.example.com"

    def test_cidr_range_slash_30(self):
        """
        A CIDR range like '10.0.0.0/30' contains 4 usable IPs
        (10.0.0.0, 10.0.0.1, 10.0.0.2, 10.0.0.3).
        Each IP should be expanded to both http and https on the default port,
        producing 8 targets total.
        """
        targets = parse_target_string("10.0.0.0/30")
        # 4 IPs * 2 schemes = 8 targets
        assert len(targets) == 8
        # Extract all unique hosts
        hosts = {t.host for t in targets}
        assert hosts == {"10.0.0.0", "10.0.0.1", "10.0.0.2", "10.0.0.3"}
        # Each host should have both schemes
        for host in hosts:
            host_targets = [t for t in targets if t.host == host]
            assert len(host_targets) == 2
            assert {t.scheme for t in host_targets} == {"http", "https"}

    def test_port_override_bare_host(self):
        """
        When ports=[443, 8443] is passed with a bare hostname,
        the parser should create targets for each port, with both schemes.
        4 targets total: http:443, https:443, http:8443, https:8443.
        """
        targets = parse_target_string("example.com", ports=[443, 8443])
        assert len(targets) == 4
        port_scheme_pairs = {(t.port, t.scheme) for t in targets}
        assert port_scheme_pairs == {
            (443, "http"), (443, "https"),
            (8443, "http"), (8443, "https"),
        }

    def test_port_override_cidr(self):
        """
        CIDR + port override: 10.0.0.0/31 has 2 IPs.
        With ports=[443, 8443], that's 2 IPs * 2 ports * 2 schemes = 8 targets.
        """
        targets = parse_target_string("10.0.0.0/31", ports=[443, 8443])
        assert len(targets) == 8

    def test_source_defaults_to_cli(self):
        """Parsed targets should have source='cli' by default."""
        targets = parse_target_string("example.com")
        for t in targets:
            assert t.source == "cli"

    def test_full_url_with_trailing_slash(self):
        """
        URLs with trailing slashes or paths should be handled gracefully.
        The host should not include any path component.
        """
        targets = parse_target_string("https://example.com:443/")
        assert len(targets) == 1
        assert targets[0].host == "example.com"
        assert targets[0].port == 443

    def test_full_url_with_path(self):
        """
        URLs with paths should strip the path and just use host:port.
        We scan hosts, not specific pages.
        """
        targets = parse_target_string("https://example.com/some/path")
        assert len(targets) == 1
        assert targets[0].host == "example.com"


# ---------------------------------------------------------------------------
# expand_targets tests
# ---------------------------------------------------------------------------

class TestExpandTargets:
    """Test the expand_targets function which processes multiple raw strings."""

    def test_deduplication(self):
        """
        If the same target is specified twice (e.g. same URL repeated),
        expand_targets should deduplicate and return only unique
        (scheme, host, port) combinations.
        """
        raw = [
            "https://example.com:443",
            "https://example.com:443",  # duplicate
        ]
        targets = expand_targets(raw)
        assert len(targets) == 1

    def test_deduplication_different_formats(self):
        """
        Even if targets are specified in different formats that resolve
        to the same (scheme, host, port), they should be deduplicated.
        For example, 'https://example.com' and 'https://example.com:443'
        are the same target.
        """
        raw = [
            "https://example.com",
            "https://example.com:443",
        ]
        targets = expand_targets(raw)
        assert len(targets) == 1

    def test_skips_comment_lines(self):
        """
        Lines starting with '#' are comments and should be skipped entirely.
        """
        raw = [
            "# This is a comment",
            "https://example.com:443",
            "  # Indented comment",
        ]
        targets = expand_targets(raw)
        assert len(targets) == 1
        assert targets[0].host == "example.com"

    def test_skips_empty_lines(self):
        """
        Empty lines and whitespace-only lines should be silently skipped.
        """
        raw = [
            "",
            "  ",
            "https://example.com:443",
            "",
        ]
        targets = expand_targets(raw)
        assert len(targets) == 1

    def test_multiple_targets(self):
        """
        expand_targets should process multiple different targets and
        return all of them, sorted consistently.
        """
        raw = [
            "https://alpha.com:443",
            "https://beta.com:443",
        ]
        targets = expand_targets(raw)
        assert len(targets) == 2
        hosts = {t.host for t in targets}
        assert hosts == {"alpha.com", "beta.com"}

    def test_expand_with_ports(self):
        """
        The ports parameter should be passed through to parse_target_string
        for bare hostnames.
        """
        raw = ["example.com"]
        targets = expand_targets(raw, ports=[443, 8443])
        # bare host + 2 ports + 2 schemes = 4 targets
        assert len(targets) == 4
