"""
Tests for the DNS security scanner module (dns_scanner.py).

These tests verify that the DNSScanner module correctly:
    1. Has the correct name ("dns") and a non-empty description
    2. Accepts both HTTP and HTTPS targets (default accepts_target)
    3. Reports missing CAA records as LOW severity findings
    4. Reports present CAA records as INFORMATIONAL findings (logging them)
    5. Performs reverse DNS lookups for IP-based targets
    6. Reports reverse DNS results as INFORMATIONAL findings
    7. Deduplicates CAA checks -- only queries CAA once per unique domain
    8. Handles targets on different ports sharing the same domain
    9. Does not perform reverse DNS for hostname-based targets
   10. Handles DNS query failures gracefully (no crashes)
   11. Produces findings with correct module name, titles, and details
   12. Verifies module registration via register_module()

All DNS queries are mocked using unittest.mock.patch -- no real DNS
lookups are performed.  We mock the utility functions from
webinspector.utils.network: check_caa_records(), reverse_dns_lookup(),
and is_ip_address().

Author: Red Siege Information Security
"""

import pytest
from unittest.mock import patch, MagicMock

from webinspector.core.target import Target
from webinspector.core.result import Finding, Severity


# ---------------------------------------------------------------------------
# Target fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def https_target():
    """An HTTPS hostname target for DNS scanning."""
    return Target(host="example.com", port=443, scheme="https")


@pytest.fixture
def http_target():
    """An HTTP hostname target for DNS scanning."""
    return Target(host="example.com", port=80, scheme="http")


@pytest.fixture
def ip_target():
    """An HTTPS IP-address target for DNS scanning."""
    return Target(host="10.0.0.1", port=443, scheme="https")


@pytest.fixture
def ip_target_http():
    """An HTTP IP-address target for DNS scanning."""
    return Target(host="10.0.0.1", port=80, scheme="http")


@pytest.fixture
def different_port_target():
    """An HTTPS target on port 8443 -- shares domain with https_target."""
    return Target(host="example.com", port=8443, scheme="https")


@pytest.fixture
def second_domain_target():
    """A target with a different domain."""
    return Target(host="other.com", port=443, scheme="https")


# ===========================================================================
# Tests for module properties
# ===========================================================================

class TestDNSScannerProperties:
    """Verify name and description properties."""

    def test_name(self):
        """Module name should be 'dns'."""
        from webinspector.modules.dns_scanner import DNSScanner
        scanner = DNSScanner()
        assert scanner.name == "dns"

    def test_description(self):
        """Module should have a non-empty description."""
        from webinspector.modules.dns_scanner import DNSScanner
        scanner = DNSScanner()
        assert len(scanner.description) > 0
        # Should mention DNS or CAA in the description.
        desc_lower = scanner.description.lower()
        assert "dns" in desc_lower or "caa" in desc_lower


# ===========================================================================
# Tests for accepts_target
# ===========================================================================

class TestDNSScannerAcceptsTarget:
    """Verify that the DNS scanner accepts all targets."""

    def test_accepts_https(self, https_target):
        """DNS scanner should accept HTTPS targets."""
        from webinspector.modules.dns_scanner import DNSScanner
        scanner = DNSScanner()
        assert scanner.accepts_target(https_target) is True

    def test_accepts_http(self, http_target):
        """DNS scanner should accept HTTP targets."""
        from webinspector.modules.dns_scanner import DNSScanner
        scanner = DNSScanner()
        assert scanner.accepts_target(http_target) is True

    def test_accepts_ip_target(self, ip_target):
        """DNS scanner should accept IP-address targets."""
        from webinspector.modules.dns_scanner import DNSScanner
        scanner = DNSScanner()
        assert scanner.accepts_target(ip_target) is True


# ===========================================================================
# Tests for CAA record checks
# ===========================================================================

class TestCAAScan:
    """Verify CAA record checking behaviour."""

    @patch("webinspector.modules.dns_scanner.is_ip_address", return_value=False)
    @patch("webinspector.modules.dns_scanner.check_caa_records", return_value=[])
    def test_missing_caa_records_low_severity(
        self, mock_caa, mock_is_ip, https_target
    ):
        """
        When a domain has no CAA records, a LOW severity finding
        ('missing_caa') should be reported.
        """
        from webinspector.modules.dns_scanner import DNSScanner
        scanner = DNSScanner()
        findings = scanner.scan(https_target)

        # Should have exactly one finding for missing CAA.
        caa_findings = [f for f in findings if f.finding_type == "missing_caa"]
        assert len(caa_findings) == 1

        finding = caa_findings[0]
        assert finding.module == "dns"
        assert finding.severity == Severity.LOW
        assert finding.target == https_target
        assert "caa" in finding.title.lower()
        assert "example.com" in finding.detail

    @patch("webinspector.modules.dns_scanner.is_ip_address", return_value=False)
    @patch(
        "webinspector.modules.dns_scanner.check_caa_records",
        return_value=['0 issue "letsencrypt.org"', '0 issuewild ";"'],
    )
    def test_present_caa_records_informational(
        self, mock_caa, mock_is_ip, https_target
    ):
        """
        When a domain has CAA records, an INFORMATIONAL finding
        ('caa_records') should be reported, listing the records.
        """
        from webinspector.modules.dns_scanner import DNSScanner
        scanner = DNSScanner()
        findings = scanner.scan(https_target)

        # Should have exactly one finding for CAA records present.
        caa_findings = [f for f in findings if f.finding_type == "caa_records"]
        assert len(caa_findings) == 1

        finding = caa_findings[0]
        assert finding.module == "dns"
        assert finding.severity == Severity.INFORMATIONAL
        assert finding.target == https_target
        # The detail should contain the actual CAA record values.
        assert "letsencrypt.org" in finding.detail
        assert "issuewild" in finding.detail

    @patch("webinspector.modules.dns_scanner.is_ip_address", return_value=False)
    @patch(
        "webinspector.modules.dns_scanner.check_caa_records",
        return_value=['0 issue "digicert.com"'],
    )
    def test_single_caa_record(self, mock_caa, mock_is_ip, https_target):
        """
        A domain with a single CAA record should produce an INFORMATIONAL
        finding that includes the record.
        """
        from webinspector.modules.dns_scanner import DNSScanner
        scanner = DNSScanner()
        findings = scanner.scan(https_target)

        caa_findings = [f for f in findings if f.finding_type == "caa_records"]
        assert len(caa_findings) == 1
        assert "digicert.com" in caa_findings[0].detail

    @patch("webinspector.modules.dns_scanner.is_ip_address", return_value=False)
    @patch("webinspector.modules.dns_scanner.check_caa_records", return_value=[])
    def test_caa_called_with_domain(self, mock_caa, mock_is_ip, https_target):
        """check_caa_records should be called with the target's host."""
        from webinspector.modules.dns_scanner import DNSScanner
        scanner = DNSScanner()
        scanner.scan(https_target)
        mock_caa.assert_called_once_with("example.com")


# ===========================================================================
# Tests for CAA deduplication
# ===========================================================================

class TestCAADeduplication:
    """
    Verify that CAA checks are only performed once per unique domain,
    even when multiple targets share the same base domain.
    """

    @patch("webinspector.modules.dns_scanner.is_ip_address", return_value=False)
    @patch("webinspector.modules.dns_scanner.check_caa_records", return_value=[])
    def test_same_domain_different_ports(
        self, mock_caa, mock_is_ip, https_target, different_port_target
    ):
        """
        Two targets with the same domain (example.com:443 and
        example.com:8443) should only trigger one CAA lookup.
        """
        from webinspector.modules.dns_scanner import DNSScanner
        scanner = DNSScanner()

        # Scan first target -- should trigger CAA lookup.
        scanner.scan(https_target)
        assert mock_caa.call_count == 1

        # Scan second target with the same domain -- should NOT trigger
        # another CAA lookup because the domain was already checked.
        scanner.scan(different_port_target)
        assert mock_caa.call_count == 1  # Still 1, not 2.

    @patch("webinspector.modules.dns_scanner.is_ip_address", return_value=False)
    @patch("webinspector.modules.dns_scanner.check_caa_records", return_value=[])
    def test_same_domain_different_schemes(
        self, mock_caa, mock_is_ip, https_target, http_target
    ):
        """
        HTTP and HTTPS targets for the same domain should only trigger
        one CAA lookup.
        """
        from webinspector.modules.dns_scanner import DNSScanner
        scanner = DNSScanner()

        scanner.scan(https_target)
        scanner.scan(http_target)
        # Only one CAA lookup for example.com, regardless of scheme.
        assert mock_caa.call_count == 1

    @patch("webinspector.modules.dns_scanner.is_ip_address", return_value=False)
    @patch("webinspector.modules.dns_scanner.check_caa_records", return_value=[])
    def test_different_domains_both_checked(
        self, mock_caa, mock_is_ip, https_target, second_domain_target
    ):
        """
        Targets with DIFFERENT domains should each get their own CAA check.
        """
        from webinspector.modules.dns_scanner import DNSScanner
        scanner = DNSScanner()

        scanner.scan(https_target)
        scanner.scan(second_domain_target)
        # Two different domains -> two CAA lookups.
        assert mock_caa.call_count == 2

    @patch("webinspector.modules.dns_scanner.is_ip_address", return_value=False)
    @patch("webinspector.modules.dns_scanner.check_caa_records", return_value=[])
    def test_dedup_only_produces_finding_on_first_scan(
        self, mock_caa, mock_is_ip, https_target, different_port_target
    ):
        """
        When the same domain is scanned a second time, no additional CAA
        findings should be produced (dedup suppresses duplicate findings).
        """
        from webinspector.modules.dns_scanner import DNSScanner
        scanner = DNSScanner()

        # First scan -- produces finding.
        findings_first = scanner.scan(https_target)
        caa_first = [f for f in findings_first if f.finding_type == "missing_caa"]
        assert len(caa_first) == 1

        # Second scan for same domain -- no CAA finding produced.
        findings_second = scanner.scan(different_port_target)
        caa_second = [
            f for f in findings_second
            if f.finding_type in ("missing_caa", "caa_records")
        ]
        assert len(caa_second) == 0


# ===========================================================================
# Tests for reverse DNS checks
# ===========================================================================

class TestReverseDNS:
    """Verify reverse DNS lookup behaviour for IP-address targets."""

    @patch("webinspector.modules.dns_scanner.reverse_dns_lookup", return_value="server.corp.com")
    @patch("webinspector.modules.dns_scanner.is_ip_address", return_value=True)
    @patch("webinspector.modules.dns_scanner.check_caa_records", return_value=[])
    def test_reverse_dns_informational(
        self, mock_caa, mock_is_ip, mock_rdns, ip_target
    ):
        """
        When a reverse DNS lookup succeeds for an IP target, an INFORMATIONAL
        finding ('reverse_dns') should be produced.
        """
        from webinspector.modules.dns_scanner import DNSScanner
        scanner = DNSScanner()
        findings = scanner.scan(ip_target)

        rdns_findings = [f for f in findings if f.finding_type == "reverse_dns"]
        assert len(rdns_findings) == 1

        finding = rdns_findings[0]
        assert finding.module == "dns"
        assert finding.severity == Severity.INFORMATIONAL
        assert finding.target == ip_target
        assert "server.corp.com" in finding.detail
        assert "10.0.0.1" in finding.detail

    @patch("webinspector.modules.dns_scanner.reverse_dns_lookup", return_value="server.corp.com")
    @patch("webinspector.modules.dns_scanner.is_ip_address", return_value=True)
    @patch("webinspector.modules.dns_scanner.check_caa_records", return_value=[])
    def test_reverse_dns_populates_rdns(
        self, mock_caa, mock_is_ip, mock_rdns, ip_target
    ):
        """
        The scanner should populate target.rdns with the reverse DNS
        hostname so downstream modules and output renderers can use it.
        """
        from webinspector.modules.dns_scanner import DNSScanner
        scanner = DNSScanner()
        scanner.scan(ip_target)

        # target.rdns should now be set.
        assert ip_target.rdns == "server.corp.com"

    @patch("webinspector.modules.dns_scanner.reverse_dns_lookup", return_value=None)
    @patch("webinspector.modules.dns_scanner.is_ip_address", return_value=True)
    @patch("webinspector.modules.dns_scanner.check_caa_records", return_value=[])
    def test_no_reverse_dns_no_finding(
        self, mock_caa, mock_is_ip, mock_rdns, ip_target
    ):
        """
        When reverse DNS lookup returns None (no PTR record), no
        reverse_dns finding should be produced.
        """
        from webinspector.modules.dns_scanner import DNSScanner
        scanner = DNSScanner()
        findings = scanner.scan(ip_target)

        rdns_findings = [f for f in findings if f.finding_type == "reverse_dns"]
        assert len(rdns_findings) == 0

    @patch("webinspector.modules.dns_scanner.reverse_dns_lookup", return_value=None)
    @patch("webinspector.modules.dns_scanner.is_ip_address", return_value=True)
    @patch("webinspector.modules.dns_scanner.check_caa_records", return_value=[])
    def test_no_reverse_dns_does_not_set_rdns(
        self, mock_caa, mock_is_ip, mock_rdns, ip_target
    ):
        """
        When reverse DNS lookup returns None, target.rdns should remain None.
        """
        from webinspector.modules.dns_scanner import DNSScanner
        scanner = DNSScanner()
        scanner.scan(ip_target)

        assert ip_target.rdns is None

    @patch("webinspector.modules.dns_scanner.is_ip_address", return_value=False)
    @patch("webinspector.modules.dns_scanner.check_caa_records", return_value=[])
    def test_hostname_target_no_reverse_dns(
        self, mock_caa, mock_is_ip, https_target
    ):
        """
        Hostname-based targets should NOT trigger a reverse DNS lookup.
        Only IP-address targets get reverse DNS lookups.
        """
        from webinspector.modules.dns_scanner import DNSScanner
        scanner = DNSScanner()

        with patch(
            "webinspector.modules.dns_scanner.reverse_dns_lookup"
        ) as mock_rdns:
            scanner.scan(https_target)
            mock_rdns.assert_not_called()

    @patch("webinspector.modules.dns_scanner.reverse_dns_lookup", return_value="server.corp.com")
    @patch("webinspector.modules.dns_scanner.is_ip_address", return_value=True)
    @patch("webinspector.modules.dns_scanner.check_caa_records", return_value=[])
    def test_reverse_dns_called_with_host(
        self, mock_caa, mock_is_ip, mock_rdns, ip_target
    ):
        """reverse_dns_lookup should be called with the target's host IP."""
        from webinspector.modules.dns_scanner import DNSScanner
        scanner = DNSScanner()
        scanner.scan(ip_target)
        mock_rdns.assert_called_once_with("10.0.0.1")


# ===========================================================================
# Tests for IP targets and CAA interaction
# ===========================================================================

class TestIPTargetCAABehaviour:
    """Verify that IP-address targets skip CAA checks."""

    @patch("webinspector.modules.dns_scanner.reverse_dns_lookup", return_value=None)
    @patch("webinspector.modules.dns_scanner.is_ip_address", return_value=True)
    @patch("webinspector.modules.dns_scanner.check_caa_records", return_value=[])
    def test_ip_target_skips_caa(self, mock_caa, mock_is_ip, mock_rdns, ip_target):
        """
        CAA records only make sense for domain names, not IP addresses.
        IP targets should skip the CAA check entirely.
        """
        from webinspector.modules.dns_scanner import DNSScanner
        scanner = DNSScanner()
        scanner.scan(ip_target)

        # check_caa_records should NOT be called for IP targets.
        mock_caa.assert_not_called()


# ===========================================================================
# Tests for combined scan behaviour
# ===========================================================================

class TestCombinedScan:
    """Verify the scanner produces correct findings for various scenarios."""

    @patch("webinspector.modules.dns_scanner.reverse_dns_lookup", return_value="web.corp.com")
    @patch("webinspector.modules.dns_scanner.is_ip_address", return_value=True)
    @patch("webinspector.modules.dns_scanner.check_caa_records", return_value=[])
    def test_ip_target_with_rdns_only(
        self, mock_caa, mock_is_ip, mock_rdns, ip_target
    ):
        """
        An IP target with reverse DNS should produce only a reverse_dns
        finding (no CAA finding since CAA is skipped for IPs).
        """
        from webinspector.modules.dns_scanner import DNSScanner
        scanner = DNSScanner()
        findings = scanner.scan(ip_target)

        # Only a reverse DNS finding -- no CAA finding for IP targets.
        assert len(findings) == 1
        assert findings[0].finding_type == "reverse_dns"

    @patch("webinspector.modules.dns_scanner.is_ip_address", return_value=False)
    @patch("webinspector.modules.dns_scanner.check_caa_records", return_value=[])
    def test_hostname_missing_caa_only(self, mock_caa, mock_is_ip, https_target):
        """
        A hostname target with no CAA records should produce only a
        missing_caa finding (no reverse DNS since it's not an IP).
        """
        from webinspector.modules.dns_scanner import DNSScanner
        scanner = DNSScanner()
        findings = scanner.scan(https_target)

        assert len(findings) == 1
        assert findings[0].finding_type == "missing_caa"
        assert findings[0].severity == Severity.LOW

    @patch("webinspector.modules.dns_scanner.is_ip_address", return_value=False)
    @patch(
        "webinspector.modules.dns_scanner.check_caa_records",
        return_value=['0 issue "letsencrypt.org"'],
    )
    def test_hostname_with_caa_records(self, mock_caa, mock_is_ip, https_target):
        """
        A hostname target with CAA records should produce only a
        caa_records finding (INFORMATIONAL).
        """
        from webinspector.modules.dns_scanner import DNSScanner
        scanner = DNSScanner()
        findings = scanner.scan(https_target)

        assert len(findings) == 1
        assert findings[0].finding_type == "caa_records"
        assert findings[0].severity == Severity.INFORMATIONAL


# ===========================================================================
# Tests for finding details and formatting
# ===========================================================================

class TestFindingDetails:
    """Verify finding titles, details, and references are correct."""

    @patch("webinspector.modules.dns_scanner.is_ip_address", return_value=False)
    @patch("webinspector.modules.dns_scanner.check_caa_records", return_value=[])
    def test_missing_caa_detail_includes_domain(
        self, mock_caa, mock_is_ip, https_target
    ):
        """Missing CAA detail should mention the domain name."""
        from webinspector.modules.dns_scanner import DNSScanner
        scanner = DNSScanner()
        findings = scanner.scan(https_target)

        finding = findings[0]
        assert "example.com" in finding.detail

    @patch("webinspector.modules.dns_scanner.is_ip_address", return_value=False)
    @patch(
        "webinspector.modules.dns_scanner.check_caa_records",
        return_value=['0 issue "ca.example.com"', '0 iodef "mailto:sec@example.com"'],
    )
    def test_caa_records_detail_includes_all_records(
        self, mock_caa, mock_is_ip, https_target
    ):
        """CAA records detail should include all returned records."""
        from webinspector.modules.dns_scanner import DNSScanner
        scanner = DNSScanner()
        findings = scanner.scan(https_target)

        finding = findings[0]
        assert "ca.example.com" in finding.detail
        assert "iodef" in finding.detail
        assert "sec@example.com" in finding.detail

    @patch("webinspector.modules.dns_scanner.reverse_dns_lookup", return_value="web01.datacenter.com")
    @patch("webinspector.modules.dns_scanner.is_ip_address", return_value=True)
    @patch("webinspector.modules.dns_scanner.check_caa_records", return_value=[])
    def test_reverse_dns_detail_includes_both_ip_and_hostname(
        self, mock_caa, mock_is_ip, mock_rdns, ip_target
    ):
        """Reverse DNS detail should mention both the IP and resolved hostname."""
        from webinspector.modules.dns_scanner import DNSScanner
        scanner = DNSScanner()
        findings = scanner.scan(ip_target)

        rdns_findings = [f for f in findings if f.finding_type == "reverse_dns"]
        finding = rdns_findings[0]
        assert "10.0.0.1" in finding.detail
        assert "web01.datacenter.com" in finding.detail

    @patch("webinspector.modules.dns_scanner.is_ip_address", return_value=False)
    @patch("webinspector.modules.dns_scanner.check_caa_records", return_value=[])
    def test_all_findings_have_dns_module(self, mock_caa, mock_is_ip, https_target):
        """All findings should have module='dns'."""
        from webinspector.modules.dns_scanner import DNSScanner
        scanner = DNSScanner()
        findings = scanner.scan(https_target)

        for finding in findings:
            assert finding.module == "dns"


# ===========================================================================
# Tests for error handling
# ===========================================================================

class TestErrorHandling:
    """Verify graceful error handling during DNS operations."""

    @patch("webinspector.modules.dns_scanner.is_ip_address", return_value=False)
    @patch(
        "webinspector.modules.dns_scanner.check_caa_records",
        side_effect=Exception("DNS query failed"),
    )
    def test_caa_exception_returns_empty(
        self, mock_caa, mock_is_ip, https_target
    ):
        """
        If check_caa_records raises an exception, scan should handle it
        gracefully and return empty findings (no crash).
        """
        from webinspector.modules.dns_scanner import DNSScanner
        scanner = DNSScanner()
        findings = scanner.scan(https_target)

        # Should not crash, may return empty or limited findings.
        # No CAA-related findings should be produced on error.
        caa_findings = [
            f for f in findings
            if f.finding_type in ("missing_caa", "caa_records")
        ]
        assert len(caa_findings) == 0

    @patch("webinspector.modules.dns_scanner.reverse_dns_lookup", side_effect=Exception("PTR query failed"))
    @patch("webinspector.modules.dns_scanner.is_ip_address", return_value=True)
    @patch("webinspector.modules.dns_scanner.check_caa_records", return_value=[])
    def test_rdns_exception_returns_empty(
        self, mock_caa, mock_is_ip, mock_rdns, ip_target
    ):
        """
        If reverse_dns_lookup raises an exception, scan should handle it
        gracefully and return empty findings (no crash).
        """
        from webinspector.modules.dns_scanner import DNSScanner
        scanner = DNSScanner()
        findings = scanner.scan(ip_target)

        # Should not crash.
        rdns_findings = [f for f in findings if f.finding_type == "reverse_dns"]
        assert len(rdns_findings) == 0


# ===========================================================================
# Tests for module registration
# ===========================================================================

class TestDNSScannerRegistration:
    """Verify that the DNS scanner registers itself with the module registry."""

    def test_registered_in_registry(self):
        """
        Importing dns_scanner.py should register the module with the
        global registry via register_module().
        """
        # Reset registry to test fresh registration.
        from webinspector.modules import _registry

        # Import the module (triggers registration at the bottom of the file).
        from webinspector.modules.dns_scanner import DNSScanner

        # Check that an instance of DNSScanner is in the registry.
        dns_modules = [m for m in _registry if isinstance(m, DNSScanner)]
        assert len(dns_modules) >= 1

    def test_registered_module_name(self):
        """The registered module should have name 'dns'."""
        from webinspector.modules import _registry
        from webinspector.modules.dns_scanner import DNSScanner

        dns_modules = [m for m in _registry if isinstance(m, DNSScanner)]
        assert dns_modules[0].name == "dns"


# ===========================================================================
# Tests for scanner reset / fresh state
# ===========================================================================

class TestScannerState:
    """Verify that scanner state management works correctly."""

    @patch("webinspector.modules.dns_scanner.is_ip_address", return_value=False)
    @patch("webinspector.modules.dns_scanner.check_caa_records", return_value=[])
    def test_new_scanner_instance_has_fresh_dedup_state(
        self, mock_caa, mock_is_ip, https_target
    ):
        """
        Each new DNSScanner instance should have its own independent
        deduplication state.  A previously checked domain in one instance
        should not affect a different instance.
        """
        from webinspector.modules.dns_scanner import DNSScanner

        # First scanner instance checks the domain.
        scanner1 = DNSScanner()
        scanner1.scan(https_target)
        assert mock_caa.call_count == 1

        # Second scanner instance should also check the domain
        # (its own dedup set is empty).
        scanner2 = DNSScanner()
        scanner2.scan(https_target)
        assert mock_caa.call_count == 2
