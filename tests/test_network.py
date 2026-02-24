"""
tests/test_network.py - Unit tests for the DNS and IP utility functions.

These utilities are used throughout webinspector for:
- Resolving hostnames to IPs (pre-scan DNS phase)
- Reverse DNS lookups for enriching IP-based targets
- CAA record lookups (DNS-based certificate authority checking)
- IP address validation and sorting

The tests here focus on pure functions (is_ip_address, ip_sort_key) that
can be tested without network access, plus tests that verify graceful
error handling for DNS lookups against nonexistent domains.

Author: Red Siege Information Security
"""

import pytest

# Import the functions under test from the network utility module.
from webinspector.utils.network import (
    is_ip_address,
    ip_sort_key,
    check_caa_records,
    batch_resolve_dns,
    reverse_dns_lookup,
)


# ---------------------------------------------------------------------------
# is_ip_address tests
# ---------------------------------------------------------------------------

class TestIsIpAddress:
    """Test the is_ip_address() validation function."""

    def test_valid_ipv4_private(self):
        """
        A standard private IPv4 address like '10.0.0.1' should return True.
        This is the most common format we see in pentests (internal ranges).
        """
        assert is_ip_address("10.0.0.1") is True

    def test_valid_ipv4_loopback(self):
        """The loopback address '127.0.0.1' should be recognized as a valid IP."""
        assert is_ip_address("127.0.0.1") is True

    def test_valid_ipv4_all_zeros(self):
        """The address '0.0.0.0' is technically valid IPv4."""
        assert is_ip_address("0.0.0.0") is True

    def test_valid_ipv4_broadcast(self):
        """The broadcast address '255.255.255.255' should be valid."""
        assert is_ip_address("255.255.255.255") is True

    def test_hostname_returns_false(self):
        """
        A hostname like 'example.com' is NOT an IP address.
        This is a critical distinction — the scanner treats IPs and
        hostnames differently (IPs get reverse DNS, hostnames get forward DNS).
        """
        assert is_ip_address("example.com") is False

    def test_invalid_octets_returns_false(self):
        """
        '999.999.999.999' has octets > 255, which is invalid IPv4.
        Should return False even though it matches the dotted-quad format.
        """
        assert is_ip_address("999.999.999.999") is False

    def test_empty_string_returns_false(self):
        """An empty string is not a valid IP address."""
        assert is_ip_address("") is False

    def test_partial_ip_returns_false(self):
        """A partial IP like '10.0.0' (only 3 octets) is not valid."""
        assert is_ip_address("10.0.0") is False

    def test_ip_with_port_returns_false(self):
        """An IP with a port suffix like '10.0.0.1:443' is not a bare IP."""
        assert is_ip_address("10.0.0.1:443") is False


# ---------------------------------------------------------------------------
# ip_sort_key tests
# ---------------------------------------------------------------------------

class TestIpSortKey:
    """Test the ip_sort_key() function for correct sorting behaviour."""

    def test_numeric_ordering(self):
        """
        IP addresses should be sorted numerically by octet, not lexicographically.
        '10.0.0.2' should come before '10.0.0.10' because 2 < 10.
        String sorting would incorrectly put '10.0.0.10' first because
        the character '1' < '2'.
        """
        key_2 = ip_sort_key("10.0.0.2")
        key_10 = ip_sort_key("10.0.0.10")
        assert key_2 < key_10, "10.0.0.2 should sort before 10.0.0.10"

    def test_first_octet_comparison(self):
        """Sorting should compare octets left-to-right (most significant first)."""
        key_1 = ip_sort_key("1.0.0.0")
        key_10 = ip_sort_key("10.0.0.0")
        assert key_1 < key_10

    def test_ips_before_hostnames(self):
        """
        IP addresses should always sort before hostnames.
        In pentest reports, IPs (internal targets) are typically shown first,
        followed by external hostnames.
        """
        ip_key = ip_sort_key("10.0.0.1")
        hostname_key = ip_sort_key("alpha.example.com")
        assert ip_key < hostname_key, "IPs should sort before hostnames"

    def test_hostnames_sort_alphabetically(self):
        """
        Non-IP strings (hostnames) should sort alphabetically among themselves.
        """
        key_alpha = ip_sort_key("alpha.example.com")
        key_beta = ip_sort_key("beta.example.com")
        assert key_alpha < key_beta, "Hostnames should sort alphabetically"

    def test_same_ip_equal_keys(self):
        """The same IP string should produce identical sort keys."""
        assert ip_sort_key("10.0.0.1") == ip_sort_key("10.0.0.1")

    def test_sort_key_in_sorted(self):
        """
        Verify that ip_sort_key works correctly as a key function for sorted().
        This is how it's actually used in the codebase.
        """
        unsorted = ["10.0.0.10", "10.0.0.2", "10.0.0.1", "192.168.1.1"]
        expected = ["10.0.0.1", "10.0.0.2", "10.0.0.10", "192.168.1.1"]
        result = sorted(unsorted, key=ip_sort_key)
        assert result == expected

    def test_mixed_ips_and_hostnames_sorting(self):
        """
        When sorting a mixed list of IPs and hostnames, all IPs should
        appear first (in numeric order), followed by hostnames (alphabetical).
        """
        unsorted = ["beta.com", "10.0.0.2", "alpha.com", "10.0.0.1"]
        result = sorted(unsorted, key=ip_sort_key)
        # IPs first (numeric order), then hostnames (alphabetical)
        assert result == ["10.0.0.1", "10.0.0.2", "alpha.com", "beta.com"]


# ---------------------------------------------------------------------------
# check_caa_records tests
# ---------------------------------------------------------------------------

class TestCheckCaaRecords:
    """Test the check_caa_records() DNS lookup function."""

    def test_nonexistent_domain_returns_empty_list(self):
        """
        A domain that doesn't exist (NXDOMAIN) should return an empty list
        rather than raising an exception.  This is important because during
        a scan, some targets may have invalid DNS entries and we don't want
        the whole scan to crash.
        """
        # Use a domain guaranteed not to exist (RFC 6761 reserved).
        result = check_caa_records("this-domain-does-not-exist.invalid")
        assert result == [], (
            "Nonexistent domain should return empty list, "
            f"got: {result}"
        )

    def test_returns_list_type(self):
        """
        check_caa_records should always return a list, even on failure.
        The caller should be able to iterate over the result without
        type-checking.
        """
        result = check_caa_records("nonexistent.invalid")
        assert isinstance(result, list)


# ---------------------------------------------------------------------------
# batch_resolve_dns tests
# ---------------------------------------------------------------------------

class TestBatchResolveDns:
    """Test the batch_resolve_dns() function."""

    def test_returns_dict(self):
        """
        batch_resolve_dns should always return a dict mapping hostnames
        to IP addresses (or None for failures).
        """
        result = batch_resolve_dns(["nonexistent.invalid"])
        assert isinstance(result, dict)

    def test_unresolvable_hostname_returns_none(self):
        """
        A hostname that cannot be resolved should map to None in the
        result dict, not raise an exception.
        """
        result = batch_resolve_dns(["this-definitely-does-not-exist.invalid"])
        assert result["this-definitely-does-not-exist.invalid"] is None

    def test_empty_list_returns_empty_dict(self):
        """An empty input list should produce an empty dict."""
        result = batch_resolve_dns([])
        assert result == {}

    def test_localhost_resolves(self):
        """
        'localhost' should resolve to 127.0.0.1 on virtually all systems.
        This gives us a reliable test case that doesn't depend on external DNS.
        """
        result = batch_resolve_dns(["localhost"])
        assert result["localhost"] is not None, "localhost should resolve"


# ---------------------------------------------------------------------------
# reverse_dns_lookup tests
# ---------------------------------------------------------------------------

class TestReverseDnsLookup:
    """Test the reverse_dns_lookup() function."""

    def test_returns_string_or_none(self):
        """
        reverse_dns_lookup should return either a hostname string or None.
        It should never raise an exception for valid IP input.
        """
        # Use a private IP that likely has no reverse DNS configured.
        result = reverse_dns_lookup("192.0.2.1")
        assert result is None or isinstance(result, str)

    def test_invalid_ip_returns_none(self):
        """
        An obviously invalid IP should return None without crashing.
        """
        result = reverse_dns_lookup("not-an-ip")
        assert result is None
