"""
webinspector.utils.network - DNS resolution, IP validation, and network utility functions.

This module provides shared network helper functions used across webinspector:

    batch_resolve_dns()   - Forward DNS resolution for a batch of hostnames
    reverse_dns_lookup()  - Reverse DNS (PTR) lookup for a single IP address
    check_caa_records()   - CAA DNS record lookup for certificate authority validation
    is_ip_address()       - Check if a string is a valid IPv4 address
    ip_sort_key()         - Convert IP/hostname strings to sortable tuples

These utilities are used primarily during the pre-scan phase (DNS resolution of
all targets), by the DNS scanner module (CAA record checks), and by the output
renderers (IP-based sorting for reports).

Design decisions:
    - All DNS lookup functions handle errors gracefully — they log warnings and
      return None or empty results rather than raising exceptions.  This is
      critical for scan robustness: a single unresolvable target should not
      crash the entire scan.
    - We use socket.gethostbyname / socket.gethostbyaddr for basic DNS operations
      because they're available everywhere and sufficient for forward/reverse lookups.
    - We use dnspython (dns.resolver) for CAA record lookups because the standard
      library's socket module doesn't support arbitrary DNS record types.

Author: Red Siege Information Security
"""

from __future__ import annotations

import ipaddress
import logging
import socket

# dnspython is used for CAA record lookups — the standard library's socket
# module only supports A/AAAA/PTR lookups, not arbitrary record types.
# dnspython is listed in requirements.txt as 'dnspython>=2.4'.
import dns.resolver
import dns.exception

# ---------------------------------------------------------------------------
# Module-level logger
# ---------------------------------------------------------------------------

# All functions in this module log their errors/warnings through this logger.
# The CLI layer configures the root logger with appropriate handlers.
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# DNS Resolution Functions
# ---------------------------------------------------------------------------

def batch_resolve_dns(hostnames: list[str]) -> dict[str, str | None]:
    """
    Resolve a list of hostnames to their IPv4 addresses.

    Performs a forward DNS lookup (A record) for each hostname and returns
    a dictionary mapping each hostname to its resolved IP address.  If a
    hostname cannot be resolved (NXDOMAIN, timeout, etc.), its value is
    set to None.

    This function is called during the pre-scan phase to populate the
    Target.ip field for hostname-based targets.  Having the IP upfront
    allows numeric sorting in reports and provides context for analysts.

    Args:
        hostnames: A list of hostname strings to resolve (e.g. ["example.com", "web.corp.local"]).

    Returns:
        A dict mapping each hostname to its resolved IPv4 address string,
        or None if resolution failed.  Every input hostname will have an
        entry in the returned dict.

    Example::

        results = batch_resolve_dns(["example.com", "nonexistent.invalid"])
        # results == {"example.com": "93.184.216.34", "nonexistent.invalid": None}
    """
    results: dict[str, str | None] = {}

    for hostname in hostnames:
        try:
            # socket.gethostbyname performs a forward DNS lookup (A record).
            # It returns the first IP address found for the hostname.
            ip = socket.gethostbyname(hostname)
            results[hostname] = ip
            logger.debug("Resolved %s -> %s", hostname, ip)
        except socket.gaierror as exc:
            # gaierror (getaddrinfo error) covers:
            # - NXDOMAIN (hostname doesn't exist)
            # - Temporary DNS failure
            # - No address associated with hostname
            results[hostname] = None
            logger.warning("DNS resolution failed for '%s': %s", hostname, exc)
        except socket.herror as exc:
            # herror covers host-related errors (less common).
            results[hostname] = None
            logger.warning("DNS host error for '%s': %s", hostname, exc)
        except OSError as exc:
            # Catch-all for any other socket-related errors.
            results[hostname] = None
            logger.warning("DNS lookup OS error for '%s': %s", hostname, exc)

    return results


def reverse_dns_lookup(ip_address: str) -> str | None:
    """
    Perform a reverse DNS (PTR) lookup for an IP address.

    Returns the hostname associated with the given IP address, or None
    if no reverse DNS entry exists or the lookup fails.

    This is used during the pre-scan phase to populate the Target.rdns
    field for IP-based targets.  Having the reverse DNS name provides
    useful context in reports — analysts can see which server name is
    associated with each IP address.

    Args:
        ip_address: An IPv4 address string (e.g. "10.0.0.1").

    Returns:
        The reverse DNS hostname string, or None if lookup fails.

    Example::

        hostname = reverse_dns_lookup("8.8.8.8")
        # hostname == "dns.google" (or similar)
    """
    try:
        # socket.gethostbyaddr returns a tuple of (hostname, aliases, addresses).
        # We only care about the primary hostname (index 0).
        hostname, _aliases, _addresses = socket.gethostbyaddr(ip_address)
        logger.debug("Reverse DNS: %s -> %s", ip_address, hostname)
        return hostname
    except socket.herror:
        # herror: host not found — no PTR record exists for this IP.
        # This is very common for internal IPs without reverse DNS configured.
        logger.debug("No reverse DNS found for %s", ip_address)
        return None
    except socket.gaierror as exc:
        # gaierror: address-related error (malformed input, etc.).
        logger.debug("Reverse DNS lookup failed for '%s': %s", ip_address, exc)
        return None
    except OSError as exc:
        # Catch-all for unexpected socket errors.
        logger.debug("Reverse DNS OS error for '%s': %s", ip_address, exc)
        return None


def check_caa_records(domain: str) -> list[str]:
    """
    Query CAA (Certificate Authority Authorization) DNS records for a domain.

    CAA records specify which Certificate Authorities (CAs) are allowed to
    issue certificates for a domain.  This is relevant during SSL/TLS
    assessments because:
    - Missing CAA records mean any CA can issue certificates (finding)
    - CAA records restrict issuance to authorized CAs only (good practice)

    Uses dnspython to query the DNS CAA record type directly.

    Args:
        domain: The domain name to query (e.g. "example.com").

    Returns:
        A list of CAA record strings (e.g. ["0 issue \"letsencrypt.org\""]).
        Returns an empty list if no CAA records exist, the domain doesn't
        exist, or the query times out.

    Example::

        records = check_caa_records("example.com")
        # records == ['0 issue "letsencrypt.org"', '0 issuewild ";"']
    """
    try:
        # Query the DNS for CAA records using dnspython's resolver.
        # CAA is record type 257 in the DNS specification (RFC 8659).
        answers = dns.resolver.resolve(domain, "CAA")

        # Convert each CAA record to its string representation.
        # dnspython's CAA rdata has flags, tag, and value attributes,
        # but the string representation is the most useful for our reports.
        records = [str(record) for record in answers]
        logger.debug("CAA records for %s: %s", domain, records)
        return records

    except dns.resolver.NXDOMAIN:
        # The domain itself does not exist in DNS.
        logger.debug("CAA lookup: domain '%s' does not exist (NXDOMAIN)", domain)
        return []

    except dns.resolver.NoAnswer:
        # The domain exists but has no CAA records.
        # This is the most common case — many domains don't set CAA.
        logger.debug("No CAA records found for %s", domain)
        return []

    except dns.resolver.NoNameservers:
        # No nameservers available to answer the query.
        logger.warning("CAA lookup: no nameservers for '%s'", domain)
        return []

    except dns.exception.Timeout:
        # DNS query timed out — network issue or slow nameserver.
        logger.warning("CAA lookup timed out for '%s'", domain)
        return []

    except dns.exception.DNSException as exc:
        # Catch-all for any other dnspython exception.
        logger.warning("CAA lookup failed for '%s': %s", domain, exc)
        return []


# ---------------------------------------------------------------------------
# IP Address Validation and Sorting
# ---------------------------------------------------------------------------

def is_ip_address(string: str) -> bool:
    """
    Check if a string is a valid IPv4 address.

    This is used throughout webinspector to determine whether a target's
    host field is an IP address or a hostname.  The distinction matters
    because:
    - IP targets need reverse DNS lookups (to find the hostname)
    - Hostname targets need forward DNS lookups (to find the IP)
    - Reports sort IPs numerically but hostnames alphabetically

    Uses Python's ipaddress module for standards-compliant validation
    rather than regex, which is error-prone for edge cases like
    leading zeros, overflow octets, etc.

    Args:
        string: The string to check (e.g. "10.0.0.1" or "example.com").

    Returns:
        True if the string is a valid IPv4 address, False otherwise.

    Example::

        is_ip_address("10.0.0.1")        # True
        is_ip_address("example.com")      # False
        is_ip_address("999.999.999.999")  # False (invalid octets)
    """
    try:
        # ipaddress.IPv4Address validates the string strictly:
        # - Must have exactly 4 octets separated by dots
        # - Each octet must be 0-255
        # - No leading zeros (in strict mode)
        # - No extra characters
        ipaddress.IPv4Address(string)
        return True
    except (ValueError, ipaddress.AddressValueError):
        # ValueError covers malformed strings that can't be parsed.
        # AddressValueError is a subclass of ValueError specific to
        # the ipaddress module, but we catch both for clarity.
        return False


def ip_sort_key(ip_string: str) -> tuple:
    """
    Convert an IP address string to a sortable tuple of integers.

    This function is designed to be used as a key function for sorted()
    or list.sort() when ordering IP addresses and hostnames together.

    Sorting logic:
        - Valid IPv4 addresses are converted to (0, (octet1, octet2, octet3, octet4)).
          The leading 0 ensures all IPs sort before all hostnames.
        - Non-IP strings (hostnames) are converted to (1, (hostname,)).
          The leading 1 pushes them after all IP addresses.

    This two-tier approach gives us:
        1. All IPs first, sorted numerically by each octet (so 10.0.0.2 < 10.0.0.10)
        2. All hostnames after, sorted alphabetically

    Args:
        ip_string: An IP address string ("10.0.0.1") or hostname ("example.com").

    Returns:
        A tuple suitable for comparison/sorting.
        IPs:       (0, (int, int, int, int))
        Hostnames: (1, (hostname_string,))

    Example::

        # Sort a mixed list of IPs and hostnames
        targets = ["beta.com", "10.0.0.2", "alpha.com", "10.0.0.1"]
        sorted(targets, key=ip_sort_key)
        # Result: ["10.0.0.1", "10.0.0.2", "alpha.com", "beta.com"]
    """
    # Attempt to parse the string as an IPv4 address.
    if is_ip_address(ip_string):
        # Split the IP into its four octets and convert each to an integer.
        # This gives us numeric comparison: 10.0.0.2 (2) < 10.0.0.10 (10).
        octets = tuple(int(octet) for octet in ip_string.split("."))
        # Prefix with 0 so all IP addresses sort before hostnames (prefix 1).
        return (0, octets)

    # Not a valid IP address — treat it as a hostname.
    # Prefix with 1 so hostnames sort after all IPs.
    # Wrap in a tuple for consistent comparison with the IP branch.
    return (1, (ip_string,))
