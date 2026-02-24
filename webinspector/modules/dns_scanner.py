"""
webinspector.modules.dns_scanner - DNS security scanner module.

Checks DNS configuration for security-relevant records and reverse DNS
information.  This module performs two categories of checks:

    1. CAA (Certificate Authority Authorization) record checks
       - Queries the domain's CAA DNS records using dnspython.
       - Missing CAA records are reported as LOW severity findings because
         without CAA, any Certificate Authority can issue certificates for
         the domain.  This weakens the defence-in-depth posture of the
         domain's TLS/SSL infrastructure.
       - Present CAA records are reported as INFORMATIONAL findings that
         log the records for analyst awareness.  This helps verify that
         the domain owner has configured certificate issuance restrictions.

    2. Reverse DNS (PTR) lookups for IP-address targets
       - When the target is an IP address, performs a reverse DNS lookup
         to discover the hostname associated with that IP.
       - Populates the target's rdns field so that downstream modules
         and output renderers can display the hostname alongside the IP.
       - Reports the resolved hostname as an INFORMATIONAL finding for
         analyst context.

Deduplication:
    CAA records are a property of the domain, not the port or scheme.
    If multiple targets share the same base domain (e.g., https://example.com:443
    and https://example.com:8443), the CAA check is only performed once.
    The scanner tracks which domains have already been checked in a set
    that persists across calls to scan() within the same DNSScanner instance.

Design decisions:
    - CAA checks are skipped for IP-address targets because CAA records
      are associated with domain names, not IP addresses.
    - Reverse DNS lookups are only performed for IP-address targets because
      hostname targets already have a domain name.
    - All DNS query errors are caught and logged gracefully.  A DNS failure
      should not crash the scan or prevent other checks from running.
    - The module uses utility functions from webinspector.utils.network
      rather than making DNS queries directly, keeping the DNS logic
      centralized and testable.

Finding types:
    - missing_caa:  Domain has no CAA records (LOW severity)
    - caa_records:  Domain has CAA records (INFORMATIONAL, logs the records)
    - reverse_dns:  IP target resolves to a hostname (INFORMATIONAL)

Author: Red Siege Information Security
"""

from __future__ import annotations

import logging
from typing import Optional

from requests import Response

from webinspector.core.target import Target
from webinspector.core.result import Finding, Severity
from webinspector.modules.base import ScanModule
from webinspector.modules import register_module

# Import DNS utility functions from the shared network module.
# These wrap dnspython and socket calls with proper error handling.
from webinspector.utils.network import (
    check_caa_records,
    reverse_dns_lookup,
    is_ip_address,
)

# ---------------------------------------------------------------------------
# Module-level logger
# ---------------------------------------------------------------------------
# All log messages from this module are emitted through this logger.
# The CLI layer configures the root logger with appropriate handlers
# and verbosity levels.
logger = logging.getLogger(__name__)


class DNSScanner(ScanModule):
    """
    DNS security scanner module.

    Checks CAA records for hostname targets and performs reverse DNS
    lookups for IP-address targets.  Deduplicates CAA checks so that
    the same domain is only queried once, even when multiple targets
    share the same base domain (different ports or schemes).

    Accepts both HTTP and HTTPS targets (the default accepts_target
    behaviour from the base class).
    """

    def __init__(self) -> None:
        """
        Initialize the DNS scanner with an empty deduplication set.

        The _checked_domains set tracks which domains have already had
        their CAA records checked.  This persists across scan() calls
        within the same DNSScanner instance, preventing duplicate DNS
        queries when the orchestrator scans multiple targets that share
        the same domain (e.g., example.com:443 and example.com:8443).
        """
        # Set of domain strings that have already been checked for CAA records.
        # Populated by _check_caa() and consulted before each CAA query.
        self._checked_domains: set[str] = set()

    # -----------------------------------------------------------------
    # ScanModule interface -- required properties
    # -----------------------------------------------------------------

    @property
    def name(self) -> str:
        """Short identifier used in CLI flags and finding output."""
        return "dns"

    @property
    def description(self) -> str:
        """Human-readable description for --help output."""
        return "DNS security checks (CAA records, reverse DNS lookups)"

    # -----------------------------------------------------------------
    # ScanModule interface -- main scan method
    # -----------------------------------------------------------------

    def scan(
        self,
        target: Target,
        http_response: Optional[Response] = None,
    ) -> list[Finding]:
        """
        Run DNS security checks against a single target.

        This method performs two independent checks:
            1. CAA record check (for hostname targets only, deduplicated)
            2. Reverse DNS lookup (for IP-address targets only)

        Each check is wrapped in its own try/except to ensure that a
        failure in one check does not prevent the other from running.

        Args:
            target:
                The scan target.  The host field determines what checks
                are performed:
                - Hostname -> CAA check (if not already done for this domain)
                - IP address -> Reverse DNS lookup

            http_response:
                Pre-fetched HTTP response from the orchestrator.
                NOT USED by this module (DNS checks don't need HTTP data).
                Accepted for interface consistency with ScanModule.

        Returns:
            List of Finding objects.  May contain:
            - One CAA finding (missing_caa or caa_records) for hostname targets
            - One reverse_dns finding for IP targets with PTR records
            - Empty list if no relevant checks apply or DNS queries fail
        """
        findings: list[Finding] = []

        # --- Determine if the target host is an IP address or a hostname ---
        # This determines which checks we run: CAA for hostnames, rDNS for IPs.
        target_is_ip = is_ip_address(target.host)

        # --- CAA record check (hostname targets only) ---
        # CAA records are a property of the domain name, so they only make
        # sense for hostname targets.  IP addresses don't have CAA records.
        if not target_is_ip:
            caa_finding = self._check_caa(target)
            if caa_finding is not None:
                findings.append(caa_finding)

        # --- Reverse DNS lookup (IP targets only) ---
        # Only IP-address targets need reverse DNS -- hostname targets
        # already have a domain name, so rDNS would be redundant.
        if target_is_ip:
            rdns_finding = self._check_reverse_dns(target)
            if rdns_finding is not None:
                findings.append(rdns_finding)

        return findings

    # -----------------------------------------------------------------
    # Private methods -- CAA record checking
    # -----------------------------------------------------------------

    def _check_caa(self, target: Target) -> Optional[Finding]:
        """
        Check CAA DNS records for the target's domain.

        Performs deduplication: if the domain has already been checked
        by this scanner instance, returns None immediately without
        querying DNS again.

        Args:
            target: The scan target with a hostname (not IP) in target.host.

        Returns:
            - A Finding with finding_type='missing_caa' (LOW) if no CAA records exist.
            - A Finding with finding_type='caa_records' (INFORMATIONAL) if CAA records
              are present, with the records listed in the detail string.
            - None if the domain was already checked (deduplication) or if the
              DNS query raised an unexpected exception.
        """
        domain = target.host

        # --- Deduplication check ---
        # If we've already checked this domain, skip it.  This prevents
        # duplicate CAA queries and duplicate findings when multiple targets
        # share the same base domain (e.g., example.com:443 and example.com:8443).
        if domain in self._checked_domains:
            logger.debug(
                "CAA already checked for '%s', skipping duplicate check", domain
            )
            return None

        # Mark this domain as checked BEFORE the query to handle the case
        # where the query fails -- we still don't want to retry it.
        self._checked_domains.add(domain)

        try:
            # Query CAA records using the shared utility function.
            # Returns a list of CAA record strings, or an empty list if
            # no records exist (or the query fails gracefully).
            records = check_caa_records(domain)

            if not records:
                # --- No CAA records found ---
                # This is a LOW severity finding because any Certificate
                # Authority can issue certificates for this domain.
                # While not an active vulnerability, it weakens the
                # defence-in-depth posture of the domain's TLS configuration.
                logger.debug("No CAA records for '%s' -- reporting as LOW", domain)
                return Finding(
                    module="dns",
                    finding_type="missing_caa",
                    severity=Severity.LOW,
                    target=target,
                    title="Missing CAA Records",
                    detail=(
                        f"No CAA (Certificate Authority Authorization) records "
                        f"found for {domain}. Without CAA records, any "
                        f"Certificate Authority can issue certificates for "
                        f"this domain."
                    ),
                    references=["RFC 8659"],
                )
            else:
                # --- CAA records are present ---
                # This is an INFORMATIONAL finding.  We log the records
                # so the analyst can verify they are configured correctly.
                # Join the records into a readable, comma-separated string.
                records_str = "; ".join(records)
                logger.debug(
                    "CAA records found for '%s': %s", domain, records_str
                )
                return Finding(
                    module="dns",
                    finding_type="caa_records",
                    severity=Severity.INFORMATIONAL,
                    target=target,
                    title="CAA Records Present",
                    detail=(
                        f"CAA records for {domain}: {records_str}"
                    ),
                    references=["RFC 8659"],
                )

        except Exception as exc:
            # Catch any unexpected exception from the CAA query.
            # The utility function already handles common DNS errors
            # (NXDOMAIN, NoAnswer, Timeout) and returns an empty list.
            # This catch-all is a safety net for truly unexpected errors
            # that should not crash the scan.
            logger.warning(
                "Unexpected error checking CAA records for '%s': %s",
                domain, exc,
            )
            return None

    # -----------------------------------------------------------------
    # Private methods -- reverse DNS lookup
    # -----------------------------------------------------------------

    def _check_reverse_dns(self, target: Target) -> Optional[Finding]:
        """
        Perform a reverse DNS (PTR) lookup for an IP-address target.

        If a hostname is resolved, populates target.rdns so that
        downstream modules and output renderers can display the
        hostname alongside the IP address.

        Args:
            target: The scan target with an IP address in target.host.

        Returns:
            - A Finding with finding_type='reverse_dns' (INFORMATIONAL) if
              a hostname was resolved, containing both the IP and hostname.
            - None if no PTR record exists or the lookup fails.
        """
        ip = target.host

        try:
            # Perform the reverse DNS lookup using the shared utility function.
            # Returns the hostname string or None if no PTR record exists.
            hostname = reverse_dns_lookup(ip)

            if hostname is not None:
                # --- PTR record found ---
                # Populate the target's rdns field so downstream components
                # (output renderers, other modules) can use the hostname.
                target.rdns = hostname

                logger.debug("Reverse DNS: %s -> %s", ip, hostname)
                return Finding(
                    module="dns",
                    finding_type="reverse_dns",
                    severity=Severity.INFORMATIONAL,
                    target=target,
                    title="Reverse DNS",
                    detail=(
                        f"IP address {ip} resolves to {hostname} via "
                        f"reverse DNS (PTR record)"
                    ),
                )
            else:
                # No PTR record -- this is common and not worth reporting.
                logger.debug("No reverse DNS (PTR) record for %s", ip)
                return None

        except Exception as exc:
            # Catch any unexpected exception from the rDNS lookup.
            # The utility function already handles common socket errors
            # (herror, gaierror, OSError) and returns None.
            # This catch-all is a safety net for truly unexpected errors.
            logger.warning(
                "Unexpected error during reverse DNS for '%s': %s",
                ip, exc,
            )
            return None


# ---------------------------------------------------------------------------
# Module registration
# ---------------------------------------------------------------------------
# Instantiate the scanner and register it with the module registry.
# This runs at import time, so importing this file is sufficient to make
# the DNS scanner available to the orchestrator.

register_module(DNSScanner())
