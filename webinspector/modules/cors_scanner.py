"""
webinspector.modules.cors_scanner - CORS misconfiguration scanner module.

Sends HTTP requests with crafted Origin headers to detect Cross-Origin
Resource Sharing (CORS) misconfigurations.  Unlike the header and cookie
scanners that analyze the shared pre-fetched HTTP response, this module
makes its OWN HTTP requests because each test requires a different Origin
header.

CORS misconfigurations are a common source of data theft vulnerabilities.
When a server reflects the Origin header in Access-Control-Allow-Origin
(ACAO) without proper validation, an attacker can craft a malicious page
that makes cross-origin requests to the target on behalf of a victim.  If
Access-Control-Allow-Credentials (ACAC) is also set to "true", the
victim's cookies (session tokens, auth cookies) are included in the
cross-origin request, allowing the attacker to steal authenticated data.

Attack vectors tested:
    1. Arbitrary origin reflection (https://evil.com)
       - Tests if the server blindly reflects any Origin header.
       - This is the most basic and most dangerous CORS misconfiguration.
       - Vulnerable regex pattern: Origin header reflected without check.

    2. Null origin (Origin: null)
       - Tests if the server allows the "null" origin.
       - The null origin is sent by browsers in several scenarios:
         * Requests from sandboxed iframes (<iframe sandbox>)
         * Requests from data: URIs
         * Requests from file:// origins
         * Redirects across origins
       - Attackers can trigger the null origin using sandboxed iframes.

    3. Subdomain hijack pattern (https://evil.target.com)
       - Tests if the server's CORS policy uses suffix matching, e.g.
         checking if the origin ends with ".target.com" but not verifying
         the full subdomain chain.
       - If the target has a dangling DNS record or weak subdomain takeover
         protections, an attacker can register evil.target.com and bypass
         the CORS policy.
       - Vulnerable regex: /\\.example\\.com$/ (matches evil.example.com)

    4. Post-domain bypass (https://target.com.evil.com)
       - Tests if the server's CORS policy uses prefix matching, e.g.
         checking if the origin starts with "target.com" but not verifying
         the domain boundary.
       - An attacker can register target.com.evil.com (their own domain)
         and bypass the CORS policy.
       - Vulnerable regex: /^https?:\\/\\/target\\.com/ (no $ anchor)

Severity model:
    - HIGH:   Origin reflected AND Access-Control-Allow-Credentials: true
              (attacker can steal authenticated data cross-origin)
    - MEDIUM: Origin reflected WITHOUT credentials
              (attacker can read cross-origin responses but without cookies)

CWE References:
    - CWE-942: Permissive Cross-domain Policy with Untrusted Domains
    - CWE-346: Origin Validation Error

Author: Red Siege Information Security
"""

import logging
from typing import Optional

from requests import Response

from webinspector.core.target import Target
from webinspector.core.result import Finding, Severity
from webinspector.modules.base import ScanModule
from webinspector.modules import register_module
from webinspector.utils.http import create_http_session

# Module-level logger for debug / error messages during CORS probing.
logger = logging.getLogger(__name__)


class CORSScanner(ScanModule):
    """
    CORS misconfiguration scanner.

    Sends HTTP requests with crafted Origin headers to detect permissive
    CORS policies.  This module makes its own HTTP requests rather than
    relying on the shared pre-fetched response, because each CORS test
    requires a different Origin header to be sent.

    The module still receives the http_response parameter from the
    orchestrator (for interface consistency) but does not use it.

    Accepts both HTTP and HTTPS targets (the default accepts_target
    behaviour from the base class).
    """

    # -----------------------------------------------------------------
    # ScanModule interface -- required properties
    # -----------------------------------------------------------------

    @property
    def name(self) -> str:
        """Short identifier used in CLI flags and finding output."""
        return "cors"

    @property
    def description(self) -> str:
        """Human-readable description for --help output."""
        return "CORS misconfiguration detection (origin reflection, null origin, bypass patterns)"

    # -----------------------------------------------------------------
    # ScanModule interface -- main scan method
    # -----------------------------------------------------------------

    def scan(
        self,
        target: Target,
        http_response: Optional[Response] = None,
    ) -> list[Finding]:
        """
        Probe the target for CORS misconfigurations using crafted origins.

        This method:
            1. Creates an HTTP session for making requests
            2. Builds a list of crafted Origin headers to test
            3. Sends a request for each crafted origin
            4. Checks if the server reflects the crafted origin in ACAO
            5. Checks if ACAC: true is also set (escalates severity)
            6. Returns a list of findings for all detected misconfigurations

        Each crafted origin test is independent -- if one request fails
        (connection error, timeout), the remaining tests still run.

        Args:
            target:        The target to scan.  Uses target.url for requests
                           and target.host for constructing bypass origins.
            http_response: Pre-fetched HTTP response from the orchestrator.
                           NOT USED by this module (we make our own requests).
                           Accepted for interface consistency with ScanModule.

        Returns:
            List of Finding objects.  Empty list means no CORS
            misconfigurations were detected.
        """
        findings: list[Finding] = []

        # --- Create an HTTP session for our CORS probes ---
        # We create a fresh session with a 10-second timeout.
        # The session provides retry logic and consistent headers.
        session, timeout = create_http_session(timeout=10)

        # --- Build the list of crafted origins to test ---
        # Each entry is a tuple of (crafted_origin, finding_type, title_prefix)
        # that maps the origin to the finding metadata if reflected.
        #
        # We use the target's scheme for subdomain and postdomain bypasses
        # so the crafted origin matches the protocol of the target.  For the
        # arbitrary origin test we always use https://evil.com.
        crafted_origins = self._build_crafted_origins(target)

        # --- Test each crafted origin ---
        for crafted_origin, finding_type, title, detail_template in crafted_origins:
            # Send a request with the crafted Origin header and check
            # if the server reflects it in Access-Control-Allow-Origin.
            finding = self._test_origin(
                session=session,
                target=target,
                timeout=timeout,
                crafted_origin=crafted_origin,
                finding_type=finding_type,
                title=title,
                detail_template=detail_template,
            )
            if finding is not None:
                findings.append(finding)

        return findings

    # -----------------------------------------------------------------
    # Private methods -- build crafted origins
    # -----------------------------------------------------------------

    def _build_crafted_origins(self, target: Target) -> list[tuple[str, str, str, str]]:
        """
        Build the list of crafted Origin headers to test against the target.

        Each entry is a tuple of:
            (crafted_origin, finding_type, title, detail_template)

        The detail_template contains a {severity_note} placeholder that
        will be filled in based on whether credentials are reflected.

        Args:
            target: The scan target, used to construct domain-specific
                    bypass origins (subdomain and post-domain patterns).

        Returns:
            List of 4-tuples, one per crafted origin to test.
        """
        # Determine the scheme prefix for domain-based bypass origins.
        # We match the target's scheme so the crafted origin looks natural
        # to the server's CORS validation logic.
        scheme = target.scheme

        return [
            # --- Test 1: Arbitrary origin reflection ---
            # Send Origin: https://evil.com to check if the server
            # reflects any arbitrary origin.  This is the most basic
            # and most dangerous CORS misconfiguration.
            (
                "https://evil.com",
                "origin_reflection",
                "CORS Arbitrary Origin Reflection",
                (
                    "The server reflects arbitrary origins in "
                    "Access-Control-Allow-Origin. Crafted origin "
                    "'https://evil.com' was reflected{severity_note}"
                ),
            ),

            # --- Test 2: Null origin acceptance ---
            # Send Origin: null to check if the server allows the null
            # origin.  This is exploitable via sandboxed iframes, data:
            # URIs, and cross-origin redirects.
            (
                "null",
                "null_origin",
                "CORS Null Origin Allowed",
                (
                    "The server allows the 'null' origin in "
                    "Access-Control-Allow-Origin. Null origin can be "
                    "triggered via sandboxed iframes, data: URIs, and "
                    "cross-origin redirects{severity_note}"
                ),
            ),

            # --- Test 3: Subdomain hijack bypass ---
            # Send Origin: https://evil.target.com to check if the server
            # uses weak suffix-based origin matching.
            (
                f"{scheme}://evil.{target.host}",
                "subdomain_bypass",
                "CORS Subdomain Bypass",
                (
                    f"The server reflects subdomain-crafted origins in "
                    f"Access-Control-Allow-Origin. Crafted origin "
                    f"'{scheme}://evil.{target.host}' was reflected. "
                    f"This suggests weak suffix-based origin validation"
                    "{severity_note}"
                ),
            ),

            # --- Test 4: Post-domain bypass ---
            # Send Origin: https://target.com.evil.com to check if the
            # server uses weak prefix-based origin matching.
            (
                f"{scheme}://{target.host}.evil.com",
                "postdomain_bypass",
                "CORS Post-Domain Bypass",
                (
                    f"The server reflects post-domain crafted origins in "
                    f"Access-Control-Allow-Origin. Crafted origin "
                    f"'{scheme}://{target.host}.evil.com' was reflected. "
                    f"This suggests weak prefix-based origin validation"
                    "{severity_note}"
                ),
            ),
        ]

    # -----------------------------------------------------------------
    # Private methods -- test a single crafted origin
    # -----------------------------------------------------------------

    def _test_origin(
        self,
        session,
        target: Target,
        timeout: int,
        crafted_origin: str,
        finding_type: str,
        title: str,
        detail_template: str,
    ) -> Optional[Finding]:
        """
        Send a request with a crafted Origin header and check if the
        server reflects it in Access-Control-Allow-Origin.

        This method handles connection errors gracefully -- if the request
        fails for any reason, it logs the error and returns None (no finding).

        Args:
            session:         The requests.Session to use for the HTTP request.
            target:          The scan target (provides .url for the request).
            timeout:         Request timeout in seconds.
            crafted_origin:  The Origin header value to send (e.g. "https://evil.com").
            finding_type:    The finding_type string for the Finding object.
            title:           The title string for the Finding object.
            detail_template: The detail template string.  Contains {severity_note}
                             placeholder that will be replaced with a credentials note.

        Returns:
            A Finding object if the crafted origin was reflected, or None if
            the origin was not reflected or the request failed.
        """
        try:
            # Send the GET request with the crafted Origin header.
            # We disable SSL verification because we're a security scanner
            # that needs to connect to servers with invalid certificates.
            resp = session.get(
                target.url,
                headers={"Origin": crafted_origin},
                timeout=timeout,
                verify=False,
            )

            # --- Extract CORS response headers ---
            # Access-Control-Allow-Origin (ACAO): the origin the server allows.
            # Access-Control-Allow-Credentials (ACAC): whether cookies are sent.
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()

            # --- Check if the crafted origin was reflected ---
            # We compare the ACAO value against the exact crafted origin.
            # A wildcard ("*") does NOT count as reflection -- it's a different
            # (and less dangerous) configuration.
            if acao == crafted_origin:
                # Determine severity based on whether credentials are allowed.
                # ACAC: true means the attacker can make credentialed cross-origin
                # requests, which is strictly more dangerous than without credentials.
                if acac == "true":
                    severity = Severity.HIGH
                    severity_note = " with Access-Control-Allow-Credentials: true (HIGH risk: authenticated data theft possible)"
                else:
                    severity = Severity.MEDIUM
                    severity_note = " without credentials (MEDIUM risk: cross-origin reads possible)"

                # Build the finding with the severity-specific detail.
                return Finding(
                    module="cors",
                    finding_type=finding_type,
                    severity=severity,
                    target=target,
                    title=title,
                    detail=detail_template.format(severity_note=severity_note),
                    references=["CWE-942", "CWE-346"],
                )

        except Exception as exc:
            # Catch ANY exception from the HTTP request.  This includes
            # ConnectionError, Timeout, TooManyRedirects, and any other
            # unexpected error.  We log it and continue to the next test
            # rather than crashing the entire scan.
            logger.debug(
                "CORS probe failed for %s with Origin '%s': %s",
                target.url,
                crafted_origin,
                exc,
            )

        # Origin was not reflected, or the request failed -- no finding.
        return None


# ---------------------------------------------------------------------------
# Module registration
# ---------------------------------------------------------------------------
# Instantiate the scanner and register it with the module registry.
# This runs at import time, so importing this file is sufficient to make
# the CORS scanner available to the orchestrator.

register_module(CORSScanner())
