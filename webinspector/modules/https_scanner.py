"""
webinspector.modules.https_scanner - HTTPS enforcement and redirect scanner module.

Checks whether HTTP targets properly redirect to HTTPS and whether HTTPS targets
have a well-configured Strict-Transport-Security (HSTS) header.  This module
complements the header_scanner's basic HSTS check by performing deeper analysis:

    1. HTTP-to-HTTPS redirect checking (unique to this module):
       - Requests the http:// version of the target with allow_redirects=False
         to inspect each hop of the redirect chain individually.
       - No redirect at all = MEDIUM finding (traffic can be intercepted).
       - Non-permanent redirect (302/303/307) instead of 301 = INFORMATIONAL.
       - Redirect chain longer than 2 hops = LOW (excessive latency).

    2. HSTS quality analysis (detailed checks unique to this module):
       - Missing HSTS on HTTPS targets = MEDIUM.
       - max-age below 31536000 (1 year) = LOW.
       - Missing includeSubDomains directive = LOW.
       - Missing preload directive = INFORMATIONAL.

The header_scanner also checks for missing HSTS.  When both modules run, there
may be duplicate HSTS findings -- this is acceptable because users can use
--only to select one module.

Design decisions:
    - This module makes its OWN HTTP requests for redirect checking because
      the orchestrator's pre-fetched response follows redirects automatically.
      We need allow_redirects=False to inspect each redirect hop individually.
    - For HSTS analysis, we prefer the pre-fetched response (if available) to
      avoid making an extra request.  If the pre-fetched response is not
      available (e.g., the orchestrator couldn't reach the target), we fall
      back to making our own request.
    - The redirect chain is followed manually with a maximum hop limit (10)
      to prevent infinite redirect loops from hanging the scan.
    - Both HTTP and HTTPS targets are accepted.  HTTP targets get redirect
      checks; HTTPS targets get HSTS quality checks.

CWE References:
    - CWE-319: Cleartext Transmission of Sensitive Information
    - CWE-311: Missing Encryption of Sensitive Data

Author: Red Siege Information Security
"""

import logging
import re
from typing import Optional

from requests import Response

from webinspector.core.target import Target
from webinspector.core.result import Finding, Severity
from webinspector.modules.base import ScanModule
from webinspector.modules import register_module
from webinspector.utils.http import create_http_session

# Module-level logger for debug / error messages during HTTPS enforcement checks.
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Minimum HSTS max-age value in seconds.  31536000 = 1 year.
# OWASP and HSTS preload requirements both specify 1 year as the minimum.
# Shorter durations provide weaker protection because the browser's HSTS
# cache expires quickly if the user doesn't revisit the site frequently.
_HSTS_MIN_MAX_AGE = 31536000

# Maximum number of redirect hops before we give up.
# This prevents infinite redirect loops from hanging the scan.
# 10 is generous -- most legitimate redirect chains are 1-3 hops.
_MAX_REDIRECT_HOPS = 10

# Redirect chain length threshold for the "excessive redirects" finding.
# Chains longer than this value produce a LOW severity finding.
# 2 hops is the threshold: e.g., http:// -> http://www. -> https://www.
# is acceptable, but 3+ hops indicates unnecessary complexity.
_EXCESSIVE_REDIRECT_THRESHOLD = 2

# HTTP status codes that indicate a redirect response.
# These are the standard redirect codes defined in RFC 7231 and RFC 7538:
#   301 Moved Permanently  -- the ideal redirect for HTTP-to-HTTPS
#   302 Found              -- temporary redirect (legacy "Moved Temporarily")
#   303 See Other          -- redirect after POST (always changes to GET)
#   307 Temporary Redirect -- temporary redirect (preserves method)
#   308 Permanent Redirect -- permanent redirect (preserves method)
_REDIRECT_STATUS_CODES = {301, 302, 303, 307, 308}

# Status codes that represent a permanent redirect.
# 301 and 308 both indicate "this resource has permanently moved".
# 301 may change the method to GET; 308 preserves the original method.
# For HTTP-to-HTTPS redirects, 301 is the standard recommendation.
_PERMANENT_REDIRECT_CODES = {301, 308}


class HTTPSScanner(ScanModule):
    """
    HTTPS enforcement and redirect quality scanner.

    Checks HTTP targets for proper redirect to HTTPS and HTTPS targets
    for well-configured HSTS headers.  Makes its own HTTP requests for
    redirect checking (with allow_redirects=False to inspect each hop)
    and uses the pre-fetched response for HSTS analysis when available.

    Accepts both HTTP and HTTPS targets (the default accepts_target
    behaviour from the base class):
        - HTTP targets  -> redirect chain analysis
        - HTTPS targets -> HSTS quality analysis
    """

    # -----------------------------------------------------------------
    # ScanModule interface -- required properties
    # -----------------------------------------------------------------

    @property
    def name(self) -> str:
        """Short identifier used in CLI flags and finding output."""
        return "https"

    @property
    def description(self) -> str:
        """Human-readable description for --help output."""
        return "HTTPS enforcement checks (redirect quality, HSTS analysis)"

    # -----------------------------------------------------------------
    # ScanModule interface -- main scan method
    # -----------------------------------------------------------------

    def scan(
        self,
        target: Target,
        http_response: Optional[Response] = None,
    ) -> list[Finding]:
        """
        Check HTTPS enforcement for the given target.

        For HTTP targets:
            - Request the http:// URL with allow_redirects=False
            - Follow the redirect chain manually, inspecting each hop
            - Check for: missing redirect, non-permanent redirect, excessive chain

        For HTTPS targets:
            - Analyse the HSTS header from the pre-fetched response (or make
              our own request if no pre-fetched response is available)
            - Check for: missing HSTS, short max-age, missing includeSubDomains,
              missing preload

        Args:
            target:        The target to scan.  Uses target.scheme to determine
                           which checks to run (HTTP vs HTTPS).
            http_response: Pre-fetched HTTP response from the orchestrator.
                           Used for HSTS analysis on HTTPS targets.  May be None
                           if the target was unreachable.

        Returns:
            List of Finding objects.  Empty list means no issues found.
        """
        findings: list[Finding] = []

        # --- Create an HTTP session for our own requests ---
        # Used for redirect checking (HTTP targets) and as a fallback for
        # HSTS checking when no pre-fetched response is available.
        session, timeout = create_http_session(timeout=10)

        # --- Branch based on target scheme ---
        if target.scheme == "http":
            # HTTP target: check for redirect to HTTPS.
            # HSTS is NOT checked on HTTP targets because browsers ignore
            # HSTS headers received over insecure connections.
            findings.extend(
                self._check_redirect_chain(session, target, timeout)
            )
        else:
            # HTTPS target: check HSTS header quality.
            # Use the pre-fetched response if available; otherwise make
            # our own request to get the HSTS header.
            hsts_response = http_response
            if hsts_response is None:
                # No pre-fetched response -- make our own request.
                hsts_response = self._fetch_https_response(
                    session, target, timeout
                )

            if hsts_response is not None:
                findings.extend(
                    self._check_hsts_quality(target, hsts_response)
                )

        return findings

    # -----------------------------------------------------------------
    # Private methods -- redirect chain analysis (HTTP targets)
    # -----------------------------------------------------------------

    def _check_redirect_chain(
        self,
        session,
        target: Target,
        timeout: int,
    ) -> list[Finding]:
        """
        Follow the redirect chain from an HTTP target and analyse each hop.

        Makes sequential HTTP requests with allow_redirects=False to inspect
        each redirect response individually.  Tracks:
            - Whether the chain reaches HTTPS at all
            - Whether the first redirect uses a permanent status code (301/308)
            - How many hops are in the chain

        The chain is followed up to _MAX_REDIRECT_HOPS to prevent infinite
        redirect loops.  Each hop's Location header is used as the URL for
        the next request.

        Args:
            session: The requests.Session for making HTTP requests.
            target:  The HTTP target being scanned.
            timeout: Request timeout in seconds.

        Returns:
            List of Finding objects for redirect issues found.
        """
        findings: list[Finding] = []

        # --- Follow the redirect chain manually ---
        # Start with the HTTP URL and follow Location headers until we
        # reach a non-redirect response or an HTTPS URL.
        current_url = target.url
        hop_count = 0
        reached_https = False
        first_redirect_status = None
        non_permanent_statuses = []

        try:
            for _ in range(_MAX_REDIRECT_HOPS):
                # Make the request with allow_redirects=False so we can
                # inspect the redirect response itself.
                resp = session.get(
                    current_url,
                    timeout=timeout,
                    verify=False,
                    allow_redirects=False,
                )

                # Check if this is a redirect response.
                if resp.status_code in _REDIRECT_STATUS_CODES:
                    hop_count += 1

                    # Record the first redirect status code for permanent
                    # vs temporary analysis.
                    if first_redirect_status is None:
                        first_redirect_status = resp.status_code

                    # Track all non-permanent redirect status codes.
                    if resp.status_code not in _PERMANENT_REDIRECT_CODES:
                        non_permanent_statuses.append(resp.status_code)

                    # Get the Location header to follow the redirect.
                    location = resp.headers.get("Location", "")

                    # Check if the redirect target is HTTPS.
                    if location.lower().startswith("https://"):
                        reached_https = True
                        break

                    # Follow the redirect to the next URL.
                    current_url = location
                else:
                    # Not a redirect -- the chain ends here without HTTPS.
                    break

        except Exception as exc:
            # Connection error, timeout, or other failure during redirect
            # following.  Log and return empty findings (can't determine
            # redirect behaviour if we can't connect).
            logger.debug(
                "Redirect check failed for %s: %s",
                target.url,
                exc,
            )
            return findings

        # --- Analyse the redirect chain results ---

        # Check 1: No redirect to HTTPS at all.
        # If the chain never reached an HTTPS URL, the target does not
        # enforce HTTPS.  This is a MEDIUM finding because traffic can
        # be intercepted in transit via a man-in-the-middle attack.
        if not reached_https:
            findings.append(Finding(
                module="https",
                finding_type="no_https_redirect",
                severity=Severity.MEDIUM,
                target=target,
                title="No HTTP-to-HTTPS Redirect",
                detail=(
                    f"The HTTP target {target.hostport} does not redirect to "
                    f"HTTPS. Traffic to this host over HTTP can be intercepted "
                    f"by a man-in-the-middle attacker"
                ),
                references=["CWE-319"],
            ))
            # If there's no redirect at all, the other redirect checks
            # are not applicable (no chain to analyse).
            if hop_count == 0:
                return findings

        # Check 2: Non-permanent redirect (302/303/307 instead of 301).
        # A temporary redirect means browsers and search engines won't
        # cache the redirect decision permanently.  Users may still visit
        # the HTTP version on subsequent requests.
        if non_permanent_statuses and reached_https:
            # Only flag if the redirect does eventually reach HTTPS.
            # If it doesn't reach HTTPS at all, the no_https_redirect
            # finding is more important.
            status_str = ", ".join(str(s) for s in non_permanent_statuses)
            findings.append(Finding(
                module="https",
                finding_type="non_permanent_redirect",
                severity=Severity.INFORMATIONAL,
                target=target,
                title="Non-Permanent HTTP-to-HTTPS Redirect",
                detail=(
                    f"The HTTP-to-HTTPS redirect uses non-permanent status "
                    f"code(s): {status_str}. A 301 (Moved Permanently) redirect "
                    f"is recommended so browsers and search engines cache the "
                    f"redirect decision permanently"
                ),
                references=["CWE-319"],
            ))

        # Check 3: Excessive redirect chain (more than 2 hops).
        # Long redirect chains add latency and complexity.  Most sites
        # need at most 2 hops: http:// -> http://www. -> https://www.
        if hop_count > _EXCESSIVE_REDIRECT_THRESHOLD:
            findings.append(Finding(
                module="https",
                finding_type="excessive_redirect_chain",
                severity=Severity.LOW,
                target=target,
                title="Excessive HTTP-to-HTTPS Redirect Chain",
                detail=(
                    f"The HTTP-to-HTTPS redirect chain has {hop_count} hops, "
                    f"which exceeds the recommended maximum of "
                    f"{_EXCESSIVE_REDIRECT_THRESHOLD}. Each additional redirect "
                    f"adds latency and increases the attack surface"
                ),
                references=["CWE-319"],
            ))

        return findings

    # -----------------------------------------------------------------
    # Private methods -- HSTS quality analysis (HTTPS targets)
    # -----------------------------------------------------------------

    def _check_hsts_quality(
        self,
        target: Target,
        response: Response,
    ) -> list[Finding]:
        """
        Analyse the Strict-Transport-Security header on an HTTPS response.

        Performs four checks:
            1. Missing HSTS header entirely (MEDIUM)
            2. max-age below 1 year / 31536000 seconds (LOW)
            3. Missing includeSubDomains directive (LOW)
            4. Missing preload directive (INFORMATIONAL)

        Args:
            target:   The HTTPS target being scanned.
            response: The HTTP response to analyse (either pre-fetched or
                      from our own request).

        Returns:
            List of Finding objects for HSTS quality issues.
        """
        findings: list[Finding] = []

        # Extract the HSTS header value.
        # requests.Response.headers is a CaseInsensitiveDict, but mock
        # objects may use a plain dict.  We use .get() for both.
        hsts_value = self._get_header(response.headers, "Strict-Transport-Security")

        # --- Check 1: Missing HSTS ---
        # Without HSTS, browsers may connect over plain HTTP on subsequent
        # visits, allowing protocol downgrade attacks (e.g., sslstrip).
        if hsts_value is None:
            findings.append(Finding(
                module="https",
                finding_type="missing_hsts",
                severity=Severity.MEDIUM,
                target=target,
                title="Missing Strict-Transport-Security (HSTS)",
                detail=(
                    "Strict-Transport-Security header is not set on this "
                    "HTTPS target. Without HSTS, browsers may connect over "
                    "plain HTTP, allowing protocol downgrade attacks "
                    "(e.g., sslstrip)"
                ),
                references=["CWE-319"],
            ))
            # No point checking quality if the header is missing entirely.
            return findings

        # HSTS is present -- check quality directives.
        hsts_lower = hsts_value.lower()

        # --- Check 2: Short max-age ---
        # Parse the max-age value from the HSTS header.
        # Format: max-age=<seconds>[; includeSubDomains][; preload]
        max_age = self._parse_hsts_max_age(hsts_value)
        if max_age is not None and max_age < _HSTS_MIN_MAX_AGE:
            findings.append(Finding(
                module="https",
                finding_type="hsts_short_max_age",
                severity=Severity.LOW,
                target=target,
                title="HSTS max-age Too Short",
                detail=(
                    f"Strict-Transport-Security max-age is {max_age} seconds "
                    f"({max_age // 86400} days), which is below the "
                    f"recommended minimum of {_HSTS_MIN_MAX_AGE} seconds "
                    f"(1 year). Short max-age values mean the browser's HSTS "
                    f"cache expires quickly, leaving a window for protocol "
                    f"downgrade attacks"
                ),
                references=["CWE-319"],
            ))

        # --- Check 3: Missing includeSubDomains ---
        # Without includeSubDomains, subdomain sites can still be served
        # over HTTP, which allows cookie injection attacks (a subdomain
        # over HTTP can set cookies for the parent domain).
        if "includesubdomains" not in hsts_lower:
            findings.append(Finding(
                module="https",
                finding_type="hsts_missing_include_subdomains",
                severity=Severity.LOW,
                target=target,
                title="HSTS Missing includeSubDomains",
                detail=(
                    "Strict-Transport-Security header does not include the "
                    "includeSubDomains directive, leaving subdomains "
                    "unprotected against protocol downgrade attacks. An "
                    "attacker could intercept traffic to a subdomain to "
                    "inject cookies for the parent domain"
                ),
                references=["CWE-319"],
            ))

        # --- Check 4: Missing preload ---
        # The preload directive signals that the site owner wants the domain
        # to be included in browser HSTS preload lists (e.g., Chrome's).
        # Preloaded domains are protected from the very first visit, eliminating
        # the trust-on-first-use problem.  Without preload, there is a window
        # on the first visit where a downgrade attack is possible.
        if "preload" not in hsts_lower:
            findings.append(Finding(
                module="https",
                finding_type="hsts_missing_preload",
                severity=Severity.INFORMATIONAL,
                target=target,
                title="HSTS Missing preload Directive",
                detail=(
                    "Strict-Transport-Security header does not include the "
                    "preload directive. Without preload, the domain is not "
                    "eligible for browser HSTS preload lists, which means "
                    "the first visit is still vulnerable to protocol downgrade "
                    "attacks (trust-on-first-use problem)"
                ),
                references=["CWE-319"],
            ))

        return findings

    # -----------------------------------------------------------------
    # Private methods -- HTTPS response fetching
    # -----------------------------------------------------------------

    def _fetch_https_response(
        self,
        session,
        target: Target,
        timeout: int,
    ) -> Optional[Response]:
        """
        Make an HTTPS request to the target to get the response for HSTS analysis.

        This is a fallback used when the orchestrator did not provide a
        pre-fetched response (e.g., the target was unreachable during the
        orchestrator's initial fetch).

        Args:
            session: The requests.Session for making HTTP requests.
            target:  The HTTPS target to fetch.
            timeout: Request timeout in seconds.

        Returns:
            The response object, or None if the request failed.
        """
        try:
            resp = session.get(
                target.url,
                timeout=timeout,
                verify=False,
                allow_redirects=True,
            )
            return resp
        except Exception as exc:
            logger.debug(
                "HTTPS request failed for %s: %s",
                target.url,
                exc,
            )
            return None

    # -----------------------------------------------------------------
    # Header and HSTS parsing helpers
    # -----------------------------------------------------------------

    def _get_header(self, headers: dict, name: str) -> Optional[str]:
        """
        Look up a header value by name, handling case-insensitive matching.

        The requests library's Response.headers is a CaseInsensitiveDict,
        so .get() already handles case-insensitive matching.  However,
        when testing with plain dict mocks, we need to handle both cases.

        Args:
            headers: The response headers dict (may be CaseInsensitiveDict
                     or plain dict).
            name:    The header name to look up (canonical casing).

        Returns:
            The header value string, or None if not found.
        """
        # Try direct lookup first (works with CaseInsensitiveDict and
        # exact-match plain dicts).
        value = headers.get(name)
        if value is not None:
            return value

        # Fallback: case-insensitive scan for plain dict mocks.
        name_lower = name.lower()
        for key, val in headers.items():
            if key.lower() == name_lower:
                return val

        return None

    def _parse_hsts_max_age(self, hsts_value: str) -> Optional[int]:
        """
        Extract the max-age value from an HSTS header string.

        The HSTS header format is:
            max-age=<seconds>[; includeSubDomains][; preload]

        We use a regex to extract the numeric max-age value, handling
        potential whitespace around the equals sign.

        Args:
            hsts_value: The raw Strict-Transport-Security header value.

        Returns:
            The max-age value as an integer, or None if parsing fails.
        """
        # Match "max-age" followed by optional whitespace, "=",
        # optional whitespace, and one or more digits.
        match = re.search(r"max-age\s*=\s*(\d+)", hsts_value, re.IGNORECASE)
        if match:
            return int(match.group(1))
        return None


# ---------------------------------------------------------------------------
# Module registration
# ---------------------------------------------------------------------------
# Instantiate the scanner and register it with the module registry.
# This runs at import time, so importing this file is sufficient to make
# the HTTPS scanner available to the orchestrator.

register_module(HTTPSScanner())
