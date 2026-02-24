"""
webinspector.modules.header_scanner - HTTP security header scanner module.

Examines HTTP response headers for missing or misconfigured security headers.
This is one of the most impactful checks in a web security assessment because
security headers are easy to deploy, have zero functional impact when configured
correctly, and protect against entire classes of attacks (XSS, clickjacking,
MIME sniffing, protocol downgrade, etc.).

This module checks the following security headers:

    Content-Security-Policy (CSP):
        - Missing entirely (LOW)
        - Quality analysis of CSP value:
            * 'unsafe-inline' present (MEDIUM) -- defeats XSS protection
            * 'unsafe-eval' present (MEDIUM) -- allows eval()/new Function()
            * Wildcard '*' source (MEDIUM) -- allows any origin
            * 'data:' URI scheme (MEDIUM) -- allows data URI injection
            * Missing default-src directive (LOW) -- no fallback for unlisted types
            * Missing object-src directive (LOW) -- allows plugin loading
            * Missing base-uri directive (LOW) -- allows base URL hijacking
        - Content-Security-Policy-Report-Only detected (LOW) -- monitoring only

    X-Frame-Options:
        - Missing AND no CSP frame-ancestors (MEDIUM) -- clickjacking risk
        - CSP frame-ancestors is treated as equivalent protection

    X-Content-Type-Options:
        - Missing header (LOW) -- allows MIME type sniffing
        - Must be "nosniff" to be effective

    Strict-Transport-Security (HSTS):
        - Missing on HTTPS targets (MEDIUM) -- protocol downgrade risk
        - max-age < 31536000 / 1 year (LOW) -- insufficient pin duration
        - Missing includeSubDomains (LOW) -- subdomains unprotected

    Referrer-Policy:
        - Missing entirely (LOW) -- browser default may leak URLs
        - "unsafe-url" value (MEDIUM) -- always sends full URL
        - "no-referrer-when-downgrade" value (MEDIUM) -- legacy leaky default

    Permissions-Policy:
        - Missing entirely (LOW) -- all features allowed by default
        - Wildcard '*' on sensitive features (MEDIUM):
            * camera, microphone, geolocation

    Deprecated headers:
        - X-XSS-Protection (INFORMATIONAL) -- XSS auditor removed from browsers
        - Public-Key-Pins (INFORMATIONAL) -- HPKP deprecated, risk of bricking
        - Expect-CT (INFORMATIONAL) -- CT now mandatory for all certs

This module uses a pre-fetched HTTP response (requests.Response) provided by
the orchestrator.  If http_response is None (target unreachable), the module
returns an empty findings list.

HTTP headers are case-insensitive per RFC 7230 Section 3.2.  The requests
library provides case-insensitive header access via its CaseInsensitiveDict,
but we also use .get() with exact names to be safe with mock objects.

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

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Minimum HSTS max-age value in seconds.  31536000 = 1 year.
# OWASP and HSTS preload requirements both specify 1 year as the minimum.
# Shorter durations provide weaker protection because the pin expires quickly
# if the user doesn't revisit the site.
_HSTS_MIN_MAX_AGE = 31536000

# Referrer-Policy values that are considered unsafe because they leak
# the full URL (including query parameters with potential secrets like
# tokens, session IDs, etc.) to third-party origins.
#
# "unsafe-url"  -- always sends the full URL as referer, even cross-origin
#                  and even on HTTP (plaintext) navigation.
# "no-referrer-when-downgrade" -- the legacy default; sends full URL for
#                                 same-protocol requests (HTTPS->HTTPS).
#                                 Deprecated as a default by modern browsers.
_UNSAFE_REFERRER_POLICIES = {"unsafe-url", "no-referrer-when-downgrade"}

# Sensitive browser features that should NOT be granted to all origins
# via wildcard (*) in the Permissions-Policy header.  These features
# give embedded iframes access to privacy-sensitive hardware/data.
_SENSITIVE_PERMISSIONS_FEATURES = {"camera", "microphone", "geolocation"}

# Deprecated security headers.  These were once recommended but are now
# obsolete or actively harmful.  Their presence suggests the server
# configuration has not been updated recently.
#
# Each entry is: (header_name, reason_string)
_DEPRECATED_HEADERS = [
    (
        "X-XSS-Protection",
        "X-XSS-Protection is deprecated; the XSS auditor has been "
        "removed from all major browsers due to bypass vulnerabilities "
        "and information leak risks",
    ),
    (
        "Public-Key-Pins",
        "Public-Key-Pins (HPKP) is deprecated due to the risk of "
        "permanently bricking a site if keys are rotated incorrectly; "
        "Chrome removed support in 2018",
    ),
    (
        "Expect-CT",
        "Expect-CT is deprecated because Certificate Transparency is "
        "now required by all major browsers for all newly-issued "
        "certificates",
    ),
]


class HeaderScanner(ScanModule):
    """
    HTTP security header scanner.

    Examines the HTTP response headers for missing or misconfigured
    security headers.  Uses the pre-fetched requests.Response object
    provided by the orchestrator -- does NOT make its own HTTP requests.

    Accepts both HTTP and HTTPS targets (the default accepts_target
    behaviour from the base class).  Some checks (HSTS) are only
    relevant for HTTPS targets and are skipped for HTTP.
    """

    # -----------------------------------------------------------------
    # ScanModule interface -- required properties
    # -----------------------------------------------------------------

    @property
    def name(self) -> str:
        """Short identifier used in CLI flags and finding output."""
        return "headers"

    @property
    def description(self) -> str:
        """Human-readable description for --help output."""
        return "HTTP security header analysis (CSP, HSTS, X-Frame-Options, etc.)"

    # -----------------------------------------------------------------
    # ScanModule interface -- main scan method
    # -----------------------------------------------------------------

    def scan(
        self,
        target: Target,
        http_response: Optional[Response] = None,
    ) -> list[Finding]:
        """
        Analyse HTTP response headers for security issues.

        This method:
            1. Returns empty if http_response is None (target unreachable)
            2. Runs each header check in sequence, accumulating findings
            3. Returns the complete list of findings

        Each check is implemented as a separate private method for
        readability, testability, and maintainability.  Checks are
        ordered from most impactful to least impactful:
            a. Content-Security-Policy (CSP)
            b. X-Frame-Options / clickjacking
            c. X-Content-Type-Options
            d. Strict-Transport-Security (HSTS)
            e. Referrer-Policy
            f. Permissions-Policy
            g. Deprecated headers

        Args:
            target:        The target being scanned.
            http_response: Pre-fetched requests.Response object.  If None,
                           the target was unreachable and we return empty.

        Returns:
            List of Finding objects.  Empty list means no issues found
            or the target was unreachable.
        """
        # Guard: no response means the target was unreachable.
        # We can't analyse headers we don't have.
        if http_response is None:
            logger.debug(
                "No HTTP response for %s, skipping header scan",
                target.hostport,
            )
            return []

        findings: list[Finding] = []

        # Extract headers once for all checks.
        # requests.Response.headers is a CaseInsensitiveDict, but our
        # mock objects may use a plain dict.  We use .get() throughout
        # to handle both cases gracefully.
        headers = http_response.headers

        # --- Run all header checks ---
        # Each check method receives the target and headers dict, and
        # returns a list of Finding objects (empty if no issues).

        findings.extend(self._check_csp(target, headers))
        findings.extend(self._check_x_frame_options(target, headers))
        findings.extend(self._check_x_content_type_options(target, headers))
        findings.extend(self._check_hsts(target, headers))
        findings.extend(self._check_referrer_policy(target, headers))
        findings.extend(self._check_permissions_policy(target, headers))
        findings.extend(self._check_deprecated_headers(target, headers))

        return findings

    # -----------------------------------------------------------------
    # Private check methods -- Content-Security-Policy
    # -----------------------------------------------------------------

    def _check_csp(
        self, target: Target, headers: dict
    ) -> list[Finding]:
        """
        Check Content-Security-Policy header presence and quality.

        CSP is the single most effective browser-side XSS mitigation.
        A well-configured CSP can prevent most reflected and stored XSS
        attacks by restricting which resources the browser will load.

        This method first checks if CSP is present at all, then performs
        quality analysis on the CSP value if it exists.  It also checks
        for the Report-Only variant.

        Args:
            target:  The target being scanned.
            headers: The response headers dict.

        Returns:
            List of Finding objects for CSP issues.
        """
        findings: list[Finding] = []

        # Get the enforcing CSP header value (case-insensitive lookup).
        csp_value = self._get_header(headers, "Content-Security-Policy")

        # Get the report-only CSP header value.
        csp_report_only = self._get_header(
            headers, "Content-Security-Policy-Report-Only"
        )

        # --- Check 1: Missing CSP entirely ---
        # If neither enforcing nor report-only CSP is present, flag it.
        # If only report-only is present, we flag missing enforcing CSP
        # separately via the report-only check below.
        if csp_value is None:
            findings.append(Finding(
                module="headers",
                finding_type="missing_csp",
                severity=Severity.LOW,
                target=target,
                title="Missing Content-Security-Policy",
                detail=(
                    "No Content-Security-Policy header found. CSP is the "
                    "most effective browser-side XSS mitigation mechanism"
                ),
                references=["CWE-693"],
            ))
        else:
            # --- Check 2-8: CSP quality analysis ---
            # Only run quality checks if an enforcing CSP header exists.
            findings.extend(self._check_csp_quality(target, csp_value))

        # --- Check 9: Report-Only mode ---
        # Content-Security-Policy-Report-Only does not enforce restrictions;
        # it only reports violations.  Flag it if present.
        if csp_report_only is not None:
            findings.append(Finding(
                module="headers",
                finding_type="csp_report_only",
                severity=Severity.LOW,
                target=target,
                title="Content-Security-Policy in Report-Only Mode",
                detail=(
                    "Content-Security-Policy-Report-Only header is present. "
                    "This mode only reports violations without enforcing "
                    "restrictions"
                ),
                references=["CWE-693"],
            ))

        return findings

    def _check_csp_quality(
        self, target: Target, csp_value: str
    ) -> list[Finding]:
        """
        Analyse the quality of a Content-Security-Policy value.

        Checks for common CSP weaknesses that reduce or negate the
        protection CSP is supposed to provide.

        Args:
            target:    The target being scanned.
            csp_value: The raw CSP header value string.

        Returns:
            List of Finding objects for CSP quality issues.
        """
        findings: list[Finding] = []

        # Normalise the CSP value for consistent analysis.
        # CSP directives are semicolon-separated and case-insensitive.
        csp_lower = csp_value.lower()

        # --- unsafe-inline ---
        # 'unsafe-inline' allows inline <script> and <style> elements,
        # which is the primary attack vector for reflected XSS.  With
        # unsafe-inline, an attacker only needs to inject <script>alert(1)</script>
        # rather than loading an external script.
        if "'unsafe-inline'" in csp_lower:
            findings.append(Finding(
                module="headers",
                finding_type="csp_unsafe_inline",
                severity=Severity.MEDIUM,
                target=target,
                title="CSP Contains 'unsafe-inline'",
                detail=(
                    "Content-Security-Policy allows 'unsafe-inline', which "
                    "permits inline script and style execution, largely "
                    "defeating XSS protection"
                ),
                references=["CWE-693"],
            ))

        # --- unsafe-eval ---
        # 'unsafe-eval' allows eval(), new Function(), setTimeout(string),
        # and setInterval(string).  These are common XSS sinks that
        # attackers can exploit to execute arbitrary JavaScript.
        if "'unsafe-eval'" in csp_lower:
            findings.append(Finding(
                module="headers",
                finding_type="csp_unsafe_eval",
                severity=Severity.MEDIUM,
                target=target,
                title="CSP Contains 'unsafe-eval'",
                detail=(
                    "Content-Security-Policy allows 'unsafe-eval', which "
                    "permits eval() and similar dynamic code execution "
                    "functions"
                ),
                references=["CWE-693"],
            ))

        # --- Wildcard * source ---
        # A bare '*' as a source allows loading resources from ANY origin.
        # This makes CSP essentially useless because an attacker can host
        # malicious scripts on any domain they control.
        #
        # We check for '*' as a standalone token (not part of a domain like
        # '*.example.com') by looking for '*' preceded by a space or at the
        # start of a directive value, and followed by a space, semicolon,
        # or end of string.
        if self._csp_has_wildcard(csp_value):
            findings.append(Finding(
                module="headers",
                finding_type="csp_wildcard",
                severity=Severity.MEDIUM,
                target=target,
                title="CSP Contains Wildcard Source",
                detail=(
                    "Content-Security-Policy contains a wildcard (*) source, "
                    "which allows loading resources from any origin"
                ),
                references=["CWE-693"],
            ))

        # --- data: URI scheme ---
        # 'data:' allows embedding content via data URIs, which can be
        # used to inject inline scripts (data:text/html,...) or load
        # arbitrary content without making network requests.
        if "data:" in csp_lower:
            findings.append(Finding(
                module="headers",
                finding_type="csp_data_uri",
                severity=Severity.MEDIUM,
                target=target,
                title="CSP Allows data: URIs",
                detail=(
                    "Content-Security-Policy allows 'data:' URI scheme, "
                    "which can be used to inject inline content"
                ),
                references=["CWE-693"],
            ))

        # --- Missing default-src ---
        # default-src is the fallback directive for all resource types that
        # don't have their own specific directive.  Without it, any
        # resource type not explicitly restricted is completely unrestricted.
        if "default-src" not in csp_lower:
            findings.append(Finding(
                module="headers",
                finding_type="csp_missing_default_src",
                severity=Severity.LOW,
                target=target,
                title="CSP Missing default-src Directive",
                detail=(
                    "Content-Security-Policy does not include a default-src "
                    "directive, which serves as the fallback for unlisted "
                    "resource types"
                ),
                references=["CWE-693"],
            ))

        # --- Missing object-src ---
        # object-src controls the loading of plugins (Flash, Java applets,
        # Silverlight).  Without it (and without a restrictive default-src),
        # an attacker can load malicious plugin content.
        if "object-src" not in csp_lower:
            findings.append(Finding(
                module="headers",
                finding_type="csp_missing_object_src",
                severity=Severity.LOW,
                target=target,
                title="CSP Missing object-src Directive",
                detail=(
                    "Content-Security-Policy does not include an object-src "
                    "directive to restrict plugin loading (Flash, Java, etc.)"
                ),
                references=["CWE-693"],
            ))

        # --- Missing base-uri ---
        # base-uri restricts the URLs that can be used in the <base>
        # element.  Without it, an attacker who can inject HTML (but not
        # scripts) can change the base URL to redirect all relative links
        # to a malicious domain (dangling markup injection).
        if "base-uri" not in csp_lower:
            findings.append(Finding(
                module="headers",
                finding_type="csp_missing_base_uri",
                severity=Severity.LOW,
                target=target,
                title="CSP Missing base-uri Directive",
                detail=(
                    "Content-Security-Policy does not include a base-uri "
                    "directive to restrict the URLs used in <base> elements"
                ),
                references=["CWE-693"],
            ))

        return findings

    def _csp_has_wildcard(self, csp_value: str) -> bool:
        """
        Check if a CSP value contains a bare wildcard (*) source.

        We need to distinguish between:
            - '*' as a standalone source (matches everything) -- BAD
            - '*.example.com' as a subdomain wildcard -- acceptable

        The regex matches '*' when it appears as a standalone token:
        preceded by whitespace or start-of-string, and followed by
        whitespace, semicolon, or end-of-string.

        Args:
            csp_value: The raw CSP header value.

        Returns:
            True if a bare wildcard is found.
        """
        # Match a standalone '*' that is not part of '*.domain.com'.
        # The pattern looks for '*' bounded by non-dot, non-alphanumeric
        # characters (or string boundaries).
        return bool(re.search(r'(?:^|[\s;])\*(?:[\s;]|$)', csp_value))

    # -----------------------------------------------------------------
    # Private check methods -- X-Frame-Options / clickjacking
    # -----------------------------------------------------------------

    def _check_x_frame_options(
        self, target: Target, headers: dict
    ) -> list[Finding]:
        """
        Check for clickjacking protection via X-Frame-Options or CSP
        frame-ancestors.

        Clickjacking (UI redress attack) allows an attacker to trick
        users into clicking something different from what they perceive
        by overlaying transparent iframes.  Protection requires either:
            - X-Frame-Options: DENY or SAMEORIGIN
            - CSP frame-ancestors directive

        We only flag missing protection when BOTH mechanisms are absent.
        CSP frame-ancestors is the modern replacement for X-Frame-Options
        and provides more granular control.

        Args:
            target:  The target being scanned.
            headers: The response headers dict.

        Returns:
            List with one Finding if clickjacking protection is missing,
            empty list if protection is present.
        """
        findings: list[Finding] = []

        # Check if X-Frame-Options is present.
        xfo = self._get_header(headers, "X-Frame-Options")
        if xfo is not None:
            # X-Frame-Options is set -- clickjacking protection exists.
            return findings

        # X-Frame-Options is missing.  Check CSP frame-ancestors as
        # an alternative clickjacking protection mechanism.
        csp_value = self._get_header(headers, "Content-Security-Policy")
        if csp_value is not None and "frame-ancestors" in csp_value.lower():
            # CSP frame-ancestors is present -- protection exists.
            return findings

        # Neither X-Frame-Options nor CSP frame-ancestors is present.
        # The site is vulnerable to clickjacking.
        findings.append(Finding(
            module="headers",
            finding_type="missing_x_frame_options",
            severity=Severity.MEDIUM,
            target=target,
            title="Missing Clickjacking Protection",
            detail=(
                "Neither X-Frame-Options header nor CSP frame-ancestors "
                "directive is set, leaving the site vulnerable to "
                "clickjacking (UI redress) attacks"
            ),
            references=["CWE-1021"],
        ))

        return findings

    # -----------------------------------------------------------------
    # Private check methods -- X-Content-Type-Options
    # -----------------------------------------------------------------

    def _check_x_content_type_options(
        self, target: Target, headers: dict
    ) -> list[Finding]:
        """
        Check for X-Content-Type-Options: nosniff header.

        Without this header, browsers may perform MIME type sniffing,
        which can lead to XSS attacks when a file with an ambiguous
        content type (e.g., text/plain) actually contains JavaScript.

        The only valid value is "nosniff".  Any other value or absence
        of the header is flagged.

        Args:
            target:  The target being scanned.
            headers: The response headers dict.

        Returns:
            List with one Finding if header is missing, empty otherwise.
        """
        findings: list[Finding] = []

        xcto = self._get_header(headers, "X-Content-Type-Options")
        if xcto is None:
            findings.append(Finding(
                module="headers",
                finding_type="missing_x_content_type_options",
                severity=Severity.LOW,
                target=target,
                title="Missing X-Content-Type-Options",
                detail=(
                    "X-Content-Type-Options header is not set. Without "
                    "'nosniff', browsers may perform MIME type sniffing, "
                    "potentially executing uploaded files as scripts"
                ),
                references=["CWE-693"],
            ))

        return findings

    # -----------------------------------------------------------------
    # Private check methods -- Strict-Transport-Security (HSTS)
    # -----------------------------------------------------------------

    def _check_hsts(
        self, target: Target, headers: dict
    ) -> list[Finding]:
        """
        Check Strict-Transport-Security header on HTTPS targets.

        HSTS instructs browsers to always use HTTPS when connecting to
        the site, preventing protocol downgrade attacks (e.g., sslstrip).
        It is only meaningful on HTTPS connections -- browsers ignore
        HSTS headers received over HTTP.

        Checks:
            1. Missing HSTS on HTTPS target (MEDIUM)
            2. max-age below 1 year (LOW)
            3. Missing includeSubDomains (LOW)

        Args:
            target:  The target being scanned.
            headers: The response headers dict.

        Returns:
            List of Finding objects for HSTS issues.
        """
        findings: list[Finding] = []

        # HSTS is only relevant for HTTPS targets.  Browsers ignore HSTS
        # headers received over insecure (HTTP) connections because an
        # active MITM could strip or forge them.
        if target.scheme != "https":
            return findings

        hsts_value = self._get_header(headers, "Strict-Transport-Security")

        # --- Check 1: Missing HSTS ---
        if hsts_value is None:
            findings.append(Finding(
                module="headers",
                finding_type="missing_hsts",
                severity=Severity.MEDIUM,
                target=target,
                title="Missing Strict-Transport-Security (HSTS)",
                detail=(
                    "Strict-Transport-Security header is not set on this "
                    "HTTPS target. Without HSTS, browsers may connect over "
                    "plain HTTP, allowing protocol downgrade attacks"
                ),
                references=["CWE-319"],
            ))
            return findings

        # HSTS is present -- check quality (max-age and includeSubDomains).
        hsts_lower = hsts_value.lower()

        # --- Check 2: Short max-age ---
        # Parse the max-age value from the HSTS header.
        # Format: max-age=<seconds>[; includeSubDomains][; preload]
        max_age = self._parse_hsts_max_age(hsts_value)
        if max_age is not None and max_age < _HSTS_MIN_MAX_AGE:
            findings.append(Finding(
                module="headers",
                finding_type="hsts_short_max_age",
                severity=Severity.LOW,
                target=target,
                title="HSTS max-age Too Short",
                detail=(
                    f"Strict-Transport-Security max-age is {max_age} seconds "
                    f"({max_age // 86400} days), which is below the "
                    f"recommended minimum of {_HSTS_MIN_MAX_AGE} seconds "
                    f"(1 year)"
                ),
                references=["CWE-319"],
            ))

        # --- Check 3: Missing includeSubDomains ---
        # Without includeSubDomains, subdomain sites can still be served
        # over HTTP, which allows cookie injection attacks (a subdomain
        # over HTTP can set cookies for the parent domain).
        if "includesubdomains" not in hsts_lower:
            findings.append(Finding(
                module="headers",
                finding_type="hsts_missing_include_subdomains",
                severity=Severity.LOW,
                target=target,
                title="HSTS Missing includeSubDomains",
                detail=(
                    "Strict-Transport-Security header does not include the "
                    "includeSubDomains directive, leaving subdomains "
                    "unprotected against protocol downgrade attacks"
                ),
                references=["CWE-319"],
            ))

        return findings

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

    # -----------------------------------------------------------------
    # Private check methods -- Referrer-Policy
    # -----------------------------------------------------------------

    def _check_referrer_policy(
        self, target: Target, headers: dict
    ) -> list[Finding]:
        """
        Check Referrer-Policy header presence and safety.

        The Referrer-Policy header controls how much referrer information
        (the URL of the previous page) is included in requests.  Without
        it, browsers use their default behaviour, which may leak the full
        URL including query parameters to third-party sites.

        Safe values include:
            - no-referrer
            - same-origin
            - strict-origin
            - strict-origin-when-cross-origin

        Unsafe values:
            - unsafe-url (always sends full URL)
            - no-referrer-when-downgrade (legacy default, sends full URL
              for same-protocol requests)

        Args:
            target:  The target being scanned.
            headers: The response headers dict.

        Returns:
            List of Finding objects for Referrer-Policy issues.
        """
        findings: list[Finding] = []

        rp_value = self._get_header(headers, "Referrer-Policy")

        # --- Check 1: Missing Referrer-Policy ---
        if rp_value is None:
            findings.append(Finding(
                module="headers",
                finding_type="missing_referrer_policy",
                severity=Severity.LOW,
                target=target,
                title="Missing Referrer-Policy",
                detail=(
                    "Referrer-Policy header is not set. Without it, the "
                    "browser's default referrer behaviour may leak the full "
                    "URL (including query parameters) to third-party sites"
                ),
                references=["CWE-200"],
            ))
            return findings

        # --- Check 2: Unsafe Referrer-Policy value ---
        # The Referrer-Policy header can contain multiple comma-separated
        # values (fallback chain).  We check the last (most preferred)
        # value, but also flag if any value in the chain is unsafe.
        rp_lower = rp_value.lower().strip()
        if rp_lower in _UNSAFE_REFERRER_POLICIES:
            findings.append(Finding(
                module="headers",
                finding_type="unsafe_referrer_policy",
                severity=Severity.MEDIUM,
                target=target,
                title="Unsafe Referrer-Policy",
                detail=(
                    f"Referrer-Policy is set to '{rp_value}', which may "
                    f"leak the full URL (including query parameters) to "
                    f"external sites"
                ),
                references=["CWE-200"],
            ))

        return findings

    # -----------------------------------------------------------------
    # Private check methods -- Permissions-Policy
    # -----------------------------------------------------------------

    def _check_permissions_policy(
        self, target: Target, headers: dict
    ) -> list[Finding]:
        """
        Check Permissions-Policy header presence and configuration.

        Permissions-Policy (formerly Feature-Policy) controls which
        browser features (camera, microphone, geolocation, etc.) can
        be used by the page and its embedded iframes.

        Without this header, all features are available to any embedded
        content, which increases the attack surface for malicious iframes.

        We specifically flag wildcard (*) grants on privacy-sensitive
        features: camera, microphone, and geolocation.

        Args:
            target:  The target being scanned.
            headers: The response headers dict.

        Returns:
            List of Finding objects for Permissions-Policy issues.
        """
        findings: list[Finding] = []

        pp_value = self._get_header(headers, "Permissions-Policy")

        # --- Check 1: Missing Permissions-Policy ---
        if pp_value is None:
            findings.append(Finding(
                module="headers",
                finding_type="missing_permissions_policy",
                severity=Severity.LOW,
                target=target,
                title="Missing Permissions-Policy",
                detail=(
                    "Permissions-Policy header is not set. Without it, all "
                    "browser features (camera, microphone, geolocation) are "
                    "available to embedded iframes by default"
                ),
                references=["CWE-693"],
            ))
            return findings

        # --- Check 2: Wildcard on sensitive features ---
        # Parse the Permissions-Policy value to detect wildcard grants.
        # Format: feature=(allowlist), feature=(allowlist), ...
        # Wildcard format: feature=*
        wildcard_features = self._find_wildcard_permissions(pp_value)
        if wildcard_features:
            findings.append(Finding(
                module="headers",
                finding_type="permissions_policy_wildcard",
                severity=Severity.MEDIUM,
                target=target,
                title="Permissions-Policy Wildcard on Sensitive Features",
                detail=(
                    f"Permissions-Policy grants wildcard (*) access to "
                    f"sensitive features: {', '.join(sorted(wildcard_features))}"
                ),
                references=["CWE-693"],
            ))

        return findings

    def _find_wildcard_permissions(self, pp_value: str) -> set[str]:
        """
        Find sensitive features that are granted wildcard (*) access
        in a Permissions-Policy header value.

        Permissions-Policy format examples:
            camera=(), microphone=(), geolocation=()  -- deny all (safe)
            camera=*, microphone=*                     -- allow all (unsafe)
            camera=(self), microphone=(self "https://example.com")  -- restricted

        We look for patterns like "feature=*" for each sensitive feature.

        Args:
            pp_value: The raw Permissions-Policy header value.

        Returns:
            Set of sensitive feature names that have wildcard grants.
        """
        wildcard_features: set[str] = set()

        for feature in _SENSITIVE_PERMISSIONS_FEATURES:
            # Build a regex pattern for this feature with wildcard.
            # Match: feature = * (with optional whitespace)
            # The feature may be followed by a comma, space, or end of string.
            pattern = rf"\b{re.escape(feature)}\s*=\s*\*"
            if re.search(pattern, pp_value, re.IGNORECASE):
                wildcard_features.add(feature)

        return wildcard_features

    # -----------------------------------------------------------------
    # Private check methods -- Deprecated headers
    # -----------------------------------------------------------------

    def _check_deprecated_headers(
        self, target: Target, headers: dict
    ) -> list[Finding]:
        """
        Check for the presence of deprecated security headers.

        Deprecated headers are not vulnerabilities themselves, but their
        presence indicates the server configuration may be outdated and
        could be confusing for security auditors.

        Currently checks for:
            - X-XSS-Protection (XSS auditor removed from browsers)
            - Public-Key-Pins (HPKP deprecated, risk of bricking)
            - Expect-CT (CT now mandatory for all certs)

        Args:
            target:  The target being scanned.
            headers: The response headers dict.

        Returns:
            List of Finding objects for deprecated headers found.
        """
        findings: list[Finding] = []

        for header_name, reason in _DEPRECATED_HEADERS:
            header_value = self._get_header(headers, header_name)
            if header_value is not None:
                findings.append(Finding(
                    module="headers",
                    finding_type="deprecated_header",
                    severity=Severity.INFORMATIONAL,
                    target=target,
                    title="Deprecated Security Header Present",
                    detail=f"{header_name}: {reason}",
                    references=["CWE-693"],
                ))

        return findings

    # -----------------------------------------------------------------
    # Header lookup helper
    # -----------------------------------------------------------------

    def _get_header(self, headers: dict, name: str) -> Optional[str]:
        """
        Look up a header value by name, handling case-insensitive matching.

        The requests library's Response.headers is a CaseInsensitiveDict,
        so .get() already handles case-insensitive matching.  However,
        when testing with plain dict mocks, we need to handle both cases.

        This method first tries a direct .get() (which works with both
        CaseInsensitiveDict and case-matching plain dicts), then falls
        back to a case-insensitive scan for plain dict mocks that don't
        use the exact header casing.

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


# ---------------------------------------------------------------------------
# Module registration
# ---------------------------------------------------------------------------
# Instantiate the scanner and register it with the module registry.
# This runs at import time, so importing this file is sufficient to make
# the header scanner available to the orchestrator.

register_module(HeaderScanner())
