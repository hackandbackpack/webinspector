"""
Tests for the HTTP security header scanner module (header_scanner.py).

These tests verify that the HeaderScanner module correctly:
    1. Accepts both HTTP and HTTPS targets (default accepts_target)
    2. Returns empty findings when http_response is None
    3. Detects missing Content-Security-Policy (CSP)
    4. Detects CSP with unsafe-inline directive
    5. Detects CSP with unsafe-eval directive
    6. Detects CSP with wildcard (*) source
    7. Detects CSP with data: URI scheme
    8. Detects CSP missing default-src directive
    9. Detects CSP missing object-src directive
   10. Detects CSP missing base-uri directive
   11. Detects Content-Security-Policy-Report-Only (not enforcing)
   12. Detects missing X-Frame-Options AND no CSP frame-ancestors (clickjacking)
   13. Detects missing X-Content-Type-Options
   14. Detects missing Strict-Transport-Security (HSTS) on HTTPS targets
   15. Detects HSTS with short max-age (< 1 year)
   16. Detects HSTS missing includeSubDomains
   17. Detects missing Referrer-Policy
   18. Detects unsafe Referrer-Policy values (unsafe-url, no-referrer-when-downgrade)
   19. Detects missing Permissions-Policy
   20. Detects Permissions-Policy wildcard on sensitive features
   21. Detects deprecated headers (X-XSS-Protection, Public-Key-Pins, Expect-CT)
   22. Returns empty findings for a fully hardened response
   23. Handles multiple findings in a single scan

All HTTP responses are mocked using unittest.mock.MagicMock -- no real
HTTP connections are made.

Author: Red Siege Information Security
"""

import pytest
from unittest.mock import MagicMock

from webinspector.core.target import Target
from webinspector.core.result import Finding, Severity


# ---------------------------------------------------------------------------
# Mock helper — build a requests.Response stand-in with specified headers
# ---------------------------------------------------------------------------

def _make_response(headers: dict) -> MagicMock:
    """
    Build a mock requests.Response with the given headers dict.

    The mock's .headers attribute is a case-insensitive dict-like object.
    We use a plain dict here; the scanner should handle case-insensitive
    header lookups internally (HTTP headers are case-insensitive per RFC 7230).

    Args:
        headers: Dict mapping header names to values.

    Returns:
        A MagicMock mimicking requests.Response with .headers set.
    """
    response = MagicMock()
    response.headers = headers
    return response


def _make_hardened_response() -> MagicMock:
    """
    Build a mock response with all recommended security headers set to
    safe values.  Scanning this should produce zero findings.

    This is the "gold standard" response that every web server should
    aspire to.  It includes:
        - Content-Security-Policy with tight directives
        - X-Frame-Options: DENY
        - X-Content-Type-Options: nosniff
        - Strict-Transport-Security with long max-age and includeSubDomains
        - Referrer-Policy: strict-origin-when-cross-origin
        - Permissions-Policy with restricted sensitive features
    """
    return _make_response({
        "Content-Security-Policy": (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self'; "
            "object-src 'none'; "
            "base-uri 'self'"
        ),
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    })


# ---------------------------------------------------------------------------
# Target fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def https_target():
    """An HTTPS target for header scanning."""
    return Target(host="example.com", port=443, scheme="https")


@pytest.fixture
def http_target():
    """An HTTP target for header scanning."""
    return Target(host="example.com", port=80, scheme="http")


# ===========================================================================
# Tests for accepts_target
# ===========================================================================

class TestHeaderScannerAcceptsTarget:
    """Verify that the header scanner accepts both HTTP and HTTPS targets."""

    def test_accepts_https(self, https_target):
        """Header scanner should accept targets with scheme='https'."""
        from webinspector.modules.header_scanner import HeaderScanner
        scanner = HeaderScanner()
        assert scanner.accepts_target(https_target) is True

    def test_accepts_http(self, http_target):
        """Header scanner should accept targets with scheme='http'."""
        from webinspector.modules.header_scanner import HeaderScanner
        scanner = HeaderScanner()
        assert scanner.accepts_target(http_target) is True


# ===========================================================================
# Tests for module properties
# ===========================================================================

class TestHeaderScannerProperties:
    """Verify name and description properties."""

    def test_name(self):
        """Module name should be 'headers'."""
        from webinspector.modules.header_scanner import HeaderScanner
        scanner = HeaderScanner()
        assert scanner.name == "headers"

    def test_description(self):
        """Module should have a non-empty description."""
        from webinspector.modules.header_scanner import HeaderScanner
        scanner = HeaderScanner()
        assert len(scanner.description) > 0
        # Should mention headers in the description
        assert "header" in scanner.description.lower()


# ===========================================================================
# Tests for None response handling
# ===========================================================================

class TestNoneResponse:
    """Verify that None http_response returns empty findings."""

    def test_none_response_returns_empty(self, https_target):
        """
        When http_response is None (target unreachable), the scanner
        should return an empty list without error.
        """
        from webinspector.modules.header_scanner import HeaderScanner
        scanner = HeaderScanner()
        findings = scanner.scan(https_target, http_response=None)
        assert isinstance(findings, list)
        assert len(findings) == 0


# ===========================================================================
# Tests for Content-Security-Policy (CSP) checks
# ===========================================================================

class TestMissingCSP:
    """Verify detection of missing Content-Security-Policy header."""

    def test_detects_missing_csp(self, https_target):
        """
        A response with no CSP header should produce a LOW severity
        finding of type missing_csp.

        CSP is the most powerful XSS mitigation mechanism available in
        browsers.  Its absence means the site relies solely on output
        encoding to prevent XSS.
        """
        from webinspector.modules.header_scanner import HeaderScanner

        response = _make_response({
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
        })

        scanner = HeaderScanner()
        findings = scanner.scan(https_target, http_response=response)

        missing_csp = [f for f in findings if f.finding_type == "missing_csp"]
        assert len(missing_csp) == 1
        assert missing_csp[0].severity == Severity.LOW

    def test_csp_present_no_missing_finding(self, https_target):
        """
        When CSP is present (even if weak), the missing_csp finding
        should NOT be produced.
        """
        from webinspector.modules.header_scanner import HeaderScanner

        response = _make_response({
            "Content-Security-Policy": "default-src 'self'",
        })

        scanner = HeaderScanner()
        findings = scanner.scan(https_target, http_response=response)

        missing_csp = [f for f in findings if f.finding_type == "missing_csp"]
        assert len(missing_csp) == 0


class TestCSPUnsafeInline:
    """Verify detection of 'unsafe-inline' in CSP."""

    def test_detects_unsafe_inline(self, https_target):
        """
        CSP with 'unsafe-inline' allows inline script/style execution,
        largely defeating the purpose of CSP for XSS prevention.
        MEDIUM severity.
        """
        from webinspector.modules.header_scanner import HeaderScanner

        response = _make_response({
            "Content-Security-Policy": "default-src 'self' 'unsafe-inline'",
        })

        scanner = HeaderScanner()
        findings = scanner.scan(https_target, http_response=response)

        unsafe = [f for f in findings if f.finding_type == "csp_unsafe_inline"]
        assert len(unsafe) == 1
        assert unsafe[0].severity == Severity.MEDIUM

    def test_no_unsafe_inline_no_finding(self, https_target):
        """CSP without 'unsafe-inline' should not produce this finding."""
        from webinspector.modules.header_scanner import HeaderScanner

        response = _make_response({
            "Content-Security-Policy": "default-src 'self'; object-src 'none'; base-uri 'self'",
        })

        scanner = HeaderScanner()
        findings = scanner.scan(https_target, http_response=response)

        unsafe = [f for f in findings if f.finding_type == "csp_unsafe_inline"]
        assert len(unsafe) == 0


class TestCSPUnsafeEval:
    """Verify detection of 'unsafe-eval' in CSP."""

    def test_detects_unsafe_eval(self, https_target):
        """
        CSP with 'unsafe-eval' allows eval() and similar dynamic code
        execution, which can be exploited for XSS.  MEDIUM severity.
        """
        from webinspector.modules.header_scanner import HeaderScanner

        response = _make_response({
            "Content-Security-Policy": "default-src 'self'; script-src 'unsafe-eval'",
        })

        scanner = HeaderScanner()
        findings = scanner.scan(https_target, http_response=response)

        unsafe = [f for f in findings if f.finding_type == "csp_unsafe_eval"]
        assert len(unsafe) == 1
        assert unsafe[0].severity == Severity.MEDIUM


class TestCSPWildcard:
    """Verify detection of wildcard (*) in CSP."""

    def test_detects_wildcard_source(self, https_target):
        """
        CSP with '*' as a source allows loading resources from any origin,
        which largely defeats the purpose of CSP.  MEDIUM severity.
        """
        from webinspector.modules.header_scanner import HeaderScanner

        response = _make_response({
            "Content-Security-Policy": "default-src *",
        })

        scanner = HeaderScanner()
        findings = scanner.scan(https_target, http_response=response)

        wildcard = [f for f in findings if f.finding_type == "csp_wildcard"]
        assert len(wildcard) == 1
        assert wildcard[0].severity == Severity.MEDIUM


class TestCSPDataURI:
    """Verify detection of data: URI in CSP."""

    def test_detects_data_uri(self, https_target):
        """
        CSP with 'data:' allows loading resources from data URIs, which
        can be used to inject inline content.  MEDIUM severity.
        """
        from webinspector.modules.header_scanner import HeaderScanner

        response = _make_response({
            "Content-Security-Policy": "default-src 'self'; script-src data:",
        })

        scanner = HeaderScanner()
        findings = scanner.scan(https_target, http_response=response)

        data_uri = [f for f in findings if f.finding_type == "csp_data_uri"]
        assert len(data_uri) == 1
        assert data_uri[0].severity == Severity.MEDIUM


class TestCSPMissingDirectives:
    """Verify detection of missing critical CSP directives."""

    def test_detects_missing_default_src(self, https_target):
        """
        CSP without default-src means there is no fallback directive for
        resource types not explicitly listed.  LOW severity.
        """
        from webinspector.modules.header_scanner import HeaderScanner

        response = _make_response({
            "Content-Security-Policy": "script-src 'self'",
        })

        scanner = HeaderScanner()
        findings = scanner.scan(https_target, http_response=response)

        missing = [f for f in findings if f.finding_type == "csp_missing_default_src"]
        assert len(missing) == 1
        assert missing[0].severity == Severity.LOW

    def test_default_src_present_no_finding(self, https_target):
        """CSP with default-src should not produce missing_default_src finding."""
        from webinspector.modules.header_scanner import HeaderScanner

        response = _make_response({
            "Content-Security-Policy": "default-src 'self'; object-src 'none'; base-uri 'self'",
        })

        scanner = HeaderScanner()
        findings = scanner.scan(https_target, http_response=response)

        missing = [f for f in findings if f.finding_type == "csp_missing_default_src"]
        assert len(missing) == 0

    def test_detects_missing_object_src(self, https_target):
        """
        CSP without object-src allows loading of plugins (Flash, Java
        applets) which can be used for code execution.  LOW severity.
        """
        from webinspector.modules.header_scanner import HeaderScanner

        response = _make_response({
            "Content-Security-Policy": "default-src 'self'; base-uri 'self'",
        })

        scanner = HeaderScanner()
        findings = scanner.scan(https_target, http_response=response)

        missing = [f for f in findings if f.finding_type == "csp_missing_object_src"]
        assert len(missing) == 1
        assert missing[0].severity == Severity.LOW

    def test_detects_missing_base_uri(self, https_target):
        """
        CSP without base-uri allows attackers to change the base URL for
        relative links, which can be used for phishing/redirect attacks.
        LOW severity.
        """
        from webinspector.modules.header_scanner import HeaderScanner

        response = _make_response({
            "Content-Security-Policy": "default-src 'self'; object-src 'none'",
        })

        scanner = HeaderScanner()
        findings = scanner.scan(https_target, http_response=response)

        missing = [f for f in findings if f.finding_type == "csp_missing_base_uri"]
        assert len(missing) == 1
        assert missing[0].severity == Severity.LOW


class TestCSPReportOnly:
    """Verify detection of Content-Security-Policy-Report-Only."""

    def test_detects_report_only_csp(self, https_target):
        """
        Content-Security-Policy-Report-Only does not enforce restrictions,
        it only reports violations.  If present WITHOUT an enforcing CSP
        header, it should produce a LOW severity finding.
        """
        from webinspector.modules.header_scanner import HeaderScanner

        response = _make_response({
            "Content-Security-Policy-Report-Only": "default-src 'self'",
        })

        scanner = HeaderScanner()
        findings = scanner.scan(https_target, http_response=response)

        report_only = [f for f in findings if f.finding_type == "csp_report_only"]
        assert len(report_only) == 1
        assert report_only[0].severity == Severity.LOW

    def test_report_only_with_enforcing_csp(self, https_target):
        """
        When both CSP and CSP-Report-Only are present, the report-only
        finding should still be produced (it's still informational that
        report-only is in use), but the missing_csp should NOT appear.
        """
        from webinspector.modules.header_scanner import HeaderScanner

        response = _make_response({
            "Content-Security-Policy": "default-src 'self'; object-src 'none'; base-uri 'self'",
            "Content-Security-Policy-Report-Only": "default-src 'self' 'unsafe-inline'",
        })

        scanner = HeaderScanner()
        findings = scanner.scan(https_target, http_response=response)

        # Should have report-only finding
        report_only = [f for f in findings if f.finding_type == "csp_report_only"]
        assert len(report_only) == 1

        # Should NOT have missing_csp since enforcing CSP is present
        missing_csp = [f for f in findings if f.finding_type == "missing_csp"]
        assert len(missing_csp) == 0


# ===========================================================================
# Tests for X-Frame-Options (clickjacking protection)
# ===========================================================================

class TestXFrameOptions:
    """Verify detection of missing clickjacking protection."""

    def test_detects_missing_x_frame_options_no_csp_frame_ancestors(self, https_target):
        """
        Missing X-Frame-Options AND no CSP frame-ancestors directive
        leaves the site vulnerable to clickjacking.  MEDIUM severity.
        """
        from webinspector.modules.header_scanner import HeaderScanner

        response = _make_response({
            "Content-Security-Policy": "default-src 'self'",
        })

        scanner = HeaderScanner()
        findings = scanner.scan(https_target, http_response=response)

        clickjack = [f for f in findings if f.finding_type == "missing_x_frame_options"]
        assert len(clickjack) == 1
        assert clickjack[0].severity == Severity.MEDIUM

    def test_x_frame_options_present_no_finding(self, https_target):
        """X-Frame-Options present should not produce clickjacking finding."""
        from webinspector.modules.header_scanner import HeaderScanner

        response = _make_response({
            "X-Frame-Options": "DENY",
            "Content-Security-Policy": "default-src 'self'; object-src 'none'; base-uri 'self'",
        })

        scanner = HeaderScanner()
        findings = scanner.scan(https_target, http_response=response)

        clickjack = [f for f in findings if f.finding_type == "missing_x_frame_options"]
        assert len(clickjack) == 0

    def test_csp_frame_ancestors_no_finding(self, https_target):
        """
        CSP frame-ancestors directive provides equivalent clickjacking
        protection to X-Frame-Options.  When present, the clickjacking
        finding should NOT be produced even without X-Frame-Options.
        """
        from webinspector.modules.header_scanner import HeaderScanner

        response = _make_response({
            "Content-Security-Policy": (
                "default-src 'self'; "
                "frame-ancestors 'self'; "
                "object-src 'none'; "
                "base-uri 'self'"
            ),
        })

        scanner = HeaderScanner()
        findings = scanner.scan(https_target, http_response=response)

        clickjack = [f for f in findings if f.finding_type == "missing_x_frame_options"]
        assert len(clickjack) == 0

    def test_no_headers_at_all_produces_clickjacking(self, https_target):
        """
        A response with no security headers at all should produce
        the missing_x_frame_options finding.
        """
        from webinspector.modules.header_scanner import HeaderScanner

        response = _make_response({})

        scanner = HeaderScanner()
        findings = scanner.scan(https_target, http_response=response)

        clickjack = [f for f in findings if f.finding_type == "missing_x_frame_options"]
        assert len(clickjack) == 1


# ===========================================================================
# Tests for X-Content-Type-Options
# ===========================================================================

class TestXContentTypeOptions:
    """Verify detection of missing X-Content-Type-Options."""

    def test_detects_missing_x_content_type_options(self, https_target):
        """
        Missing X-Content-Type-Options allows MIME sniffing, which can
        lead to XSS when a file with an ambiguous content type is served.
        LOW severity.
        """
        from webinspector.modules.header_scanner import HeaderScanner

        response = _make_response({})

        scanner = HeaderScanner()
        findings = scanner.scan(https_target, http_response=response)

        missing = [f for f in findings if f.finding_type == "missing_x_content_type_options"]
        assert len(missing) == 1
        assert missing[0].severity == Severity.LOW

    def test_nosniff_present_no_finding(self, https_target):
        """X-Content-Type-Options: nosniff should not produce a finding."""
        from webinspector.modules.header_scanner import HeaderScanner

        response = _make_response({
            "X-Content-Type-Options": "nosniff",
        })

        scanner = HeaderScanner()
        findings = scanner.scan(https_target, http_response=response)

        missing = [f for f in findings if f.finding_type == "missing_x_content_type_options"]
        assert len(missing) == 0


# ===========================================================================
# Tests for Strict-Transport-Security (HSTS)
# ===========================================================================

class TestHSTS:
    """Verify detection of HSTS issues on HTTPS targets."""

    def test_detects_missing_hsts_on_https(self, https_target):
        """
        Missing HSTS on an HTTPS target allows protocol downgrade attacks.
        MEDIUM severity because HTTPS is already being used.
        """
        from webinspector.modules.header_scanner import HeaderScanner

        response = _make_response({})

        scanner = HeaderScanner()
        findings = scanner.scan(https_target, http_response=response)

        missing_hsts = [f for f in findings if f.finding_type == "missing_hsts"]
        assert len(missing_hsts) == 1
        assert missing_hsts[0].severity == Severity.MEDIUM

    def test_no_hsts_finding_on_http(self, http_target):
        """
        HSTS on an HTTP target is meaningless (browsers ignore it on
        insecure connections), so no missing_hsts finding should be
        produced for HTTP targets.
        """
        from webinspector.modules.header_scanner import HeaderScanner

        response = _make_response({})

        scanner = HeaderScanner()
        findings = scanner.scan(http_target, http_response=response)

        missing_hsts = [f for f in findings if f.finding_type == "missing_hsts"]
        assert len(missing_hsts) == 0

    def test_hsts_present_no_missing_finding(self, https_target):
        """HSTS with adequate max-age should not produce a missing_hsts finding."""
        from webinspector.modules.header_scanner import HeaderScanner

        response = _make_response({
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        })

        scanner = HeaderScanner()
        findings = scanner.scan(https_target, http_response=response)

        missing_hsts = [f for f in findings if f.finding_type == "missing_hsts"]
        assert len(missing_hsts) == 0

    def test_detects_short_max_age(self, https_target):
        """
        HSTS max-age below 31536000 (1 year) is considered insufficient
        because short max-age values are easily bypassed if the user
        doesn't visit the site frequently.  LOW severity.
        """
        from webinspector.modules.header_scanner import HeaderScanner

        response = _make_response({
            "Strict-Transport-Security": "max-age=86400",  # 1 day
        })

        scanner = HeaderScanner()
        findings = scanner.scan(https_target, http_response=response)

        short = [f for f in findings if f.finding_type == "hsts_short_max_age"]
        assert len(short) == 1
        assert short[0].severity == Severity.LOW

    def test_adequate_max_age_no_short_finding(self, https_target):
        """HSTS max-age >= 31536000 should not produce hsts_short_max_age finding."""
        from webinspector.modules.header_scanner import HeaderScanner

        response = _make_response({
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        })

        scanner = HeaderScanner()
        findings = scanner.scan(https_target, http_response=response)

        short = [f for f in findings if f.finding_type == "hsts_short_max_age"]
        assert len(short) == 0

    def test_detects_missing_include_subdomains(self, https_target):
        """
        HSTS without includeSubDomains allows subdomains to be served
        over HTTP, which can be exploited for cookie injection attacks.
        LOW severity.
        """
        from webinspector.modules.header_scanner import HeaderScanner

        response = _make_response({
            "Strict-Transport-Security": "max-age=31536000",
        })

        scanner = HeaderScanner()
        findings = scanner.scan(https_target, http_response=response)

        missing_sub = [f for f in findings if f.finding_type == "hsts_missing_include_subdomains"]
        assert len(missing_sub) == 1
        assert missing_sub[0].severity == Severity.LOW

    def test_include_subdomains_present_no_finding(self, https_target):
        """HSTS with includeSubDomains should not produce the finding."""
        from webinspector.modules.header_scanner import HeaderScanner

        response = _make_response({
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        })

        scanner = HeaderScanner()
        findings = scanner.scan(https_target, http_response=response)

        missing_sub = [f for f in findings if f.finding_type == "hsts_missing_include_subdomains"]
        assert len(missing_sub) == 0


# ===========================================================================
# Tests for Referrer-Policy
# ===========================================================================

class TestReferrerPolicy:
    """Verify detection of Referrer-Policy issues."""

    def test_detects_missing_referrer_policy(self, https_target):
        """
        Missing Referrer-Policy means the browser's default behaviour
        applies, which may leak the full URL (including query params)
        as a referer.  LOW severity.
        """
        from webinspector.modules.header_scanner import HeaderScanner

        response = _make_response({})

        scanner = HeaderScanner()
        findings = scanner.scan(https_target, http_response=response)

        missing = [f for f in findings if f.finding_type == "missing_referrer_policy"]
        assert len(missing) == 1
        assert missing[0].severity == Severity.LOW

    def test_referrer_policy_present_no_missing_finding(self, https_target):
        """A safe Referrer-Policy should not produce a missing finding."""
        from webinspector.modules.header_scanner import HeaderScanner

        response = _make_response({
            "Referrer-Policy": "strict-origin-when-cross-origin",
        })

        scanner = HeaderScanner()
        findings = scanner.scan(https_target, http_response=response)

        missing = [f for f in findings if f.finding_type == "missing_referrer_policy"]
        assert len(missing) == 0

    def test_detects_unsafe_url_referrer_policy(self, https_target):
        """
        Referrer-Policy: unsafe-url always sends the full URL as the
        referer, even for cross-origin requests over HTTP.  This leaks
        potentially sensitive URL parameters.  MEDIUM severity.
        """
        from webinspector.modules.header_scanner import HeaderScanner

        response = _make_response({
            "Referrer-Policy": "unsafe-url",
        })

        scanner = HeaderScanner()
        findings = scanner.scan(https_target, http_response=response)

        unsafe = [f for f in findings if f.finding_type == "unsafe_referrer_policy"]
        assert len(unsafe) == 1
        assert unsafe[0].severity == Severity.MEDIUM

    def test_detects_no_referrer_when_downgrade(self, https_target):
        """
        Referrer-Policy: no-referrer-when-downgrade sends the full URL
        as referer for same-protocol requests.  This is the legacy
        default and leaks URL parameters.  MEDIUM severity.
        """
        from webinspector.modules.header_scanner import HeaderScanner

        response = _make_response({
            "Referrer-Policy": "no-referrer-when-downgrade",
        })

        scanner = HeaderScanner()
        findings = scanner.scan(https_target, http_response=response)

        unsafe = [f for f in findings if f.finding_type == "unsafe_referrer_policy"]
        assert len(unsafe) == 1
        assert unsafe[0].severity == Severity.MEDIUM

    def test_safe_referrer_policy_no_unsafe_finding(self, https_target):
        """A safe Referrer-Policy value should not produce unsafe finding."""
        from webinspector.modules.header_scanner import HeaderScanner

        response = _make_response({
            "Referrer-Policy": "no-referrer",
        })

        scanner = HeaderScanner()
        findings = scanner.scan(https_target, http_response=response)

        unsafe = [f for f in findings if f.finding_type == "unsafe_referrer_policy"]
        assert len(unsafe) == 0


# ===========================================================================
# Tests for Permissions-Policy
# ===========================================================================

class TestPermissionsPolicy:
    """Verify detection of Permissions-Policy issues."""

    def test_detects_missing_permissions_policy(self, https_target):
        """
        Missing Permissions-Policy allows all browser features by default,
        including sensitive ones like camera, microphone, geolocation.
        LOW severity.
        """
        from webinspector.modules.header_scanner import HeaderScanner

        response = _make_response({})

        scanner = HeaderScanner()
        findings = scanner.scan(https_target, http_response=response)

        missing = [f for f in findings if f.finding_type == "missing_permissions_policy"]
        assert len(missing) == 1
        assert missing[0].severity == Severity.LOW

    def test_permissions_policy_present_no_missing_finding(self, https_target):
        """A Permissions-Policy should not produce a missing finding."""
        from webinspector.modules.header_scanner import HeaderScanner

        response = _make_response({
            "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
        })

        scanner = HeaderScanner()
        findings = scanner.scan(https_target, http_response=response)

        missing = [f for f in findings if f.finding_type == "missing_permissions_policy"]
        assert len(missing) == 0

    def test_detects_wildcard_camera(self, https_target):
        """
        Permissions-Policy granting camera=* allows any embedded frame
        to access the user's camera.  MEDIUM severity.
        """
        from webinspector.modules.header_scanner import HeaderScanner

        response = _make_response({
            "Permissions-Policy": "camera=*, microphone=()",
        })

        scanner = HeaderScanner()
        findings = scanner.scan(https_target, http_response=response)

        wildcard = [f for f in findings if f.finding_type == "permissions_policy_wildcard"]
        assert len(wildcard) >= 1
        assert wildcard[0].severity == Severity.MEDIUM

    def test_detects_wildcard_microphone(self, https_target):
        """
        Permissions-Policy granting microphone=* allows any embedded
        frame to access the user's microphone.  MEDIUM severity.
        """
        from webinspector.modules.header_scanner import HeaderScanner

        response = _make_response({
            "Permissions-Policy": "microphone=*, camera=()",
        })

        scanner = HeaderScanner()
        findings = scanner.scan(https_target, http_response=response)

        wildcard = [f for f in findings if f.finding_type == "permissions_policy_wildcard"]
        assert len(wildcard) >= 1
        assert wildcard[0].severity == Severity.MEDIUM

    def test_detects_wildcard_geolocation(self, https_target):
        """
        Permissions-Policy granting geolocation=* allows any embedded
        frame to access the user's location.  MEDIUM severity.
        """
        from webinspector.modules.header_scanner import HeaderScanner

        response = _make_response({
            "Permissions-Policy": "geolocation=*",
        })

        scanner = HeaderScanner()
        findings = scanner.scan(https_target, http_response=response)

        wildcard = [f for f in findings if f.finding_type == "permissions_policy_wildcard"]
        assert len(wildcard) >= 1
        assert wildcard[0].severity == Severity.MEDIUM

    def test_restricted_permissions_no_wildcard_finding(self, https_target):
        """
        Permissions-Policy with restricted sensitive features should not
        produce a wildcard finding.
        """
        from webinspector.modules.header_scanner import HeaderScanner

        response = _make_response({
            "Permissions-Policy": "camera=(), microphone=(), geolocation=(self)",
        })

        scanner = HeaderScanner()
        findings = scanner.scan(https_target, http_response=response)

        wildcard = [f for f in findings if f.finding_type == "permissions_policy_wildcard"]
        assert len(wildcard) == 0


# ===========================================================================
# Tests for deprecated headers
# ===========================================================================

class TestDeprecatedHeaders:
    """Verify detection of deprecated security headers."""

    def test_detects_x_xss_protection(self, https_target):
        """
        X-XSS-Protection is deprecated.  Modern browsers have removed
        their XSS auditors because they caused more problems than they
        solved (information leaks, incorrect blocking).  INFORMATIONAL.
        """
        from webinspector.modules.header_scanner import HeaderScanner

        response = _make_response({
            "X-XSS-Protection": "1; mode=block",
        })

        scanner = HeaderScanner()
        findings = scanner.scan(https_target, http_response=response)

        deprecated = [f for f in findings if f.finding_type == "deprecated_header"
                      and "X-XSS-Protection" in f.detail]
        assert len(deprecated) == 1
        assert deprecated[0].severity == Severity.INFORMATIONAL

    def test_detects_public_key_pins(self, https_target):
        """
        Public-Key-Pins (HPKP) is deprecated due to the risk of
        permanently bricking a site if keys are rotated incorrectly.
        Chrome removed support in 2018.  INFORMATIONAL.
        """
        from webinspector.modules.header_scanner import HeaderScanner

        response = _make_response({
            "Public-Key-Pins": 'pin-sha256="abc123"; max-age=5184000',
        })

        scanner = HeaderScanner()
        findings = scanner.scan(https_target, http_response=response)

        deprecated = [f for f in findings if f.finding_type == "deprecated_header"
                      and "Public-Key-Pins" in f.detail]
        assert len(deprecated) == 1
        assert deprecated[0].severity == Severity.INFORMATIONAL

    def test_detects_expect_ct(self, https_target):
        """
        Expect-CT is deprecated since Certificate Transparency is now
        required by all major browsers for all certificates.
        INFORMATIONAL.
        """
        from webinspector.modules.header_scanner import HeaderScanner

        response = _make_response({
            "Expect-CT": "max-age=86400, enforce",
        })

        scanner = HeaderScanner()
        findings = scanner.scan(https_target, http_response=response)

        deprecated = [f for f in findings if f.finding_type == "deprecated_header"
                      and "Expect-CT" in f.detail]
        assert len(deprecated) == 1
        assert deprecated[0].severity == Severity.INFORMATIONAL

    def test_no_deprecated_headers_no_finding(self, https_target):
        """
        A response without deprecated headers should not produce any
        deprecated_header findings.
        """
        from webinspector.modules.header_scanner import HeaderScanner

        response = _make_hardened_response()

        scanner = HeaderScanner()
        findings = scanner.scan(https_target, http_response=response)

        deprecated = [f for f in findings if f.finding_type == "deprecated_header"]
        assert len(deprecated) == 0


# ===========================================================================
# Tests for clean (fully hardened) response
# ===========================================================================

class TestCleanResponse:
    """Verify that a fully hardened response produces zero findings."""

    def test_hardened_https_response_no_findings(self, https_target):
        """
        A response with all recommended security headers properly
        configured should produce zero findings.
        """
        from webinspector.modules.header_scanner import HeaderScanner

        response = _make_hardened_response()

        scanner = HeaderScanner()
        findings = scanner.scan(https_target, http_response=response)

        assert len(findings) == 0

    def test_hardened_http_response_minimal_findings(self, http_target):
        """
        A hardened response on an HTTP target should not produce
        HSTS-related findings (HSTS is only relevant for HTTPS).
        """
        from webinspector.modules.header_scanner import HeaderScanner

        response = _make_hardened_response()

        scanner = HeaderScanner()
        findings = scanner.scan(http_target, http_response=response)

        # No HSTS findings on HTTP
        hsts_findings = [f for f in findings if "hsts" in f.finding_type]
        assert len(hsts_findings) == 0


# ===========================================================================
# Tests for multiple findings in a single scan
# ===========================================================================

class TestMultipleFindings:
    """Verify that multiple issues on a single target are all reported."""

    def test_empty_headers_produces_multiple_findings(self, https_target):
        """
        A response with no security headers at all should produce
        multiple findings covering all the missing header checks.
        """
        from webinspector.modules.header_scanner import HeaderScanner

        response = _make_response({})

        scanner = HeaderScanner()
        findings = scanner.scan(https_target, http_response=response)

        # Extract finding types
        types = {f.finding_type for f in findings}

        # Should have findings for all missing headers
        assert "missing_csp" in types
        assert "missing_x_frame_options" in types
        assert "missing_x_content_type_options" in types
        assert "missing_hsts" in types
        assert "missing_referrer_policy" in types
        assert "missing_permissions_policy" in types

    def test_findings_have_correct_module(self, https_target):
        """Every finding should have module='headers'."""
        from webinspector.modules.header_scanner import HeaderScanner

        response = _make_response({})

        scanner = HeaderScanner()
        findings = scanner.scan(https_target, http_response=response)

        assert len(findings) >= 2
        for finding in findings:
            assert finding.module == "headers"
            assert finding.target is https_target

    def test_findings_have_titles_and_details(self, https_target):
        """Every finding should have non-empty title and detail."""
        from webinspector.modules.header_scanner import HeaderScanner

        response = _make_response({})

        scanner = HeaderScanner()
        findings = scanner.scan(https_target, http_response=response)

        for finding in findings:
            assert len(finding.title) > 0
            assert len(finding.detail) > 0

    def test_csp_quality_checks_with_weak_csp(self, https_target):
        """
        A CSP that is present but weak should produce multiple CSP
        quality findings but NOT a missing_csp finding.
        """
        from webinspector.modules.header_scanner import HeaderScanner

        response = _make_response({
            "Content-Security-Policy": "script-src 'unsafe-inline' 'unsafe-eval' * data:",
        })

        scanner = HeaderScanner()
        findings = scanner.scan(https_target, http_response=response)

        types = {f.finding_type for f in findings}

        # Should NOT have missing_csp
        assert "missing_csp" not in types

        # Should have all CSP quality findings
        assert "csp_unsafe_inline" in types
        assert "csp_unsafe_eval" in types
        assert "csp_wildcard" in types
        assert "csp_data_uri" in types
        assert "csp_missing_default_src" in types


# ===========================================================================
# Test module registration
# ===========================================================================

class TestHeaderScannerRegistration:
    """Verify that importing the module registers it."""

    def test_module_registers(self):
        """
        Importing header_scanner should call register_module() at the
        bottom of the file, making it discoverable by the module registry.
        """
        from webinspector.modules import _registry
        from webinspector.modules.header_scanner import HeaderScanner

        # The module registers itself at import time.
        # Check that an instance of HeaderScanner is in the registry.
        header_modules = [m for m in _registry if m.name == "headers"]
        assert len(header_modules) >= 1
        assert isinstance(header_modules[0], HeaderScanner)
