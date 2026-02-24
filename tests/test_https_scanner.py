"""
Tests for the HTTPS enforcement scanner module (https_scanner.py).

These tests verify that the HTTPSScanner module correctly:
    1. Has the correct name and description properties
    2. Accepts both HTTP and HTTPS targets
    3. Detects missing HTTP-to-HTTPS redirect on HTTP targets (MEDIUM)
    4. Detects non-permanent redirects (302/303/307 instead of 301) (INFORMATIONAL)
    5. Detects excessive redirect chains (more than 2 hops) (LOW)
    6. Detects missing HSTS header on HTTPS targets (MEDIUM)
    7. Detects HSTS with short max-age (< 31536000 / 1 year) (LOW)
    8. Detects HSTS missing includeSubDomains directive (LOW)
    9. Detects HSTS missing preload directive (INFORMATIONAL)
   10. Returns empty findings for a properly configured HTTPS target
   11. Handles connection errors gracefully (no crashes)
   12. Produces findings with correct module name, titles, and details
   13. Verifies module registration via register_module()

All HTTP requests are mocked using unittest.mock.patch -- no real network
connections are made.  We mock the session.get() method to simulate server
responses with various redirect and HSTS header configurations.

Author: Red Siege Information Security
"""

import pytest
from unittest.mock import MagicMock, patch

from webinspector.core.target import Target
from webinspector.core.result import Finding, Severity


# ---------------------------------------------------------------------------
# Mock helpers -- simulate HTTP responses with redirect and HSTS behaviour
# ---------------------------------------------------------------------------

def _make_response(status_code=200, headers=None, url=None):
    """
    Build a mock requests.Response with the given status code and headers.

    Args:
        status_code: HTTP status code for the response (e.g., 301, 302, 200).
        headers:     Dict mapping header names to values.  If None, empty dict.
        url:         The URL of the response (useful for verifying redirect target).

    Returns:
        A MagicMock mimicking requests.Response with .status_code, .headers,
        and .url attributes set.
    """
    response = MagicMock()
    response.status_code = status_code
    response.headers = headers or {}
    response.url = url or "https://example.com:443"
    return response


def _make_redirect_response(status_code, location, url=None):
    """
    Build a mock redirect response with a Location header.

    Simulates an HTTP redirect response (301, 302, 303, 307, etc.)
    with the given Location header pointing to the redirect target.

    Args:
        status_code: The redirect HTTP status code (e.g., 301, 302).
        location:    The value of the Location header (redirect target URL).
        url:         The URL of this response (the source of the redirect).

    Returns:
        A MagicMock mimicking a redirect requests.Response.
    """
    return _make_response(
        status_code=status_code,
        headers={"Location": location},
        url=url or "http://example.com:80",
    )


def _make_hsts_response(hsts_value=None, extra_headers=None):
    """
    Build a mock HTTPS response with an optional HSTS header.

    Args:
        hsts_value:    The Strict-Transport-Security header value.
                       If None, the header is omitted.
        extra_headers: Additional headers to include in the response.

    Returns:
        A MagicMock mimicking an HTTPS response.
    """
    headers = {}
    if hsts_value is not None:
        headers["Strict-Transport-Security"] = hsts_value
    if extra_headers:
        headers.update(extra_headers)
    return _make_response(
        status_code=200,
        headers=headers,
        url="https://example.com:443",
    )


# ---------------------------------------------------------------------------
# Target fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def https_target():
    """An HTTPS target for HTTPS enforcement scanning."""
    return Target(host="example.com", port=443, scheme="https")


@pytest.fixture
def http_target():
    """An HTTP target for HTTPS enforcement scanning."""
    return Target(host="example.com", port=80, scheme="http")


# ===========================================================================
# Tests for module properties
# ===========================================================================

class TestHTTPSScannerProperties:
    """Verify name and description properties of the HTTPS scanner."""

    def test_name(self):
        """Module name should be 'https'."""
        from webinspector.modules.https_scanner import HTTPSScanner
        scanner = HTTPSScanner()
        assert scanner.name == "https"

    def test_description(self):
        """Module should have a non-empty description mentioning HTTPS."""
        from webinspector.modules.https_scanner import HTTPSScanner
        scanner = HTTPSScanner()
        assert len(scanner.description) > 0
        assert "https" in scanner.description.lower()


# ===========================================================================
# Tests for accepts_target
# ===========================================================================

class TestHTTPSScannerAcceptsTarget:
    """Verify that the HTTPS scanner accepts both HTTP and HTTPS targets."""

    def test_accepts_https(self, https_target):
        """HTTPS scanner should accept targets with scheme='https'."""
        from webinspector.modules.https_scanner import HTTPSScanner
        scanner = HTTPSScanner()
        assert scanner.accepts_target(https_target) is True

    def test_accepts_http(self, http_target):
        """HTTPS scanner should accept targets with scheme='http'."""
        from webinspector.modules.https_scanner import HTTPSScanner
        scanner = HTTPSScanner()
        assert scanner.accepts_target(http_target) is True


# ===========================================================================
# Tests for HTTP-to-HTTPS redirect checking (HTTP targets)
# ===========================================================================

class TestNoHTTPSRedirect:
    """Verify detection of missing HTTP-to-HTTPS redirect."""

    @patch("webinspector.modules.https_scanner.create_http_session")
    def test_detects_no_redirect(self, mock_create, http_target):
        """
        When an HTTP target responds with 200 (no redirect), this is a MEDIUM
        finding because traffic can be intercepted in transit.

        The scanner should request http://example.com:80 with
        allow_redirects=False and see a 200 response (no redirect).
        """
        from webinspector.modules.https_scanner import HTTPSScanner

        session = MagicMock()
        # HTTP request returns 200 (no redirect)
        session.get.return_value = _make_response(
            status_code=200,
            url="http://example.com:80",
        )
        mock_create.return_value = (session, 10)

        scanner = HTTPSScanner()
        findings = scanner.scan(http_target)

        no_redirect = [f for f in findings if f.finding_type == "no_https_redirect"]
        assert len(no_redirect) == 1
        assert no_redirect[0].severity == Severity.MEDIUM

    @patch("webinspector.modules.https_scanner.create_http_session")
    def test_301_redirect_to_https_no_finding(self, mock_create, http_target):
        """
        When the HTTP target responds with a 301 redirect to an HTTPS URL,
        no no_https_redirect finding should be produced.

        This is the ideal configuration: permanent redirect to HTTPS.
        """
        from webinspector.modules.https_scanner import HTTPSScanner

        session = MagicMock()
        # First hop: 301 redirect to HTTPS
        session.get.return_value = _make_redirect_response(
            status_code=301,
            location="https://example.com/",
            url="http://example.com:80",
        )
        mock_create.return_value = (session, 10)

        scanner = HTTPSScanner()
        findings = scanner.scan(http_target)

        no_redirect = [f for f in findings if f.finding_type == "no_https_redirect"]
        assert len(no_redirect) == 0

    @patch("webinspector.modules.https_scanner.create_http_session")
    def test_non_redirect_status_4xx(self, mock_create, http_target):
        """
        When an HTTP target responds with a 4xx error (not a redirect),
        it should be treated as missing the HTTPS redirect.
        """
        from webinspector.modules.https_scanner import HTTPSScanner

        session = MagicMock()
        session.get.return_value = _make_response(
            status_code=403,
            url="http://example.com:80",
        )
        mock_create.return_value = (session, 10)

        scanner = HTTPSScanner()
        findings = scanner.scan(http_target)

        no_redirect = [f for f in findings if f.finding_type == "no_https_redirect"]
        assert len(no_redirect) == 1


class TestNonPermanentRedirect:
    """Verify detection of non-permanent (302/303/307) redirects."""

    @patch("webinspector.modules.https_scanner.create_http_session")
    def test_detects_302_redirect(self, mock_create, http_target):
        """
        A 302 (Found/Temporary) redirect to HTTPS instead of 301 (Permanent)
        is an INFORMATIONAL finding.  Search engines and browsers treat 302
        as temporary, so they don't cache the redirect decision permanently.
        """
        from webinspector.modules.https_scanner import HTTPSScanner

        session = MagicMock()
        session.get.return_value = _make_redirect_response(
            status_code=302,
            location="https://example.com/",
            url="http://example.com:80",
        )
        mock_create.return_value = (session, 10)

        scanner = HTTPSScanner()
        findings = scanner.scan(http_target)

        non_perm = [f for f in findings if f.finding_type == "non_permanent_redirect"]
        assert len(non_perm) == 1
        assert non_perm[0].severity == Severity.INFORMATIONAL

    @patch("webinspector.modules.https_scanner.create_http_session")
    def test_detects_303_redirect(self, mock_create, http_target):
        """
        A 303 (See Other) redirect to HTTPS should also be flagged as
        non-permanent.  INFORMATIONAL severity.
        """
        from webinspector.modules.https_scanner import HTTPSScanner

        session = MagicMock()
        session.get.return_value = _make_redirect_response(
            status_code=303,
            location="https://example.com/",
            url="http://example.com:80",
        )
        mock_create.return_value = (session, 10)

        scanner = HTTPSScanner()
        findings = scanner.scan(http_target)

        non_perm = [f for f in findings if f.finding_type == "non_permanent_redirect"]
        assert len(non_perm) == 1
        assert non_perm[0].severity == Severity.INFORMATIONAL

    @patch("webinspector.modules.https_scanner.create_http_session")
    def test_detects_307_redirect(self, mock_create, http_target):
        """
        A 307 (Temporary Redirect) to HTTPS should be flagged as
        non-permanent.  INFORMATIONAL severity.
        """
        from webinspector.modules.https_scanner import HTTPSScanner

        session = MagicMock()
        session.get.return_value = _make_redirect_response(
            status_code=307,
            location="https://example.com/",
            url="http://example.com:80",
        )
        mock_create.return_value = (session, 10)

        scanner = HTTPSScanner()
        findings = scanner.scan(http_target)

        non_perm = [f for f in findings if f.finding_type == "non_permanent_redirect"]
        assert len(non_perm) == 1
        assert non_perm[0].severity == Severity.INFORMATIONAL

    @patch("webinspector.modules.https_scanner.create_http_session")
    def test_301_redirect_no_non_permanent_finding(self, mock_create, http_target):
        """
        A 301 redirect to HTTPS is the correct behaviour and should NOT
        produce a non_permanent_redirect finding.
        """
        from webinspector.modules.https_scanner import HTTPSScanner

        session = MagicMock()
        session.get.return_value = _make_redirect_response(
            status_code=301,
            location="https://example.com/",
            url="http://example.com:80",
        )
        mock_create.return_value = (session, 10)

        scanner = HTTPSScanner()
        findings = scanner.scan(http_target)

        non_perm = [f for f in findings if f.finding_type == "non_permanent_redirect"]
        assert len(non_perm) == 0


class TestExcessiveRedirectChain:
    """Verify detection of redirect chains with more than 2 hops."""

    @patch("webinspector.modules.https_scanner.create_http_session")
    def test_detects_excessive_redirects(self, mock_create, http_target):
        """
        When there are more than 2 redirect hops to reach HTTPS, this is
        a LOW finding indicating unnecessary latency and complexity.

        We simulate: HTTP -> 301 HTTP -> 301 HTTP -> 301 HTTPS (3 hops).
        """
        from webinspector.modules.https_scanner import HTTPSScanner

        session = MagicMock()
        # Simulate a chain of 3 redirects by returning successive redirect
        # responses.  The scanner should follow redirects manually (with
        # allow_redirects=False) and count the hops.
        responses = [
            _make_redirect_response(301, "http://www.example.com/", url="http://example.com:80"),
            _make_redirect_response(301, "http://www.example.com/en/", url="http://www.example.com/"),
            _make_redirect_response(301, "https://www.example.com/en/", url="http://www.example.com/en/"),
        ]
        session.get.side_effect = responses
        mock_create.return_value = (session, 10)

        scanner = HTTPSScanner()
        findings = scanner.scan(http_target)

        excessive = [f for f in findings if f.finding_type == "excessive_redirect_chain"]
        assert len(excessive) == 1
        assert excessive[0].severity == Severity.LOW

    @patch("webinspector.modules.https_scanner.create_http_session")
    def test_two_hop_redirect_no_excessive_finding(self, mock_create, http_target):
        """
        A redirect chain of exactly 2 hops should NOT produce an
        excessive_redirect_chain finding (the threshold is >2).

        Simulate: HTTP -> 301 HTTP -> 301 HTTPS (2 hops).
        """
        from webinspector.modules.https_scanner import HTTPSScanner

        session = MagicMock()
        responses = [
            _make_redirect_response(301, "http://www.example.com/", url="http://example.com:80"),
            _make_redirect_response(301, "https://www.example.com/", url="http://www.example.com/"),
        ]
        session.get.side_effect = responses
        mock_create.return_value = (session, 10)

        scanner = HTTPSScanner()
        findings = scanner.scan(http_target)

        excessive = [f for f in findings if f.finding_type == "excessive_redirect_chain"]
        assert len(excessive) == 0

    @patch("webinspector.modules.https_scanner.create_http_session")
    def test_single_redirect_no_excessive_finding(self, mock_create, http_target):
        """
        A single-hop redirect (the ideal case) should NOT produce an
        excessive_redirect_chain finding.

        Simulate: HTTP -> 301 HTTPS (1 hop).
        """
        from webinspector.modules.https_scanner import HTTPSScanner

        session = MagicMock()
        session.get.return_value = _make_redirect_response(
            status_code=301,
            location="https://example.com/",
            url="http://example.com:80",
        )
        mock_create.return_value = (session, 10)

        scanner = HTTPSScanner()
        findings = scanner.scan(http_target)

        excessive = [f for f in findings if f.finding_type == "excessive_redirect_chain"]
        assert len(excessive) == 0


# ===========================================================================
# Tests for HSTS header analysis (HTTPS targets)
# ===========================================================================

class TestMissingHSTS:
    """Verify detection of missing HSTS header on HTTPS targets."""

    @patch("webinspector.modules.https_scanner.create_http_session")
    def test_detects_missing_hsts(self, mock_create, https_target):
        """
        An HTTPS target without the Strict-Transport-Security header is
        vulnerable to protocol downgrade attacks.  MEDIUM severity.
        """
        from webinspector.modules.https_scanner import HTTPSScanner

        session = MagicMock()
        # Return 200 with no HSTS header
        session.get.return_value = _make_hsts_response(hsts_value=None)
        mock_create.return_value = (session, 10)

        scanner = HTTPSScanner()
        # Pass the pre-fetched response for HSTS analysis
        findings = scanner.scan(https_target, http_response=_make_hsts_response(hsts_value=None))

        missing_hsts = [f for f in findings if f.finding_type == "missing_hsts"]
        assert len(missing_hsts) == 1
        assert missing_hsts[0].severity == Severity.MEDIUM

    @patch("webinspector.modules.https_scanner.create_http_session")
    def test_hsts_present_no_missing_finding(self, mock_create, https_target):
        """
        When HSTS is present with adequate max-age, includeSubDomains,
        and preload, no missing_hsts finding should be produced.
        """
        from webinspector.modules.https_scanner import HTTPSScanner

        session = MagicMock()
        resp = _make_hsts_response(
            hsts_value="max-age=31536000; includeSubDomains; preload"
        )
        session.get.return_value = resp
        mock_create.return_value = (session, 10)

        scanner = HTTPSScanner()
        findings = scanner.scan(https_target, http_response=resp)

        missing_hsts = [f for f in findings if f.finding_type == "missing_hsts"]
        assert len(missing_hsts) == 0


class TestHSTSShortMaxAge:
    """Verify detection of HSTS with short max-age value."""

    @patch("webinspector.modules.https_scanner.create_http_session")
    def test_detects_short_max_age(self, mock_create, https_target):
        """
        HSTS max-age below 31536000 seconds (1 year) is insufficient.
        Shorter durations mean the browser's HSTS cache expires quickly,
        leaving a window for protocol downgrade attacks.  LOW severity.
        """
        from webinspector.modules.https_scanner import HTTPSScanner

        session = MagicMock()
        resp = _make_hsts_response(
            hsts_value="max-age=86400; includeSubDomains; preload"
        )
        session.get.return_value = resp
        mock_create.return_value = (session, 10)

        scanner = HTTPSScanner()
        findings = scanner.scan(https_target, http_response=resp)

        short = [f for f in findings if f.finding_type == "hsts_short_max_age"]
        assert len(short) == 1
        assert short[0].severity == Severity.LOW

    @patch("webinspector.modules.https_scanner.create_http_session")
    def test_adequate_max_age_no_short_finding(self, mock_create, https_target):
        """
        HSTS max-age of exactly 31536000 (1 year) should NOT produce
        an hsts_short_max_age finding.
        """
        from webinspector.modules.https_scanner import HTTPSScanner

        session = MagicMock()
        resp = _make_hsts_response(
            hsts_value="max-age=31536000; includeSubDomains; preload"
        )
        session.get.return_value = resp
        mock_create.return_value = (session, 10)

        scanner = HTTPSScanner()
        findings = scanner.scan(https_target, http_response=resp)

        short = [f for f in findings if f.finding_type == "hsts_short_max_age"]
        assert len(short) == 0

    @patch("webinspector.modules.https_scanner.create_http_session")
    def test_max_age_zero_triggers_short_finding(self, mock_create, https_target):
        """
        HSTS max-age=0 disables HSTS entirely and should be flagged
        as hsts_short_max_age.  LOW severity.
        """
        from webinspector.modules.https_scanner import HTTPSScanner

        session = MagicMock()
        resp = _make_hsts_response(
            hsts_value="max-age=0; includeSubDomains; preload"
        )
        session.get.return_value = resp
        mock_create.return_value = (session, 10)

        scanner = HTTPSScanner()
        findings = scanner.scan(https_target, http_response=resp)

        short = [f for f in findings if f.finding_type == "hsts_short_max_age"]
        assert len(short) == 1


class TestHSTSMissingIncludeSubDomains:
    """Verify detection of HSTS missing includeSubDomains."""

    @patch("webinspector.modules.https_scanner.create_http_session")
    def test_detects_missing_include_subdomains(self, mock_create, https_target):
        """
        HSTS without includeSubDomains allows subdomains to be served over
        HTTP, which enables cookie injection attacks.  LOW severity.
        """
        from webinspector.modules.https_scanner import HTTPSScanner

        session = MagicMock()
        resp = _make_hsts_response(
            hsts_value="max-age=31536000; preload"
        )
        session.get.return_value = resp
        mock_create.return_value = (session, 10)

        scanner = HTTPSScanner()
        findings = scanner.scan(https_target, http_response=resp)

        missing_sub = [f for f in findings if f.finding_type == "hsts_missing_include_subdomains"]
        assert len(missing_sub) == 1
        assert missing_sub[0].severity == Severity.LOW

    @patch("webinspector.modules.https_scanner.create_http_session")
    def test_include_subdomains_present_no_finding(self, mock_create, https_target):
        """
        HSTS with includeSubDomains should not produce the finding.
        """
        from webinspector.modules.https_scanner import HTTPSScanner

        session = MagicMock()
        resp = _make_hsts_response(
            hsts_value="max-age=31536000; includeSubDomains; preload"
        )
        session.get.return_value = resp
        mock_create.return_value = (session, 10)

        scanner = HTTPSScanner()
        findings = scanner.scan(https_target, http_response=resp)

        missing_sub = [f for f in findings if f.finding_type == "hsts_missing_include_subdomains"]
        assert len(missing_sub) == 0


class TestHSTSMissingPreload:
    """Verify detection of HSTS missing preload directive."""

    @patch("webinspector.modules.https_scanner.create_http_session")
    def test_detects_missing_preload(self, mock_create, https_target):
        """
        HSTS without the preload directive means the site is not eligible for
        browser preload lists.  INFORMATIONAL severity -- preload is a bonus,
        not a requirement.
        """
        from webinspector.modules.https_scanner import HTTPSScanner

        session = MagicMock()
        resp = _make_hsts_response(
            hsts_value="max-age=31536000; includeSubDomains"
        )
        session.get.return_value = resp
        mock_create.return_value = (session, 10)

        scanner = HTTPSScanner()
        findings = scanner.scan(https_target, http_response=resp)

        missing_preload = [f for f in findings if f.finding_type == "hsts_missing_preload"]
        assert len(missing_preload) == 1
        assert missing_preload[0].severity == Severity.INFORMATIONAL

    @patch("webinspector.modules.https_scanner.create_http_session")
    def test_preload_present_no_finding(self, mock_create, https_target):
        """HSTS with preload should not produce the finding."""
        from webinspector.modules.https_scanner import HTTPSScanner

        session = MagicMock()
        resp = _make_hsts_response(
            hsts_value="max-age=31536000; includeSubDomains; preload"
        )
        session.get.return_value = resp
        mock_create.return_value = (session, 10)

        scanner = HTTPSScanner()
        findings = scanner.scan(https_target, http_response=resp)

        missing_preload = [f for f in findings if f.finding_type == "hsts_missing_preload"]
        assert len(missing_preload) == 0


# ===========================================================================
# Tests for clean (fully hardened) HTTPS target
# ===========================================================================

class TestCleanHTTPSTarget:
    """Verify that a fully hardened HTTPS target produces minimal findings."""

    @patch("webinspector.modules.https_scanner.create_http_session")
    def test_hardened_https_no_hsts_findings(self, mock_create, https_target):
        """
        An HTTPS target with a properly configured HSTS header should
        produce zero HSTS-related findings.
        """
        from webinspector.modules.https_scanner import HTTPSScanner

        session = MagicMock()
        resp = _make_hsts_response(
            hsts_value="max-age=31536000; includeSubDomains; preload"
        )
        session.get.return_value = resp
        mock_create.return_value = (session, 10)

        scanner = HTTPSScanner()
        findings = scanner.scan(https_target, http_response=resp)

        # No HSTS findings at all
        hsts_findings = [f for f in findings if "hsts" in f.finding_type]
        assert len(hsts_findings) == 0

        # No missing_hsts finding
        missing_hsts = [f for f in findings if f.finding_type == "missing_hsts"]
        assert len(missing_hsts) == 0


class TestCleanHTTPTarget:
    """Verify that a properly configured HTTP target (with 301 redirect) is clean."""

    @patch("webinspector.modules.https_scanner.create_http_session")
    def test_proper_301_redirect_minimal_findings(self, mock_create, http_target):
        """
        An HTTP target that responds with a 301 redirect to HTTPS should
        produce zero redirect-related findings.
        """
        from webinspector.modules.https_scanner import HTTPSScanner

        session = MagicMock()
        session.get.return_value = _make_redirect_response(
            status_code=301,
            location="https://example.com/",
            url="http://example.com:80",
        )
        mock_create.return_value = (session, 10)

        scanner = HTTPSScanner()
        findings = scanner.scan(http_target)

        # No redirect-related findings
        redirect_findings = [
            f for f in findings
            if f.finding_type in ("no_https_redirect", "non_permanent_redirect", "excessive_redirect_chain")
        ]
        assert len(redirect_findings) == 0


# ===========================================================================
# Tests for connection error handling
# ===========================================================================

class TestConnectionErrors:
    """Verify graceful handling of HTTP request failures."""

    @patch("webinspector.modules.https_scanner.create_http_session")
    def test_connection_error_returns_empty(self, mock_create, http_target):
        """
        When the HTTP request fails with a connection error, the scanner
        should return an empty findings list without raising exceptions.
        """
        from webinspector.modules.https_scanner import HTTPSScanner

        session = MagicMock()
        session.get.side_effect = Exception("Connection refused")
        mock_create.return_value = (session, 10)

        scanner = HTTPSScanner()
        findings = scanner.scan(http_target)

        assert isinstance(findings, list)
        assert len(findings) == 0

    @patch("webinspector.modules.https_scanner.create_http_session")
    def test_connection_error_on_https_with_response(self, mock_create, https_target):
        """
        When an HTTPS target's redirect check fails but a pre-fetched
        response is available, HSTS checks should still run.
        """
        from webinspector.modules.https_scanner import HTTPSScanner

        session = MagicMock()
        session.get.side_effect = Exception("Connection refused")
        mock_create.return_value = (session, 10)

        # Pre-fetched response has no HSTS
        resp = _make_hsts_response(hsts_value=None)

        scanner = HTTPSScanner()
        findings = scanner.scan(https_target, http_response=resp)

        # Should still detect missing HSTS from the pre-fetched response
        missing_hsts = [f for f in findings if f.finding_type == "missing_hsts"]
        assert len(missing_hsts) == 1


# ===========================================================================
# Tests for finding structure and content
# ===========================================================================

class TestFindingStructure:
    """Verify that findings have correct module, title, detail fields."""

    @patch("webinspector.modules.https_scanner.create_http_session")
    def test_findings_have_correct_module(self, mock_create, http_target):
        """Every finding should have module='https'."""
        from webinspector.modules.https_scanner import HTTPSScanner

        session = MagicMock()
        session.get.return_value = _make_response(
            status_code=200,
            url="http://example.com:80",
        )
        mock_create.return_value = (session, 10)

        scanner = HTTPSScanner()
        findings = scanner.scan(http_target)

        assert len(findings) >= 1
        for finding in findings:
            assert finding.module == "https"
            assert finding.target is http_target

    @patch("webinspector.modules.https_scanner.create_http_session")
    def test_findings_have_titles_and_details(self, mock_create, http_target):
        """Every finding should have non-empty title and detail."""
        from webinspector.modules.https_scanner import HTTPSScanner

        session = MagicMock()
        session.get.return_value = _make_response(
            status_code=200,
            url="http://example.com:80",
        )
        mock_create.return_value = (session, 10)

        scanner = HTTPSScanner()
        findings = scanner.scan(http_target)

        for finding in findings:
            assert len(finding.title) > 0
            assert len(finding.detail) > 0

    @patch("webinspector.modules.https_scanner.create_http_session")
    def test_findings_have_references(self, mock_create, http_target):
        """Every finding should include at least one CWE reference."""
        from webinspector.modules.https_scanner import HTTPSScanner

        session = MagicMock()
        session.get.return_value = _make_response(
            status_code=200,
            url="http://example.com:80",
        )
        mock_create.return_value = (session, 10)

        scanner = HTTPSScanner()
        findings = scanner.scan(http_target)

        for finding in findings:
            assert len(finding.references) > 0


# ===========================================================================
# Tests for redirect to non-HTTPS location
# ===========================================================================

class TestRedirectToHTTP:
    """Verify behaviour when the redirect target is still HTTP."""

    @patch("webinspector.modules.https_scanner.create_http_session")
    def test_redirect_to_http_still_no_https(self, mock_create, http_target):
        """
        A 301 redirect that points to another HTTP URL (not HTTPS) should
        still be counted in the chain.  If the chain never reaches HTTPS,
        the no_https_redirect finding should be produced.
        """
        from webinspector.modules.https_scanner import HTTPSScanner

        session = MagicMock()
        # Redirect chain stays on HTTP: http -> http -> 200 (no HTTPS)
        responses = [
            _make_redirect_response(301, "http://www.example.com/", url="http://example.com:80"),
            _make_response(status_code=200, url="http://www.example.com/"),
        ]
        session.get.side_effect = responses
        mock_create.return_value = (session, 10)

        scanner = HTTPSScanner()
        findings = scanner.scan(http_target)

        no_redirect = [f for f in findings if f.finding_type == "no_https_redirect"]
        assert len(no_redirect) == 1


# ===========================================================================
# Tests for HTTPS target behaviour (no redirect checking needed)
# ===========================================================================

class TestHTTPSTargetBehaviour:
    """Verify behaviour specific to HTTPS targets."""

    @patch("webinspector.modules.https_scanner.create_http_session")
    def test_https_target_skips_redirect_checks(self, mock_create, https_target):
        """
        For HTTPS targets, the scanner should only run HSTS checks,
        not redirect checks (redirects are checked on HTTP targets only).
        """
        from webinspector.modules.https_scanner import HTTPSScanner

        session = MagicMock()
        resp = _make_hsts_response(
            hsts_value="max-age=31536000; includeSubDomains; preload"
        )
        session.get.return_value = resp
        mock_create.return_value = (session, 10)

        scanner = HTTPSScanner()
        findings = scanner.scan(https_target, http_response=resp)

        # No redirect findings should be produced for HTTPS targets
        redirect_types = {"no_https_redirect", "non_permanent_redirect", "excessive_redirect_chain"}
        redirect_findings = [f for f in findings if f.finding_type in redirect_types]
        assert len(redirect_findings) == 0

    @patch("webinspector.modules.https_scanner.create_http_session")
    def test_https_target_no_response_checks_hsts_via_own_request(self, mock_create, https_target):
        """
        When an HTTPS target has no pre-fetched response, the scanner
        should make its own request to check HSTS.
        """
        from webinspector.modules.https_scanner import HTTPSScanner

        session = MagicMock()
        # The scanner's own request returns a response without HSTS
        session.get.return_value = _make_hsts_response(hsts_value=None)
        mock_create.return_value = (session, 10)

        scanner = HTTPSScanner()
        # No pre-fetched response
        findings = scanner.scan(https_target, http_response=None)

        missing_hsts = [f for f in findings if f.finding_type == "missing_hsts"]
        assert len(missing_hsts) == 1


# ===========================================================================
# Tests for HTTP target with HSTS (should not check HSTS on HTTP)
# ===========================================================================

class TestHTTPTargetNoHSTS:
    """Verify that HSTS is NOT checked on HTTP targets."""

    @patch("webinspector.modules.https_scanner.create_http_session")
    def test_http_target_no_hsts_findings(self, mock_create, http_target):
        """
        HSTS checks should only run on HTTPS targets.  Browsers ignore
        HSTS headers received over insecure connections, so checking
        HSTS on HTTP is meaningless.
        """
        from webinspector.modules.https_scanner import HTTPSScanner

        session = MagicMock()
        session.get.return_value = _make_response(
            status_code=200,
            url="http://example.com:80",
        )
        mock_create.return_value = (session, 10)

        scanner = HTTPSScanner()
        findings = scanner.scan(http_target)

        hsts_types = {"missing_hsts", "hsts_short_max_age",
                      "hsts_missing_include_subdomains", "hsts_missing_preload"}
        hsts_findings = [f for f in findings if f.finding_type in hsts_types]
        assert len(hsts_findings) == 0


# ===========================================================================
# Tests for multiple findings in a single scan
# ===========================================================================

class TestMultipleFindings:
    """Verify that multiple issues on a single target are all reported."""

    @patch("webinspector.modules.https_scanner.create_http_session")
    def test_https_target_multiple_hsts_issues(self, mock_create, https_target):
        """
        An HTTPS target with HSTS present but with short max-age, missing
        includeSubDomains, and missing preload should produce all three
        HSTS quality findings.
        """
        from webinspector.modules.https_scanner import HTTPSScanner

        session = MagicMock()
        resp = _make_hsts_response(hsts_value="max-age=86400")
        session.get.return_value = resp
        mock_create.return_value = (session, 10)

        scanner = HTTPSScanner()
        findings = scanner.scan(https_target, http_response=resp)

        types = {f.finding_type for f in findings}
        assert "hsts_short_max_age" in types
        assert "hsts_missing_include_subdomains" in types
        assert "hsts_missing_preload" in types

    @patch("webinspector.modules.https_scanner.create_http_session")
    def test_http_target_302_and_excessive_redirects(self, mock_create, http_target):
        """
        An HTTP target with a 302 redirect chain that is also excessive
        (>2 hops) should produce both non_permanent_redirect and
        excessive_redirect_chain findings.
        """
        from webinspector.modules.https_scanner import HTTPSScanner

        session = MagicMock()
        responses = [
            _make_redirect_response(302, "http://www.example.com/", url="http://example.com:80"),
            _make_redirect_response(302, "http://www.example.com/en/", url="http://www.example.com/"),
            _make_redirect_response(302, "https://www.example.com/en/", url="http://www.example.com/en/"),
        ]
        session.get.side_effect = responses
        mock_create.return_value = (session, 10)

        scanner = HTTPSScanner()
        findings = scanner.scan(http_target)

        types = {f.finding_type for f in findings}
        assert "non_permanent_redirect" in types
        assert "excessive_redirect_chain" in types


# ===========================================================================
# Test module registration
# ===========================================================================

class TestHTTPSScannerRegistration:
    """Verify that importing the module registers it."""

    def test_module_registers(self):
        """
        Importing https_scanner should call register_module() at the
        bottom of the file, making it discoverable by the module registry.
        """
        from webinspector.modules import _registry
        from webinspector.modules.https_scanner import HTTPSScanner

        # The module registers itself at import time.
        # Check that an instance of HTTPSScanner is in the registry.
        https_modules = [m for m in _registry if m.name == "https"]
        assert len(https_modules) >= 1
        assert isinstance(https_modules[0], HTTPSScanner)
