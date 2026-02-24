"""
Tests for the cookie security scanner module (cookie_scanner.py).

These tests verify that the CookieScanner module correctly:
    1. Accepts both HTTP and HTTPS targets (default accepts_target)
    2. Returns empty findings when http_response is None
    3. Returns empty findings when no Set-Cookie headers are present
    4. Detects missing Secure flag on session cookies (MEDIUM)
    5. Detects missing Secure flag on regular cookies (LOW)
    6. Detects missing HttpOnly flag on session cookies (MEDIUM)
    7. Detects missing HttpOnly flag on regular cookies (LOW)
    8. Detects missing SameSite attribute (LOW)
    9. Detects SameSite=None without Secure flag (MEDIUM)
   10. Detects persistent session cookies (Expires/Max-Age on session cookies) (LOW)
   11. Correctly identifies session cookies by name pattern matching
   12. Returns empty findings for a fully hardened cookie
   13. Handles multiple cookies in a single response
   14. Handles multiple findings on a single cookie

All HTTP responses are mocked using unittest.mock.MagicMock -- no real
HTTP connections are made.  Set-Cookie headers are accessed via
response.raw.headers.getlist("Set-Cookie") which returns a list of
individual cookie strings.

Author: Red Siege Information Security
"""

import pytest
from unittest.mock import MagicMock

from webinspector.core.target import Target
from webinspector.core.result import Finding, Severity


# ---------------------------------------------------------------------------
# Mock helper -- build a requests.Response stand-in with Set-Cookie headers
# ---------------------------------------------------------------------------

def _make_response(set_cookie_list: list[str]) -> MagicMock:
    """
    Build a mock requests.Response with the given Set-Cookie header values.

    Each item in set_cookie_list is a single raw Set-Cookie header string,
    for example: "JSESSIONID=abc123; Path=/; Secure; HttpOnly; SameSite=Strict"

    We mock response.raw.headers.getlist("Set-Cookie") to return the full
    list of Set-Cookie strings, which is the standard way to retrieve all
    Set-Cookie headers from a urllib3 response without them being merged.

    We also set response.headers as a dict with the merged Set-Cookie
    header (comma-separated) for the fallback path.

    Args:
        set_cookie_list: List of raw Set-Cookie header strings.

    Returns:
        A MagicMock mimicking requests.Response with .raw.headers mocked.
    """
    response = MagicMock()

    # Primary path: response.raw.headers.getlist("Set-Cookie")
    # This returns individual Set-Cookie strings without merging.
    raw_headers = MagicMock()
    raw_headers.getlist.return_value = set_cookie_list
    response.raw = MagicMock()
    response.raw.headers = raw_headers

    # Fallback path: response.headers as a dict
    # The requests library merges multiple Set-Cookie headers with ", "
    # which is problematic for parsing but serves as our fallback.
    if set_cookie_list:
        response.headers = {"Set-Cookie": ", ".join(set_cookie_list)}
    else:
        response.headers = {}

    return response


def _make_hardened_session_cookie() -> MagicMock:
    """
    Build a mock response with a fully hardened session cookie that should
    produce zero findings.

    The cookie includes:
        - Secure flag (only sent over HTTPS)
        - HttpOnly flag (not accessible via JavaScript)
        - SameSite=Strict (not sent on cross-site requests)
        - No Expires or Max-Age (session-scoped -- deleted when browser closes)
    """
    return _make_response([
        "JSESSIONID=abc123; Path=/; Secure; HttpOnly; SameSite=Strict",
    ])


# ---------------------------------------------------------------------------
# Target fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def https_target():
    """An HTTPS target for cookie scanning."""
    return Target(host="example.com", port=443, scheme="https")


@pytest.fixture
def http_target():
    """An HTTP target for cookie scanning."""
    return Target(host="example.com", port=80, scheme="http")


# ===========================================================================
# Tests for accepts_target
# ===========================================================================

class TestCookieScannerAcceptsTarget:
    """Verify that the cookie scanner accepts both HTTP and HTTPS targets."""

    def test_accepts_https(self, https_target):
        """Cookie scanner should accept targets with scheme='https'."""
        from webinspector.modules.cookie_scanner import CookieScanner
        scanner = CookieScanner()
        assert scanner.accepts_target(https_target) is True

    def test_accepts_http(self, http_target):
        """Cookie scanner should accept targets with scheme='http'."""
        from webinspector.modules.cookie_scanner import CookieScanner
        scanner = CookieScanner()
        assert scanner.accepts_target(http_target) is True


# ===========================================================================
# Tests for module properties
# ===========================================================================

class TestCookieScannerProperties:
    """Verify name and description properties."""

    def test_name(self):
        """Module name should be 'cookies'."""
        from webinspector.modules.cookie_scanner import CookieScanner
        scanner = CookieScanner()
        assert scanner.name == "cookies"

    def test_description(self):
        """Module should have a non-empty description."""
        from webinspector.modules.cookie_scanner import CookieScanner
        scanner = CookieScanner()
        assert len(scanner.description) > 0
        # Should mention cookies in the description
        assert "cookie" in scanner.description.lower()


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
        from webinspector.modules.cookie_scanner import CookieScanner
        scanner = CookieScanner()
        findings = scanner.scan(https_target, http_response=None)
        assert isinstance(findings, list)
        assert len(findings) == 0


# ===========================================================================
# Tests for no Set-Cookie headers
# ===========================================================================

class TestNoCookies:
    """Verify that responses without Set-Cookie headers produce no findings."""

    def test_no_set_cookie_headers(self, https_target):
        """
        A response with no Set-Cookie headers should produce zero
        cookie-related findings.
        """
        from webinspector.modules.cookie_scanner import CookieScanner

        response = _make_response([])
        scanner = CookieScanner()
        findings = scanner.scan(https_target, http_response=response)

        assert isinstance(findings, list)
        assert len(findings) == 0


# ===========================================================================
# Tests for missing Secure flag
# ===========================================================================

class TestMissingSecureFlag:
    """Verify detection of missing Secure flag on cookies."""

    def test_missing_secure_on_session_cookie_medium(self, https_target):
        """
        Missing Secure flag on a session cookie (JSESSIONID) should
        produce a MEDIUM severity finding.  Without Secure, the cookie
        is sent over unencrypted HTTP connections, allowing session
        hijacking via network sniffing.
        """
        from webinspector.modules.cookie_scanner import CookieScanner

        response = _make_response([
            "JSESSIONID=abc123; Path=/; HttpOnly; SameSite=Strict",
        ])

        scanner = CookieScanner()
        findings = scanner.scan(https_target, http_response=response)

        secure_findings = [f for f in findings
                           if f.finding_type == "missing_secure_flag"]
        assert len(secure_findings) == 1
        assert secure_findings[0].severity == Severity.MEDIUM

    def test_missing_secure_on_regular_cookie_low(self, https_target):
        """
        Missing Secure flag on a non-session cookie should produce a
        LOW severity finding.  Regular cookies are less sensitive but
        should still be protected.
        """
        from webinspector.modules.cookie_scanner import CookieScanner

        response = _make_response([
            "theme=dark; Path=/; HttpOnly; SameSite=Strict",
        ])

        scanner = CookieScanner()
        findings = scanner.scan(https_target, http_response=response)

        secure_findings = [f for f in findings
                           if f.finding_type == "missing_secure_flag"]
        assert len(secure_findings) == 1
        assert secure_findings[0].severity == Severity.LOW

    def test_secure_present_no_finding(self, https_target):
        """
        A cookie with the Secure flag present should not produce a
        missing_secure_flag finding.
        """
        from webinspector.modules.cookie_scanner import CookieScanner

        response = _make_response([
            "JSESSIONID=abc123; Path=/; Secure; HttpOnly; SameSite=Strict",
        ])

        scanner = CookieScanner()
        findings = scanner.scan(https_target, http_response=response)

        secure_findings = [f for f in findings
                           if f.finding_type == "missing_secure_flag"]
        assert len(secure_findings) == 0

    def test_secure_case_insensitive(self, https_target):
        """
        The Secure flag should be detected regardless of casing (e.g.,
        'secure', 'SECURE', 'Secure').
        """
        from webinspector.modules.cookie_scanner import CookieScanner

        response = _make_response([
            "JSESSIONID=abc123; Path=/; secure; HttpOnly; SameSite=Strict",
        ])

        scanner = CookieScanner()
        findings = scanner.scan(https_target, http_response=response)

        secure_findings = [f for f in findings
                           if f.finding_type == "missing_secure_flag"]
        assert len(secure_findings) == 0


# ===========================================================================
# Tests for missing HttpOnly flag
# ===========================================================================

class TestMissingHttpOnlyFlag:
    """Verify detection of missing HttpOnly flag on cookies."""

    def test_missing_httponly_on_session_cookie_medium(self, https_target):
        """
        Missing HttpOnly flag on a session cookie should produce a MEDIUM
        severity finding.  Without HttpOnly, the cookie is accessible via
        document.cookie in JavaScript, enabling session theft via XSS.
        """
        from webinspector.modules.cookie_scanner import CookieScanner

        response = _make_response([
            "PHPSESSID=sess123; Path=/; Secure; SameSite=Strict",
        ])

        scanner = CookieScanner()
        findings = scanner.scan(https_target, http_response=response)

        httponly_findings = [f for f in findings
                            if f.finding_type == "missing_httponly_flag"]
        assert len(httponly_findings) == 1
        assert httponly_findings[0].severity == Severity.MEDIUM

    def test_missing_httponly_on_regular_cookie_low(self, https_target):
        """
        Missing HttpOnly flag on a non-session cookie should produce a
        LOW severity finding.
        """
        from webinspector.modules.cookie_scanner import CookieScanner

        response = _make_response([
            "preferences=compact; Path=/; Secure; SameSite=Strict",
        ])

        scanner = CookieScanner()
        findings = scanner.scan(https_target, http_response=response)

        httponly_findings = [f for f in findings
                            if f.finding_type == "missing_httponly_flag"]
        assert len(httponly_findings) == 1
        assert httponly_findings[0].severity == Severity.LOW

    def test_httponly_present_no_finding(self, https_target):
        """
        A cookie with the HttpOnly flag present should not produce a
        missing_httponly_flag finding.
        """
        from webinspector.modules.cookie_scanner import CookieScanner

        response = _make_response([
            "PHPSESSID=sess123; Path=/; Secure; HttpOnly; SameSite=Strict",
        ])

        scanner = CookieScanner()
        findings = scanner.scan(https_target, http_response=response)

        httponly_findings = [f for f in findings
                            if f.finding_type == "missing_httponly_flag"]
        assert len(httponly_findings) == 0

    def test_httponly_case_insensitive(self, https_target):
        """
        The HttpOnly flag should be detected regardless of casing (e.g.,
        'httponly', 'HTTPONLY', 'HttpOnly').
        """
        from webinspector.modules.cookie_scanner import CookieScanner

        response = _make_response([
            "PHPSESSID=sess123; Path=/; Secure; httponly; SameSite=Strict",
        ])

        scanner = CookieScanner()
        findings = scanner.scan(https_target, http_response=response)

        httponly_findings = [f for f in findings
                            if f.finding_type == "missing_httponly_flag"]
        assert len(httponly_findings) == 0


# ===========================================================================
# Tests for missing SameSite attribute
# ===========================================================================

class TestMissingSameSite:
    """Verify detection of missing SameSite attribute."""

    def test_missing_samesite_low(self, https_target):
        """
        Missing SameSite attribute means the browser uses its default
        behaviour (Lax in modern browsers, None in older browsers).
        Explicit SameSite is recommended for predictable behaviour.
        LOW severity.
        """
        from webinspector.modules.cookie_scanner import CookieScanner

        response = _make_response([
            "JSESSIONID=abc123; Path=/; Secure; HttpOnly",
        ])

        scanner = CookieScanner()
        findings = scanner.scan(https_target, http_response=response)

        samesite_findings = [f for f in findings
                             if f.finding_type == "missing_samesite"]
        assert len(samesite_findings) == 1
        assert samesite_findings[0].severity == Severity.LOW

    def test_samesite_strict_no_finding(self, https_target):
        """SameSite=Strict should not produce a missing_samesite finding."""
        from webinspector.modules.cookie_scanner import CookieScanner

        response = _make_response([
            "JSESSIONID=abc123; Path=/; Secure; HttpOnly; SameSite=Strict",
        ])

        scanner = CookieScanner()
        findings = scanner.scan(https_target, http_response=response)

        samesite_findings = [f for f in findings
                             if f.finding_type == "missing_samesite"]
        assert len(samesite_findings) == 0

    def test_samesite_lax_no_finding(self, https_target):
        """SameSite=Lax should not produce a missing_samesite finding."""
        from webinspector.modules.cookie_scanner import CookieScanner

        response = _make_response([
            "JSESSIONID=abc123; Path=/; Secure; HttpOnly; SameSite=Lax",
        ])

        scanner = CookieScanner()
        findings = scanner.scan(https_target, http_response=response)

        samesite_findings = [f for f in findings
                             if f.finding_type == "missing_samesite"]
        assert len(samesite_findings) == 0

    def test_samesite_none_no_missing_finding(self, https_target):
        """
        SameSite=None should not produce a missing_samesite finding
        (it IS set, even though it's permissive).  SameSite=None without
        Secure is a separate check.
        """
        from webinspector.modules.cookie_scanner import CookieScanner

        response = _make_response([
            "JSESSIONID=abc123; Path=/; Secure; HttpOnly; SameSite=None",
        ])

        scanner = CookieScanner()
        findings = scanner.scan(https_target, http_response=response)

        samesite_findings = [f for f in findings
                             if f.finding_type == "missing_samesite"]
        assert len(samesite_findings) == 0

    def test_samesite_case_insensitive(self, https_target):
        """
        The SameSite attribute should be detected regardless of casing.
        """
        from webinspector.modules.cookie_scanner import CookieScanner

        response = _make_response([
            "JSESSIONID=abc123; Path=/; Secure; HttpOnly; samesite=strict",
        ])

        scanner = CookieScanner()
        findings = scanner.scan(https_target, http_response=response)

        samesite_findings = [f for f in findings
                             if f.finding_type == "missing_samesite"]
        assert len(samesite_findings) == 0


# ===========================================================================
# Tests for SameSite=None without Secure
# ===========================================================================

class TestSameSiteNoneWithoutSecure:
    """Verify detection of SameSite=None without the Secure flag."""

    def test_samesite_none_without_secure_medium(self, https_target):
        """
        SameSite=None without Secure is rejected by modern browsers
        and indicates a misconfiguration.  When SameSite=None, the cookie
        must also have the Secure flag.  MEDIUM severity.
        """
        from webinspector.modules.cookie_scanner import CookieScanner

        response = _make_response([
            "tracker=xyz; Path=/; HttpOnly; SameSite=None",
        ])

        scanner = CookieScanner()
        findings = scanner.scan(https_target, http_response=response)

        samesite_none_findings = [f for f in findings
                                  if f.finding_type == "samesite_none_without_secure"]
        assert len(samesite_none_findings) == 1
        assert samesite_none_findings[0].severity == Severity.MEDIUM

    def test_samesite_none_with_secure_no_finding(self, https_target):
        """
        SameSite=None with Secure is a valid configuration (used for
        cross-site cookies like SSO).  Should not produce this finding.
        """
        from webinspector.modules.cookie_scanner import CookieScanner

        response = _make_response([
            "tracker=xyz; Path=/; Secure; HttpOnly; SameSite=None",
        ])

        scanner = CookieScanner()
        findings = scanner.scan(https_target, http_response=response)

        samesite_none_findings = [f for f in findings
                                  if f.finding_type == "samesite_none_without_secure"]
        assert len(samesite_none_findings) == 0

    def test_samesite_none_case_insensitive_detection(self, https_target):
        """
        SameSite=None detection should be case-insensitive.
        """
        from webinspector.modules.cookie_scanner import CookieScanner

        response = _make_response([
            "tracker=xyz; Path=/; HttpOnly; samesite=none",
        ])

        scanner = CookieScanner()
        findings = scanner.scan(https_target, http_response=response)

        samesite_none_findings = [f for f in findings
                                  if f.finding_type == "samesite_none_without_secure"]
        assert len(samesite_none_findings) == 1


# ===========================================================================
# Tests for persistent session cookies
# ===========================================================================

class TestPersistentSessionCookie:
    """Verify detection of persistent session cookies."""

    def test_session_cookie_with_expires_low(self, https_target):
        """
        A session cookie with an Expires attribute makes it persistent,
        meaning it survives browser restarts.  This increases the window
        for session hijacking.  LOW severity.
        """
        from webinspector.modules.cookie_scanner import CookieScanner

        response = _make_response([
            "JSESSIONID=abc123; Path=/; Secure; HttpOnly; SameSite=Strict; "
            "Expires=Thu, 01 Jan 2099 00:00:00 GMT",
        ])

        scanner = CookieScanner()
        findings = scanner.scan(https_target, http_response=response)

        persistent_findings = [f for f in findings
                               if f.finding_type == "persistent_session_cookie"]
        assert len(persistent_findings) == 1
        assert persistent_findings[0].severity == Severity.LOW

    def test_session_cookie_with_max_age_low(self, https_target):
        """
        A session cookie with a Max-Age attribute is also persistent.
        LOW severity.
        """
        from webinspector.modules.cookie_scanner import CookieScanner

        response = _make_response([
            "JSESSIONID=abc123; Path=/; Secure; HttpOnly; SameSite=Strict; "
            "Max-Age=86400",
        ])

        scanner = CookieScanner()
        findings = scanner.scan(https_target, http_response=response)

        persistent_findings = [f for f in findings
                               if f.finding_type == "persistent_session_cookie"]
        assert len(persistent_findings) == 1
        assert persistent_findings[0].severity == Severity.LOW

    def test_regular_cookie_with_expires_no_finding(self, https_target):
        """
        A non-session cookie with Expires/Max-Age is normal and should
        not produce a persistent_session_cookie finding.
        """
        from webinspector.modules.cookie_scanner import CookieScanner

        response = _make_response([
            "theme=dark; Path=/; Secure; HttpOnly; SameSite=Strict; "
            "Expires=Thu, 01 Jan 2099 00:00:00 GMT",
        ])

        scanner = CookieScanner()
        findings = scanner.scan(https_target, http_response=response)

        persistent_findings = [f for f in findings
                               if f.finding_type == "persistent_session_cookie"]
        assert len(persistent_findings) == 0

    def test_session_cookie_without_expires_no_finding(self, https_target):
        """
        A session cookie without Expires or Max-Age is a proper session
        cookie and should not produce a persistent_session_cookie finding.
        """
        from webinspector.modules.cookie_scanner import CookieScanner

        response = _make_response([
            "JSESSIONID=abc123; Path=/; Secure; HttpOnly; SameSite=Strict",
        ])

        scanner = CookieScanner()
        findings = scanner.scan(https_target, http_response=response)

        persistent_findings = [f for f in findings
                               if f.finding_type == "persistent_session_cookie"]
        assert len(persistent_findings) == 0


# ===========================================================================
# Tests for session cookie name detection
# ===========================================================================

class TestSessionCookieDetection:
    """Verify that session cookie names are detected correctly."""

    @pytest.mark.parametrize("cookie_name", [
        "JSESSIONID",
        "PHPSESSID",
        "ASP.NET_SessionId",
        "connect.sid",
        "laravel_session",
        "CFID",
        "CFTOKEN",
        "ci_session",
        "rack.session",
        "_session_id",
        "express.sid",
        "PLAY_SESSION",
        "sessionid",
        "session_id",
    ])
    def test_known_session_cookie_names(self, https_target, cookie_name):
        """
        Each known session cookie name pattern should be detected as a
        session cookie, resulting in MEDIUM severity for missing Secure
        flag instead of LOW.
        """
        from webinspector.modules.cookie_scanner import CookieScanner

        response = _make_response([
            f"{cookie_name}=value123; Path=/; HttpOnly; SameSite=Strict",
        ])

        scanner = CookieScanner()
        findings = scanner.scan(https_target, http_response=response)

        # Missing Secure flag on a session cookie => MEDIUM
        secure_findings = [f for f in findings
                           if f.finding_type == "missing_secure_flag"]
        assert len(secure_findings) == 1, (
            f"Expected missing_secure_flag finding for {cookie_name}"
        )
        assert secure_findings[0].severity == Severity.MEDIUM, (
            f"Expected MEDIUM severity for session cookie {cookie_name}, "
            f"got {secure_findings[0].severity}"
        )

    def test_unknown_cookie_name_not_session(self, https_target):
        """
        A cookie with a name that doesn't match any session cookie
        pattern should be treated as a regular cookie.
        """
        from webinspector.modules.cookie_scanner import CookieScanner

        response = _make_response([
            "theme=dark; Path=/; HttpOnly; SameSite=Strict",
        ])

        scanner = CookieScanner()
        findings = scanner.scan(https_target, http_response=response)

        # Missing Secure flag on a regular cookie => LOW
        secure_findings = [f for f in findings
                           if f.finding_type == "missing_secure_flag"]
        assert len(secure_findings) == 1
        assert secure_findings[0].severity == Severity.LOW


# ===========================================================================
# Tests for fully hardened cookie (no findings)
# ===========================================================================

class TestHardenedCookie:
    """Verify that a fully hardened cookie produces zero findings."""

    def test_hardened_session_cookie_no_findings(self, https_target):
        """
        A session cookie with Secure, HttpOnly, SameSite=Strict, and no
        Expires/Max-Age should produce zero findings.
        """
        from webinspector.modules.cookie_scanner import CookieScanner

        response = _make_hardened_session_cookie()
        scanner = CookieScanner()
        findings = scanner.scan(https_target, http_response=response)

        assert len(findings) == 0

    def test_hardened_regular_cookie_no_findings(self, https_target):
        """
        A non-session cookie with Secure, HttpOnly, and SameSite should
        produce zero findings (Expires is fine for regular cookies).
        """
        from webinspector.modules.cookie_scanner import CookieScanner

        response = _make_response([
            "theme=dark; Path=/; Secure; HttpOnly; SameSite=Lax; "
            "Max-Age=31536000",
        ])

        scanner = CookieScanner()
        findings = scanner.scan(https_target, http_response=response)

        assert len(findings) == 0


# ===========================================================================
# Tests for multiple cookies in a single response
# ===========================================================================

class TestMultipleCookies:
    """Verify that multiple cookies are each checked independently."""

    def test_multiple_cookies_multiple_findings(self, https_target):
        """
        Multiple cookies with different issues should each produce
        their own findings.
        """
        from webinspector.modules.cookie_scanner import CookieScanner

        response = _make_response([
            # Session cookie missing Secure
            "JSESSIONID=abc; Path=/; HttpOnly; SameSite=Strict",
            # Regular cookie missing HttpOnly
            "theme=dark; Path=/; Secure; SameSite=Lax",
        ])

        scanner = CookieScanner()
        findings = scanner.scan(https_target, http_response=response)

        # Should have at least one missing_secure_flag and one missing_httponly_flag
        secure_findings = [f for f in findings
                           if f.finding_type == "missing_secure_flag"]
        httponly_findings = [f for f in findings
                            if f.finding_type == "missing_httponly_flag"]

        assert len(secure_findings) >= 1
        assert len(httponly_findings) >= 1

    def test_all_cookies_checked(self, https_target):
        """
        When multiple cookies have the same issue, each should produce
        a separate finding.
        """
        from webinspector.modules.cookie_scanner import CookieScanner

        response = _make_response([
            "JSESSIONID=abc; Path=/; HttpOnly; SameSite=Strict",
            "PHPSESSID=def; Path=/; HttpOnly; SameSite=Lax",
        ])

        scanner = CookieScanner()
        findings = scanner.scan(https_target, http_response=response)

        # Both cookies are missing Secure
        secure_findings = [f for f in findings
                           if f.finding_type == "missing_secure_flag"]
        assert len(secure_findings) == 2


# ===========================================================================
# Tests for multiple findings on a single cookie
# ===========================================================================

class TestMultipleFindingsPerCookie:
    """Verify that a single cookie can produce multiple findings."""

    def test_cookie_with_all_issues(self, https_target):
        """
        A session cookie missing Secure, HttpOnly, and SameSite should
        produce three separate findings.
        """
        from webinspector.modules.cookie_scanner import CookieScanner

        response = _make_response([
            "JSESSIONID=abc123; Path=/",
        ])

        scanner = CookieScanner()
        findings = scanner.scan(https_target, http_response=response)

        types = {f.finding_type for f in findings}

        assert "missing_secure_flag" in types
        assert "missing_httponly_flag" in types
        assert "missing_samesite" in types

    def test_samesite_none_without_secure_also_flags_missing_secure(self, https_target):
        """
        A cookie with SameSite=None but no Secure should produce both
        samesite_none_without_secure AND missing_secure_flag.
        """
        from webinspector.modules.cookie_scanner import CookieScanner

        response = _make_response([
            "tracker=xyz; Path=/; HttpOnly; SameSite=None",
        ])

        scanner = CookieScanner()
        findings = scanner.scan(https_target, http_response=response)

        types = {f.finding_type for f in findings}

        assert "samesite_none_without_secure" in types
        assert "missing_secure_flag" in types


# ===========================================================================
# Tests for cookie name in finding details
# ===========================================================================

class TestFindingDetails:
    """Verify that finding details include the cookie name."""

    def test_finding_includes_cookie_name(self, https_target):
        """
        Each finding should include the cookie name in its detail string
        so the analyst knows which cookie has the issue.
        """
        from webinspector.modules.cookie_scanner import CookieScanner

        response = _make_response([
            "JSESSIONID=abc123; Path=/",
        ])

        scanner = CookieScanner()
        findings = scanner.scan(https_target, http_response=response)

        # All findings should mention the cookie name
        for finding in findings:
            assert "JSESSIONID" in finding.detail

    def test_findings_have_correct_module(self, https_target):
        """Every finding should have module='cookies'."""
        from webinspector.modules.cookie_scanner import CookieScanner

        response = _make_response([
            "JSESSIONID=abc123; Path=/",
        ])

        scanner = CookieScanner()
        findings = scanner.scan(https_target, http_response=response)

        assert len(findings) >= 1
        for finding in findings:
            assert finding.module == "cookies"
            assert finding.target is https_target

    def test_findings_have_titles_and_details(self, https_target):
        """Every finding should have non-empty title and detail."""
        from webinspector.modules.cookie_scanner import CookieScanner

        response = _make_response([
            "JSESSIONID=abc123; Path=/",
        ])

        scanner = CookieScanner()
        findings = scanner.scan(https_target, http_response=response)

        for finding in findings:
            assert len(finding.title) > 0
            assert len(finding.detail) > 0


# ===========================================================================
# Tests for fallback parsing (no raw headers)
# ===========================================================================

class TestFallbackParsing:
    """Verify that the scanner handles responses without raw headers."""

    def test_fallback_when_no_raw_attribute(self, https_target):
        """
        When response.raw is not available (e.g., in some mocking
        scenarios), the scanner should fall back to parsing
        response.headers["Set-Cookie"].
        """
        from webinspector.modules.cookie_scanner import CookieScanner

        response = MagicMock()
        response.raw = None
        response.headers = {
            "Set-Cookie": "JSESSIONID=abc123; Path=/; HttpOnly; SameSite=Strict",
        }

        scanner = CookieScanner()
        findings = scanner.scan(https_target, http_response=response)

        # Should detect missing Secure flag on the session cookie
        secure_findings = [f for f in findings
                           if f.finding_type == "missing_secure_flag"]
        assert len(secure_findings) == 1
        assert secure_findings[0].severity == Severity.MEDIUM


# ===========================================================================
# Test module registration
# ===========================================================================

class TestCookieScannerRegistration:
    """Verify that importing the module registers it."""

    def test_module_registers(self):
        """
        Importing cookie_scanner should call register_module() at the
        bottom of the file, making it discoverable by the module registry.
        """
        from webinspector.modules import _registry
        from webinspector.modules.cookie_scanner import CookieScanner

        # The module registers itself at import time.
        # Check that an instance of CookieScanner is in the registry.
        cookie_modules = [m for m in _registry if m.name == "cookies"]
        assert len(cookie_modules) >= 1
        assert isinstance(cookie_modules[0], CookieScanner)
