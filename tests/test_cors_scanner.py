"""
Tests for the CORS misconfiguration scanner module (cors_scanner.py).

These tests verify that the CORSScanner module correctly:
    1. Has the correct name and description properties
    2. Accepts both HTTP and HTTPS targets (default accepts_target)
    3. Sends requests with crafted Origin headers to detect misconfigurations
    4. Detects arbitrary origin reflection (evil.com) -- HIGH with credentials
    5. Detects arbitrary origin reflection without credentials -- MEDIUM
    6. Detects null origin acceptance -- HIGH with credentials
    7. Detects null origin acceptance without credentials -- MEDIUM
    8. Detects subdomain bypass pattern (evil.target.com) -- HIGH with credentials
    9. Detects subdomain bypass pattern without credentials -- MEDIUM
   10. Detects post-domain bypass pattern (target.com.evil.com) -- HIGH with creds
   11. Detects post-domain bypass pattern without credentials -- MEDIUM
   12. Returns empty findings when no CORS headers are reflected
   13. Returns empty findings when ACAO does not match crafted origins
   14. Handles connection errors gracefully (no crashes)
   15. Produces findings with correct module name, titles, and details
   16. Verifies module registration via register_module()

All HTTP requests are mocked using unittest.mock.patch -- no real network
connections are made.  We mock the session.get() method to simulate server
responses with various Access-Control-Allow-Origin and
Access-Control-Allow-Credentials header combinations.

Author: Red Siege Information Security
"""

import pytest
from unittest.mock import MagicMock, patch, call

from webinspector.core.target import Target
from webinspector.core.result import Finding, Severity


# ---------------------------------------------------------------------------
# Mock helpers -- simulate HTTP responses with CORS headers
# ---------------------------------------------------------------------------

def _make_cors_response(acao_value=None, acac_value=None):
    """
    Build a mock requests.Response with the given CORS headers.

    Args:
        acao_value: Value for Access-Control-Allow-Origin header.
                    If None, the header is not present in the response.
        acac_value: Value for Access-Control-Allow-Credentials header.
                    If None, the header is not present in the response.

    Returns:
        A MagicMock mimicking requests.Response with .headers set.
    """
    response = MagicMock()
    headers = {}
    if acao_value is not None:
        headers["Access-Control-Allow-Origin"] = acao_value
    if acac_value is not None:
        headers["Access-Control-Allow-Credentials"] = acac_value
    response.headers = headers
    return response


def _make_reflecting_session(target_url, reflect_all=False, reflect_origins=None,
                             with_credentials=False, raise_on=None):
    """
    Build a mock HTTP session whose .get() reflects crafted origins in ACAO.

    This simulates a vulnerable server that reflects the Origin header back
    in the Access-Control-Allow-Origin response header.

    Args:
        target_url:       The target URL that session.get() will be called with.
        reflect_all:      If True, reflect ALL Origin headers back as ACAO.
        reflect_origins:  Set of specific origin strings to reflect.  Only these
                          origins will be reflected; others get no ACAO header.
        with_credentials: If True, include Access-Control-Allow-Credentials: true.
        raise_on:         Set of origin strings that should raise an exception
                          (simulating connection errors for those requests).

    Returns:
        A MagicMock session with a configured .get() side_effect.
    """
    session = MagicMock()
    reflect_origins = reflect_origins or set()
    raise_on = raise_on or set()

    def mock_get(url, headers=None, timeout=None, verify=None):
        """Side effect for session.get() that conditionally reflects origins."""
        origin = headers.get("Origin", "") if headers else ""

        # Simulate a connection error for certain origins.
        if origin in raise_on:
            raise Exception(f"Connection error for origin {origin}")

        resp = MagicMock()
        resp_headers = {}

        # Reflect the origin if configured to do so.
        if reflect_all or origin in reflect_origins:
            resp_headers["Access-Control-Allow-Origin"] = origin
            if with_credentials:
                resp_headers["Access-Control-Allow-Credentials"] = "true"

        resp.headers = resp_headers
        return resp

    session.get = MagicMock(side_effect=mock_get)
    return session


# ---------------------------------------------------------------------------
# Target fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def https_target():
    """An HTTPS target for CORS scanning."""
    return Target(host="example.com", port=443, scheme="https")


@pytest.fixture
def http_target():
    """An HTTP target for CORS scanning."""
    return Target(host="example.com", port=80, scheme="http")


# ===========================================================================
# Tests for module properties
# ===========================================================================

class TestCORSScannerProperties:
    """Verify name and description properties of the CORS scanner."""

    def test_name(self):
        """Module name should be 'cors'."""
        from webinspector.modules.cors_scanner import CORSScanner
        scanner = CORSScanner()
        assert scanner.name == "cors"

    def test_description(self):
        """Module should have a non-empty description mentioning CORS."""
        from webinspector.modules.cors_scanner import CORSScanner
        scanner = CORSScanner()
        assert len(scanner.description) > 0
        assert "cors" in scanner.description.lower()


# ===========================================================================
# Tests for accepts_target
# ===========================================================================

class TestCORSScannerAcceptsTarget:
    """Verify that the CORS scanner accepts both HTTP and HTTPS targets."""

    def test_accepts_https(self, https_target):
        """CORS scanner should accept targets with scheme='https'."""
        from webinspector.modules.cors_scanner import CORSScanner
        scanner = CORSScanner()
        assert scanner.accepts_target(https_target) is True

    def test_accepts_http(self, http_target):
        """CORS scanner should accept targets with scheme='http'."""
        from webinspector.modules.cors_scanner import CORSScanner
        scanner = CORSScanner()
        assert scanner.accepts_target(http_target) is True


# ===========================================================================
# Tests for arbitrary origin reflection (evil.com)
# ===========================================================================

class TestOriginReflection:
    """Verify detection of arbitrary origin reflection (evil.com)."""

    @patch("webinspector.modules.cors_scanner.create_http_session")
    def test_detects_origin_reflection_with_credentials(self, mock_create, https_target):
        """
        When the server reflects an arbitrary origin (https://evil.com)
        AND sends Access-Control-Allow-Credentials: true, this is a HIGH
        severity finding because an attacker can steal data cross-origin
        with the victim's cookies.
        """
        from webinspector.modules.cors_scanner import CORSScanner

        # Configure mock session to reflect all origins with credentials.
        session = _make_reflecting_session(
            https_target.url, reflect_all=True, with_credentials=True
        )
        mock_create.return_value = (session, 10)

        scanner = CORSScanner()
        findings = scanner.scan(https_target)

        # Should detect origin_reflection finding.
        reflection = [f for f in findings if f.finding_type == "origin_reflection"]
        assert len(reflection) >= 1
        assert reflection[0].severity == Severity.HIGH

    @patch("webinspector.modules.cors_scanner.create_http_session")
    def test_detects_origin_reflection_without_credentials(self, mock_create, https_target):
        """
        When the server reflects an arbitrary origin but does NOT send
        Access-Control-Allow-Credentials: true, severity is MEDIUM because
        cross-origin reads are possible but cookies are not included.
        """
        from webinspector.modules.cors_scanner import CORSScanner

        # Configure mock session to reflect all origins without credentials.
        session = _make_reflecting_session(
            https_target.url, reflect_all=True, with_credentials=False
        )
        mock_create.return_value = (session, 10)

        scanner = CORSScanner()
        findings = scanner.scan(https_target)

        # Should detect origin_reflection finding with MEDIUM severity.
        reflection = [f for f in findings if f.finding_type == "origin_reflection"]
        assert len(reflection) >= 1
        assert reflection[0].severity == Severity.MEDIUM


# ===========================================================================
# Tests for null origin attack
# ===========================================================================

class TestNullOrigin:
    """Verify detection of null origin acceptance."""

    @patch("webinspector.modules.cors_scanner.create_http_session")
    def test_detects_null_origin_with_credentials(self, mock_create, https_target):
        """
        When the server accepts Origin: null and responds with
        Access-Control-Allow-Origin: null plus credentials, this is HIGH
        severity.  Null origin attacks are possible via sandboxed iframes,
        data: URIs, and local file redirects.
        """
        from webinspector.modules.cors_scanner import CORSScanner

        session = _make_reflecting_session(
            https_target.url,
            reflect_origins={"null"},
            with_credentials=True,
        )
        mock_create.return_value = (session, 10)

        scanner = CORSScanner()
        findings = scanner.scan(https_target)

        null_findings = [f for f in findings if f.finding_type == "null_origin"]
        assert len(null_findings) == 1
        assert null_findings[0].severity == Severity.HIGH

    @patch("webinspector.modules.cors_scanner.create_http_session")
    def test_detects_null_origin_without_credentials(self, mock_create, https_target):
        """
        Null origin reflected without credentials is MEDIUM severity --
        still exploitable but without cookie access.
        """
        from webinspector.modules.cors_scanner import CORSScanner

        session = _make_reflecting_session(
            https_target.url,
            reflect_origins={"null"},
            with_credentials=False,
        )
        mock_create.return_value = (session, 10)

        scanner = CORSScanner()
        findings = scanner.scan(https_target)

        null_findings = [f for f in findings if f.finding_type == "null_origin"]
        assert len(null_findings) == 1
        assert null_findings[0].severity == Severity.MEDIUM


# ===========================================================================
# Tests for subdomain bypass pattern (evil.target.com)
# ===========================================================================

class TestSubdomainBypass:
    """Verify detection of subdomain hijack bypass (evil.example.com)."""

    @patch("webinspector.modules.cors_scanner.create_http_session")
    def test_detects_subdomain_bypass_with_credentials(self, mock_create, https_target):
        """
        When the server accepts Origin: https://evil.example.com with
        credentials, this is HIGH severity.  If any subdomain is
        compromised or an attacker can register one, they can steal
        cross-origin data.
        """
        from webinspector.modules.cors_scanner import CORSScanner

        # The CORS scanner should craft: https://evil.example.com
        crafted_origin = f"https://evil.{https_target.host}"
        session = _make_reflecting_session(
            https_target.url,
            reflect_origins={crafted_origin},
            with_credentials=True,
        )
        mock_create.return_value = (session, 10)

        scanner = CORSScanner()
        findings = scanner.scan(https_target)

        subdomain = [f for f in findings if f.finding_type == "subdomain_bypass"]
        assert len(subdomain) == 1
        assert subdomain[0].severity == Severity.HIGH

    @patch("webinspector.modules.cors_scanner.create_http_session")
    def test_detects_subdomain_bypass_without_credentials(self, mock_create, https_target):
        """
        Subdomain bypass without credentials is MEDIUM severity.
        """
        from webinspector.modules.cors_scanner import CORSScanner

        crafted_origin = f"https://evil.{https_target.host}"
        session = _make_reflecting_session(
            https_target.url,
            reflect_origins={crafted_origin},
            with_credentials=False,
        )
        mock_create.return_value = (session, 10)

        scanner = CORSScanner()
        findings = scanner.scan(https_target)

        subdomain = [f for f in findings if f.finding_type == "subdomain_bypass"]
        assert len(subdomain) == 1
        assert subdomain[0].severity == Severity.MEDIUM


# ===========================================================================
# Tests for post-domain bypass pattern (example.com.evil.com)
# ===========================================================================

class TestPostdomainBypass:
    """Verify detection of post-domain bypass (example.com.evil.com)."""

    @patch("webinspector.modules.cors_scanner.create_http_session")
    def test_detects_postdomain_bypass_with_credentials(self, mock_create, https_target):
        """
        When the server accepts Origin: https://example.com.evil.com with
        credentials, this is HIGH severity.  A regex like /example\.com$/
        would incorrectly match example.com.evil.com, allowing an attacker-
        controlled domain to pass the origin check.
        """
        from webinspector.modules.cors_scanner import CORSScanner

        crafted_origin = f"https://{https_target.host}.evil.com"
        session = _make_reflecting_session(
            https_target.url,
            reflect_origins={crafted_origin},
            with_credentials=True,
        )
        mock_create.return_value = (session, 10)

        scanner = CORSScanner()
        findings = scanner.scan(https_target)

        postdomain = [f for f in findings if f.finding_type == "postdomain_bypass"]
        assert len(postdomain) == 1
        assert postdomain[0].severity == Severity.HIGH

    @patch("webinspector.modules.cors_scanner.create_http_session")
    def test_detects_postdomain_bypass_without_credentials(self, mock_create, https_target):
        """
        Post-domain bypass without credentials is MEDIUM severity.
        """
        from webinspector.modules.cors_scanner import CORSScanner

        crafted_origin = f"https://{https_target.host}.evil.com"
        session = _make_reflecting_session(
            https_target.url,
            reflect_origins={crafted_origin},
            with_credentials=False,
        )
        mock_create.return_value = (session, 10)

        scanner = CORSScanner()
        findings = scanner.scan(https_target)

        postdomain = [f for f in findings if f.finding_type == "postdomain_bypass"]
        assert len(postdomain) == 1
        assert postdomain[0].severity == Severity.MEDIUM


# ===========================================================================
# Tests for no CORS misconfiguration (clean server)
# ===========================================================================

class TestNoCORSIssues:
    """Verify that a properly configured server produces no findings."""

    @patch("webinspector.modules.cors_scanner.create_http_session")
    def test_no_acao_header_returns_empty(self, mock_create, https_target):
        """
        When the server does not include Access-Control-Allow-Origin in
        any response, no findings should be produced.  This is the common
        case for servers that don't implement CORS at all.
        """
        from webinspector.modules.cors_scanner import CORSScanner

        # Session that never reflects origins.
        session = _make_reflecting_session(
            https_target.url, reflect_all=False, reflect_origins=set()
        )
        mock_create.return_value = (session, 10)

        scanner = CORSScanner()
        findings = scanner.scan(https_target)

        assert isinstance(findings, list)
        assert len(findings) == 0

    @patch("webinspector.modules.cors_scanner.create_http_session")
    def test_acao_with_fixed_origin_no_finding(self, mock_create, https_target):
        """
        When the server returns a fixed ACAO value (like https://trusted.com)
        that does NOT match the crafted origin, no findings should be produced.
        """
        from webinspector.modules.cors_scanner import CORSScanner

        session = MagicMock()

        def mock_get(url, headers=None, timeout=None, verify=None):
            """Always return a fixed ACAO that doesn't match the crafted origin."""
            resp = MagicMock()
            resp.headers = {
                "Access-Control-Allow-Origin": "https://trusted.com"
            }
            return resp

        session.get = MagicMock(side_effect=mock_get)
        mock_create.return_value = (session, 10)

        scanner = CORSScanner()
        findings = scanner.scan(https_target)

        assert len(findings) == 0

    @patch("webinspector.modules.cors_scanner.create_http_session")
    def test_acao_wildcard_no_finding(self, mock_create, https_target):
        """
        When the server returns Access-Control-Allow-Origin: *, this is NOT
        an origin reflection vulnerability (the wildcard does not match a
        specific crafted origin).  No findings should be produced.

        Note: ACAO: * with ACAC: true is technically invalid per the spec,
        but we only flag when the specific crafted origin is reflected.
        """
        from webinspector.modules.cors_scanner import CORSScanner

        session = MagicMock()

        def mock_get(url, headers=None, timeout=None, verify=None):
            """Return ACAO: * for all requests."""
            resp = MagicMock()
            resp.headers = {"Access-Control-Allow-Origin": "*"}
            return resp

        session.get = MagicMock(side_effect=mock_get)
        mock_create.return_value = (session, 10)

        scanner = CORSScanner()
        findings = scanner.scan(https_target)

        assert len(findings) == 0


# ===========================================================================
# Tests for connection error handling
# ===========================================================================

class TestConnectionErrors:
    """Verify graceful handling of HTTP request failures."""

    @patch("webinspector.modules.cors_scanner.create_http_session")
    def test_connection_error_returns_empty(self, mock_create, https_target):
        """
        When ALL requests to the target fail with connection errors,
        the scanner should return an empty findings list without raising
        any exceptions.
        """
        from webinspector.modules.cors_scanner import CORSScanner

        session = MagicMock()
        # Make all requests raise an exception.
        session.get = MagicMock(side_effect=Exception("Connection refused"))
        mock_create.return_value = (session, 10)

        scanner = CORSScanner()
        findings = scanner.scan(https_target)

        assert isinstance(findings, list)
        assert len(findings) == 0

    @patch("webinspector.modules.cors_scanner.create_http_session")
    def test_partial_connection_errors_still_reports(self, mock_create, https_target):
        """
        When some requests fail but others succeed and reveal CORS
        misconfigurations, the scanner should still report the findings
        from the successful requests.
        """
        from webinspector.modules.cors_scanner import CORSScanner

        # Only reflect the null origin; make evil.com requests fail.
        session = _make_reflecting_session(
            https_target.url,
            reflect_origins={"null"},
            with_credentials=True,
            raise_on={"https://evil.com"},
        )
        mock_create.return_value = (session, 10)

        scanner = CORSScanner()
        findings = scanner.scan(https_target)

        # Should still detect null origin even though evil.com request failed.
        null_findings = [f for f in findings if f.finding_type == "null_origin"]
        assert len(null_findings) == 1


# ===========================================================================
# Tests for finding structure and content
# ===========================================================================

class TestFindingStructure:
    """Verify that findings have correct module, title, detail fields."""

    @patch("webinspector.modules.cors_scanner.create_http_session")
    def test_findings_have_correct_module(self, mock_create, https_target):
        """Every finding should have module='cors'."""
        from webinspector.modules.cors_scanner import CORSScanner

        session = _make_reflecting_session(
            https_target.url, reflect_all=True, with_credentials=True
        )
        mock_create.return_value = (session, 10)

        scanner = CORSScanner()
        findings = scanner.scan(https_target)

        assert len(findings) >= 1
        for finding in findings:
            assert finding.module == "cors"
            assert finding.target is https_target

    @patch("webinspector.modules.cors_scanner.create_http_session")
    def test_findings_have_titles_and_details(self, mock_create, https_target):
        """Every finding should have non-empty title and detail."""
        from webinspector.modules.cors_scanner import CORSScanner

        session = _make_reflecting_session(
            https_target.url, reflect_all=True, with_credentials=True
        )
        mock_create.return_value = (session, 10)

        scanner = CORSScanner()
        findings = scanner.scan(https_target)

        for finding in findings:
            assert len(finding.title) > 0
            assert len(finding.detail) > 0

    @patch("webinspector.modules.cors_scanner.create_http_session")
    def test_findings_have_references(self, mock_create, https_target):
        """Every finding should include at least one CWE reference."""
        from webinspector.modules.cors_scanner import CORSScanner

        session = _make_reflecting_session(
            https_target.url, reflect_all=True, with_credentials=True
        )
        mock_create.return_value = (session, 10)

        scanner = CORSScanner()
        findings = scanner.scan(https_target)

        for finding in findings:
            assert len(finding.references) > 0

    @patch("webinspector.modules.cors_scanner.create_http_session")
    def test_all_four_finding_types_with_full_reflection(self, mock_create, https_target):
        """
        When the server reflects ALL crafted origins, the scanner should
        produce findings for all four check types:
        origin_reflection, null_origin, subdomain_bypass, postdomain_bypass.
        """
        from webinspector.modules.cors_scanner import CORSScanner

        session = _make_reflecting_session(
            https_target.url, reflect_all=True, with_credentials=True
        )
        mock_create.return_value = (session, 10)

        scanner = CORSScanner()
        findings = scanner.scan(https_target)

        types = {f.finding_type for f in findings}
        assert "origin_reflection" in types
        assert "null_origin" in types
        assert "subdomain_bypass" in types
        assert "postdomain_bypass" in types


# ===========================================================================
# Tests for HTTP target (different scheme in crafted origins)
# ===========================================================================

class TestHTTPTarget:
    """Verify CORS scanner works correctly with HTTP targets."""

    @patch("webinspector.modules.cors_scanner.create_http_session")
    def test_http_target_crafts_correct_origins(self, mock_create, http_target):
        """
        When scanning an HTTP target, the scanner should send requests
        and detect misconfigurations just like with HTTPS targets.
        """
        from webinspector.modules.cors_scanner import CORSScanner

        session = _make_reflecting_session(
            http_target.url, reflect_all=True, with_credentials=True
        )
        mock_create.return_value = (session, 10)

        scanner = CORSScanner()
        findings = scanner.scan(http_target)

        # Should detect at least origin_reflection.
        types = {f.finding_type for f in findings}
        assert "origin_reflection" in types


# ===========================================================================
# Tests for requests being made with correct Origin headers
# ===========================================================================

class TestCraftedOrigins:
    """Verify that the scanner sends the correct crafted Origin headers."""

    @patch("webinspector.modules.cors_scanner.create_http_session")
    def test_sends_evil_com_origin(self, mock_create, https_target):
        """
        The scanner should send a request with Origin: https://evil.com
        to test for arbitrary origin reflection.
        """
        from webinspector.modules.cors_scanner import CORSScanner

        session = _make_reflecting_session(
            https_target.url, reflect_all=False
        )
        mock_create.return_value = (session, 10)

        scanner = CORSScanner()
        scanner.scan(https_target)

        # Check that session.get was called with Origin: https://evil.com
        calls = session.get.call_args_list
        origins_sent = [
            c.kwargs.get("headers", c.args[1] if len(c.args) > 1 else {}).get("Origin", "")
            if c.kwargs.get("headers") else ""
            for c in calls
        ]
        # More robust: extract from kwargs or positional args
        origins = []
        for c in calls:
            hdrs = c.kwargs.get("headers", {}) or {}
            if not hdrs and len(c.args) > 1:
                hdrs = c.args[1] or {}
            origins.append(hdrs.get("Origin", ""))

        assert "https://evil.com" in origins

    @patch("webinspector.modules.cors_scanner.create_http_session")
    def test_sends_null_origin(self, mock_create, https_target):
        """
        The scanner should send a request with Origin: null
        to test for null origin acceptance.
        """
        from webinspector.modules.cors_scanner import CORSScanner

        session = _make_reflecting_session(
            https_target.url, reflect_all=False
        )
        mock_create.return_value = (session, 10)

        scanner = CORSScanner()
        scanner.scan(https_target)

        origins = []
        for c in session.get.call_args_list:
            hdrs = c.kwargs.get("headers", {}) or {}
            origins.append(hdrs.get("Origin", ""))

        assert "null" in origins

    @patch("webinspector.modules.cors_scanner.create_http_session")
    def test_sends_subdomain_origin(self, mock_create, https_target):
        """
        The scanner should send Origin: https://evil.example.com
        to test for subdomain bypass.
        """
        from webinspector.modules.cors_scanner import CORSScanner

        session = _make_reflecting_session(
            https_target.url, reflect_all=False
        )
        mock_create.return_value = (session, 10)

        scanner = CORSScanner()
        scanner.scan(https_target)

        expected = f"https://evil.{https_target.host}"
        origins = []
        for c in session.get.call_args_list:
            hdrs = c.kwargs.get("headers", {}) or {}
            origins.append(hdrs.get("Origin", ""))

        assert expected in origins

    @patch("webinspector.modules.cors_scanner.create_http_session")
    def test_sends_postdomain_origin(self, mock_create, https_target):
        """
        The scanner should send Origin: https://example.com.evil.com
        to test for post-domain bypass.
        """
        from webinspector.modules.cors_scanner import CORSScanner

        session = _make_reflecting_session(
            https_target.url, reflect_all=False
        )
        mock_create.return_value = (session, 10)

        scanner = CORSScanner()
        scanner.scan(https_target)

        expected = f"https://{https_target.host}.evil.com"
        origins = []
        for c in session.get.call_args_list:
            hdrs = c.kwargs.get("headers", {}) or {}
            origins.append(hdrs.get("Origin", ""))

        assert expected in origins


# ===========================================================================
# Test module registration
# ===========================================================================

class TestCORSScannerRegistration:
    """Verify that importing the module registers it."""

    def test_module_registers(self):
        """
        Importing cors_scanner should call register_module() at the
        bottom of the file, making it discoverable by the module registry.
        """
        from webinspector.modules import _registry
        from webinspector.modules.cors_scanner import CORSScanner

        # The module registers itself at import time.
        # Check that an instance of CORSScanner is in the registry.
        cors_modules = [m for m in _registry if m.name == "cors"]
        assert len(cors_modules) >= 1
        assert isinstance(cors_modules[0], CORSScanner)
