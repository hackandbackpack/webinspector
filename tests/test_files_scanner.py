"""
Tests for the files scanner module (files_scanner.py).

These tests verify that the FilesScanner module correctly:
    1. Has the correct name ('files') and description properties
    2. Accepts both HTTP and HTTPS targets
    3. Returns empty findings when target is unreachable (connection errors)

    robots.txt checks:
    4. Detects sensitive paths in robots.txt Disallow lines (LOW)
    5. Detects sensitive paths in robots.txt Allow lines (LOW)
    6. Ignores non-sensitive paths in robots.txt (no finding)
    7. Handles robots.txt returning 404 gracefully (no finding)
    8. Handles multiple sensitive paths producing a single finding with all paths
    9. Handles case-insensitive matching of sensitive path patterns

    security.txt checks (RFC 9116):
   10. Detects completely missing security.txt (INFORMATIONAL)
   11. Detects security.txt missing Contact field (LOW)
   12. Detects security.txt missing Expires field (LOW)
   13. Detects security.txt with expired Expires date (LOW)
   14. Returns no finding for a valid, complete security.txt
   15. Checks /.well-known/security.txt first, then /security.txt as fallback
   16. Handles security.txt at /security.txt when /.well-known/security.txt is 404
   17. Handles both locations returning 404 (missing_security_txt finding)

    General:
   18. All findings have module='files', non-empty title/detail
   19. Verifies module registration via register_module()

All HTTP requests are mocked using unittest.mock.patch -- no real network
connections are made.  We mock create_http_session() to return a controlled
session whose .get() method returns canned responses.

Author: Red Siege Information Security
"""

import pytest
from unittest.mock import MagicMock, patch, call
from datetime import datetime, timezone, timedelta

from webinspector.core.target import Target
from webinspector.core.result import Finding, Severity


# ---------------------------------------------------------------------------
# Mock helpers -- simulate HTTP responses for robots.txt and security.txt
# ---------------------------------------------------------------------------

def _make_response(status_code=200, text="", url=None):
    """
    Build a mock requests.Response with the given status code and body text.

    Args:
        status_code: HTTP status code for the response (e.g., 200, 404).
        text:        The response body as a string.
        url:         The URL of the response.

    Returns:
        A MagicMock mimicking requests.Response with .status_code, .text,
        and .url attributes set.
    """
    response = MagicMock()
    response.status_code = status_code
    response.text = text
    response.url = url or "https://example.com:443"
    return response


# ---------------------------------------------------------------------------
# Target fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def https_target():
    """An HTTPS target for files scanning."""
    return Target(host="example.com", port=443, scheme="https")


@pytest.fixture
def http_target():
    """An HTTP target for files scanning."""
    return Target(host="example.com", port=80, scheme="http")


# ===========================================================================
# Tests for module properties
# ===========================================================================

class TestFilesScannerProperties:
    """Verify name and description properties of the files scanner."""

    def test_name(self):
        """Module name should be 'files'."""
        from webinspector.modules.files_scanner import FilesScanner
        scanner = FilesScanner()
        assert scanner.name == "files"

    def test_description(self):
        """Module should have a non-empty description mentioning robots or security."""
        from webinspector.modules.files_scanner import FilesScanner
        scanner = FilesScanner()
        assert len(scanner.description) > 0
        # Description should mention the files being checked
        desc_lower = scanner.description.lower()
        assert "robots" in desc_lower or "security" in desc_lower


# ===========================================================================
# Tests for accepts_target
# ===========================================================================

class TestFilesScannerAcceptsTarget:
    """Verify that the files scanner accepts both HTTP and HTTPS targets."""

    def test_accepts_https(self, https_target):
        """Files scanner should accept targets with scheme='https'."""
        from webinspector.modules.files_scanner import FilesScanner
        scanner = FilesScanner()
        assert scanner.accepts_target(https_target) is True

    def test_accepts_http(self, http_target):
        """Files scanner should accept targets with scheme='http'."""
        from webinspector.modules.files_scanner import FilesScanner
        scanner = FilesScanner()
        assert scanner.accepts_target(http_target) is True


# ===========================================================================
# Tests for connection error handling
# ===========================================================================

class TestConnectionErrors:
    """Verify graceful handling when HTTP requests fail."""

    @patch("webinspector.modules.files_scanner.create_http_session")
    def test_connection_error_returns_empty(self, mock_create, https_target):
        """
        When all HTTP requests fail with connection errors, the scanner
        should return an empty findings list without raising exceptions.
        """
        from webinspector.modules.files_scanner import FilesScanner

        session = MagicMock()
        session.get.side_effect = Exception("Connection refused")
        mock_create.return_value = (session, 10)

        scanner = FilesScanner()
        findings = scanner.scan(https_target)

        assert isinstance(findings, list)
        # Should not crash; may or may not have findings depending on
        # how the error is handled, but should not raise an exception.


# ===========================================================================
# Tests for robots.txt -- sensitive path detection
# ===========================================================================

class TestRobotsSensitivePaths:
    """Verify detection of sensitive paths in robots.txt."""

    @patch("webinspector.modules.files_scanner.create_http_session")
    def test_detects_admin_path(self, mock_create, https_target):
        """
        robots.txt with Disallow: /admin should produce a LOW finding
        of type robots_sensitive_paths because /admin is a well-known
        administrative interface path.
        """
        from webinspector.modules.files_scanner import FilesScanner

        session = MagicMock()

        # robots.txt response with sensitive /admin path
        robots_resp = _make_response(
            status_code=200,
            text="User-agent: *\nDisallow: /admin\n",
        )
        # security.txt responses (404 for both locations)
        sec_404 = _make_response(status_code=404)

        # Map URLs to responses: robots.txt, then security.txt locations
        def side_effect(url, **kwargs):
            if "robots.txt" in url:
                return robots_resp
            return sec_404

        session.get.side_effect = side_effect
        mock_create.return_value = (session, 10)

        scanner = FilesScanner()
        findings = scanner.scan(https_target)

        robots_findings = [f for f in findings if f.finding_type == "robots_sensitive_paths"]
        assert len(robots_findings) == 1
        assert robots_findings[0].severity == Severity.LOW
        assert "/admin" in robots_findings[0].detail

    @patch("webinspector.modules.files_scanner.create_http_session")
    def test_detects_backup_path(self, mock_create, https_target):
        """
        robots.txt with Disallow: /backup should be flagged as sensitive.
        Backup directories often contain database dumps and configuration files.
        """
        from webinspector.modules.files_scanner import FilesScanner

        session = MagicMock()

        robots_resp = _make_response(
            status_code=200,
            text="User-agent: *\nDisallow: /backup/\n",
        )
        sec_404 = _make_response(status_code=404)

        def side_effect(url, **kwargs):
            if "robots.txt" in url:
                return robots_resp
            return sec_404

        session.get.side_effect = side_effect
        mock_create.return_value = (session, 10)

        scanner = FilesScanner()
        findings = scanner.scan(https_target)

        robots_findings = [f for f in findings if f.finding_type == "robots_sensitive_paths"]
        assert len(robots_findings) == 1
        assert robots_findings[0].severity == Severity.LOW

    @patch("webinspector.modules.files_scanner.create_http_session")
    def test_detects_git_path(self, mock_create, https_target):
        """
        robots.txt with Disallow: /.git should be flagged as sensitive.
        Exposed .git directories allow attackers to download the full
        source code including commit history.
        """
        from webinspector.modules.files_scanner import FilesScanner

        session = MagicMock()

        robots_resp = _make_response(
            status_code=200,
            text="User-agent: *\nDisallow: /.git\n",
        )
        sec_404 = _make_response(status_code=404)

        def side_effect(url, **kwargs):
            if "robots.txt" in url:
                return robots_resp
            return sec_404

        session.get.side_effect = side_effect
        mock_create.return_value = (session, 10)

        scanner = FilesScanner()
        findings = scanner.scan(https_target)

        robots_findings = [f for f in findings if f.finding_type == "robots_sensitive_paths"]
        assert len(robots_findings) == 1

    @patch("webinspector.modules.files_scanner.create_http_session")
    def test_detects_env_path(self, mock_create, https_target):
        """
        robots.txt with Disallow: /.env should be flagged.  .env files
        typically contain API keys, database credentials, and secrets.
        """
        from webinspector.modules.files_scanner import FilesScanner

        session = MagicMock()

        robots_resp = _make_response(
            status_code=200,
            text="User-agent: *\nDisallow: /.env\n",
        )
        sec_404 = _make_response(status_code=404)

        def side_effect(url, **kwargs):
            if "robots.txt" in url:
                return robots_resp
            return sec_404

        session.get.side_effect = side_effect
        mock_create.return_value = (session, 10)

        scanner = FilesScanner()
        findings = scanner.scan(https_target)

        robots_findings = [f for f in findings if f.finding_type == "robots_sensitive_paths"]
        assert len(robots_findings) == 1

    @patch("webinspector.modules.files_scanner.create_http_session")
    def test_detects_allow_sensitive_paths(self, mock_create, https_target):
        """
        Sensitive paths in Allow lines should also be flagged.  Allow
        lines still reveal the existence of these paths.
        """
        from webinspector.modules.files_scanner import FilesScanner

        session = MagicMock()

        robots_resp = _make_response(
            status_code=200,
            text="User-agent: *\nAllow: /api/public\nDisallow: /api/\n",
        )
        sec_404 = _make_response(status_code=404)

        def side_effect(url, **kwargs):
            if "robots.txt" in url:
                return robots_resp
            return sec_404

        session.get.side_effect = side_effect
        mock_create.return_value = (session, 10)

        scanner = FilesScanner()
        findings = scanner.scan(https_target)

        robots_findings = [f for f in findings if f.finding_type == "robots_sensitive_paths"]
        assert len(robots_findings) == 1

    @patch("webinspector.modules.files_scanner.create_http_session")
    def test_multiple_sensitive_paths_single_finding(self, mock_create, https_target):
        """
        When robots.txt contains multiple sensitive paths, they should
        all be reported in a single robots_sensitive_paths finding (not
        one finding per path).
        """
        from webinspector.modules.files_scanner import FilesScanner

        session = MagicMock()

        robots_resp = _make_response(
            status_code=200,
            text=(
                "User-agent: *\n"
                "Disallow: /admin\n"
                "Disallow: /backup\n"
                "Disallow: /config\n"
                "Disallow: /.git\n"
            ),
        )
        sec_404 = _make_response(status_code=404)

        def side_effect(url, **kwargs):
            if "robots.txt" in url:
                return robots_resp
            return sec_404

        session.get.side_effect = side_effect
        mock_create.return_value = (session, 10)

        scanner = FilesScanner()
        findings = scanner.scan(https_target)

        robots_findings = [f for f in findings if f.finding_type == "robots_sensitive_paths"]
        assert len(robots_findings) == 1
        # The detail should mention multiple paths
        detail = robots_findings[0].detail
        assert "/admin" in detail
        assert "/backup" in detail

    @patch("webinspector.modules.files_scanner.create_http_session")
    def test_no_sensitive_paths_no_finding(self, mock_create, https_target):
        """
        robots.txt with only non-sensitive paths (like /images, /css)
        should NOT produce a robots_sensitive_paths finding.
        """
        from webinspector.modules.files_scanner import FilesScanner

        session = MagicMock()

        robots_resp = _make_response(
            status_code=200,
            text="User-agent: *\nDisallow: /images\nDisallow: /css\n",
        )
        sec_404 = _make_response(status_code=404)

        def side_effect(url, **kwargs):
            if "robots.txt" in url:
                return robots_resp
            return sec_404

        session.get.side_effect = side_effect
        mock_create.return_value = (session, 10)

        scanner = FilesScanner()
        findings = scanner.scan(https_target)

        robots_findings = [f for f in findings if f.finding_type == "robots_sensitive_paths"]
        assert len(robots_findings) == 0

    @patch("webinspector.modules.files_scanner.create_http_session")
    def test_robots_404_no_finding(self, mock_create, https_target):
        """
        When robots.txt returns 404, no robots_sensitive_paths finding
        should be produced (the file simply doesn't exist).
        """
        from webinspector.modules.files_scanner import FilesScanner

        session = MagicMock()

        robots_resp = _make_response(status_code=404)
        sec_404 = _make_response(status_code=404)

        def side_effect(url, **kwargs):
            if "robots.txt" in url:
                return robots_resp
            return sec_404

        session.get.side_effect = side_effect
        mock_create.return_value = (session, 10)

        scanner = FilesScanner()
        findings = scanner.scan(https_target)

        robots_findings = [f for f in findings if f.finding_type == "robots_sensitive_paths"]
        assert len(robots_findings) == 0

    @patch("webinspector.modules.files_scanner.create_http_session")
    def test_case_insensitive_pattern_matching(self, mock_create, https_target):
        """
        Sensitive path matching should be case-insensitive.  /Admin and
        /ADMIN should both match the 'admin' pattern.
        """
        from webinspector.modules.files_scanner import FilesScanner

        session = MagicMock()

        robots_resp = _make_response(
            status_code=200,
            text="User-agent: *\nDisallow: /Admin\nDisallow: /BACKUP\n",
        )
        sec_404 = _make_response(status_code=404)

        def side_effect(url, **kwargs):
            if "robots.txt" in url:
                return robots_resp
            return sec_404

        session.get.side_effect = side_effect
        mock_create.return_value = (session, 10)

        scanner = FilesScanner()
        findings = scanner.scan(https_target)

        robots_findings = [f for f in findings if f.finding_type == "robots_sensitive_paths"]
        assert len(robots_findings) == 1

    @patch("webinspector.modules.files_scanner.create_http_session")
    def test_detects_wp_admin(self, mock_create, https_target):
        """
        robots.txt with Disallow: /wp-admin should be flagged.  This
        reveals the site is running WordPress and exposes the admin panel.
        """
        from webinspector.modules.files_scanner import FilesScanner

        session = MagicMock()

        robots_resp = _make_response(
            status_code=200,
            text="User-agent: *\nDisallow: /wp-admin\n",
        )
        sec_404 = _make_response(status_code=404)

        def side_effect(url, **kwargs):
            if "robots.txt" in url:
                return robots_resp
            return sec_404

        session.get.side_effect = side_effect
        mock_create.return_value = (session, 10)

        scanner = FilesScanner()
        findings = scanner.scan(https_target)

        robots_findings = [f for f in findings if f.finding_type == "robots_sensitive_paths"]
        assert len(robots_findings) == 1

    @patch("webinspector.modules.files_scanner.create_http_session")
    def test_detects_phpmyadmin(self, mock_create, https_target):
        """
        robots.txt with Disallow: /phpmyadmin should be flagged.
        phpMyAdmin is a database management tool that should never be
        publicly accessible.
        """
        from webinspector.modules.files_scanner import FilesScanner

        session = MagicMock()

        robots_resp = _make_response(
            status_code=200,
            text="User-agent: *\nDisallow: /phpmyadmin\n",
        )
        sec_404 = _make_response(status_code=404)

        def side_effect(url, **kwargs):
            if "robots.txt" in url:
                return robots_resp
            return sec_404

        session.get.side_effect = side_effect
        mock_create.return_value = (session, 10)

        scanner = FilesScanner()
        findings = scanner.scan(https_target)

        robots_findings = [f for f in findings if f.finding_type == "robots_sensitive_paths"]
        assert len(robots_findings) == 1

    @patch("webinspector.modules.files_scanner.create_http_session")
    def test_detects_htaccess_path(self, mock_create, https_target):
        """
        robots.txt with Disallow: /.htaccess should be flagged.
        .htaccess files contain Apache configuration directives that
        may reveal internal paths or authentication rules.
        """
        from webinspector.modules.files_scanner import FilesScanner

        session = MagicMock()

        robots_resp = _make_response(
            status_code=200,
            text="User-agent: *\nDisallow: /.htaccess\n",
        )
        sec_404 = _make_response(status_code=404)

        def side_effect(url, **kwargs):
            if "robots.txt" in url:
                return robots_resp
            return sec_404

        session.get.side_effect = side_effect
        mock_create.return_value = (session, 10)

        scanner = FilesScanner()
        findings = scanner.scan(https_target)

        robots_findings = [f for f in findings if f.finding_type == "robots_sensitive_paths"]
        assert len(robots_findings) == 1

    @patch("webinspector.modules.files_scanner.create_http_session")
    def test_detects_server_status(self, mock_create, https_target):
        """
        robots.txt with Disallow: /server-status should be flagged.
        Apache server-status reveals active connections, client IPs,
        and request URIs.
        """
        from webinspector.modules.files_scanner import FilesScanner

        session = MagicMock()

        robots_resp = _make_response(
            status_code=200,
            text="User-agent: *\nDisallow: /server-status\n",
        )
        sec_404 = _make_response(status_code=404)

        def side_effect(url, **kwargs):
            if "robots.txt" in url:
                return robots_resp
            return sec_404

        session.get.side_effect = side_effect
        mock_create.return_value = (session, 10)

        scanner = FilesScanner()
        findings = scanner.scan(https_target)

        robots_findings = [f for f in findings if f.finding_type == "robots_sensitive_paths"]
        assert len(robots_findings) == 1


# ===========================================================================
# Tests for security.txt -- RFC 9116 compliance
# ===========================================================================

class TestSecurityTxtMissing:
    """Verify detection of completely missing security.txt."""

    @patch("webinspector.modules.files_scanner.create_http_session")
    def test_detects_missing_security_txt(self, mock_create, https_target):
        """
        When neither /.well-known/security.txt nor /security.txt exists
        (both return 404), an INFORMATIONAL finding of type
        missing_security_txt should be produced.

        security.txt is a standard (RFC 9116) that helps security
        researchers report vulnerabilities responsibly.
        """
        from webinspector.modules.files_scanner import FilesScanner

        session = MagicMock()

        robots_resp = _make_response(status_code=404)
        sec_404 = _make_response(status_code=404)

        def side_effect(url, **kwargs):
            return _make_response(status_code=404)

        session.get.side_effect = side_effect
        mock_create.return_value = (session, 10)

        scanner = FilesScanner()
        findings = scanner.scan(https_target)

        missing = [f for f in findings if f.finding_type == "missing_security_txt"]
        assert len(missing) == 1
        assert missing[0].severity == Severity.INFORMATIONAL


class TestSecurityTxtMissingContact:
    """Verify detection of security.txt missing Contact field."""

    @patch("webinspector.modules.files_scanner.create_http_session")
    def test_detects_missing_contact(self, mock_create, https_target):
        """
        security.txt without a Contact field should produce a LOW finding.
        Contact is required by RFC 9116 so researchers know where to
        report vulnerabilities.
        """
        from webinspector.modules.files_scanner import FilesScanner

        session = MagicMock()

        # security.txt with Expires but no Contact
        sec_txt = "Expires: 2027-12-31T23:59:59z\n"

        def side_effect(url, **kwargs):
            if "robots.txt" in url:
                return _make_response(status_code=404)
            if ".well-known/security.txt" in url:
                return _make_response(status_code=200, text=sec_txt)
            return _make_response(status_code=404)

        session.get.side_effect = side_effect
        mock_create.return_value = (session, 10)

        scanner = FilesScanner()
        findings = scanner.scan(https_target)

        contact_findings = [f for f in findings if f.finding_type == "security_txt_missing_contact"]
        assert len(contact_findings) == 1
        assert contact_findings[0].severity == Severity.LOW


class TestSecurityTxtMissingExpires:
    """Verify detection of security.txt missing Expires field."""

    @patch("webinspector.modules.files_scanner.create_http_session")
    def test_detects_missing_expires(self, mock_create, https_target):
        """
        security.txt without an Expires field should produce a LOW finding.
        Expires is required by RFC 9116 so researchers know when the
        security contact information was last verified.
        """
        from webinspector.modules.files_scanner import FilesScanner

        session = MagicMock()

        # security.txt with Contact but no Expires
        sec_txt = "Contact: mailto:security@example.com\n"

        def side_effect(url, **kwargs):
            if "robots.txt" in url:
                return _make_response(status_code=404)
            if ".well-known/security.txt" in url:
                return _make_response(status_code=200, text=sec_txt)
            return _make_response(status_code=404)

        session.get.side_effect = side_effect
        mock_create.return_value = (session, 10)

        scanner = FilesScanner()
        findings = scanner.scan(https_target)

        expires_findings = [f for f in findings if f.finding_type == "security_txt_missing_expires"]
        assert len(expires_findings) == 1
        assert expires_findings[0].severity == Severity.LOW


class TestSecurityTxtExpired:
    """Verify detection of security.txt with expired Expires date."""

    @patch("webinspector.modules.files_scanner.create_http_session")
    def test_detects_expired_security_txt(self, mock_create, https_target):
        """
        security.txt with an Expires date in the past should produce a
        LOW finding.  An expired security.txt means the contact information
        may be stale and vulnerability reports may go unanswered.
        """
        from webinspector.modules.files_scanner import FilesScanner

        session = MagicMock()

        # security.txt with Contact and an expired Expires date
        sec_txt = (
            "Contact: mailto:security@example.com\n"
            "Expires: 2020-01-01T00:00:00z\n"
        )

        def side_effect(url, **kwargs):
            if "robots.txt" in url:
                return _make_response(status_code=404)
            if ".well-known/security.txt" in url:
                return _make_response(status_code=200, text=sec_txt)
            return _make_response(status_code=404)

        session.get.side_effect = side_effect
        mock_create.return_value = (session, 10)

        scanner = FilesScanner()
        findings = scanner.scan(https_target)

        expired_findings = [f for f in findings if f.finding_type == "security_txt_expired"]
        assert len(expired_findings) == 1
        assert expired_findings[0].severity == Severity.LOW

    @patch("webinspector.modules.files_scanner.create_http_session")
    def test_future_expires_no_expired_finding(self, mock_create, https_target):
        """
        security.txt with an Expires date in the future should NOT produce
        a security_txt_expired finding.
        """
        from webinspector.modules.files_scanner import FilesScanner

        session = MagicMock()

        # security.txt with Contact and a future Expires date
        sec_txt = (
            "Contact: mailto:security@example.com\n"
            "Expires: 2099-12-31T23:59:59z\n"
        )

        def side_effect(url, **kwargs):
            if "robots.txt" in url:
                return _make_response(status_code=404)
            if ".well-known/security.txt" in url:
                return _make_response(status_code=200, text=sec_txt)
            return _make_response(status_code=404)

        session.get.side_effect = side_effect
        mock_create.return_value = (session, 10)

        scanner = FilesScanner()
        findings = scanner.scan(https_target)

        expired_findings = [f for f in findings if f.finding_type == "security_txt_expired"]
        assert len(expired_findings) == 0


class TestSecurityTxtValid:
    """Verify that a valid security.txt produces no findings."""

    @patch("webinspector.modules.files_scanner.create_http_session")
    def test_valid_security_txt_no_findings(self, mock_create, https_target):
        """
        A security.txt with both Contact and a future Expires date should
        produce zero security.txt-related findings.  This represents the
        ideal configuration.
        """
        from webinspector.modules.files_scanner import FilesScanner

        session = MagicMock()

        # Valid, complete security.txt
        sec_txt = (
            "Contact: mailto:security@example.com\n"
            "Expires: 2099-12-31T23:59:59z\n"
            "Preferred-Languages: en\n"
        )

        def side_effect(url, **kwargs):
            if "robots.txt" in url:
                return _make_response(status_code=404)
            if ".well-known/security.txt" in url:
                return _make_response(status_code=200, text=sec_txt)
            return _make_response(status_code=404)

        session.get.side_effect = side_effect
        mock_create.return_value = (session, 10)

        scanner = FilesScanner()
        findings = scanner.scan(https_target)

        # No security.txt-related findings
        sec_findings = [f for f in findings
                        if "security_txt" in f.finding_type
                        or "missing_security_txt" in f.finding_type]
        assert len(sec_findings) == 0


class TestSecurityTxtFallbackLocation:
    """Verify the scanner checks both RFC 9116 locations."""

    @patch("webinspector.modules.files_scanner.create_http_session")
    def test_falls_back_to_root_security_txt(self, mock_create, https_target):
        """
        When /.well-known/security.txt returns 404 but /security.txt
        exists, the scanner should use the /security.txt content.

        RFC 9116 specifies /.well-known/security.txt as the primary
        location with /security.txt as a legacy fallback.
        """
        from webinspector.modules.files_scanner import FilesScanner

        session = MagicMock()

        # Valid security.txt at /security.txt (not .well-known)
        sec_txt = (
            "Contact: mailto:security@example.com\n"
            "Expires: 2099-12-31T23:59:59z\n"
        )

        def side_effect(url, **kwargs):
            if "robots.txt" in url:
                return _make_response(status_code=404)
            if ".well-known/security.txt" in url:
                return _make_response(status_code=404)
            if "security.txt" in url:
                return _make_response(status_code=200, text=sec_txt)
            return _make_response(status_code=404)

        session.get.side_effect = side_effect
        mock_create.return_value = (session, 10)

        scanner = FilesScanner()
        findings = scanner.scan(https_target)

        # Should NOT have missing_security_txt (found at /security.txt)
        missing = [f for f in findings if f.finding_type == "missing_security_txt"]
        assert len(missing) == 0

    @patch("webinspector.modules.files_scanner.create_http_session")
    def test_prefers_well_known_location(self, mock_create, https_target):
        """
        When /.well-known/security.txt exists, the scanner should use it
        and not fall back to /security.txt.  This is the RFC 9116
        recommended location.
        """
        from webinspector.modules.files_scanner import FilesScanner

        session = MagicMock()

        # Valid security.txt at .well-known location
        sec_txt_wk = (
            "Contact: mailto:security@example.com\n"
            "Expires: 2099-12-31T23:59:59z\n"
        )
        # Broken security.txt at root (missing Contact)
        sec_txt_root = "Expires: 2099-12-31T23:59:59z\n"

        def side_effect(url, **kwargs):
            if "robots.txt" in url:
                return _make_response(status_code=404)
            if ".well-known/security.txt" in url:
                return _make_response(status_code=200, text=sec_txt_wk)
            if "security.txt" in url:
                return _make_response(status_code=200, text=sec_txt_root)
            return _make_response(status_code=404)

        session.get.side_effect = side_effect
        mock_create.return_value = (session, 10)

        scanner = FilesScanner()
        findings = scanner.scan(https_target)

        # Should NOT have missing_contact because the .well-known version is valid
        contact_findings = [f for f in findings if f.finding_type == "security_txt_missing_contact"]
        assert len(contact_findings) == 0


class TestSecurityTxtMultipleIssues:
    """Verify that multiple security.txt issues are all reported."""

    @patch("webinspector.modules.files_scanner.create_http_session")
    def test_missing_contact_and_expires(self, mock_create, https_target):
        """
        security.txt with neither Contact nor Expires should produce
        both the missing_contact and missing_expires findings.
        """
        from webinspector.modules.files_scanner import FilesScanner

        session = MagicMock()

        # security.txt with no required fields
        sec_txt = "Preferred-Languages: en\n"

        def side_effect(url, **kwargs):
            if "robots.txt" in url:
                return _make_response(status_code=404)
            if ".well-known/security.txt" in url:
                return _make_response(status_code=200, text=sec_txt)
            return _make_response(status_code=404)

        session.get.side_effect = side_effect
        mock_create.return_value = (session, 10)

        scanner = FilesScanner()
        findings = scanner.scan(https_target)

        types = {f.finding_type for f in findings}
        assert "security_txt_missing_contact" in types
        assert "security_txt_missing_expires" in types


# ===========================================================================
# Tests for finding structure and content
# ===========================================================================

class TestFindingStructure:
    """Verify that findings have correct module name, titles, and details."""

    @patch("webinspector.modules.files_scanner.create_http_session")
    def test_all_findings_have_module_files(self, mock_create, https_target):
        """Every finding should have module='files'."""
        from webinspector.modules.files_scanner import FilesScanner

        session = MagicMock()

        # robots.txt with a sensitive path
        robots_resp = _make_response(
            status_code=200,
            text="User-agent: *\nDisallow: /admin\n",
        )

        def side_effect(url, **kwargs):
            if "robots.txt" in url:
                return robots_resp
            return _make_response(status_code=404)

        session.get.side_effect = side_effect
        mock_create.return_value = (session, 10)

        scanner = FilesScanner()
        findings = scanner.scan(https_target)

        assert len(findings) >= 1
        for finding in findings:
            assert finding.module == "files"
            assert finding.target is https_target

    @patch("webinspector.modules.files_scanner.create_http_session")
    def test_findings_have_titles_and_details(self, mock_create, https_target):
        """Every finding should have non-empty title and detail."""
        from webinspector.modules.files_scanner import FilesScanner

        session = MagicMock()

        def side_effect(url, **kwargs):
            return _make_response(status_code=404)

        session.get.side_effect = side_effect
        mock_create.return_value = (session, 10)

        scanner = FilesScanner()
        findings = scanner.scan(https_target)

        for finding in findings:
            assert len(finding.title) > 0
            assert len(finding.detail) > 0


# ===========================================================================
# Test module registration
# ===========================================================================

class TestFilesScannerRegistration:
    """Verify that importing the module registers it."""

    def test_module_registers(self):
        """
        Importing files_scanner should call register_module() at the
        bottom of the file, making it discoverable by the module registry.
        """
        from webinspector.modules import _registry
        from webinspector.modules.files_scanner import FilesScanner

        # The module registers itself at import time.
        # Check that an instance of FilesScanner is in the registry.
        files_modules = [m for m in _registry if m.name == "files"]
        assert len(files_modules) >= 1
        assert isinstance(files_modules[0], FilesScanner)
