"""
Tests for the content analysis scanner module (content_scanner.py).

These tests verify that the ContentScanner module correctly:
    1. Has the correct name ("content") and a non-empty description
    2. Accepts both HTTP and HTTPS targets (default accepts_target)
    3. Returns empty findings when http_response is None
    4. Detects active mixed content (script, link, iframe loading http:// on https://)
    5. Detects passive mixed content (img, audio, video loading http:// on https://)
    6. Does NOT flag mixed content on plain HTTP pages (only https:// pages)
    7. Detects external script/link tags missing the integrity (SRI) attribute
    8. Does NOT flag SRI for same-origin or relative script/link tags
    9. Detects RFC 1918 internal IP address disclosure in the response body
   10. Detects email address disclosure in the response body
   11. Detects sensitive HTML comments (TODO, FIXME, password, secret, etc.)
   12. Detects error pages: Java stack traces, Python tracebacks, PHP errors,
       ASP.NET errors, Django debug pages, SQL errors, directory listings
   13. Detects default server pages (Apache, nginx, IIS)
   14. Returns empty findings for a clean HTML page with no issues
   15. Handles multiple findings in a single scan
   16. Registers itself with the module registry at import time

All HTTP responses are mocked using unittest.mock.MagicMock -- no real
HTTP connections are made.

Author: Red Siege Information Security
"""

import pytest
from unittest.mock import MagicMock

from webinspector.core.target import Target
from webinspector.core.result import Finding, Severity


# ---------------------------------------------------------------------------
# Mock helpers — build a requests.Response stand-in with body text
# ---------------------------------------------------------------------------

def _make_response(body: str, url: str = "https://example.com:443/") -> MagicMock:
    """
    Build a mock requests.Response with the given HTML body text and URL.

    The mock's .text attribute contains the response body (HTML).
    The mock's .url attribute contains the final URL after redirects.
    The mock's .headers attribute is an empty dict unless overridden.

    Args:
        body: The HTML body text to assign to .text.
        url:  The final URL of the response (used for scheme detection).

    Returns:
        A MagicMock mimicking requests.Response with .text and .url set.
    """
    response = MagicMock()
    response.text = body
    response.url = url
    response.headers = {}
    return response


def _make_clean_html() -> str:
    """
    Return a minimal, clean HTML page with no security issues.

    This page uses only relative/same-origin resources, contains no internal
    IPs, no email addresses, no sensitive comments, no error patterns, and
    no mixed content.
    """
    return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Clean Page</title>
    <link rel="stylesheet" href="/css/style.css">
    <script src="/js/app.js"></script>
</head>
<body>
    <h1>Welcome</h1>
    <p>This is a clean page with no security issues.</p>
    <img src="/images/logo.png" alt="Logo">
</body>
</html>"""


# ---------------------------------------------------------------------------
# Target fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def https_target():
    """An HTTPS target for content scanning."""
    return Target(host="example.com", port=443, scheme="https")


@pytest.fixture
def http_target():
    """An HTTP target for content scanning."""
    return Target(host="example.com", port=80, scheme="http")


# ===========================================================================
# Tests for module properties
# ===========================================================================

class TestContentScannerProperties:
    """Verify name and description properties."""

    def test_name(self):
        """Module name should be 'content'."""
        from webinspector.modules.content_scanner import ContentScanner
        scanner = ContentScanner()
        assert scanner.name == "content"

    def test_description(self):
        """Module should have a non-empty description."""
        from webinspector.modules.content_scanner import ContentScanner
        scanner = ContentScanner()
        assert len(scanner.description) > 0
        # Should mention content in the description.
        assert "content" in scanner.description.lower()


# ===========================================================================
# Tests for accepts_target
# ===========================================================================

class TestContentScannerAcceptsTarget:
    """Verify that the content scanner accepts both HTTP and HTTPS targets."""

    def test_accepts_https(self, https_target):
        """Content scanner should accept HTTPS targets."""
        from webinspector.modules.content_scanner import ContentScanner
        scanner = ContentScanner()
        assert scanner.accepts_target(https_target) is True

    def test_accepts_http(self, http_target):
        """Content scanner should accept HTTP targets."""
        from webinspector.modules.content_scanner import ContentScanner
        scanner = ContentScanner()
        assert scanner.accepts_target(http_target) is True


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
        from webinspector.modules.content_scanner import ContentScanner
        scanner = ContentScanner()
        findings = scanner.scan(https_target, http_response=None)
        assert isinstance(findings, list)
        assert len(findings) == 0


# ===========================================================================
# Tests for mixed content detection
# ===========================================================================

class TestMixedContentActive:
    """Verify detection of active mixed content on HTTPS pages."""

    def test_detects_script_http_on_https(self, https_target):
        """
        A <script src="http://..."> on an HTTPS page is active mixed content.
        Should produce a MEDIUM severity finding of type mixed_content_active.
        """
        from webinspector.modules.content_scanner import ContentScanner

        html = '<html><head><script src="http://cdn.evil.com/malware.js"></script></head><body></body></html>'
        response = _make_response(html, url="https://example.com:443/")

        scanner = ContentScanner()
        findings = scanner.scan(https_target, http_response=response)

        active = [f for f in findings if f.finding_type == "mixed_content_active"]
        assert len(active) >= 1
        assert active[0].severity == Severity.MEDIUM

    def test_detects_link_http_on_https(self, https_target):
        """
        A <link href="http://..."> stylesheet on an HTTPS page is active mixed
        content because CSS can execute JavaScript via expressions/behaviors.
        MEDIUM severity.
        """
        from webinspector.modules.content_scanner import ContentScanner

        html = '<html><head><link rel="stylesheet" href="http://cdn.example.com/style.css"></head><body></body></html>'
        response = _make_response(html, url="https://example.com:443/")

        scanner = ContentScanner()
        findings = scanner.scan(https_target, http_response=response)

        active = [f for f in findings if f.finding_type == "mixed_content_active"]
        assert len(active) >= 1
        assert active[0].severity == Severity.MEDIUM

    def test_detects_iframe_http_on_https(self, https_target):
        """
        An <iframe src="http://..."> on an HTTPS page is active mixed content.
        MEDIUM severity.
        """
        from webinspector.modules.content_scanner import ContentScanner

        html = '<html><body><iframe src="http://other.example.com/embed"></iframe></body></html>'
        response = _make_response(html, url="https://example.com:443/")

        scanner = ContentScanner()
        findings = scanner.scan(https_target, http_response=response)

        active = [f for f in findings if f.finding_type == "mixed_content_active"]
        assert len(active) >= 1
        assert active[0].severity == Severity.MEDIUM

    def test_no_mixed_content_on_http_page(self, http_target):
        """
        Mixed content is only relevant for HTTPS pages.  An HTTP page loading
        http:// resources is normal behaviour and should NOT produce a finding.
        """
        from webinspector.modules.content_scanner import ContentScanner

        html = '<html><head><script src="http://cdn.example.com/app.js"></script></head><body></body></html>'
        response = _make_response(html, url="http://example.com:80/")

        scanner = ContentScanner()
        findings = scanner.scan(http_target, http_response=response)

        mixed = [f for f in findings if "mixed_content" in f.finding_type]
        assert len(mixed) == 0

    def test_https_script_on_https_page_no_finding(self, https_target):
        """
        A <script src="https://..."> on an HTTPS page is NOT mixed content.
        Should not produce a mixed_content finding.
        """
        from webinspector.modules.content_scanner import ContentScanner

        html = '<html><head><script src="https://cdn.example.com/app.js"></script></head><body></body></html>'
        response = _make_response(html, url="https://example.com:443/")

        scanner = ContentScanner()
        findings = scanner.scan(https_target, http_response=response)

        mixed = [f for f in findings if "mixed_content" in f.finding_type]
        assert len(mixed) == 0


class TestMixedContentPassive:
    """Verify detection of passive mixed content on HTTPS pages."""

    def test_detects_img_http_on_https(self, https_target):
        """
        An <img src="http://..."> on an HTTPS page is passive mixed content.
        Should produce a LOW severity finding of type mixed_content_passive.
        """
        from webinspector.modules.content_scanner import ContentScanner

        html = '<html><body><img src="http://images.example.com/photo.jpg"></body></html>'
        response = _make_response(html, url="https://example.com:443/")

        scanner = ContentScanner()
        findings = scanner.scan(https_target, http_response=response)

        passive = [f for f in findings if f.finding_type == "mixed_content_passive"]
        assert len(passive) >= 1
        assert passive[0].severity == Severity.LOW

    def test_detects_audio_http_on_https(self, https_target):
        """
        An <audio src="http://..."> on an HTTPS page is passive mixed content.
        LOW severity.
        """
        from webinspector.modules.content_scanner import ContentScanner

        html = '<html><body><audio src="http://media.example.com/track.mp3"></audio></body></html>'
        response = _make_response(html, url="https://example.com:443/")

        scanner = ContentScanner()
        findings = scanner.scan(https_target, http_response=response)

        passive = [f for f in findings if f.finding_type == "mixed_content_passive"]
        assert len(passive) >= 1
        assert passive[0].severity == Severity.LOW

    def test_detects_video_http_on_https(self, https_target):
        """
        A <video src="http://..."> on an HTTPS page is passive mixed content.
        LOW severity.
        """
        from webinspector.modules.content_scanner import ContentScanner

        html = '<html><body><video src="http://media.example.com/clip.mp4"></video></body></html>'
        response = _make_response(html, url="https://example.com:443/")

        scanner = ContentScanner()
        findings = scanner.scan(https_target, http_response=response)

        passive = [f for f in findings if f.finding_type == "mixed_content_passive"]
        assert len(passive) >= 1
        assert passive[0].severity == Severity.LOW


# ===========================================================================
# Tests for missing SRI (Subresource Integrity)
# ===========================================================================

class TestMissingSRI:
    """Verify detection of external scripts/links missing the integrity attribute."""

    def test_detects_external_script_missing_integrity(self, https_target):
        """
        An external <script> from a CDN/third-party without an integrity
        attribute should produce a LOW severity missing_sri finding.
        """
        from webinspector.modules.content_scanner import ContentScanner

        html = '<html><head><script src="https://cdn.jsdelivr.net/npm/lodash@4.17.21/lodash.min.js"></script></head><body></body></html>'
        response = _make_response(html, url="https://example.com:443/")

        scanner = ContentScanner()
        findings = scanner.scan(https_target, http_response=response)

        sri = [f for f in findings if f.finding_type == "missing_sri"]
        assert len(sri) >= 1
        assert sri[0].severity == Severity.LOW

    def test_detects_external_link_missing_integrity(self, https_target):
        """
        An external <link> stylesheet from a CDN without an integrity
        attribute should produce a LOW severity missing_sri finding.
        """
        from webinspector.modules.content_scanner import ContentScanner

        html = '<html><head><link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css"></head><body></body></html>'
        response = _make_response(html, url="https://example.com:443/")

        scanner = ContentScanner()
        findings = scanner.scan(https_target, http_response=response)

        sri = [f for f in findings if f.finding_type == "missing_sri"]
        assert len(sri) >= 1
        assert sri[0].severity == Severity.LOW

    def test_external_script_with_integrity_no_finding(self, https_target):
        """
        An external script WITH an integrity attribute should NOT produce
        a missing_sri finding.
        """
        from webinspector.modules.content_scanner import ContentScanner

        html = (
            '<html><head>'
            '<script src="https://cdn.jsdelivr.net/npm/lodash@4.17.21/lodash.min.js" '
            'integrity="sha384-abc123" crossorigin="anonymous"></script>'
            '</head><body></body></html>'
        )
        response = _make_response(html, url="https://example.com:443/")

        scanner = ContentScanner()
        findings = scanner.scan(https_target, http_response=response)

        sri = [f for f in findings if f.finding_type == "missing_sri"]
        assert len(sri) == 0

    def test_same_origin_script_no_sri_finding(self, https_target):
        """
        A same-origin script (relative path or same domain) should NOT produce
        a missing_sri finding, because SRI is primarily for third-party resources.
        """
        from webinspector.modules.content_scanner import ContentScanner

        html = (
            '<html><head>'
            '<script src="/js/app.js"></script>'
            '<script src="https://example.com/js/app.js"></script>'
            '</head><body></body></html>'
        )
        response = _make_response(html, url="https://example.com:443/")

        scanner = ContentScanner()
        findings = scanner.scan(https_target, http_response=response)

        sri = [f for f in findings if f.finding_type == "missing_sri"]
        assert len(sri) == 0


# ===========================================================================
# Tests for internal IP disclosure
# ===========================================================================

class TestInternalIPDisclosure:
    """Verify detection of RFC 1918 internal IP addresses in response body."""

    def test_detects_10_x_x_x(self, https_target):
        """
        A 10.x.x.x address (RFC 1918 Class A private) in the body should
        produce a LOW severity internal_ip_disclosure finding.
        """
        from webinspector.modules.content_scanner import ContentScanner

        html = '<html><body><!-- Backend server: 10.0.1.50 --></body></html>'
        response = _make_response(html, url="https://example.com:443/")

        scanner = ContentScanner()
        findings = scanner.scan(https_target, http_response=response)

        ips = [f for f in findings if f.finding_type == "internal_ip_disclosure"]
        assert len(ips) >= 1
        assert ips[0].severity == Severity.LOW

    def test_detects_172_16_x_x(self, https_target):
        """
        A 172.16.x.x through 172.31.x.x address (RFC 1918 Class B private)
        in the body should produce a LOW severity finding.
        """
        from webinspector.modules.content_scanner import ContentScanner

        html = '<html><body><p>Server: 172.16.254.1</p></body></html>'
        response = _make_response(html, url="https://example.com:443/")

        scanner = ContentScanner()
        findings = scanner.scan(https_target, http_response=response)

        ips = [f for f in findings if f.finding_type == "internal_ip_disclosure"]
        assert len(ips) >= 1
        assert ips[0].severity == Severity.LOW

    def test_detects_192_168_x_x(self, https_target):
        """
        A 192.168.x.x address (RFC 1918 Class C private) in the body
        should produce a LOW severity finding.
        """
        from webinspector.modules.content_scanner import ContentScanner

        html = '<html><body>Connected to 192.168.1.100</body></html>'
        response = _make_response(html, url="https://example.com:443/")

        scanner = ContentScanner()
        findings = scanner.scan(https_target, http_response=response)

        ips = [f for f in findings if f.finding_type == "internal_ip_disclosure"]
        assert len(ips) >= 1
        assert ips[0].severity == Severity.LOW

    def test_no_internal_ip_no_finding(self, https_target):
        """
        A page with only public IP addresses or no IPs at all should NOT
        produce an internal_ip_disclosure finding.
        """
        from webinspector.modules.content_scanner import ContentScanner

        html = '<html><body><p>Our server IP is 203.0.113.50</p></body></html>'
        response = _make_response(html, url="https://example.com:443/")

        scanner = ContentScanner()
        findings = scanner.scan(https_target, http_response=response)

        ips = [f for f in findings if f.finding_type == "internal_ip_disclosure"]
        assert len(ips) == 0

    def test_172_32_not_private(self, https_target):
        """
        172.32.x.x is NOT a private address (only 172.16.0.0 through
        172.31.255.255 are private).  Should NOT produce a finding.
        """
        from webinspector.modules.content_scanner import ContentScanner

        html = '<html><body><p>Host: 172.32.0.1</p></body></html>'
        response = _make_response(html, url="https://example.com:443/")

        scanner = ContentScanner()
        findings = scanner.scan(https_target, http_response=response)

        ips = [f for f in findings if f.finding_type == "internal_ip_disclosure"]
        assert len(ips) == 0


# ===========================================================================
# Tests for email disclosure
# ===========================================================================

class TestEmailDisclosure:
    """Verify detection of email addresses in the response body."""

    def test_detects_email_address(self, https_target):
        """
        An email address in the HTML body should produce an INFORMATIONAL
        severity email_disclosure finding.
        """
        from webinspector.modules.content_scanner import ContentScanner

        html = '<html><body><p>Contact us at admin@example.com</p></body></html>'
        response = _make_response(html, url="https://example.com:443/")

        scanner = ContentScanner()
        findings = scanner.scan(https_target, http_response=response)

        emails = [f for f in findings if f.finding_type == "email_disclosure"]
        assert len(emails) >= 1
        assert emails[0].severity == Severity.INFORMATIONAL

    def test_detects_multiple_emails(self, https_target):
        """
        Multiple distinct email addresses should be reported.
        """
        from webinspector.modules.content_scanner import ContentScanner

        html = (
            '<html><body>'
            '<p>admin@example.com</p>'
            '<p>support@example.com</p>'
            '</body></html>'
        )
        response = _make_response(html, url="https://example.com:443/")

        scanner = ContentScanner()
        findings = scanner.scan(https_target, http_response=response)

        emails = [f for f in findings if f.finding_type == "email_disclosure"]
        assert len(emails) >= 1
        # The detail should mention both addresses.
        all_details = " ".join(f.detail for f in emails)
        assert "admin@example.com" in all_details
        assert "support@example.com" in all_details

    def test_no_email_no_finding(self, https_target):
        """A page with no email addresses should NOT produce email_disclosure."""
        from webinspector.modules.content_scanner import ContentScanner

        html = '<html><body><p>No contact info here.</p></body></html>'
        response = _make_response(html, url="https://example.com:443/")

        scanner = ContentScanner()
        findings = scanner.scan(https_target, http_response=response)

        emails = [f for f in findings if f.finding_type == "email_disclosure"]
        assert len(emails) == 0


# ===========================================================================
# Tests for sensitive HTML comments
# ===========================================================================

class TestSensitiveComments:
    """Verify detection of HTML comments containing sensitive keywords."""

    def test_detects_todo_comment(self, https_target):
        """
        An HTML comment containing 'TODO' should produce an INFORMATIONAL
        sensitive_comment finding.
        """
        from webinspector.modules.content_scanner import ContentScanner

        html = '<html><body><!-- TODO: remove this debug endpoint --></body></html>'
        response = _make_response(html, url="https://example.com:443/")

        scanner = ContentScanner()
        findings = scanner.scan(https_target, http_response=response)

        comments = [f for f in findings if f.finding_type == "sensitive_comment"]
        assert len(comments) >= 1
        assert comments[0].severity == Severity.INFORMATIONAL

    def test_detects_fixme_comment(self, https_target):
        """An HTML comment containing 'FIXME' should be flagged."""
        from webinspector.modules.content_scanner import ContentScanner

        html = '<html><body><!-- FIXME: authentication bypass for testing --></body></html>'
        response = _make_response(html, url="https://example.com:443/")

        scanner = ContentScanner()
        findings = scanner.scan(https_target, http_response=response)

        comments = [f for f in findings if f.finding_type == "sensitive_comment"]
        assert len(comments) >= 1

    def test_detects_password_comment(self, https_target):
        """An HTML comment containing 'password' should be flagged."""
        from webinspector.modules.content_scanner import ContentScanner

        html = '<html><body><!-- default password is admin123 --></body></html>'
        response = _make_response(html, url="https://example.com:443/")

        scanner = ContentScanner()
        findings = scanner.scan(https_target, http_response=response)

        comments = [f for f in findings if f.finding_type == "sensitive_comment"]
        assert len(comments) >= 1

    def test_detects_api_key_comment(self, https_target):
        """An HTML comment containing 'api_key' should be flagged."""
        from webinspector.modules.content_scanner import ContentScanner

        html = '<html><body><!-- api_key=sk_live_abc123xyz --></body></html>'
        response = _make_response(html, url="https://example.com:443/")

        scanner = ContentScanner()
        findings = scanner.scan(https_target, http_response=response)

        comments = [f for f in findings if f.finding_type == "sensitive_comment"]
        assert len(comments) >= 1

    def test_detects_secret_comment(self, https_target):
        """An HTML comment containing 'secret' should be flagged."""
        from webinspector.modules.content_scanner import ContentScanner

        html = '<html><body><!-- client_secret = abcdef123456 --></body></html>'
        response = _make_response(html, url="https://example.com:443/")

        scanner = ContentScanner()
        findings = scanner.scan(https_target, http_response=response)

        comments = [f for f in findings if f.finding_type == "sensitive_comment"]
        assert len(comments) >= 1

    def test_detects_token_comment(self, https_target):
        """An HTML comment containing 'token' should be flagged."""
        from webinspector.modules.content_scanner import ContentScanner

        html = '<html><body><!-- auth token: eyJhbGciOiJIUzI1NiJ9 --></body></html>'
        response = _make_response(html, url="https://example.com:443/")

        scanner = ContentScanner()
        findings = scanner.scan(https_target, http_response=response)

        comments = [f for f in findings if f.finding_type == "sensitive_comment"]
        assert len(comments) >= 1

    def test_detects_credentials_comment(self, https_target):
        """An HTML comment containing 'credentials' should be flagged."""
        from webinspector.modules.content_scanner import ContentScanner

        html = '<html><body><!-- credentials: user/pass123 --></body></html>'
        response = _make_response(html, url="https://example.com:443/")

        scanner = ContentScanner()
        findings = scanner.scan(https_target, http_response=response)

        comments = [f for f in findings if f.finding_type == "sensitive_comment"]
        assert len(comments) >= 1

    def test_detects_key_comment(self, https_target):
        """An HTML comment containing 'key' as a sensitive term should be flagged."""
        from webinspector.modules.content_scanner import ContentScanner

        html = '<html><body><!-- encryption key = AES256KEY --></body></html>'
        response = _make_response(html, url="https://example.com:443/")

        scanner = ContentScanner()
        findings = scanner.scan(https_target, http_response=response)

        comments = [f for f in findings if f.finding_type == "sensitive_comment"]
        assert len(comments) >= 1

    def test_benign_comment_no_finding(self, https_target):
        """
        An HTML comment with benign content (no sensitive keywords) should
        NOT produce a sensitive_comment finding.
        """
        from webinspector.modules.content_scanner import ContentScanner

        html = '<html><body><!-- Navigation menu starts here --></body></html>'
        response = _make_response(html, url="https://example.com:443/")

        scanner = ContentScanner()
        findings = scanner.scan(https_target, http_response=response)

        comments = [f for f in findings if f.finding_type == "sensitive_comment"]
        assert len(comments) == 0


# ===========================================================================
# Tests for error page detection
# ===========================================================================

class TestErrorPageDetection:
    """Verify detection of error pages, stack traces, and debug pages."""

    def test_detects_java_stacktrace(self, https_target):
        """
        A page containing Java stack trace patterns ('at java.', 'at org.',
        'Exception in thread') should produce a MEDIUM error_page finding.
        """
        from webinspector.modules.content_scanner import ContentScanner

        html = """<html><body><pre>
java.lang.NullPointerException
    at org.apache.catalina.connector.CoyoteAdapter.service(CoyoteAdapter.java:367)
    at java.lang.Thread.run(Thread.java:748)
</pre></body></html>"""
        response = _make_response(html, url="https://example.com:443/")

        scanner = ContentScanner()
        findings = scanner.scan(https_target, http_response=response)

        errors = [f for f in findings if f.finding_type == "error_page"]
        assert len(errors) >= 1
        assert errors[0].severity == Severity.MEDIUM

    def test_detects_python_traceback(self, https_target):
        """
        A page containing a Python traceback should produce a MEDIUM
        error_page finding.
        """
        from webinspector.modules.content_scanner import ContentScanner

        html = """<html><body><pre>
Traceback (most recent call last):
  File "/app/views.py", line 42, in index
    result = do_something()
TypeError: unsupported operand type(s)
</pre></body></html>"""
        response = _make_response(html, url="https://example.com:443/")

        scanner = ContentScanner()
        findings = scanner.scan(https_target, http_response=response)

        errors = [f for f in findings if f.finding_type == "error_page"]
        assert len(errors) >= 1
        assert errors[0].severity == Severity.MEDIUM

    def test_detects_php_error(self, https_target):
        """
        A page containing PHP error messages ('Fatal error:', 'Parse error:')
        with file paths should produce a MEDIUM error_page finding.
        """
        from webinspector.modules.content_scanner import ContentScanner

        html = '<html><body>Fatal error: Uncaught Exception in /var/www/html/index.php on line 42</body></html>'
        response = _make_response(html, url="https://example.com:443/")

        scanner = ContentScanner()
        findings = scanner.scan(https_target, http_response=response)

        errors = [f for f in findings if f.finding_type == "error_page"]
        assert len(errors) >= 1
        assert errors[0].severity == Severity.MEDIUM

    def test_detects_aspnet_error(self, https_target):
        """
        A page containing ASP.NET error patterns ('Server Error in',
        'Stack Trace:', 'System.Web.') should produce a MEDIUM error_page finding.
        """
        from webinspector.modules.content_scanner import ContentScanner

        html = """<html><body>
<h1>Server Error in '/' Application.</h1>
<h2>Stack Trace:</h2>
<pre>System.Web.HttpException: The file does not exist.</pre>
</body></html>"""
        response = _make_response(html, url="https://example.com:443/")

        scanner = ContentScanner()
        findings = scanner.scan(https_target, http_response=response)

        errors = [f for f in findings if f.finding_type == "error_page"]
        assert len(errors) >= 1
        assert errors[0].severity == Severity.MEDIUM

    def test_detects_django_debug(self, https_target):
        """
        A Django debug page ('Django Version:', 'DJANGO_SETTINGS_MODULE')
        should produce a MEDIUM error_page finding.
        """
        from webinspector.modules.content_scanner import ContentScanner

        html = """<html><body>
<h1>TemplateSyntaxError</h1>
<table>
<tr><td>Django Version:</td><td>4.2.1</td></tr>
<tr><td>DJANGO_SETTINGS_MODULE</td><td>myapp.settings</td></tr>
</table>
</body></html>"""
        response = _make_response(html, url="https://example.com:443/")

        scanner = ContentScanner()
        findings = scanner.scan(https_target, http_response=response)

        errors = [f for f in findings if f.finding_type == "error_page"]
        assert len(errors) >= 1
        assert errors[0].severity == Severity.MEDIUM

    def test_detects_sql_error(self, https_target):
        """
        A page with SQL error messages ('SQL syntax', 'mysql_', 'ORA-',
        'PostgreSQL') should produce a MEDIUM error_page finding.
        """
        from webinspector.modules.content_scanner import ContentScanner

        html = '<html><body>You have an error in your SQL syntax; check the manual near line 1</body></html>'
        response = _make_response(html, url="https://example.com:443/")

        scanner = ContentScanner()
        findings = scanner.scan(https_target, http_response=response)

        errors = [f for f in findings if f.finding_type == "error_page"]
        assert len(errors) >= 1
        assert errors[0].severity == Severity.MEDIUM

    def test_detects_directory_listing(self, https_target):
        """
        A page with 'Index of /' and 'Parent Directory' patterns indicates
        directory listing.  Should produce a MEDIUM error_page finding.
        """
        from webinspector.modules.content_scanner import ContentScanner

        html = """<html><body>
<h1>Index of /uploads</h1>
<a href="?C=N;O=D">Name</a>
<a href="../">Parent Directory</a>
<a href="secret.txt">secret.txt</a>
</body></html>"""
        response = _make_response(html, url="https://example.com:443/")

        scanner = ContentScanner()
        findings = scanner.scan(https_target, http_response=response)

        errors = [f for f in findings if f.finding_type == "error_page"]
        assert len(errors) >= 1
        assert errors[0].severity == Severity.MEDIUM

    def test_no_error_page_no_finding(self, https_target):
        """
        A normal page with no error patterns should NOT produce an
        error_page finding.
        """
        from webinspector.modules.content_scanner import ContentScanner

        html = _make_clean_html()
        response = _make_response(html, url="https://example.com:443/")

        scanner = ContentScanner()
        findings = scanner.scan(https_target, http_response=response)

        errors = [f for f in findings if f.finding_type == "error_page"]
        assert len(errors) == 0


# ===========================================================================
# Tests for default page detection
# ===========================================================================

class TestDefaultPageDetection:
    """Verify detection of default web server pages."""

    def test_detects_apache_default(self, https_target):
        """
        The Apache default page ('It works!' or 'Apache2 Default Page')
        should produce a LOW default_page finding.
        """
        from webinspector.modules.content_scanner import ContentScanner

        html = '<html><body><h1>Apache2 Ubuntu Default Page</h1><p>It works!</p></body></html>'
        response = _make_response(html, url="https://example.com:443/")

        scanner = ContentScanner()
        findings = scanner.scan(https_target, http_response=response)

        defaults = [f for f in findings if f.finding_type == "default_page"]
        assert len(defaults) >= 1
        assert defaults[0].severity == Severity.LOW

    def test_detects_nginx_default(self, https_target):
        """
        The nginx default page should produce a LOW default_page finding.
        """
        from webinspector.modules.content_scanner import ContentScanner

        html = '<html><head><title>Welcome to nginx!</title></head><body><h1>Welcome to nginx!</h1></body></html>'
        response = _make_response(html, url="https://example.com:443/")

        scanner = ContentScanner()
        findings = scanner.scan(https_target, http_response=response)

        defaults = [f for f in findings if f.finding_type == "default_page"]
        assert len(defaults) >= 1
        assert defaults[0].severity == Severity.LOW

    def test_detects_iis_default(self, https_target):
        """
        The IIS default page should produce a LOW default_page finding.
        """
        from webinspector.modules.content_scanner import ContentScanner

        html = '<html><body><img src="iisstart.png" alt="IIS"><h1>Internet Information Services</h1></body></html>'
        response = _make_response(html, url="https://example.com:443/")

        scanner = ContentScanner()
        findings = scanner.scan(https_target, http_response=response)

        defaults = [f for f in findings if f.finding_type == "default_page"]
        assert len(defaults) >= 1
        assert defaults[0].severity == Severity.LOW

    def test_normal_page_no_default_finding(self, https_target):
        """
        A normal page should NOT produce a default_page finding.
        """
        from webinspector.modules.content_scanner import ContentScanner

        html = _make_clean_html()
        response = _make_response(html, url="https://example.com:443/")

        scanner = ContentScanner()
        findings = scanner.scan(https_target, http_response=response)

        defaults = [f for f in findings if f.finding_type == "default_page"]
        assert len(defaults) == 0


# ===========================================================================
# Tests for clean page (no findings)
# ===========================================================================

class TestCleanPage:
    """Verify that a clean page with no issues produces zero findings."""

    def test_clean_page_no_findings(self, https_target):
        """
        A page with only relative/same-origin resources, no IPs, no emails,
        no sensitive comments, and no error patterns should produce zero findings.
        """
        from webinspector.modules.content_scanner import ContentScanner

        html = _make_clean_html()
        response = _make_response(html, url="https://example.com:443/")

        scanner = ContentScanner()
        findings = scanner.scan(https_target, http_response=response)

        assert len(findings) == 0


# ===========================================================================
# Tests for multiple findings in a single scan
# ===========================================================================

class TestMultipleFindings:
    """Verify that multiple issues on a single page are all reported."""

    def test_page_with_many_issues(self, https_target):
        """
        A page that has mixed content, missing SRI, internal IPs, emails,
        sensitive comments, and error patterns should produce findings
        for each category.
        """
        from webinspector.modules.content_scanner import ContentScanner

        html = """<html>
<head>
    <script src="http://cdn.evil.com/malware.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/lodash@4.17.21/lodash.min.js"></script>
</head>
<body>
    <!-- TODO: remove hardcoded password before release -->
    <img src="http://images.example.com/photo.jpg">
    <p>Backend: 10.0.1.50</p>
    <p>Contact: admin@internal.corp</p>
    <pre>Traceback (most recent call last):
  File "/app/views.py", line 42, in index
    result = do_something()
</pre>
</body></html>"""
        response = _make_response(html, url="https://example.com:443/")

        scanner = ContentScanner()
        findings = scanner.scan(https_target, http_response=response)

        types = {f.finding_type for f in findings}

        # Should have findings for multiple categories.
        assert "mixed_content_active" in types
        assert "mixed_content_passive" in types
        assert "missing_sri" in types
        assert "internal_ip_disclosure" in types
        assert "email_disclosure" in types
        assert "sensitive_comment" in types
        assert "error_page" in types

    def test_all_findings_have_correct_module(self, https_target):
        """Every finding should have module='content'."""
        from webinspector.modules.content_scanner import ContentScanner

        html = """<html><body>
<!-- TODO: fix this -->
<p>admin@example.com</p>
<p>10.0.1.50</p>
</body></html>"""
        response = _make_response(html, url="https://example.com:443/")

        scanner = ContentScanner()
        findings = scanner.scan(https_target, http_response=response)

        assert len(findings) >= 2
        for finding in findings:
            assert finding.module == "content"
            assert finding.target is https_target

    def test_all_findings_have_titles_and_details(self, https_target):
        """Every finding should have non-empty title and detail."""
        from webinspector.modules.content_scanner import ContentScanner

        html = """<html><body>
<!-- password: admin123 -->
<p>support@example.com</p>
<p>192.168.1.1</p>
</body></html>"""
        response = _make_response(html, url="https://example.com:443/")

        scanner = ContentScanner()
        findings = scanner.scan(https_target, http_response=response)

        for finding in findings:
            assert len(finding.title) > 0
            assert len(finding.detail) > 0


# ===========================================================================
# Tests for module registration
# ===========================================================================

class TestContentScannerRegistration:
    """Verify that importing the module registers it."""

    def test_module_registers(self):
        """
        Importing content_scanner should call register_module() at the
        bottom of the file, making it discoverable by the module registry.
        """
        from webinspector.modules import _registry
        from webinspector.modules.content_scanner import ContentScanner

        # The module registers itself at import time.
        # Check that an instance of ContentScanner is in the registry.
        content_modules = [m for m in _registry if m.name == "content"]
        assert len(content_modules) >= 1
        assert isinstance(content_modules[0], ContentScanner)
