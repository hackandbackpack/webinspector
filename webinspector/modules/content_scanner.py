"""
webinspector.modules.content_scanner - HTML content analysis scanner module.

Parses the HTTP response body to identify security issues embedded in the
HTML content itself, rather than in HTTP headers or transport-layer settings.
This module complements the header_scanner by examining what the server
actually *sends* to the browser, not just how it configures headers.

This module checks the following content-level security issues:

    Mixed Content:
        When an HTTPS page loads sub-resources over plain HTTP, the security
        guarantees of HTTPS are undermined.  Browsers classify mixed content
        as either "active" (can execute code / alter the DOM) or "passive"
        (display-only content).

        Active mixed content (MEDIUM):
            - <script src="http://...">   -- can execute arbitrary JavaScript
            - <link href="http://...">    -- CSS can execute via expressions
            - <iframe src="http://...">   -- can run scripts in the frame

        Passive mixed content (LOW):
            - <img src="http://...">      -- can be tampered but not execute code
            - <audio src="http://...">    -- media can be intercepted
            - <video src="http://...">    -- media can be intercepted

    Missing Subresource Integrity (SRI) (LOW):
        External scripts and stylesheets loaded from CDNs or third-party
        origins should include an "integrity" attribute containing a
        cryptographic hash of the expected content.  Without SRI, a
        compromised CDN or MITM attacker can inject malicious code.
        Only flagged for cross-origin resources (different hostname from
        the page's origin).

    Internal IP Disclosure (LOW):
        RFC 1918 private IP addresses (10.0.0.0/8, 172.16.0.0/12,
        192.168.0.0/16) found in the response body indicate potential
        information disclosure about internal network topology.

    Email Address Disclosure (INFORMATIONAL):
        Email addresses found in the response body can be harvested for
        phishing and spam campaigns.  This is informational because many
        sites intentionally display contact emails.

    Sensitive HTML Comments (INFORMATIONAL):
        HTML comments containing keywords like TODO, FIXME, password, key,
        secret, token, api_key, or credentials may reveal development notes,
        hardcoded secrets, or internal implementation details that should
        not be exposed in production.

    Error Page Detection:
        Stack traces, debug pages, and verbose error messages reveal
        internal implementation details (file paths, class names, database
        structure) that assist attackers in crafting targeted exploits.

        Stack traces / debug pages (MEDIUM):
            - Java:    "at java.", "at org.", "Exception in thread", "java.lang."
            - Python:  "Traceback (most recent call last)", "File \"", "line \\d+"
            - PHP:     "Fatal error:", "Parse error:", "Warning:" (with file path)
            - ASP.NET: "Server Error in", "Stack Trace:", "System.Web."
            - Django:  "Django Version:", "Traceback:", "DJANGO_SETTINGS_MODULE"
            - SQL:     "SQL syntax", "mysql_", "ORA-", "PostgreSQL", "ODBC", "SQLite"
            - Directory listing: "Index of /", "Parent Directory"

        Default server pages (LOW):
            - Apache default page ("Apache2 Default Page", "It works!")
            - nginx default page ("Welcome to nginx!")
            - IIS default page ("Internet Information Services")

This module uses html.parser from the Python standard library for HTML
parsing.  No external dependency on BeautifulSoup is required.

Author: Red Siege Information Security
"""

import logging
import re
from html.parser import HTMLParser
from typing import Optional
from urllib.parse import urlparse

from requests import Response

from webinspector.core.target import Target
from webinspector.core.result import Finding, Severity
from webinspector.modules.base import ScanModule
from webinspector.modules import register_module

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants — sensitive keywords for HTML comment scanning
# ---------------------------------------------------------------------------

# Keywords that indicate a potentially sensitive HTML comment.  These are
# matched case-insensitively against the text inside HTML comments.
# Each keyword suggests that the comment may contain development notes,
# hardcoded credentials, or internal implementation details.
_SENSITIVE_COMMENT_KEYWORDS = [
    "todo",
    "fixme",
    "password",
    "key",
    "secret",
    "token",
    "api_key",
    "credentials",
]


# ---------------------------------------------------------------------------
# Constants — error page detection patterns
# ---------------------------------------------------------------------------

# Each tuple is (compiled_regex, description_string).
# Patterns are checked against the full response body text.
# We compile them once at import time for efficiency.
#
# These are ordered by specificity — more specific patterns first to produce
# the most accurate description in findings.

_ERROR_PAGE_PATTERNS: list[tuple[re.Pattern, str]] = [
    # ---- Java stack traces ----
    # Java exceptions include "at package.Class.method(File.java:line)"
    (re.compile(r"at\s+(?:java|org|com)\.\S+\.\S+\(", re.IGNORECASE),
     "Java stack trace detected"),
    (re.compile(r"Exception\s+in\s+thread", re.IGNORECASE),
     "Java exception detected"),
    (re.compile(r"java\.lang\.\w+Exception", re.IGNORECASE),
     "Java exception detected"),

    # ---- Python tracebacks ----
    # Python's standard traceback format: "Traceback (most recent call last):"
    (re.compile(r"Traceback\s+\(most\s+recent\s+call\s+last\)", re.IGNORECASE),
     "Python traceback detected"),

    # ---- PHP errors ----
    # PHP error messages include the error type and file path.
    (re.compile(r"Fatal\s+error\s*:.*(?:/|\\)\S+\.php", re.IGNORECASE),
     "PHP fatal error detected"),
    (re.compile(r"Parse\s+error\s*:.*(?:/|\\)\S+\.php", re.IGNORECASE),
     "PHP parse error detected"),

    # ---- ASP.NET errors ----
    # ASP.NET detailed error pages include "Server Error in '/' Application"
    # and "Stack Trace:" sections with System.Web namespace references.
    (re.compile(r"Server\s+Error\s+in\s+['\"]", re.IGNORECASE),
     "ASP.NET error page detected"),
    (re.compile(r"Stack\s+Trace\s*:", re.IGNORECASE),
     "Stack trace detected"),
    (re.compile(r"System\.Web\.", re.IGNORECASE),
     "ASP.NET error detected"),

    # ---- Django debug page ----
    # Django's DEBUG=True error page includes the Django version and settings.
    (re.compile(r"Django\s+Version\s*:", re.IGNORECASE),
     "Django debug page detected"),
    (re.compile(r"DJANGO_SETTINGS_MODULE", re.IGNORECASE),
     "Django debug page detected"),

    # ---- SQL errors ----
    # SQL error messages from various database engines.  These indicate that
    # raw database errors are being exposed to the user, which may allow
    # SQL injection exploitation.
    (re.compile(r"SQL\s+syntax", re.IGNORECASE),
     "SQL error message detected"),
    (re.compile(r"\bmysql_", re.IGNORECASE),
     "MySQL error detected"),
    (re.compile(r"\bORA-\d+", re.IGNORECASE),
     "Oracle database error detected"),
    (re.compile(r"\bPostgreSQL\b", re.IGNORECASE),
     "PostgreSQL error detected"),
    (re.compile(r"\bODBC\b", re.IGNORECASE),
     "ODBC error detected"),
    (re.compile(r"\bSQLite\b", re.IGNORECASE),
     "SQLite error detected"),

    # ---- Directory listings ----
    # Apache/nginx directory listings contain "Index of /" and "Parent Directory".
    (re.compile(r"Index\s+of\s+/", re.IGNORECASE),
     "Directory listing detected"),
]


# ---------------------------------------------------------------------------
# Constants — default server page detection patterns
# ---------------------------------------------------------------------------

# Patterns for detecting default/unconfigured web server pages.  These are
# less severe than error pages (LOW vs MEDIUM) because they don't reveal
# application internals, but they indicate the server has not been properly
# configured for production use.

_DEFAULT_PAGE_PATTERNS: list[tuple[re.Pattern, str]] = [
    # ---- Apache default page ----
    (re.compile(r"Apache2?\s+(?:Ubuntu\s+)?Default\s+Page", re.IGNORECASE),
     "Apache default page detected"),
    (re.compile(r"<title>\s*Apache2?\s+(?:Ubuntu\s+)?Default\s+Page", re.IGNORECASE),
     "Apache default page detected"),

    # ---- nginx default page ----
    (re.compile(r"Welcome\s+to\s+nginx\s*!", re.IGNORECASE),
     "nginx default page detected"),

    # ---- IIS default page ----
    (re.compile(r"Internet\s+Information\s+Services", re.IGNORECASE),
     "IIS default page detected"),
    (re.compile(r"iisstart\.png", re.IGNORECASE),
     "IIS default page detected"),
]


# ---------------------------------------------------------------------------
# Constants — internal IP address regex
# ---------------------------------------------------------------------------

# Regex to match RFC 1918 private IPv4 addresses:
#   10.0.0.0/8       — 10.0.0.0 to 10.255.255.255
#   172.16.0.0/12    — 172.16.0.0 to 172.31.255.255
#   192.168.0.0/16   — 192.168.0.0 to 192.168.255.255
#
# We use word boundaries (\b) to avoid matching partial numbers like
# "210.0.0.1" (which starts with 10 but is a public IP).  The second
# octet range for 172.x is restricted to 16-31 using alternation.

_INTERNAL_IP_RE = re.compile(
    r"\b("
    r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}"        # 10.x.x.x
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"  # 172.16-31.x.x
    r"|192\.168\.\d{1,3}\.\d{1,3}"           # 192.168.x.x
    r")\b"
)


# ---------------------------------------------------------------------------
# Constants — email address regex
# ---------------------------------------------------------------------------

# A simple but effective email regex.  We don't need RFC 5322 compliance;
# we just need to catch the common patterns that would appear in HTML pages.
# This avoids matching CSS selectors, JavaScript objects, or URL parameters
# that happen to contain @ signs by requiring word characters around the @.

_EMAIL_RE = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)


# ---------------------------------------------------------------------------
# HTML parser — extracts tags, attributes, and comments from HTML
# ---------------------------------------------------------------------------

class _ContentHTMLParser(HTMLParser):
    """
    Custom HTML parser that extracts security-relevant data from HTML.

    This parser collects:
        - Tags with src/href attributes (for mixed content and SRI checks)
        - HTML comments (for sensitive keyword scanning)

    It extends html.parser.HTMLParser from the standard library, which is
    a SAX-style event-driven parser.  We override handle_starttag() to
    capture element attributes and handle_comment() to capture comments.

    The parser is intentionally lenient — it does not raise errors on
    malformed HTML, which is common in real-world web pages.
    """

    def __init__(self):
        """Initialise the parser and set up data collection lists."""
        super().__init__()

        # List of (tag_name, attrs_dict) for tags that have src or href.
        # Example: ("script", {"src": "http://cdn.example.com/app.js"})
        self.resource_tags: list[tuple[str, dict[str, str | None]]] = []

        # List of comment text strings (the content between <!-- and -->).
        self.comments: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        """
        Called for each opening HTML tag.

        We capture tags that have src or href attributes because these are
        the tags that can load external resources (scripts, stylesheets,
        images, iframes, etc.).

        Args:
            tag:   The tag name in lowercase (e.g., "script", "img").
            attrs: List of (attribute_name, attribute_value) tuples.
        """
        # Convert the attrs list to a dict for easier lookup.
        attrs_dict = dict(attrs)

        # Only collect tags that reference external resources.
        if "src" in attrs_dict or "href" in attrs_dict:
            self.resource_tags.append((tag, attrs_dict))

    def handle_comment(self, data: str) -> None:
        """
        Called for each HTML comment (<!-- ... -->).

        We collect all comment text for later keyword scanning.

        Args:
            data: The text content of the comment (without <!-- and -->).
        """
        self.comments.append(data)

    def error(self, message: str) -> None:
        """
        Override the error handler to silently ignore parse errors.

        Real-world HTML is often malformed.  We don't want parsing errors
        to abort the security scan.
        """
        pass


# ---------------------------------------------------------------------------
# ContentScanner module
# ---------------------------------------------------------------------------

class ContentScanner(ScanModule):
    """
    HTML content analysis scanner.

    Examines the HTTP response body for security issues including mixed
    content, missing SRI, internal IP disclosure, email disclosure,
    sensitive HTML comments, error pages, and default server pages.

    Uses html.parser from the Python standard library — no BeautifulSoup
    dependency required.

    Accepts both HTTP and HTTPS targets (the default accepts_target
    behaviour from the base class).  Some checks (mixed content) are
    only relevant for HTTPS pages.
    """

    # -----------------------------------------------------------------
    # ScanModule interface — required properties
    # -----------------------------------------------------------------

    @property
    def name(self) -> str:
        """Short identifier used in CLI flags and finding output."""
        return "content"

    @property
    def description(self) -> str:
        """Human-readable description for --help output."""
        return (
            "HTML content analysis (mixed content, SRI, IP/email disclosure, "
            "error pages)"
        )

    # -----------------------------------------------------------------
    # ScanModule interface — main scan method
    # -----------------------------------------------------------------

    def scan(
        self,
        target: Target,
        http_response: Optional[Response] = None,
    ) -> list[Finding]:
        """
        Analyse the HTTP response body for content-level security issues.

        This method:
            1. Returns empty if http_response is None (target unreachable)
            2. Parses the HTML body using html.parser
            3. Runs each content check in sequence, accumulating findings
            4. Returns the complete list of findings

        Each check is implemented as a separate private method for
        readability, testability, and maintainability.  Checks are
        ordered from most impactful to least impactful:
            a. Mixed content (MEDIUM / LOW)
            b. Missing SRI (LOW)
            c. Internal IP disclosure (LOW)
            d. Email disclosure (INFORMATIONAL)
            e. Sensitive HTML comments (INFORMATIONAL)
            f. Error page detection (MEDIUM)
            g. Default page detection (LOW)

        Args:
            target:        The target being scanned.
            http_response: Pre-fetched requests.Response object.  If None,
                           the target was unreachable and we return empty.

        Returns:
            List of Finding objects.  Empty list means no issues found
            or the target was unreachable.
        """
        # Guard: no response means the target was unreachable.
        # We can't analyse content we don't have.
        if http_response is None:
            logger.debug(
                "No HTTP response for %s, skipping content scan",
                target.hostport,
            )
            return []

        findings: list[Finding] = []

        # Extract the response body text.  This is the full HTML source.
        body = http_response.text

        # Determine the page URL (after any redirects) for scheme detection.
        # The response.url attribute contains the final URL.
        page_url = getattr(http_response, "url", target.url)

        # Parse the HTML body to extract resource tags and comments.
        parser = _ContentHTMLParser()
        try:
            parser.feed(body)
        except Exception:
            # html.parser may raise on severely malformed HTML.
            # Log and continue — we can still do regex-based checks
            # on the raw body text even if parsing fails.
            logger.debug(
                "HTML parse error for %s, continuing with regex-only checks",
                target.hostport,
            )

        # --- Determine if the page is served over HTTPS ---
        # Mixed content checks only apply to HTTPS pages.
        is_https_page = page_url.startswith("https://")

        # --- Extract the page's origin hostname for SRI checks ---
        # SRI is only required for cross-origin resources.
        page_hostname = self._extract_hostname(page_url)

        # --- Run all content checks ---
        # Each check method receives the target, parsed data, and/or raw
        # body text, and returns a list of Finding objects (empty if no issues).

        # Mixed content (only on HTTPS pages).
        if is_https_page:
            findings.extend(
                self._check_mixed_content(target, parser.resource_tags)
            )

        # Missing SRI on external resources.
        findings.extend(
            self._check_missing_sri(target, parser.resource_tags, page_hostname)
        )

        # Internal IP address disclosure in the raw body text.
        findings.extend(self._check_internal_ips(target, body))

        # Email address disclosure in the raw body text.
        findings.extend(self._check_email_disclosure(target, body))

        # Sensitive HTML comments.
        findings.extend(
            self._check_sensitive_comments(target, parser.comments)
        )

        # Error page detection (stack traces, debug pages).
        findings.extend(self._check_error_pages(target, body))

        # Default server page detection.
        findings.extend(self._check_default_pages(target, body))

        return findings

    # -----------------------------------------------------------------
    # Private check methods — mixed content
    # -----------------------------------------------------------------

    def _check_mixed_content(
        self,
        target: Target,
        resource_tags: list[tuple[str, dict[str, str | None]]],
    ) -> list[Finding]:
        """
        Check for mixed content on an HTTPS page.

        Mixed content occurs when an HTTPS page loads sub-resources over
        plain HTTP.  This is classified as either "active" (can execute
        code) or "passive" (display-only).

        Active mixed content tags: script, link, iframe
        Passive mixed content tags: img, audio, video

        Args:
            target:        The target being scanned.
            resource_tags: List of (tag_name, attrs_dict) from the parser.

        Returns:
            List of Finding objects for mixed content issues.
        """
        findings: list[Finding] = []

        # Tags that constitute active mixed content — these can execute code
        # or alter the DOM, so a MITM attacker could inject malicious logic.
        active_tags = {"script", "link", "iframe"}

        # Tags that constitute passive mixed content — display-only resources
        # that can be tampered with (e.g., replacing an image) but cannot
        # execute code.
        passive_tags = {"img", "audio", "video"}

        # Track URLs we've already reported to avoid duplicate findings.
        reported_active: set[str] = set()
        reported_passive: set[str] = set()

        for tag_name, attrs in resource_tags:
            # Get the resource URL from src or href attribute.
            url = attrs.get("src") or attrs.get("href")
            if url is None:
                continue

            # Only flag http:// URLs (not relative, not https://, not data:, etc.).
            if not url.lower().startswith("http://"):
                continue

            # --- Active mixed content ---
            if tag_name in active_tags and url not in reported_active:
                reported_active.add(url)
                findings.append(Finding(
                    module="content",
                    finding_type="mixed_content_active",
                    severity=Severity.MEDIUM,
                    target=target,
                    title="Active Mixed Content",
                    detail=(
                        f"<{tag_name}> loads resource over HTTP on HTTPS page: "
                        f"{url}"
                    ),
                    references=["CWE-311"],
                ))

            # --- Passive mixed content ---
            elif tag_name in passive_tags and url not in reported_passive:
                reported_passive.add(url)
                findings.append(Finding(
                    module="content",
                    finding_type="mixed_content_passive",
                    severity=Severity.LOW,
                    target=target,
                    title="Passive Mixed Content",
                    detail=(
                        f"<{tag_name}> loads resource over HTTP on HTTPS page: "
                        f"{url}"
                    ),
                    references=["CWE-311"],
                ))

        return findings

    # -----------------------------------------------------------------
    # Private check methods — missing SRI
    # -----------------------------------------------------------------

    def _check_missing_sri(
        self,
        target: Target,
        resource_tags: list[tuple[str, dict[str, str | None]]],
        page_hostname: str,
    ) -> list[Finding]:
        """
        Check for external scripts/links missing the integrity attribute.

        Subresource Integrity (SRI) ensures that resources fetched from
        CDNs or third-party origins have not been tampered with.  The
        browser verifies the fetched content against the hash in the
        "integrity" attribute before executing/applying it.

        Only external resources (different hostname from the page) are
        checked.  Same-origin resources don't need SRI because if the
        origin is compromised, the attacker can modify the HTML itself.

        Args:
            target:         The target being scanned.
            resource_tags:  List of (tag_name, attrs_dict) from the parser.
            page_hostname:  The hostname of the page being scanned.

        Returns:
            List of Finding objects for missing SRI.
        """
        findings: list[Finding] = []

        # Tags that support the integrity attribute.
        sri_tags = {"script", "link"}

        # Track URLs we've already reported to avoid duplicate findings.
        reported: set[str] = set()

        for tag_name, attrs in resource_tags:
            # Only check script and link tags.
            if tag_name not in sri_tags:
                continue

            # Get the resource URL.
            url = attrs.get("src") or attrs.get("href")
            if url is None:
                continue

            # Skip relative URLs and same-origin resources.
            # SRI is only meaningful for cross-origin resources.
            if not url.startswith("http://") and not url.startswith("https://"):
                # Relative URL — same origin by definition.
                continue

            # Extract the hostname of the resource.
            resource_hostname = self._extract_hostname(url)

            # Skip same-origin resources.
            if resource_hostname == page_hostname:
                continue

            # Check if the integrity attribute is present.
            if "integrity" in attrs:
                # SRI is present — no issue.
                continue

            # External resource without SRI.
            if url not in reported:
                reported.add(url)
                findings.append(Finding(
                    module="content",
                    finding_type="missing_sri",
                    severity=Severity.LOW,
                    target=target,
                    title="Missing Subresource Integrity (SRI)",
                    detail=(
                        f"External <{tag_name}> from {resource_hostname} "
                        f"lacks integrity attribute: {url}"
                    ),
                    references=["CWE-353"],
                ))

        return findings

    # -----------------------------------------------------------------
    # Private check methods — internal IP disclosure
    # -----------------------------------------------------------------

    def _check_internal_ips(
        self, target: Target, body: str
    ) -> list[Finding]:
        """
        Check for RFC 1918 internal IP addresses in the response body.

        Private IP addresses in public-facing pages reveal internal network
        topology information that can help attackers map the target's
        infrastructure and identify potential pivot points.

        RFC 1918 ranges:
            10.0.0.0/8       — Class A private
            172.16.0.0/12    — Class B private
            192.168.0.0/16   — Class C private

        Args:
            target: The target being scanned.
            body:   The raw response body text.

        Returns:
            List of Finding objects for internal IP disclosure.
        """
        findings: list[Finding] = []

        # Find all RFC 1918 IP addresses in the body.
        matches = _INTERNAL_IP_RE.findall(body)

        if matches:
            # Deduplicate the matches while preserving order.
            unique_ips = list(dict.fromkeys(matches))

            findings.append(Finding(
                module="content",
                finding_type="internal_ip_disclosure",
                severity=Severity.LOW,
                target=target,
                title="Internal IP Address Disclosure",
                detail=(
                    f"RFC 1918 private IP address(es) found in response body: "
                    f"{', '.join(unique_ips)}"
                ),
                references=["CWE-200"],
            ))

        return findings

    # -----------------------------------------------------------------
    # Private check methods — email disclosure
    # -----------------------------------------------------------------

    def _check_email_disclosure(
        self, target: Target, body: str
    ) -> list[Finding]:
        """
        Check for email addresses in the response body.

        Email addresses can be harvested by spammers and used in targeted
        phishing campaigns.  While many sites intentionally display contact
        emails, this finding provides an inventory for the security analyst.

        Args:
            target: The target being scanned.
            body:   The raw response body text.

        Returns:
            List of Finding objects for email disclosure.
        """
        findings: list[Finding] = []

        # Find all email addresses in the body.
        matches = _EMAIL_RE.findall(body)

        if matches:
            # Deduplicate the matches while preserving order.
            unique_emails = list(dict.fromkeys(matches))

            findings.append(Finding(
                module="content",
                finding_type="email_disclosure",
                severity=Severity.INFORMATIONAL,
                target=target,
                title="Email Address Disclosure",
                detail=(
                    f"Email address(es) found in response body: "
                    f"{', '.join(unique_emails)}"
                ),
                references=["CWE-200"],
            ))

        return findings

    # -----------------------------------------------------------------
    # Private check methods — sensitive HTML comments
    # -----------------------------------------------------------------

    def _check_sensitive_comments(
        self, target: Target, comments: list[str]
    ) -> list[Finding]:
        """
        Check HTML comments for sensitive keywords.

        Development comments containing keywords like TODO, FIXME, password,
        secret, token, etc. may reveal implementation details, hardcoded
        credentials, or internal notes that should not be exposed in
        production.

        Args:
            target:   The target being scanned.
            comments: List of HTML comment text strings from the parser.

        Returns:
            List of Finding objects for sensitive comments.
        """
        findings: list[Finding] = []

        for comment_text in comments:
            # Check each comment against all sensitive keywords.
            comment_lower = comment_text.lower()

            matched_keywords: list[str] = []
            for keyword in _SENSITIVE_COMMENT_KEYWORDS:
                if keyword in comment_lower:
                    matched_keywords.append(keyword)

            if matched_keywords:
                # Truncate the comment for the finding detail to avoid
                # excessively long output.
                truncated = comment_text.strip()
                if len(truncated) > 200:
                    truncated = truncated[:200] + "..."

                findings.append(Finding(
                    module="content",
                    finding_type="sensitive_comment",
                    severity=Severity.INFORMATIONAL,
                    target=target,
                    title="Sensitive HTML Comment",
                    detail=(
                        f"HTML comment contains sensitive keyword(s) "
                        f"[{', '.join(matched_keywords)}]: "
                        f"<!-- {truncated} -->"
                    ),
                    references=["CWE-615"],
                ))

        return findings

    # -----------------------------------------------------------------
    # Private check methods — error page detection
    # -----------------------------------------------------------------

    def _check_error_pages(
        self, target: Target, body: str
    ) -> list[Finding]:
        """
        Check for error pages, stack traces, and debug pages.

        Verbose error messages reveal internal implementation details
        (file paths, class names, database structure, framework versions)
        that help attackers craft targeted exploits.

        Args:
            target: The target being scanned.
            body:   The raw response body text.

        Returns:
            List of Finding objects for error pages detected.
        """
        findings: list[Finding] = []

        # Track which error descriptions we've already reported to avoid
        # producing multiple findings for the same type of error.
        reported_descriptions: set[str] = set()

        for pattern, description in _ERROR_PAGE_PATTERNS:
            if description in reported_descriptions:
                continue

            if pattern.search(body):
                reported_descriptions.add(description)
                findings.append(Finding(
                    module="content",
                    finding_type="error_page",
                    severity=Severity.MEDIUM,
                    target=target,
                    title="Error Page / Stack Trace Detected",
                    detail=description,
                    references=["CWE-209"],
                ))

        return findings

    # -----------------------------------------------------------------
    # Private check methods — default page detection
    # -----------------------------------------------------------------

    def _check_default_pages(
        self, target: Target, body: str
    ) -> list[Finding]:
        """
        Check for default web server pages.

        Default pages indicate the server has not been properly configured
        for production use.  While not a direct vulnerability, they confirm
        the server software and may indicate that the administrator has not
        applied security hardening.

        Args:
            target: The target being scanned.
            body:   The raw response body text.

        Returns:
            List of Finding objects for default pages detected.
        """
        findings: list[Finding] = []

        # Track which default page descriptions we've already reported.
        reported_descriptions: set[str] = set()

        for pattern, description in _DEFAULT_PAGE_PATTERNS:
            if description in reported_descriptions:
                continue

            if pattern.search(body):
                reported_descriptions.add(description)
                findings.append(Finding(
                    module="content",
                    finding_type="default_page",
                    severity=Severity.LOW,
                    target=target,
                    title="Default Server Page Detected",
                    detail=description,
                    references=["CWE-200"],
                ))

        return findings

    # -----------------------------------------------------------------
    # Private helper methods
    # -----------------------------------------------------------------

    def _extract_hostname(self, url: str) -> str:
        """
        Extract the hostname from a URL string.

        Uses urllib.parse.urlparse for robust URL parsing.  Returns an
        empty string if the URL cannot be parsed.

        Args:
            url: The URL string to parse.

        Returns:
            The hostname portion of the URL, or empty string on failure.
        """
        try:
            parsed = urlparse(url)
            return parsed.hostname or ""
        except Exception:
            return ""


# ---------------------------------------------------------------------------
# Module registration
# ---------------------------------------------------------------------------
# Instantiate the scanner and register it with the module registry.
# This runs at import time, so importing this file is sufficient to make
# the content scanner available to the orchestrator.

register_module(ContentScanner())
