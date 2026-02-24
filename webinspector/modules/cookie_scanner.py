"""
webinspector.modules.cookie_scanner - Cookie security attribute scanner module.

Examines HTTP response Set-Cookie headers for missing or misconfigured
security attributes.  Cookies are one of the primary mechanisms for
maintaining session state in web applications, so their security flags
directly affect the application's resistance to session hijacking, XSS,
and CSRF attacks.

This module checks the following cookie security attributes:

    Missing Secure flag:
        - On session cookie (MEDIUM) -- session token sent over plain HTTP
        - On regular cookie (LOW) -- less sensitive data exposed

    Missing HttpOnly flag:
        - On session cookie (MEDIUM) -- session token accessible via JavaScript
        - On regular cookie (LOW) -- data exposed to XSS

    Missing SameSite attribute:
        - Any cookie (LOW) -- browser default may vary; explicit is safer

    SameSite=None without Secure:
        - Any cookie (MEDIUM) -- modern browsers reject this combination;
          indicates misconfiguration

    Persistent session cookie:
        - Session cookie with Expires or Max-Age (LOW) -- session token
          survives browser restart, widening the attack window

Session cookie detection uses name pattern matching against well-known
session cookie names from common web frameworks:

    JSESSIONID          -- Java (Servlet, Spring, Tomcat)
    PHPSESSID           -- PHP
    ASP.NET_SessionId   -- ASP.NET
    connect.sid         -- Node.js (Express with connect-session)
    laravel_session     -- PHP (Laravel)
    CFID                -- ColdFusion
    CFTOKEN             -- ColdFusion
    ci_session          -- PHP (CodeIgniter)
    rack.session        -- Ruby (Rack)
    _session_id         -- Ruby on Rails
    express.sid         -- Node.js (Express)
    PLAY_SESSION        -- Scala/Java (Play Framework)
    sessionid           -- Django (default name)
    session_id          -- Generic session ID pattern

Parsing approach:
    The requests library's response.headers is a CaseInsensitiveDict that
    merges duplicate headers with ", " -- but Set-Cookie values can contain
    commas (e.g., in Expires dates like "Thu, 01 Jan 2099 00:00:00 GMT"),
    making this merged string unreliable for parsing.

    To get individual Set-Cookie headers, we use:
        response.raw.headers.getlist("Set-Cookie")
    which accesses the underlying urllib3 response and returns each
    Set-Cookie header as a separate string without merging.

    If response.raw is unavailable (e.g., in some mock or proxy scenarios),
    we fall back to response.headers.get("Set-Cookie") and treat it as a
    single cookie string.

    Each raw Set-Cookie header is parsed by splitting on ";" to extract
    the cookie name and its attributes.  Attribute matching is done
    case-insensitively per RFC 6265 Section 5.2.

Author: Red Siege Information Security
"""

import logging
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

# Well-known session cookie names from common web frameworks.
# These names are used to determine whether a cookie is a session cookie,
# which affects the severity of missing security flags (MEDIUM for session
# cookies vs. LOW for regular cookies).
#
# The set contains lowercase versions for case-insensitive matching.
# We compare the actual cookie name lowercased against this set.
_SESSION_COOKIE_NAMES = {
    "jsessionid",         # Java (Servlet, Spring, Tomcat)
    "phpsessid",          # PHP
    "asp.net_sessionid",  # ASP.NET
    "connect.sid",        # Node.js (Express with connect-session)
    "laravel_session",    # PHP (Laravel)
    "cfid",               # ColdFusion
    "cftoken",            # ColdFusion
    "ci_session",         # PHP (CodeIgniter)
    "rack.session",       # Ruby (Rack)
    "_session_id",        # Ruby on Rails
    "express.sid",        # Node.js (Express)
    "play_session",       # Scala/Java (Play Framework)
    "sessionid",          # Django (default name)
    "session_id",         # Generic session ID pattern
}


class CookieScanner(ScanModule):
    """
    Cookie security attribute scanner.

    Examines Set-Cookie headers in the HTTP response for missing or
    misconfigured security attributes (Secure, HttpOnly, SameSite).
    Also detects persistent session cookies that have Expires or Max-Age
    set, which increases the window for session hijacking attacks.

    Uses the pre-fetched requests.Response object provided by the
    orchestrator -- does NOT make its own HTTP requests.

    Accepts both HTTP and HTTPS targets (the default accepts_target
    behaviour from the base class).
    """

    # -----------------------------------------------------------------
    # ScanModule interface -- required properties
    # -----------------------------------------------------------------

    @property
    def name(self) -> str:
        """Short identifier used in CLI flags and finding output."""
        return "cookies"

    @property
    def description(self) -> str:
        """Human-readable description for --help output."""
        return "Cookie security attribute analysis (Secure, HttpOnly, SameSite)"

    # -----------------------------------------------------------------
    # ScanModule interface -- main scan method
    # -----------------------------------------------------------------

    def scan(
        self,
        target: Target,
        http_response: Optional[Response] = None,
    ) -> list[Finding]:
        """
        Analyse Set-Cookie headers for security issues.

        This method:
            1. Returns empty if http_response is None (target unreachable)
            2. Extracts all Set-Cookie headers from the response
            3. Parses each cookie and checks its security attributes
            4. Returns the complete list of findings

        Each cookie is checked for:
            a. Missing Secure flag
            b. Missing HttpOnly flag
            c. Missing SameSite attribute
            d. SameSite=None without Secure flag
            e. Persistent session cookie (Expires/Max-Age on session cookie)

        Args:
            target:        The target being scanned.
            http_response: Pre-fetched requests.Response object.  If None,
                           the target was unreachable and we return empty.

        Returns:
            List of Finding objects.  Empty list means no issues found
            or the target was unreachable.
        """
        # Guard: no response means the target was unreachable.
        # We can't analyse cookies we don't have.
        if http_response is None:
            logger.debug(
                "No HTTP response for %s, skipping cookie scan",
                target.hostport,
            )
            return []

        findings: list[Finding] = []

        # --- Extract raw Set-Cookie headers ---
        # We need individual Set-Cookie strings, not the merged version
        # from response.headers (which joins them with ", " and breaks
        # cookie parsing when values contain commas).
        raw_cookies = self._extract_raw_cookies(http_response)

        # If no Set-Cookie headers are present, there's nothing to check.
        if not raw_cookies:
            logger.debug(
                "No Set-Cookie headers for %s, skipping cookie scan",
                target.hostport,
            )
            return []

        # --- Analyse each cookie individually ---
        for raw_cookie in raw_cookies:
            # Parse the cookie string into its name and attribute dict.
            cookie_name, attrs = self._parse_cookie(raw_cookie)

            # Skip cookies we couldn't parse (empty or malformed).
            if not cookie_name:
                logger.debug(
                    "Skipping unparseable Set-Cookie header: %s",
                    raw_cookie[:80],
                )
                continue

            # Determine if this is a session cookie (affects severity).
            is_session = self._is_session_cookie(cookie_name)

            # Run all attribute checks on this cookie.
            findings.extend(
                self._check_secure_flag(target, cookie_name, attrs, is_session)
            )
            findings.extend(
                self._check_httponly_flag(target, cookie_name, attrs, is_session)
            )
            findings.extend(
                self._check_samesite(target, cookie_name, attrs)
            )
            findings.extend(
                self._check_samesite_none_without_secure(
                    target, cookie_name, attrs
                )
            )
            findings.extend(
                self._check_persistent_session(
                    target, cookie_name, attrs, is_session
                )
            )

        return findings

    # -----------------------------------------------------------------
    # Cookie extraction from the HTTP response
    # -----------------------------------------------------------------

    def _extract_raw_cookies(self, response) -> list[str]:
        """
        Extract individual Set-Cookie header strings from the response.

        The primary approach uses response.raw.headers.getlist("Set-Cookie")
        to get each Set-Cookie header as a separate string without merging.
        This avoids the comma-splitting problem with the requests library's
        merged header approach.

        Falls back to response.headers.get("Set-Cookie") as a single
        string if the raw headers are unavailable.

        Args:
            response: The requests.Response (or mock) object.

        Returns:
            List of raw Set-Cookie header strings, one per cookie.
        """
        raw_cookies = []

        # Primary path: use response.raw.headers.getlist() to get
        # individual Set-Cookie headers without merging.
        if (
            hasattr(response, "raw")
            and response.raw is not None
            and hasattr(response.raw, "headers")
            and response.raw.headers is not None
            and hasattr(response.raw.headers, "getlist")
        ):
            raw_cookies = response.raw.headers.getlist("Set-Cookie")

        # Fallback path: use the merged Set-Cookie header from
        # response.headers.  This may be unreliable for cookies with
        # commas in their values, but it's better than nothing.
        if not raw_cookies:
            cookie_header = ""
            # Use .get() for both CaseInsensitiveDict and plain dict.
            if hasattr(response, "headers") and response.headers:
                cookie_header = response.headers.get("Set-Cookie", "")
            if cookie_header:
                raw_cookies = [cookie_header]

        return raw_cookies

    # -----------------------------------------------------------------
    # Cookie string parsing
    # -----------------------------------------------------------------

    def _parse_cookie(self, raw_cookie: str) -> tuple[str, dict[str, str]]:
        """
        Parse a raw Set-Cookie header string into a cookie name and
        attribute dictionary.

        Set-Cookie format (RFC 6265):
            name=value; attr1; attr2=val2; attr3

        The first token before ";" is the name=value pair.  Subsequent
        tokens are attributes.  Attributes can be:
            - Flag-only: "Secure", "HttpOnly" (no value)
            - Key=value: "SameSite=Strict", "Path=/", "Max-Age=3600"

        Attribute names are normalised to lowercase for case-insensitive
        matching per RFC 6265 Section 5.2.

        Args:
            raw_cookie: The raw Set-Cookie header string.

        Returns:
            A tuple of (cookie_name, attrs_dict) where:
            - cookie_name is the name portion of the name=value pair
            - attrs_dict maps lowercase attribute names to their values
              (empty string for flag-only attributes like Secure, HttpOnly)
        """
        # Split the cookie string on ";" to separate name=value from attributes.
        parts = [p.strip() for p in raw_cookie.split(";")]

        # The first part should be the name=value pair.
        if not parts or not parts[0]:
            return ("", {})

        name_value = parts[0]

        # Extract the cookie name from the name=value pair.
        # The name is everything before the first "=".
        if "=" in name_value:
            cookie_name = name_value.split("=", 1)[0].strip()
        else:
            # Malformed cookie without "=" -- use the whole first part as name.
            cookie_name = name_value.strip()

        # Parse remaining parts as attributes.
        attrs: dict[str, str] = {}
        for part in parts[1:]:
            part = part.strip()
            if not part:
                continue

            if "=" in part:
                # Key=value attribute (e.g., "SameSite=Strict", "Max-Age=3600").
                attr_name, attr_value = part.split("=", 1)
                attrs[attr_name.strip().lower()] = attr_value.strip()
            else:
                # Flag-only attribute (e.g., "Secure", "HttpOnly").
                attrs[part.strip().lower()] = ""

        return (cookie_name, attrs)

    # -----------------------------------------------------------------
    # Session cookie detection
    # -----------------------------------------------------------------

    def _is_session_cookie(self, cookie_name: str) -> bool:
        """
        Determine if a cookie is a session cookie based on its name.

        Session cookies contain authentication/session tokens and are
        more sensitive than regular cookies.  Missing security flags on
        session cookies are rated higher severity (MEDIUM vs. LOW).

        Detection is based on case-insensitive matching against a set of
        well-known session cookie names from common web frameworks.

        Args:
            cookie_name: The name of the cookie to check.

        Returns:
            True if the cookie name matches a known session cookie pattern.
        """
        return cookie_name.lower() in _SESSION_COOKIE_NAMES

    # -----------------------------------------------------------------
    # Private check methods -- Missing Secure flag
    # -----------------------------------------------------------------

    def _check_secure_flag(
        self,
        target: Target,
        cookie_name: str,
        attrs: dict[str, str],
        is_session: bool,
    ) -> list[Finding]:
        """
        Check for missing Secure flag on a cookie.

        The Secure flag instructs the browser to only send the cookie
        over HTTPS connections.  Without it, the cookie is sent over
        plain HTTP, allowing attackers on the network to intercept
        session tokens via passive sniffing.

        Severity:
            - Session cookie: MEDIUM (session hijacking via network sniffing)
            - Regular cookie: LOW (less sensitive data exposed)

        Args:
            target:      The target being scanned.
            cookie_name: The name of the cookie.
            attrs:       Parsed cookie attributes (lowercase keys).
            is_session:  Whether this is a session cookie.

        Returns:
            List with one Finding if Secure is missing, empty otherwise.
        """
        findings: list[Finding] = []

        # Check if the Secure flag is present in the attributes.
        # The Secure flag is a flag-only attribute (no value needed).
        if "secure" not in attrs:
            severity = Severity.MEDIUM if is_session else Severity.LOW
            cookie_type = "session" if is_session else "regular"

            findings.append(Finding(
                module="cookies",
                finding_type="missing_secure_flag",
                severity=severity,
                target=target,
                title="Cookie Missing Secure Flag",
                detail=(
                    f"Cookie '{cookie_name}' ({cookie_type}) does not have "
                    f"the Secure flag set. Without Secure, the cookie is "
                    f"sent over unencrypted HTTP connections, allowing "
                    f"interception via network sniffing"
                ),
                references=["CWE-614"],
            ))

        return findings

    # -----------------------------------------------------------------
    # Private check methods -- Missing HttpOnly flag
    # -----------------------------------------------------------------

    def _check_httponly_flag(
        self,
        target: Target,
        cookie_name: str,
        attrs: dict[str, str],
        is_session: bool,
    ) -> list[Finding]:
        """
        Check for missing HttpOnly flag on a cookie.

        The HttpOnly flag prevents JavaScript from accessing the cookie
        via document.cookie.  Without it, a cross-site scripting (XSS)
        attack can steal the cookie value and send it to an attacker-
        controlled server.

        Severity:
            - Session cookie: MEDIUM (XSS leads directly to session theft)
            - Regular cookie: LOW (less sensitive data exposed to XSS)

        Args:
            target:      The target being scanned.
            cookie_name: The name of the cookie.
            attrs:       Parsed cookie attributes (lowercase keys).
            is_session:  Whether this is a session cookie.

        Returns:
            List with one Finding if HttpOnly is missing, empty otherwise.
        """
        findings: list[Finding] = []

        # Check if the HttpOnly flag is present in the attributes.
        if "httponly" not in attrs:
            severity = Severity.MEDIUM if is_session else Severity.LOW
            cookie_type = "session" if is_session else "regular"

            findings.append(Finding(
                module="cookies",
                finding_type="missing_httponly_flag",
                severity=severity,
                target=target,
                title="Cookie Missing HttpOnly Flag",
                detail=(
                    f"Cookie '{cookie_name}' ({cookie_type}) does not have "
                    f"the HttpOnly flag set. Without HttpOnly, the cookie is "
                    f"accessible via JavaScript (document.cookie), enabling "
                    f"session theft via XSS attacks"
                ),
                references=["CWE-1004"],
            ))

        return findings

    # -----------------------------------------------------------------
    # Private check methods -- Missing SameSite attribute
    # -----------------------------------------------------------------

    def _check_samesite(
        self,
        target: Target,
        cookie_name: str,
        attrs: dict[str, str],
    ) -> list[Finding]:
        """
        Check for missing SameSite attribute on a cookie.

        The SameSite attribute controls whether the cookie is sent with
        cross-site requests.  Without it, the browser uses its default
        behaviour, which varies:
            - Modern browsers default to Lax (safe)
            - Older browsers default to None (unsafe, allows CSRF)

        Setting SameSite explicitly ensures predictable behaviour across
        all browser versions.

        Severity: LOW (most modern browsers default to Lax, but explicit
        is always better for defence-in-depth).

        Args:
            target:      The target being scanned.
            cookie_name: The name of the cookie.
            attrs:       Parsed cookie attributes (lowercase keys).

        Returns:
            List with one Finding if SameSite is missing, empty otherwise.
        """
        findings: list[Finding] = []

        # Check if the SameSite attribute is present in the attributes.
        if "samesite" not in attrs:
            findings.append(Finding(
                module="cookies",
                finding_type="missing_samesite",
                severity=Severity.LOW,
                target=target,
                title="Cookie Missing SameSite Attribute",
                detail=(
                    f"Cookie '{cookie_name}' does not have the SameSite "
                    f"attribute set. Without explicit SameSite, the browser "
                    f"uses its default behaviour, which may vary across "
                    f"browser versions"
                ),
                references=["CWE-1275"],
            ))

        return findings

    # -----------------------------------------------------------------
    # Private check methods -- SameSite=None without Secure
    # -----------------------------------------------------------------

    def _check_samesite_none_without_secure(
        self,
        target: Target,
        cookie_name: str,
        attrs: dict[str, str],
    ) -> list[Finding]:
        """
        Check for SameSite=None without the Secure flag.

        When SameSite=None, the cookie is sent on all cross-site requests
        (the most permissive setting).  Modern browsers require the Secure
        flag when SameSite=None -- without it, the cookie is rejected.

        This combination indicates either:
            - A misconfiguration (cookie won't work in modern browsers)
            - An attempt to use cross-site cookies without HTTPS protection

        Severity: MEDIUM (misconfiguration that can break functionality
        or indicate insecure cross-site cookie usage).

        Args:
            target:      The target being scanned.
            cookie_name: The name of the cookie.
            attrs:       Parsed cookie attributes (lowercase keys).

        Returns:
            List with one Finding if SameSite=None without Secure,
            empty otherwise.
        """
        findings: list[Finding] = []

        # Check if SameSite is set to "None" (case-insensitive).
        samesite_value = attrs.get("samesite", "").lower()

        if samesite_value == "none" and "secure" not in attrs:
            findings.append(Finding(
                module="cookies",
                finding_type="samesite_none_without_secure",
                severity=Severity.MEDIUM,
                target=target,
                title="SameSite=None Without Secure Flag",
                detail=(
                    f"Cookie '{cookie_name}' has SameSite=None but is missing "
                    f"the Secure flag. Modern browsers reject cookies with "
                    f"SameSite=None that do not also have the Secure flag"
                ),
                references=["CWE-1275"],
            ))

        return findings

    # -----------------------------------------------------------------
    # Private check methods -- Persistent session cookie
    # -----------------------------------------------------------------

    def _check_persistent_session(
        self,
        target: Target,
        cookie_name: str,
        attrs: dict[str, str],
        is_session: bool,
    ) -> list[Finding]:
        """
        Check for persistent session cookies (Expires or Max-Age set on
        a session cookie).

        Session cookies should be session-scoped (no Expires or Max-Age),
        meaning they are deleted when the user closes their browser.
        Adding Expires or Max-Age makes the cookie persistent, which means:
            - The session token survives browser restarts
            - The attack window for session hijacking is extended
            - Users on shared/public computers may leave active sessions

        This check only applies to session cookies.  Regular cookies with
        Expires/Max-Age are perfectly normal and expected.

        Severity: LOW (extends attack window but doesn't create a new
        vulnerability by itself).

        Args:
            target:      The target being scanned.
            cookie_name: The name of the cookie.
            attrs:       Parsed cookie attributes (lowercase keys).
            is_session:  Whether this is a session cookie.

        Returns:
            List with one Finding if persistent session cookie detected,
            empty otherwise.
        """
        findings: list[Finding] = []

        # Only check session cookies for persistence.  Regular cookies
        # with Expires/Max-Age are normal and expected.
        if not is_session:
            return findings

        # Check if Expires or Max-Age is present in the attributes.
        has_expires = "expires" in attrs
        has_max_age = "max-age" in attrs

        if has_expires or has_max_age:
            # Determine which persistence mechanism is used for the detail.
            persistence_type = []
            if has_expires:
                persistence_type.append("Expires")
            if has_max_age:
                persistence_type.append("Max-Age")

            findings.append(Finding(
                module="cookies",
                finding_type="persistent_session_cookie",
                severity=Severity.LOW,
                target=target,
                title="Persistent Session Cookie",
                detail=(
                    f"Session cookie '{cookie_name}' has "
                    f"{' and '.join(persistence_type)} set, making it "
                    f"persistent across browser restarts. Session cookies "
                    f"should be session-scoped (no Expires/Max-Age) to limit "
                    f"the window for session hijacking"
                ),
                references=["CWE-539"],
            ))

        return findings


# ---------------------------------------------------------------------------
# Module registration
# ---------------------------------------------------------------------------
# Instantiate the scanner and register it with the module registry.
# This runs at import time, so importing this file is sufficient to make
# the cookie scanner available to the orchestrator.

register_module(CookieScanner())
