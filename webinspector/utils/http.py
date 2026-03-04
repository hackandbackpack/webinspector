"""
webinspector.utils.http - Shared HTTP session factory and URL fetching utility.

This module provides a centralized HTTP client configuration that all scanner
modules share.  Using a single session factory ensures consistent behavior
across the tool:
    - Same User-Agent header everywhere (avoids detection by simple WAFs)
    - Same retry logic (no scanner module randomly retries 100 times)
    - Same timeout settings (predictable scan durations)
    - Same SSL verification behavior (disabled — we're testing certs, not trusting them)

The key functions are:
    create_http_session()  - Build a pre-configured requests.Session
    fetch_url()            - Safely fetch a URL with error handling

Why we disable SSL verification:
    webinspector is a security assessment tool.  We need to connect to servers
    with expired certificates, self-signed certificates, and other SSL issues
    that would normally cause requests to reject the connection.  We disable
    verification globally so we can *inspect* the certificates rather than
    *trust* them.

Why we suppress InsecureRequestWarning:
    With verify=False, urllib3 emits a warning for every HTTPS request.
    In a scan of 500 targets, that's 500+ warning messages cluttering the
    output.  We suppress them once at module import time.

Author: Red Siege Information Security
"""

from __future__ import annotations

import logging

# requests is the HTTP library used for all web requests.
# Listed in requirements.txt as 'requests>=2.31'.
import requests
from requests.adapters import HTTPAdapter

# urllib3 is the underlying library that requests uses for HTTP.
# We import Retry for configuring automatic retry behavior, and
# we suppress the InsecureRequestWarning that fires when verify=False.
from urllib3.util.retry import Retry
import urllib3


# ---------------------------------------------------------------------------
# Module-level logger
# ---------------------------------------------------------------------------

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Suppress SSL verification warnings
# ---------------------------------------------------------------------------

# Disable the "InsecureRequestWarning: Unverified HTTPS request" message.
# We intentionally disable SSL verification because we're a security scanner
# that needs to connect to hosts with broken/invalid certificates.
# Without this, every single HTTPS request would print a warning line.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Suppress urllib3 retry warnings that flood output during scans.
# When targets are unreachable (connection refused, SSL handshake failures,
# timeouts), the retry adapter logs a WARNING for every single retry attempt.
# With 3 retries per target and dozens of targets, this creates hundreds of
# noisy warning lines that drown out actual findings.
logging.getLogger("urllib3.util.retry").setLevel(logging.ERROR)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Default User-Agent string — Firefox on Windows 10.
# We use a realistic browser User-Agent to avoid basic WAF detection that
# blocks requests from tools like "python-requests/2.31.0".
# This is an ethical pentest tool, and the team has authorization to scan,
# but some WAFs block non-browser UAs indiscriminately.
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) "
    "Gecko/20100101 Firefox/120.0"
)

# Default request timeout in seconds.
# 10 seconds is generous enough for slow servers but fast enough to not
# stall the scan.  Each scanner module can override this if needed.
DEFAULT_TIMEOUT = 10

# Default maximum number of retries for transient failures.
# 1 retry keeps the scan moving quickly when hitting many unreachable
# hosts while still catching transient 502/503/504 errors.
DEFAULT_MAX_RETRIES = 1

# HTTP status codes that should trigger an automatic retry.
# These are all server-side errors that may be transient:
#   502 Bad Gateway       - Upstream server is temporarily unavailable
#   503 Service Unavailable - Server is overloaded or in maintenance
#   504 Gateway Timeout   - Upstream server didn't respond in time
RETRY_STATUS_CODES = [502, 503, 504]

# Backoff factor for retry delays.
# With factor=0.5 and 3 retries, the delays are:
#   Retry 1: 0.5 * (2^0) = 0.5 seconds
#   Retry 2: 0.5 * (2^1) = 1.0 seconds
#   Retry 3: 0.5 * (2^2) = 2.0 seconds
# Total worst-case wait: 3.5 seconds before giving up.
RETRY_BACKOFF_FACTOR = 0.5


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def create_http_session(
    timeout: int = DEFAULT_TIMEOUT,
    user_agent: str = DEFAULT_USER_AGENT,
    proxy: str | None = None,
    max_retries: int = DEFAULT_MAX_RETRIES,
) -> tuple[requests.Session, int]:
    """
    Create a requests.Session pre-configured for web security scanning.

    The session is set up with:
    - Retry adapter with exponential backoff (0.5s, 1s, 2s) for transient errors
    - Custom User-Agent header (Firefox by default, to avoid WAF detection)
    - SSL verification disabled (we inspect certs, we don't trust them)
    - Optional proxy support (HTTP or SOCKS5, for testing through Burp/ZAP)
    - Configurable timeout returned alongside the session

    Args:
        timeout:     Request timeout in seconds (default 10).
                     Returned as the second element of the tuple so callers
                     can pass it to session.get(url, timeout=timeout).
        user_agent:  User-Agent header string (default is Firefox on Windows).
        proxy:       Optional proxy URL (e.g. "http://127.0.0.1:8080" for Burp,
                     or "socks5://127.0.0.1:1080" for a SOCKS proxy).
                     If None, no proxy is used.
        max_retries: Maximum number of automatic retries for failed requests
                     (default 3).  Set to 0 to disable retries.

    Returns:
        A tuple of (session, timeout):
        - session:  A fully configured requests.Session ready for use.
        - timeout:  The timeout value (int) to pass to individual requests.

    Example::

        session, timeout = create_http_session(timeout=15, proxy="http://127.0.0.1:8080")
        response = session.get("https://target.com", timeout=timeout, verify=False)
    """
    # --- Create a new session ---
    session = requests.Session()

    # --- Configure retry logic ---
    # The Retry object defines how urllib3 handles transient failures.
    # We retry on connection errors, specific HTTP status codes (502/503/504),
    # and use exponential backoff to avoid hammering struggling servers.
    retry_strategy = Retry(
        total=max_retries,                      # Maximum number of retries
        backoff_factor=RETRY_BACKOFF_FACTOR,     # Exponential backoff multiplier
        status_forcelist=RETRY_STATUS_CODES,     # HTTP codes that trigger retries
        allowed_methods=["GET", "HEAD"],         # Only retry safe HTTP methods
        raise_on_status=False,                   # Don't raise on non-2xx after retries
    )

    # Create an HTTP adapter with the retry strategy.
    # The adapter sits between the Session and urllib3's connection pool.
    adapter = HTTPAdapter(max_retries=retry_strategy)

    # Mount the adapter on both http:// and https:// so all requests
    # benefit from the retry logic regardless of scheme.
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    # --- Set headers ---
    # The User-Agent header is the most important for avoiding WAF blocks.
    # We set it at the session level so every request inherits it automatically.
    session.headers.update({
        "User-Agent": user_agent,
    })

    # --- Disable SSL verification globally for this session ---
    # This is intentional: webinspector is a security scanner that needs to
    # connect to servers with invalid, expired, or self-signed certificates.
    # We inspect the cert details separately (ssl_analyzer module), so we
    # don't need requests to enforce verification.
    session.verify = False

    # --- Configure proxy if provided ---
    # Proxy support is useful when the pentest team wants to route traffic
    # through an intercepting proxy like Burp Suite or ZAP for additional
    # analysis, or through a SOCKS proxy for network routing.
    if proxy:
        # requests expects a dict mapping scheme to proxy URL.
        # We use the same proxy for both HTTP and HTTPS traffic.
        session.proxies = {
            "http": proxy,
            "https": proxy,
        }
        logger.info("HTTP session configured with proxy: %s", proxy)

    logger.debug(
        "HTTP session created: timeout=%ds, retries=%d, ua=%s",
        timeout,
        max_retries,
        user_agent[:50],  # Truncate UA for log readability
    )

    # Return both the session and timeout as a tuple.
    # The timeout is not a session-level setting in requests — it must be
    # passed to each individual request call (session.get(url, timeout=...)).
    return session, timeout


def fetch_url(
    session: requests.Session,
    url: str,
    timeout: int = DEFAULT_TIMEOUT,
) -> tuple[requests.Response | None, str | None]:
    """
    Fetch a URL using the configured session, with comprehensive error handling.

    This is the standard way to make HTTP requests throughout webinspector.
    It wraps session.get() with exception handling so that callers never need
    to write their own try/except blocks for HTTP errors.

    The function follows the "never raise" pattern: instead of raising
    exceptions, it returns the error as a string.  This simplifies scanner
    module code — they just check ``if error: skip_target()``.

    Args:
        session:  A requests.Session (typically from create_http_session()).
        url:      The full URL to fetch (e.g. "https://example.com:443").
        timeout:  Request timeout in seconds (default 10).

    Returns:
        A tuple of (response, error):
        - On success: (Response object, None)
        - On failure: (None, error description string)

    Example::

        session, timeout = create_http_session()
        response, error = fetch_url(session, "https://example.com", timeout)
        if error:
            print(f"Request failed: {error}")
        else:
            print(f"Status: {response.status_code}")
    """
    try:
        # Make the GET request.
        # - timeout: how long to wait for a response (seconds)
        # - verify=False: already set at session level, but explicit here for clarity
        # - allow_redirects=True: follow HTTP 301/302/303/307/308 redirects
        response = session.get(
            url,
            timeout=timeout,
            verify=False,
            allow_redirects=True,
        )

        # If we got a response (even a 4xx or 5xx), return it.
        # Scanner modules may want to inspect error responses too
        # (e.g. checking headers on a 403 page).
        logger.debug("Fetched %s -> HTTP %d", url, response.status_code)
        return response, None

    except requests.exceptions.ConnectionError as exc:
        # Connection failed — server refused, DNS failed, network unreachable, etc.
        # This is the most common failure during pentests (host is down, firewall blocks).
        error_msg = f"Connection error: {exc}"
        logger.debug("Connection error for %s: %s", url, exc)
        return None, error_msg

    except requests.exceptions.Timeout as exc:
        # The request timed out — server didn't respond within the timeout period.
        # Common for heavily firewalled hosts that drop packets silently.
        error_msg = f"Request timed out after {timeout}s"
        logger.debug("Timeout for %s: %s", url, exc)
        return None, error_msg

    except requests.exceptions.TooManyRedirects as exc:
        # The server sent too many redirects (default limit is 30).
        # This can indicate a misconfigured server or redirect loop.
        error_msg = f"Too many redirects: {exc}"
        logger.debug("Redirect loop for %s: %s", url, exc)
        return None, error_msg

    except requests.exceptions.HTTPError as exc:
        # An HTTP error occurred (raised by response.raise_for_status()).
        # Note: we don't call raise_for_status(), but this catches it if
        # a future code change does.
        error_msg = f"HTTP error: {exc}"
        logger.debug("HTTP error for %s: %s", url, exc)
        return None, error_msg

    except requests.exceptions.RequestException as exc:
        # Catch-all for any other requests-related exception.
        # This includes SSL errors, chunked encoding errors, etc.
        error_msg = f"Request failed: {exc}"
        logger.debug("Request exception for %s: %s", url, exc)
        return None, error_msg
