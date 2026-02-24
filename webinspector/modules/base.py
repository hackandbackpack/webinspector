"""
webinspector.modules.base - Abstract base class for all scanner modules.

Every scanner module (SSL, headers, cookies, CORS, etc.) inherits from
ScanModule and implements the scan() method.  This ensures a consistent
interface across all modules, making it easy to add new checks without
modifying the orchestrator.

The orchestrator calls each module's scan() method with:
    1. A Target object describing *what* to scan (host, port, scheme, IP).
    2. An optional pre-fetched HTTP Response that is shared across all
       HTTP-based modules to avoid duplicate requests.

Each module returns a list of Finding objects.  An empty list means
"no issues detected" — this is the happy path, not an error.

Design decisions:
    - We use Python's ABC (Abstract Base Class) to *enforce* at import time
      that every scanner module implements the required interface.  If a
      developer forgets to implement scan(), Python raises TypeError when
      instantiating the class — failing fast instead of at runtime.
    - The accepts_target() method has a default (return True) so most modules
      don't need to override it.  Only modules with scheme-specific logic
      (e.g., SSL only runs on HTTPS targets) need to override.
    - We accept Optional[Response] for http_response because some modules
      (like the SSL module) make their own socket connections and don't need
      an HTTP response at all.

Usage example:
    class MyScanner(ScanModule):
        @property
        def name(self) -> str:
            return "my_scanner"

        @property
        def description(self) -> str:
            return "Checks for XYZ vulnerability"

        def scan(self, target, http_response=None) -> list[Finding]:
            findings = []
            # ... perform security checks ...
            return findings

Author: Red Siege Information Security
"""

from abc import ABC, abstractmethod
from typing import Optional

# requests.Response is used as a type hint for the pre-fetched HTTP response
# that the orchestrator passes to each HTTP-based module.
from requests import Response

# Import the core data structures that every module consumes / produces.
# Target = what we're scanning; Finding = what we found.
from webinspector.core.target import Target
from webinspector.core.result import Finding


class ScanModule(ABC):
    """
    Abstract base class for scanner modules.

    Each module performs one category of security checks (e.g., SSL/TLS,
    HTTP headers, cookies).  Modules receive a pre-fetched HTTP response
    to avoid making duplicate requests -- multiple modules examine the
    same response.

    Subclasses MUST implement:
        - name        (property) : Short identifier for CLI flags
        - description (property) : Human-readable description for --help
        - scan        (method)   : The actual security check logic

    Subclasses MAY override:
        - accepts_target : Return False to skip irrelevant targets

    The orchestrator calls modules in this order:
        1. accepts_target(target)  -- should this module run?
        2. scan(target, response)  -- perform the checks
    """

    # -----------------------------------------------------------------
    # Abstract properties — subclasses MUST implement these
    # -----------------------------------------------------------------

    @property
    @abstractmethod
    def name(self) -> str:
        """
        Short identifier for CLI flags (e.g., 'ssl', 'headers', 'cookies').

        This name is used in:
            - --only ssl,headers  (include only these modules)
            - --no-ssl            (exclude this module)
            - JSON output keys    (module field in findings)
            - Verbose log lines   ("[ssl] Checking TLS protocols...")

        Must be unique across all registered modules.  Convention is
        lowercase, no spaces, using underscores if needed.
        """
        ...

    @property
    @abstractmethod
    def description(self) -> str:
        """
        Human-readable description shown in --help and verbose output.

        Should be a concise one-liner explaining what the module checks.
        Example: "Evaluates SSL/TLS configuration and cipher suites"
        """
        ...

    # -----------------------------------------------------------------
    # Abstract methods — subclasses MUST implement these
    # -----------------------------------------------------------------

    @abstractmethod
    def scan(
        self,
        target: Target,
        http_response: Optional[Response] = None,
    ) -> list[Finding]:
        """
        Run security checks against a single target.

        This is the core method that every scanner module implements.
        It examines the target (and optionally the HTTP response) for
        security issues and returns a list of Finding objects.

        Args:
            target:
                The scan target containing host, port, scheme, and
                optionally the resolved IP address.  Use target.url
                for making HTTP requests, target.hostport for display.

            http_response:
                Pre-fetched HTTP GET response from the target.  This is
                shared across all HTTP-based modules for this target so
                we don't make N duplicate requests for N modules.

                May be None in two cases:
                    1. The target was unreachable (connection error, timeout).
                    2. This module does its own connections (e.g., the SSL
                       module opens raw TLS sockets via sslyze).

                Modules that require an HTTP response should check for None
                and return an empty list early if it's missing.

        Returns:
            List of Finding objects.  Empty list means no issues found,
            which is a perfectly valid and common result.
        """
        ...

    # -----------------------------------------------------------------
    # Optional methods — subclasses MAY override these
    # -----------------------------------------------------------------

    def accepts_target(self, target: Target) -> bool:
        """
        Check if this module should run against a given target.

        The orchestrator calls this before scan() to allow modules to skip
        targets that are irrelevant to their checks.  This avoids wasting
        time and producing confusing error messages.

        Override in subclasses to skip irrelevant targets.  Examples:
            - SSL module returns False for http:// targets (no TLS to test)
            - HTTPS enforcement module only runs on http:// targets
            - DNS module might skip targets that are raw IP addresses

        Default implementation: accept ALL targets.  Most modules don't
        need to override this because they can handle any target.

        Args:
            target: The target to evaluate.

        Returns:
            True if this module should scan the target, False to skip it.
        """
        # Default: accept all targets.  Subclasses override when they have
        # scheme-specific or protocol-specific requirements.
        return True
