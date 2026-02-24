"""
webinspector.modules.disclosure_scanner - Information disclosure header scanner module.

Examines HTTP response headers for information disclosure — headers that reveal
details about the server's technology stack, debugging state, infrastructure,
caching layer, container orchestration, load balancing, authentication system,
or internal architecture.  These headers do not represent direct vulnerabilities,
but they provide valuable reconnaissance data that helps attackers map the
target's attack surface and identify software with known CVEs.

This module checks approximately 90+ headers across 8 categories, ported from
headerinspect's INFO_DISCLOSURE_HEADERS dictionary:

    Technology Stack (22 headers + 2 prefix patterns):
        Exact:  X-Powered-By, Server, X-AspNet-Version, X-AspNetMvc-Version,
                X-Generator, X-Drupal-Cache, X-Drupal-Dynamic-Cache, X-WordPress,
                X-Pingback, X-Redirect-By, X-PHP-Version, X-Runtime,
                X-CF-Powered-By, Liferay-Portal, X-Turbo-Charged-By, X-Lithium,
                X-Shopify-Stage, X-ShopId, MicrosoftSharePointTeamServices,
                SPRequestGuid
        Prefix: X-Wix-*, X-Oracle-DMS-*

    Debugging/Development (11 headers):
        X-Debug-Token, X-Debug-Token-Link, X-Trace-Id, X-Request-Id,
        X-Correlation-Id, X-Debug, X-Debug-Info, X-DebugKit,
        X-Clockwork-Id, X-Clockwork-Version, Server-Timing

    Infrastructure/Proxy (8 headers):
        Via, X-Forwarded-Server, X-Backend-Server, X-Served-By,
        X-Server, X-Host, X-Origin-Server, X-Real-IP

    Caching/CDN (9 headers + 1 prefix pattern):
        Exact:  X-Varnish, X-Cache, X-Cache-Hits, X-Fastly-Request-ID,
                CF-Ray, CF-Cache-Status, X-CDN, X-CDN-Pop
        Prefix: X-Akamai-*

    Container/Orchestration (3 headers + 2 prefix patterns):
        Exact:  X-Container-Id, X-Pod-Name, X-Namespace
        Prefix: X-Kubernetes-*, X-Docker-*

    Load Balancer (3 headers + 2 prefix patterns):
        Exact:  X-LB-Server, X-Upstream, X-Proxy-Cache
        Prefix: X-Haproxy-*, X-Nginx-*

    Authentication (3 headers):
        X-Auth-Server, X-OAuth-Scopes, X-Accepted-OAuth-Scopes

    Miscellaneous (8 headers):
        X-Hostname, X-Instance-ID, X-Node, X-Request-Handler,
        X-Datacenter, X-Pool, X-Rack, X-Cluster-Name

Finding format:
    Each finding represents a single disclosure header found in the response.
    The console and text renderers have special handling for the disclosure module:
    they group findings by category (finding_type) and render the header value
    (detail) with the target URL.

    - module:       "disclosure"
    - finding_type: Category name (e.g., "Technology Stack", "Debugging/Development")
    - title:        The header name as found in the response (e.g., "Server")
    - detail:       The header value (e.g., "nginx/1.18.0")
    - severity:     INFORMATIONAL for all disclosure headers

Design decisions:
    - We use two data structures for header matching:
        1. _EXACT_HEADERS: Dict mapping lowercase header names to their category.
           Used for O(1) lookup of exact header matches.
        2. _PREFIX_PATTERNS: List of (lowercase_prefix, category) tuples.
           Used for wildcard/prefix matching (e.g., X-Wix-*).
    - Header matching is case-insensitive per RFC 7230 Section 3.2.  We
      normalise all response header names to lowercase before matching.
    - The finding title preserves the original header casing from the response
      (e.g., if the response has "x-powered-by", the title is "x-powered-by").
    - One finding per disclosure header found.  Multiple disclosure headers
      in the same response produce multiple findings.

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
# Disclosure header database
# ---------------------------------------------------------------------------
# Two data structures for efficient matching:
#
# 1. _EXACT_HEADERS: Maps lowercase header names to their category string.
#    Supports O(1) lookup for headers with known exact names.
#
# 2. _PREFIX_PATTERNS: List of (lowercase_prefix, category) tuples for
#    wildcard/prefix matching.  Headers like X-Wix-*, X-Akamai-*, etc.
#    are matched by checking if the response header starts with the prefix.
#    Prefix patterns are checked after exact matches, so an exact match
#    always takes priority.
#
# Categories match the 8 groups defined in the task specification.  The
# category name is used as the finding_type, which the console and text
# renderers use for section headers.
# ---------------------------------------------------------------------------

# -- Exact-match header -> category mapping --
# All keys are lowercase for case-insensitive matching.
_EXACT_HEADERS: dict[str, str] = {
    # ---- Technology Stack ----
    # These headers reveal the software, frameworks, CMS platforms, and
    # programming languages running on the server.  Attackers use this
    # information to search for known CVEs in specific versions.
    "x-powered-by": "Technology Stack",
    "server": "Technology Stack",
    "x-aspnet-version": "Technology Stack",
    "x-aspnetmvc-version": "Technology Stack",
    "x-generator": "Technology Stack",
    "x-drupal-cache": "Technology Stack",
    "x-drupal-dynamic-cache": "Technology Stack",
    "x-wordpress": "Technology Stack",
    "x-pingback": "Technology Stack",
    "x-redirect-by": "Technology Stack",
    "x-php-version": "Technology Stack",
    "x-runtime": "Technology Stack",
    "x-cf-powered-by": "Technology Stack",
    "liferay-portal": "Technology Stack",
    "x-turbo-charged-by": "Technology Stack",
    "x-lithium": "Technology Stack",
    "x-shopify-stage": "Technology Stack",
    "x-shopid": "Technology Stack",
    "microsoftsharepointteamservices": "Technology Stack",
    "sprequestguid": "Technology Stack",

    # ---- Debugging/Development ----
    # These headers indicate that debugging or development tools are active.
    # They often provide links to profiler pages, trace IDs, or timing data
    # that should never be exposed in production environments.
    "x-debug-token": "Debugging/Development",
    "x-debug-token-link": "Debugging/Development",
    "x-trace-id": "Debugging/Development",
    "x-request-id": "Debugging/Development",
    "x-correlation-id": "Debugging/Development",
    "x-debug": "Debugging/Development",
    "x-debug-info": "Debugging/Development",
    "x-debugkit": "Debugging/Development",
    "x-clockwork-id": "Debugging/Development",
    "x-clockwork-version": "Debugging/Development",
    "server-timing": "Debugging/Development",

    # ---- Infrastructure/Proxy ----
    # These headers reveal the names, IPs, and software of intermediate
    # proxies, reverse proxies, and backend servers.  This information
    # exposes internal network topology.
    "via": "Infrastructure/Proxy",
    "x-forwarded-server": "Infrastructure/Proxy",
    "x-backend-server": "Infrastructure/Proxy",
    "x-served-by": "Infrastructure/Proxy",
    "x-server": "Infrastructure/Proxy",
    "x-host": "Infrastructure/Proxy",
    "x-origin-server": "Infrastructure/Proxy",
    "x-real-ip": "Infrastructure/Proxy",

    # ---- Caching/CDN ----
    # These headers reveal caching layer details including the CDN provider,
    # cache hit/miss status, request IDs, and datacenter identifiers.
    "x-varnish": "Caching/CDN",
    "x-cache": "Caching/CDN",
    "x-cache-hits": "Caching/CDN",
    "x-fastly-request-id": "Caching/CDN",
    "cf-ray": "Caching/CDN",
    "cf-cache-status": "Caching/CDN",
    "x-cdn": "Caching/CDN",
    "x-cdn-pop": "Caching/CDN",

    # ---- Container/Orchestration ----
    # These headers reveal container runtime and orchestration details
    # including container IDs, pod names, and Kubernetes namespaces.
    "x-container-id": "Container/Orchestration",
    "x-pod-name": "Container/Orchestration",
    "x-namespace": "Container/Orchestration",

    # ---- Load Balancer ----
    # These headers reveal load balancer configuration, upstream server
    # details, and proxy cache status.
    "x-lb-server": "Load Balancer",
    "x-upstream": "Load Balancer",
    "x-proxy-cache": "Load Balancer",

    # ---- Authentication ----
    # These headers reveal authentication server details and OAuth scope
    # information.  This can help attackers understand the authentication
    # architecture and available permissions.
    "x-auth-server": "Authentication",
    "x-oauth-scopes": "Authentication",
    "x-accepted-oauth-scopes": "Authentication",

    # ---- Miscellaneous ----
    # These headers reveal internal infrastructure details that don't fit
    # neatly into the above categories: hostnames, instance IDs, datacenter
    # locations, cluster names, etc.
    "x-hostname": "Miscellaneous",
    "x-instance-id": "Miscellaneous",
    "x-node": "Miscellaneous",
    "x-request-handler": "Miscellaneous",
    "x-datacenter": "Miscellaneous",
    "x-pool": "Miscellaneous",
    "x-rack": "Miscellaneous",
    "x-cluster-name": "Miscellaneous",
}

# -- Prefix patterns for wildcard matching --
# Each tuple is (lowercase_prefix, category).  A response header matches
# if its lowercase name starts with the prefix.  The prefix includes the
# trailing hyphen to avoid false positives (e.g., "x-wix-" won't match
# "x-wixyz" but will match "x-wix-request-id").
_PREFIX_PATTERNS: list[tuple[str, str]] = [
    # Technology Stack prefix patterns
    ("x-wix-", "Technology Stack"),
    ("x-oracle-dms-", "Technology Stack"),

    # Caching/CDN prefix patterns
    ("x-akamai-", "Caching/CDN"),

    # Container/Orchestration prefix patterns
    ("x-kubernetes-", "Container/Orchestration"),
    ("x-docker-", "Container/Orchestration"),

    # Load Balancer prefix patterns
    ("x-haproxy-", "Load Balancer"),
    ("x-nginx-", "Load Balancer"),
]


class DisclosureScanner(ScanModule):
    """
    Information disclosure header scanner.

    Examines HTTP response headers for information that reveals details about
    the server's technology stack, debugging state, infrastructure, caching
    layer, container orchestration, load balancing, authentication system,
    or internal architecture.

    All findings are INFORMATIONAL severity — they are not vulnerabilities
    but provide valuable reconnaissance data for attackers and useful context
    for security analysts.

    Accepts both HTTP and HTTPS targets (the default accepts_target
    behaviour from the base class).
    """

    # -----------------------------------------------------------------
    # ScanModule interface -- required properties
    # -----------------------------------------------------------------

    @property
    def name(self) -> str:
        """Short identifier used in CLI flags and finding output."""
        return "disclosure"

    @property
    def description(self) -> str:
        """Human-readable description for --help output."""
        return "Information disclosure header detection (~90+ headers across 8 categories)"

    # -----------------------------------------------------------------
    # ScanModule interface -- main scan method
    # -----------------------------------------------------------------

    def scan(
        self,
        target: Target,
        http_response: Optional[Response] = None,
    ) -> list[Finding]:
        """
        Scan HTTP response headers for information disclosure.

        This method:
            1. Returns empty if http_response is None (target unreachable)
            2. Iterates through all response headers
            3. For each header, checks if it matches a known disclosure header
               (exact match first, then prefix/wildcard patterns)
            4. Creates an INFORMATIONAL finding for each match

        The matching process is case-insensitive per RFC 7230 Section 3.2.
        The finding title preserves the original header casing from the
        response for accurate reporting.

        Args:
            target:        The target being scanned.
            http_response: Pre-fetched requests.Response object.  If None,
                           the target was unreachable and we return empty.

        Returns:
            List of Finding objects.  Empty list means no disclosure headers
            were found or the target was unreachable.
        """
        # Guard: no response means the target was unreachable.
        # We can't analyse headers we don't have.
        if http_response is None:
            logger.debug(
                "No HTTP response for %s, skipping disclosure scan",
                target.hostport,
            )
            return []

        findings: list[Finding] = []

        # Extract the response headers.  We iterate through all headers
        # and check each one against our disclosure database.
        headers = http_response.headers

        # Iterate through every header in the response.
        # For each header, try exact match first (O(1) dict lookup), then
        # fall back to prefix pattern matching (linear scan of ~7 patterns).
        for header_name, header_value in headers.items():
            # Normalise the header name to lowercase for case-insensitive
            # matching.  HTTP headers are case-insensitive per RFC 7230.
            header_lower = header_name.lower()

            # --- Attempt 1: Exact match ---
            # Check if the lowercase header name exists in our exact-match dict.
            # This is the fast path — O(1) dict lookup covers ~70+ headers.
            category = _EXACT_HEADERS.get(header_lower)

            # --- Attempt 2: Prefix/wildcard match ---
            # If no exact match, check if the header starts with any known
            # prefix pattern (e.g., "x-wix-", "x-akamai-", "x-kubernetes-").
            if category is None:
                category = self._match_prefix(header_lower)

            # If we found a matching category, create a finding.
            if category is not None:
                findings.append(Finding(
                    module="disclosure",
                    finding_type=category,
                    severity=Severity.INFORMATIONAL,
                    target=target,
                    title=header_name,
                    detail=header_value,
                    references=[],  # Disclosure is informational — no CWE refs
                ))

        return findings

    # -----------------------------------------------------------------
    # Private helper methods
    # -----------------------------------------------------------------

    def _match_prefix(self, header_lower: str) -> Optional[str]:
        """
        Check if a lowercase header name matches any prefix pattern.

        Prefix patterns represent wildcard headers like X-Wix-*, X-Akamai-*,
        X-Kubernetes-*, etc.  A header matches if its lowercase name starts
        with the prefix string (which includes the trailing hyphen).

        Args:
            header_lower: The lowercase header name to check.

        Returns:
            The category name if a prefix match is found, None otherwise.
        """
        for prefix, category in _PREFIX_PATTERNS:
            if header_lower.startswith(prefix):
                return category

        # No prefix pattern matched.
        return None


# ---------------------------------------------------------------------------
# Module registration
# ---------------------------------------------------------------------------
# Instantiate the scanner and register it with the module registry.
# This runs at import time, so importing this file is sufficient to make
# the disclosure scanner available to the orchestrator.

register_module(DisclosureScanner())
