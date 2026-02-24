"""
Tests for the information disclosure header scanner module (disclosure_scanner.py).

These tests verify that the DisclosureScanner module correctly:
    1. Accepts both HTTP and HTTPS targets (default accepts_target)
    2. Returns empty findings when http_response is None
    3. Returns empty findings when no disclosure headers are present
    4. Detects Technology Stack headers (X-Powered-By, Server, X-AspNet-Version, etc.)
    5. Detects Debugging/Development headers (X-Debug-Token, X-Trace-Id, etc.)
    6. Detects Infrastructure/Proxy headers (Via, X-Forwarded-Server, etc.)
    7. Detects Caching/CDN headers (X-Varnish, X-Cache, CF-Ray, etc.)
    8. Detects Container/Orchestration headers (X-Kubernetes-*, X-Docker-*, etc.)
    9. Detects Load Balancer headers (X-Haproxy-*, X-LB-Server, etc.)
   10. Detects Authentication headers (X-Auth-Server, X-OAuth-Scopes, etc.)
   11. Detects Miscellaneous headers (X-Hostname, X-Instance-ID, etc.)
   12. Matches wildcard/prefix patterns (X-Wix-*, X-Akamai-*, X-Kubernetes-*, etc.)
   13. All findings have severity INFORMATIONAL
   14. All findings have module="disclosure"
   15. Finding type matches the category name (e.g., "Technology Stack")
   16. Finding title is the header name (e.g., "Server")
   17. Finding detail is the header value (e.g., "nginx/1.18.0")
   18. Handles multiple disclosure headers in a single response
   19. Handles case-insensitive header matching
   20. Registers with the module registry on import

All HTTP responses are mocked using unittest.mock.MagicMock -- no real
HTTP connections are made.

Author: Red Siege Information Security
"""

import pytest
from unittest.mock import MagicMock

from webinspector.core.target import Target
from webinspector.core.result import Finding, Severity


# ---------------------------------------------------------------------------
# Mock helper -- build a requests.Response stand-in with specified headers
# ---------------------------------------------------------------------------

def _make_response(headers: dict) -> MagicMock:
    """
    Build a mock requests.Response with the given headers dict.

    The mock's .headers attribute is a plain dict.  The scanner should
    handle case-insensitive header lookups internally (HTTP headers are
    case-insensitive per RFC 7230).

    Args:
        headers: Dict mapping header names to values.

    Returns:
        A MagicMock mimicking requests.Response with .headers set.
    """
    response = MagicMock()
    response.headers = headers
    return response


# ---------------------------------------------------------------------------
# Target fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def https_target():
    """An HTTPS target for disclosure scanning."""
    return Target(host="example.com", port=443, scheme="https")


@pytest.fixture
def http_target():
    """An HTTP target for disclosure scanning."""
    return Target(host="example.com", port=80, scheme="http")


# ===========================================================================
# Tests for module properties
# ===========================================================================

class TestDisclosureScannerProperties:
    """Verify name and description properties."""

    def test_name(self):
        """Module name should be 'disclosure'."""
        from webinspector.modules.disclosure_scanner import DisclosureScanner
        scanner = DisclosureScanner()
        assert scanner.name == "disclosure"

    def test_description(self):
        """Module should have a non-empty description."""
        from webinspector.modules.disclosure_scanner import DisclosureScanner
        scanner = DisclosureScanner()
        assert len(scanner.description) > 0
        # Should mention disclosure or information in the description
        assert "disclosure" in scanner.description.lower() or "information" in scanner.description.lower()


# ===========================================================================
# Tests for accepts_target
# ===========================================================================

class TestDisclosureScannerAcceptsTarget:
    """Verify that the disclosure scanner accepts both HTTP and HTTPS targets."""

    def test_accepts_https(self, https_target):
        """Disclosure scanner should accept targets with scheme='https'."""
        from webinspector.modules.disclosure_scanner import DisclosureScanner
        scanner = DisclosureScanner()
        assert scanner.accepts_target(https_target) is True

    def test_accepts_http(self, http_target):
        """Disclosure scanner should accept targets with scheme='http'."""
        from webinspector.modules.disclosure_scanner import DisclosureScanner
        scanner = DisclosureScanner()
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
        from webinspector.modules.disclosure_scanner import DisclosureScanner
        scanner = DisclosureScanner()
        findings = scanner.scan(https_target, http_response=None)
        assert isinstance(findings, list)
        assert len(findings) == 0


# ===========================================================================
# Tests for no disclosure headers
# ===========================================================================

class TestNoDisclosureHeaders:
    """Verify that clean responses produce zero findings."""

    def test_no_disclosure_headers(self, https_target):
        """
        A response with standard security headers but NO information
        disclosure headers should produce zero findings.
        """
        from webinspector.modules.disclosure_scanner import DisclosureScanner

        response = _make_response({
            "Content-Type": "text/html; charset=utf-8",
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        })

        scanner = DisclosureScanner()
        findings = scanner.scan(https_target, http_response=response)
        assert len(findings) == 0

    def test_empty_headers(self, https_target):
        """An empty headers dict should produce zero findings."""
        from webinspector.modules.disclosure_scanner import DisclosureScanner

        response = _make_response({})
        scanner = DisclosureScanner()
        findings = scanner.scan(https_target, http_response=response)
        assert len(findings) == 0


# ===========================================================================
# Tests for Technology Stack headers
# ===========================================================================

class TestTechnologyStackHeaders:
    """Verify detection of Technology Stack disclosure headers."""

    def test_detects_x_powered_by(self, https_target):
        """
        X-Powered-By reveals the server-side technology stack (e.g.,
        'PHP/8.1.2', 'ASP.NET', 'Express').  This information helps
        attackers target known vulnerabilities in specific versions.
        """
        from webinspector.modules.disclosure_scanner import DisclosureScanner

        response = _make_response({"X-Powered-By": "PHP/8.1.2"})
        scanner = DisclosureScanner()
        findings = scanner.scan(https_target, http_response=response)

        assert len(findings) == 1
        assert findings[0].module == "disclosure"
        assert findings[0].finding_type == "Technology Stack"
        assert findings[0].title == "X-Powered-By"
        assert findings[0].detail == "PHP/8.1.2"
        assert findings[0].severity == Severity.INFORMATIONAL

    def test_detects_server_header(self, https_target):
        """
        Server header reveals the web server software and version.
        Common values: 'nginx/1.18.0', 'Apache/2.4.54', 'Microsoft-IIS/10.0'.
        """
        from webinspector.modules.disclosure_scanner import DisclosureScanner

        response = _make_response({"Server": "nginx/1.18.0"})
        scanner = DisclosureScanner()
        findings = scanner.scan(https_target, http_response=response)

        server_findings = [f for f in findings if f.title == "Server"]
        assert len(server_findings) == 1
        assert server_findings[0].finding_type == "Technology Stack"
        assert server_findings[0].detail == "nginx/1.18.0"

    def test_detects_x_aspnet_version(self, https_target):
        """X-AspNet-Version reveals the ASP.NET framework version."""
        from webinspector.modules.disclosure_scanner import DisclosureScanner

        response = _make_response({"X-AspNet-Version": "4.0.30319"})
        scanner = DisclosureScanner()
        findings = scanner.scan(https_target, http_response=response)

        aspnet = [f for f in findings if f.title == "X-AspNet-Version"]
        assert len(aspnet) == 1
        assert aspnet[0].finding_type == "Technology Stack"

    def test_detects_x_aspnetmvc_version(self, https_target):
        """X-AspNetMvc-Version reveals the ASP.NET MVC framework version."""
        from webinspector.modules.disclosure_scanner import DisclosureScanner

        response = _make_response({"X-AspNetMvc-Version": "5.2"})
        scanner = DisclosureScanner()
        findings = scanner.scan(https_target, http_response=response)

        mvc = [f for f in findings if f.title == "X-AspNetMvc-Version"]
        assert len(mvc) == 1
        assert mvc[0].finding_type == "Technology Stack"

    def test_detects_x_generator(self, https_target):
        """X-Generator reveals the CMS or site generator."""
        from webinspector.modules.disclosure_scanner import DisclosureScanner

        response = _make_response({"X-Generator": "WordPress 6.4"})
        scanner = DisclosureScanner()
        findings = scanner.scan(https_target, http_response=response)

        gen = [f for f in findings if f.title == "X-Generator"]
        assert len(gen) == 1
        assert gen[0].finding_type == "Technology Stack"
        assert gen[0].detail == "WordPress 6.4"

    def test_detects_x_drupal_cache(self, https_target):
        """X-Drupal-Cache reveals Drupal CMS is in use."""
        from webinspector.modules.disclosure_scanner import DisclosureScanner

        response = _make_response({"X-Drupal-Cache": "HIT"})
        scanner = DisclosureScanner()
        findings = scanner.scan(https_target, http_response=response)

        drupal = [f for f in findings if f.title == "X-Drupal-Cache"]
        assert len(drupal) == 1
        assert drupal[0].finding_type == "Technology Stack"

    def test_detects_x_php_version(self, https_target):
        """X-PHP-Version reveals the PHP version running on the server."""
        from webinspector.modules.disclosure_scanner import DisclosureScanner

        response = _make_response({"X-PHP-Version": "8.2.0"})
        scanner = DisclosureScanner()
        findings = scanner.scan(https_target, http_response=response)

        php = [f for f in findings if f.title == "X-PHP-Version"]
        assert len(php) == 1
        assert php[0].finding_type == "Technology Stack"

    def test_detects_liferay_portal(self, https_target):
        """Liferay-Portal reveals the Liferay portal software."""
        from webinspector.modules.disclosure_scanner import DisclosureScanner

        response = _make_response({"Liferay-Portal": "Liferay Community Edition 7.4.0"})
        scanner = DisclosureScanner()
        findings = scanner.scan(https_target, http_response=response)

        liferay = [f for f in findings if f.title == "Liferay-Portal"]
        assert len(liferay) == 1
        assert liferay[0].finding_type == "Technology Stack"

    def test_detects_x_wix_prefix(self, https_target):
        """
        X-Wix-* wildcard pattern matches any header starting with 'X-Wix-'.
        This reveals the site is hosted on the Wix platform.
        """
        from webinspector.modules.disclosure_scanner import DisclosureScanner

        response = _make_response({"X-Wix-Request-Id": "abc-123"})
        scanner = DisclosureScanner()
        findings = scanner.scan(https_target, http_response=response)

        wix = [f for f in findings if f.title == "X-Wix-Request-Id"]
        assert len(wix) == 1
        assert wix[0].finding_type == "Technology Stack"

    def test_detects_microsoftsharepoint(self, https_target):
        """MicrosoftSharePointTeamServices reveals SharePoint is in use."""
        from webinspector.modules.disclosure_scanner import DisclosureScanner

        response = _make_response({"MicrosoftSharePointTeamServices": "16.0.0.5"})
        scanner = DisclosureScanner()
        findings = scanner.scan(https_target, http_response=response)

        sp = [f for f in findings if f.title == "MicrosoftSharePointTeamServices"]
        assert len(sp) == 1
        assert sp[0].finding_type == "Technology Stack"

    def test_detects_x_shopify_stage(self, https_target):
        """X-Shopify-Stage reveals the Shopify environment stage."""
        from webinspector.modules.disclosure_scanner import DisclosureScanner

        response = _make_response({"X-Shopify-Stage": "production"})
        scanner = DisclosureScanner()
        findings = scanner.scan(https_target, http_response=response)

        shopify = [f for f in findings if f.title == "X-Shopify-Stage"]
        assert len(shopify) == 1
        assert shopify[0].finding_type == "Technology Stack"


# ===========================================================================
# Tests for Debugging/Development headers
# ===========================================================================

class TestDebuggingHeaders:
    """Verify detection of Debugging/Development disclosure headers."""

    def test_detects_x_debug_token(self, https_target):
        """
        X-Debug-Token is used by Symfony's web profiler.  It reveals
        debugging information that should never be exposed in production.
        """
        from webinspector.modules.disclosure_scanner import DisclosureScanner

        response = _make_response({"X-Debug-Token": "abc123"})
        scanner = DisclosureScanner()
        findings = scanner.scan(https_target, http_response=response)

        debug = [f for f in findings if f.title == "X-Debug-Token"]
        assert len(debug) == 1
        assert debug[0].finding_type == "Debugging/Development"
        assert debug[0].severity == Severity.INFORMATIONAL

    def test_detects_x_debug_token_link(self, https_target):
        """X-Debug-Token-Link provides a direct URL to the Symfony profiler."""
        from webinspector.modules.disclosure_scanner import DisclosureScanner

        response = _make_response({
            "X-Debug-Token-Link": "https://example.com/_profiler/abc123"
        })
        scanner = DisclosureScanner()
        findings = scanner.scan(https_target, http_response=response)

        link = [f for f in findings if f.title == "X-Debug-Token-Link"]
        assert len(link) == 1
        assert link[0].finding_type == "Debugging/Development"

    def test_detects_x_trace_id(self, https_target):
        """X-Trace-Id reveals distributed tracing identifiers."""
        from webinspector.modules.disclosure_scanner import DisclosureScanner

        response = _make_response({"X-Trace-Id": "trace-123-abc"})
        scanner = DisclosureScanner()
        findings = scanner.scan(https_target, http_response=response)

        trace = [f for f in findings if f.title == "X-Trace-Id"]
        assert len(trace) == 1
        assert trace[0].finding_type == "Debugging/Development"

    def test_detects_x_request_id(self, https_target):
        """X-Request-Id reveals request tracking identifiers."""
        from webinspector.modules.disclosure_scanner import DisclosureScanner

        response = _make_response({"X-Request-Id": "req-abc-123"})
        scanner = DisclosureScanner()
        findings = scanner.scan(https_target, http_response=response)

        req = [f for f in findings if f.title == "X-Request-Id"]
        assert len(req) == 1
        assert req[0].finding_type == "Debugging/Development"

    def test_detects_server_timing(self, https_target):
        """
        Server-Timing reveals backend performance metrics that can
        help attackers understand the server's internal architecture.
        """
        from webinspector.modules.disclosure_scanner import DisclosureScanner

        response = _make_response({
            "Server-Timing": "db;dur=53, app;dur=47.2"
        })
        scanner = DisclosureScanner()
        findings = scanner.scan(https_target, http_response=response)

        timing = [f for f in findings if f.title == "Server-Timing"]
        assert len(timing) == 1
        assert timing[0].finding_type == "Debugging/Development"

    def test_detects_x_correlation_id(self, https_target):
        """X-Correlation-Id reveals request correlation identifiers."""
        from webinspector.modules.disclosure_scanner import DisclosureScanner

        response = _make_response({"X-Correlation-Id": "corr-abc-123"})
        scanner = DisclosureScanner()
        findings = scanner.scan(https_target, http_response=response)

        corr = [f for f in findings if f.title == "X-Correlation-Id"]
        assert len(corr) == 1
        assert corr[0].finding_type == "Debugging/Development"

    def test_detects_x_clockwork_id(self, https_target):
        """X-Clockwork-Id reveals Clockwork Laravel debugger info."""
        from webinspector.modules.disclosure_scanner import DisclosureScanner

        response = _make_response({"X-Clockwork-Id": "1234567890"})
        scanner = DisclosureScanner()
        findings = scanner.scan(https_target, http_response=response)

        clockwork = [f for f in findings if f.title == "X-Clockwork-Id"]
        assert len(clockwork) == 1
        assert clockwork[0].finding_type == "Debugging/Development"


# ===========================================================================
# Tests for Infrastructure/Proxy headers
# ===========================================================================

class TestInfrastructureHeaders:
    """Verify detection of Infrastructure/Proxy disclosure headers."""

    def test_detects_via(self, https_target):
        """
        Via header reveals intermediate proxies and their software.
        Example: 'Via: 1.1 varnish (Varnish/6.0)'.
        """
        from webinspector.modules.disclosure_scanner import DisclosureScanner

        response = _make_response({"Via": "1.1 varnish (Varnish/6.0)"})
        scanner = DisclosureScanner()
        findings = scanner.scan(https_target, http_response=response)

        via = [f for f in findings if f.title == "Via"]
        assert len(via) == 1
        assert via[0].finding_type == "Infrastructure/Proxy"
        assert via[0].severity == Severity.INFORMATIONAL

    def test_detects_x_forwarded_server(self, https_target):
        """X-Forwarded-Server reveals the internal server hostname."""
        from webinspector.modules.disclosure_scanner import DisclosureScanner

        response = _make_response({"X-Forwarded-Server": "web-server-01"})
        scanner = DisclosureScanner()
        findings = scanner.scan(https_target, http_response=response)

        fwd = [f for f in findings if f.title == "X-Forwarded-Server"]
        assert len(fwd) == 1
        assert fwd[0].finding_type == "Infrastructure/Proxy"

    def test_detects_x_backend_server(self, https_target):
        """X-Backend-Server reveals internal backend server names."""
        from webinspector.modules.disclosure_scanner import DisclosureScanner

        response = _make_response({"X-Backend-Server": "backend-app-01.internal"})
        scanner = DisclosureScanner()
        findings = scanner.scan(https_target, http_response=response)

        backend = [f for f in findings if f.title == "X-Backend-Server"]
        assert len(backend) == 1
        assert backend[0].finding_type == "Infrastructure/Proxy"

    def test_detects_x_served_by(self, https_target):
        """X-Served-By reveals the server that handled the request."""
        from webinspector.modules.disclosure_scanner import DisclosureScanner

        response = _make_response({"X-Served-By": "cache-lax-1234"})
        scanner = DisclosureScanner()
        findings = scanner.scan(https_target, http_response=response)

        served = [f for f in findings if f.title == "X-Served-By"]
        assert len(served) == 1
        assert served[0].finding_type == "Infrastructure/Proxy"

    def test_detects_x_real_ip(self, https_target):
        """X-Real-IP reveals the internal IP of the server or client."""
        from webinspector.modules.disclosure_scanner import DisclosureScanner

        response = _make_response({"X-Real-IP": "10.0.0.5"})
        scanner = DisclosureScanner()
        findings = scanner.scan(https_target, http_response=response)

        real_ip = [f for f in findings if f.title == "X-Real-IP"]
        assert len(real_ip) == 1
        assert real_ip[0].finding_type == "Infrastructure/Proxy"


# ===========================================================================
# Tests for Caching/CDN headers
# ===========================================================================

class TestCachingCDNHeaders:
    """Verify detection of Caching/CDN disclosure headers."""

    def test_detects_x_varnish(self, https_target):
        """X-Varnish reveals the Varnish cache server and request ID."""
        from webinspector.modules.disclosure_scanner import DisclosureScanner

        response = _make_response({"X-Varnish": "123456789"})
        scanner = DisclosureScanner()
        findings = scanner.scan(https_target, http_response=response)

        varnish = [f for f in findings if f.title == "X-Varnish"]
        assert len(varnish) == 1
        assert varnish[0].finding_type == "Caching/CDN"
        assert varnish[0].severity == Severity.INFORMATIONAL

    def test_detects_cf_ray(self, https_target):
        """CF-Ray reveals the Cloudflare ray ID and datacenter."""
        from webinspector.modules.disclosure_scanner import DisclosureScanner

        response = _make_response({"CF-Ray": "7a1b2c3d4e5f6-LAX"})
        scanner = DisclosureScanner()
        findings = scanner.scan(https_target, http_response=response)

        cf = [f for f in findings if f.title == "CF-Ray"]
        assert len(cf) == 1
        assert cf[0].finding_type == "Caching/CDN"

    def test_detects_cf_cache_status(self, https_target):
        """CF-Cache-Status reveals Cloudflare caching status."""
        from webinspector.modules.disclosure_scanner import DisclosureScanner

        response = _make_response({"CF-Cache-Status": "HIT"})
        scanner = DisclosureScanner()
        findings = scanner.scan(https_target, http_response=response)

        cf_cache = [f for f in findings if f.title == "CF-Cache-Status"]
        assert len(cf_cache) == 1
        assert cf_cache[0].finding_type == "Caching/CDN"

    def test_detects_x_cache(self, https_target):
        """X-Cache reveals cache hit/miss status."""
        from webinspector.modules.disclosure_scanner import DisclosureScanner

        response = _make_response({"X-Cache": "HIT from proxy"})
        scanner = DisclosureScanner()
        findings = scanner.scan(https_target, http_response=response)

        cache = [f for f in findings if f.title == "X-Cache"]
        assert len(cache) == 1
        assert cache[0].finding_type == "Caching/CDN"

    def test_detects_x_cache_hits(self, https_target):
        """X-Cache-Hits reveals cache hit count."""
        from webinspector.modules.disclosure_scanner import DisclosureScanner

        response = _make_response({"X-Cache-Hits": "42"})
        scanner = DisclosureScanner()
        findings = scanner.scan(https_target, http_response=response)

        hits = [f for f in findings if f.title == "X-Cache-Hits"]
        assert len(hits) == 1
        assert hits[0].finding_type == "Caching/CDN"

    def test_detects_x_fastly_request_id(self, https_target):
        """X-Fastly-Request-ID reveals Fastly CDN request identifier."""
        from webinspector.modules.disclosure_scanner import DisclosureScanner

        response = _make_response({"X-Fastly-Request-ID": "abc-def-123"})
        scanner = DisclosureScanner()
        findings = scanner.scan(https_target, http_response=response)

        fastly = [f for f in findings if f.title == "X-Fastly-Request-ID"]
        assert len(fastly) == 1
        assert fastly[0].finding_type == "Caching/CDN"

    def test_detects_x_akamai_prefix(self, https_target):
        """
        X-Akamai-* wildcard pattern matches any header starting with
        'X-Akamai-'.  This reveals Akamai CDN infrastructure details.
        """
        from webinspector.modules.disclosure_scanner import DisclosureScanner

        response = _make_response({"X-Akamai-Session-Info": "session-abc"})
        scanner = DisclosureScanner()
        findings = scanner.scan(https_target, http_response=response)

        akamai = [f for f in findings if f.title == "X-Akamai-Session-Info"]
        assert len(akamai) == 1
        assert akamai[0].finding_type == "Caching/CDN"

    def test_detects_x_cdn(self, https_target):
        """X-CDN reveals the CDN provider in use."""
        from webinspector.modules.disclosure_scanner import DisclosureScanner

        response = _make_response({"X-CDN": "Fastly"})
        scanner = DisclosureScanner()
        findings = scanner.scan(https_target, http_response=response)

        cdn = [f for f in findings if f.title == "X-CDN"]
        assert len(cdn) == 1
        assert cdn[0].finding_type == "Caching/CDN"


# ===========================================================================
# Tests for Container/Orchestration headers
# ===========================================================================

class TestContainerHeaders:
    """Verify detection of Container/Orchestration disclosure headers."""

    def test_detects_x_kubernetes_prefix(self, https_target):
        """
        X-Kubernetes-* wildcard pattern matches any header starting with
        'X-Kubernetes-'.  This reveals Kubernetes cluster details.
        """
        from webinspector.modules.disclosure_scanner import DisclosureScanner

        response = _make_response({"X-Kubernetes-Pf-Flowschema-Uid": "uid-123"})
        scanner = DisclosureScanner()
        findings = scanner.scan(https_target, http_response=response)

        k8s = [f for f in findings if f.title == "X-Kubernetes-Pf-Flowschema-Uid"]
        assert len(k8s) == 1
        assert k8s[0].finding_type == "Container/Orchestration"
        assert k8s[0].severity == Severity.INFORMATIONAL

    def test_detects_x_docker_prefix(self, https_target):
        """
        X-Docker-* wildcard pattern matches any header starting with
        'X-Docker-'.  This reveals Docker container details.
        """
        from webinspector.modules.disclosure_scanner import DisclosureScanner

        response = _make_response({"X-Docker-Container-Id": "abc123def456"})
        scanner = DisclosureScanner()
        findings = scanner.scan(https_target, http_response=response)

        docker = [f for f in findings if f.title == "X-Docker-Container-Id"]
        assert len(docker) == 1
        assert docker[0].finding_type == "Container/Orchestration"

    def test_detects_x_container_id(self, https_target):
        """X-Container-Id reveals the container identifier."""
        from webinspector.modules.disclosure_scanner import DisclosureScanner

        response = _make_response({"X-Container-Id": "container-abc"})
        scanner = DisclosureScanner()
        findings = scanner.scan(https_target, http_response=response)

        container = [f for f in findings if f.title == "X-Container-Id"]
        assert len(container) == 1
        assert container[0].finding_type == "Container/Orchestration"

    def test_detects_x_pod_name(self, https_target):
        """X-Pod-Name reveals the Kubernetes pod name."""
        from webinspector.modules.disclosure_scanner import DisclosureScanner

        response = _make_response({"X-Pod-Name": "web-app-abc123-xyz"})
        scanner = DisclosureScanner()
        findings = scanner.scan(https_target, http_response=response)

        pod = [f for f in findings if f.title == "X-Pod-Name"]
        assert len(pod) == 1
        assert pod[0].finding_type == "Container/Orchestration"

    def test_detects_x_namespace(self, https_target):
        """X-Namespace reveals the Kubernetes namespace."""
        from webinspector.modules.disclosure_scanner import DisclosureScanner

        response = _make_response({"X-Namespace": "production"})
        scanner = DisclosureScanner()
        findings = scanner.scan(https_target, http_response=response)

        ns = [f for f in findings if f.title == "X-Namespace"]
        assert len(ns) == 1
        assert ns[0].finding_type == "Container/Orchestration"


# ===========================================================================
# Tests for Load Balancer headers
# ===========================================================================

class TestLoadBalancerHeaders:
    """Verify detection of Load Balancer disclosure headers."""

    def test_detects_x_haproxy_prefix(self, https_target):
        """
        X-Haproxy-* wildcard pattern matches any header starting with
        'X-Haproxy-'.  This reveals HAProxy load balancer details.
        """
        from webinspector.modules.disclosure_scanner import DisclosureScanner

        response = _make_response({"X-Haproxy-Server-State": "active"})
        scanner = DisclosureScanner()
        findings = scanner.scan(https_target, http_response=response)

        haproxy = [f for f in findings if f.title == "X-Haproxy-Server-State"]
        assert len(haproxy) == 1
        assert haproxy[0].finding_type == "Load Balancer"
        assert haproxy[0].severity == Severity.INFORMATIONAL

    def test_detects_x_lb_server(self, https_target):
        """X-LB-Server reveals the load balancer server name."""
        from webinspector.modules.disclosure_scanner import DisclosureScanner

        response = _make_response({"X-LB-Server": "lb-east-01"})
        scanner = DisclosureScanner()
        findings = scanner.scan(https_target, http_response=response)

        lb = [f for f in findings if f.title == "X-LB-Server"]
        assert len(lb) == 1
        assert lb[0].finding_type == "Load Balancer"

    def test_detects_x_upstream(self, https_target):
        """X-Upstream reveals the upstream backend server."""
        from webinspector.modules.disclosure_scanner import DisclosureScanner

        response = _make_response({"X-Upstream": "10.0.0.5:8080"})
        scanner = DisclosureScanner()
        findings = scanner.scan(https_target, http_response=response)

        upstream = [f for f in findings if f.title == "X-Upstream"]
        assert len(upstream) == 1
        assert upstream[0].finding_type == "Load Balancer"

    def test_detects_x_nginx_prefix(self, https_target):
        """
        X-Nginx-* wildcard pattern matches any header starting with
        'X-Nginx-'.  This reveals Nginx details.
        """
        from webinspector.modules.disclosure_scanner import DisclosureScanner

        response = _make_response({"X-Nginx-Cache-Status": "HIT"})
        scanner = DisclosureScanner()
        findings = scanner.scan(https_target, http_response=response)

        nginx = [f for f in findings if f.title == "X-Nginx-Cache-Status"]
        assert len(nginx) == 1
        assert nginx[0].finding_type == "Load Balancer"

    def test_detects_x_proxy_cache(self, https_target):
        """X-Proxy-Cache reveals proxy cache status."""
        from webinspector.modules.disclosure_scanner import DisclosureScanner

        response = _make_response({"X-Proxy-Cache": "MISS"})
        scanner = DisclosureScanner()
        findings = scanner.scan(https_target, http_response=response)

        proxy = [f for f in findings if f.title == "X-Proxy-Cache"]
        assert len(proxy) == 1
        assert proxy[0].finding_type == "Load Balancer"


# ===========================================================================
# Tests for Authentication headers
# ===========================================================================

class TestAuthenticationHeaders:
    """Verify detection of Authentication disclosure headers."""

    def test_detects_x_auth_server(self, https_target):
        """X-Auth-Server reveals the authentication server identity."""
        from webinspector.modules.disclosure_scanner import DisclosureScanner

        response = _make_response({"X-Auth-Server": "auth.internal.corp"})
        scanner = DisclosureScanner()
        findings = scanner.scan(https_target, http_response=response)

        auth = [f for f in findings if f.title == "X-Auth-Server"]
        assert len(auth) == 1
        assert auth[0].finding_type == "Authentication"
        assert auth[0].severity == Severity.INFORMATIONAL

    def test_detects_x_oauth_scopes(self, https_target):
        """X-OAuth-Scopes reveals the granted OAuth scopes."""
        from webinspector.modules.disclosure_scanner import DisclosureScanner

        response = _make_response({"X-OAuth-Scopes": "read, write, admin"})
        scanner = DisclosureScanner()
        findings = scanner.scan(https_target, http_response=response)

        oauth = [f for f in findings if f.title == "X-OAuth-Scopes"]
        assert len(oauth) == 1
        assert oauth[0].finding_type == "Authentication"

    def test_detects_x_accepted_oauth_scopes(self, https_target):
        """X-Accepted-OAuth-Scopes reveals the accepted OAuth scopes."""
        from webinspector.modules.disclosure_scanner import DisclosureScanner

        response = _make_response({"X-Accepted-OAuth-Scopes": "read, write"})
        scanner = DisclosureScanner()
        findings = scanner.scan(https_target, http_response=response)

        accepted = [f for f in findings if f.title == "X-Accepted-OAuth-Scopes"]
        assert len(accepted) == 1
        assert accepted[0].finding_type == "Authentication"


# ===========================================================================
# Tests for Miscellaneous headers
# ===========================================================================

class TestMiscellaneousHeaders:
    """Verify detection of Miscellaneous disclosure headers."""

    def test_detects_x_hostname(self, https_target):
        """X-Hostname reveals the internal hostname of the server."""
        from webinspector.modules.disclosure_scanner import DisclosureScanner

        response = _make_response({"X-Hostname": "web-prod-01.internal"})
        scanner = DisclosureScanner()
        findings = scanner.scan(https_target, http_response=response)

        hostname = [f for f in findings if f.title == "X-Hostname"]
        assert len(hostname) == 1
        assert hostname[0].finding_type == "Miscellaneous"
        assert hostname[0].severity == Severity.INFORMATIONAL

    def test_detects_x_instance_id(self, https_target):
        """X-Instance-ID reveals the server instance identifier."""
        from webinspector.modules.disclosure_scanner import DisclosureScanner

        response = _make_response({"X-Instance-ID": "i-0abc123def456"})
        scanner = DisclosureScanner()
        findings = scanner.scan(https_target, http_response=response)

        instance = [f for f in findings if f.title == "X-Instance-ID"]
        assert len(instance) == 1
        assert instance[0].finding_type == "Miscellaneous"

    def test_detects_x_datacenter(self, https_target):
        """X-Datacenter reveals the datacenter location."""
        from webinspector.modules.disclosure_scanner import DisclosureScanner

        response = _make_response({"X-Datacenter": "us-east-1"})
        scanner = DisclosureScanner()
        findings = scanner.scan(https_target, http_response=response)

        dc = [f for f in findings if f.title == "X-Datacenter"]
        assert len(dc) == 1
        assert dc[0].finding_type == "Miscellaneous"

    def test_detects_x_node(self, https_target):
        """X-Node reveals the cluster node serving the request."""
        from webinspector.modules.disclosure_scanner import DisclosureScanner

        response = _make_response({"X-Node": "node-03"})
        scanner = DisclosureScanner()
        findings = scanner.scan(https_target, http_response=response)

        node = [f for f in findings if f.title == "X-Node"]
        assert len(node) == 1
        assert node[0].finding_type == "Miscellaneous"

    def test_detects_x_request_handler(self, https_target):
        """X-Request-Handler reveals the request handler identity."""
        from webinspector.modules.disclosure_scanner import DisclosureScanner

        response = _make_response({"X-Request-Handler": "handler-app-01"})
        scanner = DisclosureScanner()
        findings = scanner.scan(https_target, http_response=response)

        handler = [f for f in findings if f.title == "X-Request-Handler"]
        assert len(handler) == 1
        assert handler[0].finding_type == "Miscellaneous"

    def test_detects_x_pool(self, https_target):
        """X-Pool reveals the server pool serving the request."""
        from webinspector.modules.disclosure_scanner import DisclosureScanner

        response = _make_response({"X-Pool": "web-pool-east"})
        scanner = DisclosureScanner()
        findings = scanner.scan(https_target, http_response=response)

        pool = [f for f in findings if f.title == "X-Pool"]
        assert len(pool) == 1
        assert pool[0].finding_type == "Miscellaneous"

    def test_detects_x_rack(self, https_target):
        """X-Rack reveals the physical/logical rack identifier."""
        from webinspector.modules.disclosure_scanner import DisclosureScanner

        response = _make_response({"X-Rack": "rack-A2"})
        scanner = DisclosureScanner()
        findings = scanner.scan(https_target, http_response=response)

        rack = [f for f in findings if f.title == "X-Rack"]
        assert len(rack) == 1
        assert rack[0].finding_type == "Miscellaneous"

    def test_detects_x_cluster_name(self, https_target):
        """X-Cluster-Name reveals the cluster name."""
        from webinspector.modules.disclosure_scanner import DisclosureScanner

        response = _make_response({"X-Cluster-Name": "prod-east-cluster"})
        scanner = DisclosureScanner()
        findings = scanner.scan(https_target, http_response=response)

        cluster = [f for f in findings if f.title == "X-Cluster-Name"]
        assert len(cluster) == 1
        assert cluster[0].finding_type == "Miscellaneous"


# ===========================================================================
# Tests for wildcard/prefix pattern matching
# ===========================================================================

class TestWildcardPatterns:
    """
    Verify that wildcard/prefix patterns correctly match headers.

    Some disclosure headers use prefix matching (e.g., X-Wix-*, X-Akamai-*,
    X-Kubernetes-*, X-Docker-*, X-Haproxy-*, X-Nginx-*, X-Oracle-DMS-*).
    These should match any header that starts with the prefix.
    """

    def test_x_wix_any_suffix(self, https_target):
        """X-Wix-* should match any X-Wix- prefixed header."""
        from webinspector.modules.disclosure_scanner import DisclosureScanner

        response = _make_response({
            "X-Wix-Some-Custom-Header": "value1",
            "X-Wix-Another": "value2",
        })
        scanner = DisclosureScanner()
        findings = scanner.scan(https_target, http_response=response)

        wix = [f for f in findings if f.title.startswith("X-Wix-")]
        assert len(wix) == 2

    def test_x_oracle_dms_prefix(self, https_target):
        """X-Oracle-DMS-* should match any X-Oracle-DMS- prefixed header."""
        from webinspector.modules.disclosure_scanner import DisclosureScanner

        response = _make_response({"X-Oracle-DMS-Request-Id": "dms-123"})
        scanner = DisclosureScanner()
        findings = scanner.scan(https_target, http_response=response)

        oracle = [f for f in findings if f.title == "X-Oracle-DMS-Request-Id"]
        assert len(oracle) == 1
        assert oracle[0].finding_type == "Technology Stack"

    def test_prefix_case_insensitive(self, https_target):
        """
        Prefix matching should be case-insensitive per HTTP header conventions.
        """
        from webinspector.modules.disclosure_scanner import DisclosureScanner

        response = _make_response({"x-kubernetes-pod-name": "my-pod"})
        scanner = DisclosureScanner()
        findings = scanner.scan(https_target, http_response=response)

        k8s = [f for f in findings if "kubernetes" in f.title.lower()]
        assert len(k8s) == 1
        assert k8s[0].finding_type == "Container/Orchestration"

    def test_non_matching_prefix_no_finding(self, https_target):
        """
        Headers that look similar but don't match any known prefix
        should NOT produce findings.
        """
        from webinspector.modules.disclosure_scanner import DisclosureScanner

        response = _make_response({
            "X-Custom-Header": "some-value",
            "X-My-App-Debug": "true",
        })
        scanner = DisclosureScanner()
        findings = scanner.scan(https_target, http_response=response)
        assert len(findings) == 0


# ===========================================================================
# Tests for finding format and attributes
# ===========================================================================

class TestFindingFormat:
    """Verify that findings have the correct format and attributes."""

    def test_all_findings_are_informational(self, https_target):
        """
        All disclosure findings should have severity INFORMATIONAL.
        Information disclosure headers are not vulnerabilities themselves,
        but they reveal useful reconnaissance data.
        """
        from webinspector.modules.disclosure_scanner import DisclosureScanner

        response = _make_response({
            "Server": "nginx/1.18.0",
            "X-Powered-By": "PHP/8.1.2",
            "X-Debug-Token": "abc123",
            "Via": "1.1 varnish",
            "X-Varnish": "123456",
            "X-Container-Id": "abc",
            "X-LB-Server": "lb-01",
            "X-Auth-Server": "auth.internal",
            "X-Hostname": "web-01",
        })
        scanner = DisclosureScanner()
        findings = scanner.scan(https_target, http_response=response)

        assert len(findings) >= 9
        for finding in findings:
            assert finding.severity == Severity.INFORMATIONAL

    def test_all_findings_have_module_disclosure(self, https_target):
        """Every finding should have module='disclosure'."""
        from webinspector.modules.disclosure_scanner import DisclosureScanner

        response = _make_response({
            "Server": "Apache/2.4.54",
            "X-Debug-Token": "token123",
        })
        scanner = DisclosureScanner()
        findings = scanner.scan(https_target, http_response=response)

        for finding in findings:
            assert finding.module == "disclosure"

    def test_finding_type_is_category_name(self, https_target):
        """
        Finding type should be the category name (e.g., 'Technology Stack').
        This is used by the console/text renderers for category sub-headers.
        """
        from webinspector.modules.disclosure_scanner import DisclosureScanner

        response = _make_response({
            "Server": "nginx",
            "X-Debug-Token": "abc",
            "Via": "1.1 proxy",
            "X-Varnish": "123",
            "X-Container-Id": "abc",
            "X-LB-Server": "lb-01",
            "X-Auth-Server": "auth",
            "X-Hostname": "host-01",
        })
        scanner = DisclosureScanner()
        findings = scanner.scan(https_target, http_response=response)

        # Collect all unique finding types
        finding_types = {f.finding_type for f in findings}

        # Should have all 8 categories represented
        expected_categories = {
            "Technology Stack",
            "Debugging/Development",
            "Infrastructure/Proxy",
            "Caching/CDN",
            "Container/Orchestration",
            "Load Balancer",
            "Authentication",
            "Miscellaneous",
        }
        assert finding_types == expected_categories

    def test_finding_title_is_header_name(self, https_target):
        """Finding title should be the header name as found in the response."""
        from webinspector.modules.disclosure_scanner import DisclosureScanner

        response = _make_response({"X-Powered-By": "Express"})
        scanner = DisclosureScanner()
        findings = scanner.scan(https_target, http_response=response)

        assert len(findings) == 1
        assert findings[0].title == "X-Powered-By"

    def test_finding_detail_is_header_value(self, https_target):
        """Finding detail should be the header value."""
        from webinspector.modules.disclosure_scanner import DisclosureScanner

        response = _make_response({"Server": "Apache/2.4.54 (Ubuntu)"})
        scanner = DisclosureScanner()
        findings = scanner.scan(https_target, http_response=response)

        server = [f for f in findings if f.title == "Server"]
        assert len(server) == 1
        assert server[0].detail == "Apache/2.4.54 (Ubuntu)"

    def test_finding_target_is_correct(self, https_target):
        """Each finding should reference the correct target object."""
        from webinspector.modules.disclosure_scanner import DisclosureScanner

        response = _make_response({"X-Powered-By": "PHP"})
        scanner = DisclosureScanner()
        findings = scanner.scan(https_target, http_response=response)

        assert len(findings) == 1
        assert findings[0].target is https_target


# ===========================================================================
# Tests for multiple disclosure headers in one response
# ===========================================================================

class TestMultipleHeaders:
    """Verify handling of multiple disclosure headers in a single response."""

    def test_multiple_headers_all_detected(self, https_target):
        """
        A response with multiple disclosure headers should produce one
        finding per disclosure header detected.
        """
        from webinspector.modules.disclosure_scanner import DisclosureScanner

        response = _make_response({
            "Server": "nginx/1.18.0",
            "X-Powered-By": "PHP/8.1.2",
            "X-AspNet-Version": "4.0.30319",
            "X-Debug-Token": "abc123",
            "Via": "1.1 varnish",
            "X-Varnish": "123456",
            "CF-Ray": "7a1b2c-LAX",
        })
        scanner = DisclosureScanner()
        findings = scanner.scan(https_target, http_response=response)

        # Should have one finding per disclosure header
        assert len(findings) == 7

        # Verify all header names are represented
        titles = {f.title for f in findings}
        assert "Server" in titles
        assert "X-Powered-By" in titles
        assert "X-AspNet-Version" in titles
        assert "X-Debug-Token" in titles
        assert "Via" in titles
        assert "X-Varnish" in titles
        assert "CF-Ray" in titles

    def test_mixed_disclosure_and_normal_headers(self, https_target):
        """
        Only disclosure headers should produce findings.  Standard
        headers like Content-Type, Content-Length, etc. should be ignored.
        """
        from webinspector.modules.disclosure_scanner import DisclosureScanner

        response = _make_response({
            "Content-Type": "text/html",
            "Content-Length": "1234",
            "Date": "Mon, 24 Feb 2026 00:00:00 GMT",
            "Server": "nginx/1.18.0",      # <-- disclosure
            "X-Powered-By": "Express",       # <-- disclosure
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
        })
        scanner = DisclosureScanner()
        findings = scanner.scan(https_target, http_response=response)

        # Only 2 disclosure headers present
        assert len(findings) == 2

    def test_same_category_multiple_headers(self, https_target):
        """
        Multiple headers from the same category should each produce
        separate findings, all with the same finding_type.
        """
        from webinspector.modules.disclosure_scanner import DisclosureScanner

        response = _make_response({
            "X-Powered-By": "PHP/8.1.2",
            "Server": "Apache/2.4.54",
            "X-AspNet-Version": "4.0.30319",
            "X-Generator": "WordPress 6.4",
        })
        scanner = DisclosureScanner()
        findings = scanner.scan(https_target, http_response=response)

        # All should be "Technology Stack" category
        assert len(findings) == 4
        for f in findings:
            assert f.finding_type == "Technology Stack"


# ===========================================================================
# Tests for case-insensitive header matching
# ===========================================================================

class TestCaseInsensitiveMatching:
    """Verify that header matching is case-insensitive."""

    def test_lowercase_header_detected(self, https_target):
        """
        HTTP headers are case-insensitive per RFC 7230 Section 3.2.
        A lowercase 'server' header should be detected as 'Server'.
        """
        from webinspector.modules.disclosure_scanner import DisclosureScanner

        response = _make_response({"server": "nginx/1.18.0"})
        scanner = DisclosureScanner()
        findings = scanner.scan(https_target, http_response=response)

        server = [f for f in findings if "server" in f.title.lower()
                  and f.finding_type == "Technology Stack"]
        assert len(server) == 1

    def test_mixed_case_header_detected(self, https_target):
        """Mixed case headers should still be detected."""
        from webinspector.modules.disclosure_scanner import DisclosureScanner

        response = _make_response({"x-POWERED-by": "Express"})
        scanner = DisclosureScanner()
        findings = scanner.scan(https_target, http_response=response)

        powered = [f for f in findings if "powered" in f.title.lower()]
        assert len(powered) == 1


# ===========================================================================
# Tests for module registration
# ===========================================================================

class TestDisclosureScannerRegistration:
    """Verify that importing the module registers it."""

    def test_module_registers(self):
        """
        Importing disclosure_scanner should call register_module() at the
        bottom of the file, making it discoverable by the module registry.
        """
        from webinspector.modules import _registry
        from webinspector.modules.disclosure_scanner import DisclosureScanner

        # The module registers itself at import time.
        # Check that an instance of DisclosureScanner is in the registry.
        disclosure_modules = [m for m in _registry if m.name == "disclosure"]
        assert len(disclosure_modules) >= 1
        assert isinstance(disclosure_modules[0], DisclosureScanner)
