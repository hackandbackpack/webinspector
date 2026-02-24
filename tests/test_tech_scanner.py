"""
Tests for the technology fingerprinting scanner module (tech_scanner.py).

These tests verify that the TechScanner module correctly:
    1. Has the correct name ("tech") and a non-empty description
    2. Accepts both HTTP and HTTPS targets (default accepts_target)
    3. Produces a single INFORMATIONAL finding with detected technologies
    4. Formats technology names with version info when available
    5. Groups technologies by category in the detail string
    6. Returns empty findings when no technologies are detected
    7. Returns empty findings when webtech is not installed (graceful degradation)
    8. Returns empty findings when webtech raises an exception
    9. Registers itself with the module registry at import time

All webtech interactions are mocked -- no real HTTP connections are made.
webtech makes its own HTTP requests internally, so we mock the WebTech class
and its start_from_url() method to return controlled tech detection results.

Author: Red Siege Information Security
"""

import pytest
from unittest.mock import patch, MagicMock

from webinspector.core.target import Target
from webinspector.core.result import Finding, Severity


# ---------------------------------------------------------------------------
# Target fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def https_target():
    """An HTTPS target for technology scanning."""
    return Target(host="example.com", port=443, scheme="https")


@pytest.fixture
def http_target():
    """An HTTP target for technology scanning."""
    return Target(host="example.com", port=80, scheme="http")


# ===========================================================================
# Tests for module properties
# ===========================================================================

class TestTechScannerProperties:
    """Verify name and description properties."""

    def test_name(self):
        """Module name should be 'tech'."""
        from webinspector.modules.tech_scanner import TechScanner
        scanner = TechScanner()
        assert scanner.name == "tech"

    def test_description(self):
        """Module should have a non-empty description."""
        from webinspector.modules.tech_scanner import TechScanner
        scanner = TechScanner()
        assert len(scanner.description) > 0
        # Should mention technology or fingerprint in the description
        desc_lower = scanner.description.lower()
        assert "technolog" in desc_lower or "fingerprint" in desc_lower


# ===========================================================================
# Tests for accepts_target
# ===========================================================================

class TestTechScannerAcceptsTarget:
    """Verify that the tech scanner accepts all targets (both HTTP and HTTPS)."""

    def test_accepts_https(self, https_target):
        """Tech scanner should accept HTTPS targets."""
        from webinspector.modules.tech_scanner import TechScanner
        scanner = TechScanner()
        assert scanner.accepts_target(https_target) is True

    def test_accepts_http(self, http_target):
        """Tech scanner should accept HTTP targets."""
        from webinspector.modules.tech_scanner import TechScanner
        scanner = TechScanner()
        assert scanner.accepts_target(http_target) is True


# ===========================================================================
# Tests for technology detection
# ===========================================================================

class TestTechDetection:
    """Verify that detected technologies are correctly reported."""

    @patch("webinspector.modules.tech_scanner.webtech")
    def test_single_technology_detected(self, mock_webtech_mod, https_target):
        """
        When webtech detects a single technology, the scanner should produce
        one INFORMATIONAL finding with the technology name in the detail.
        """
        from webinspector.modules.tech_scanner import TechScanner

        # Configure mock: webtech detects nginx
        mock_wt_instance = MagicMock()
        mock_wt_instance.start_from_url.return_value = {
            "tech": [
                {"name": "nginx", "categories": ["Web servers"]},
            ]
        }
        mock_webtech_mod.WebTech.return_value = mock_wt_instance

        scanner = TechScanner()
        findings = scanner.scan(https_target)

        # Should produce exactly one finding
        assert len(findings) == 1
        assert findings[0].finding_type == "technology_detected"
        assert findings[0].severity == Severity.INFORMATIONAL
        assert findings[0].module == "tech"
        assert "nginx" in findings[0].detail

    @patch("webinspector.modules.tech_scanner.webtech")
    def test_multiple_technologies_detected(self, mock_webtech_mod, https_target):
        """
        When webtech detects multiple technologies, all should appear in a
        single finding's detail string, comma-separated.
        """
        from webinspector.modules.tech_scanner import TechScanner

        # Configure mock: webtech detects multiple technologies
        mock_wt_instance = MagicMock()
        mock_wt_instance.start_from_url.return_value = {
            "tech": [
                {"name": "nginx", "categories": ["Web servers"]},
                {"name": "PHP", "categories": ["Programming languages"]},
                {"name": "WordPress", "categories": ["CMS"]},
            ]
        }
        mock_webtech_mod.WebTech.return_value = mock_wt_instance

        scanner = TechScanner()
        findings = scanner.scan(https_target)

        # Should produce exactly one finding with all technologies
        assert len(findings) == 1
        assert findings[0].finding_type == "technology_detected"
        assert findings[0].severity == Severity.INFORMATIONAL
        # All three technologies should be mentioned
        assert "nginx" in findings[0].detail
        assert "PHP" in findings[0].detail
        assert "WordPress" in findings[0].detail

    @patch("webinspector.modules.tech_scanner.webtech")
    def test_technology_with_version(self, mock_webtech_mod, https_target):
        """
        When webtech provides version information, it should be included
        in the detail string (e.g., "nginx/1.18.0").
        """
        from webinspector.modules.tech_scanner import TechScanner

        # Configure mock: webtech detects versioned technologies
        mock_wt_instance = MagicMock()
        mock_wt_instance.start_from_url.return_value = {
            "tech": [
                {"name": "nginx", "categories": ["Web servers"], "version": "1.18.0"},
                {"name": "PHP", "categories": ["Programming languages"], "version": "8.1.2"},
            ]
        }
        mock_webtech_mod.WebTech.return_value = mock_wt_instance

        scanner = TechScanner()
        findings = scanner.scan(https_target)

        assert len(findings) == 1
        # Version info should be included in the detail
        detail = findings[0].detail
        assert "1.18.0" in detail
        assert "8.1.2" in detail

    @patch("webinspector.modules.tech_scanner.webtech")
    def test_technology_without_version(self, mock_webtech_mod, https_target):
        """
        When webtech does not provide version information for a technology,
        only the name should appear (no trailing slash or empty version).
        """
        from webinspector.modules.tech_scanner import TechScanner

        # Configure mock: technology without version key
        mock_wt_instance = MagicMock()
        mock_wt_instance.start_from_url.return_value = {
            "tech": [
                {"name": "WordPress", "categories": ["CMS"]},
            ]
        }
        mock_webtech_mod.WebTech.return_value = mock_wt_instance

        scanner = TechScanner()
        findings = scanner.scan(https_target)

        assert len(findings) == 1
        detail = findings[0].detail
        # Should contain just the name without a trailing slash
        assert "WordPress" in detail
        # Should NOT have trailing slash or empty version marker
        assert "WordPress/" not in detail

    @patch("webinspector.modules.tech_scanner.webtech")
    def test_mixed_versioned_and_unversioned(self, mock_webtech_mod, https_target):
        """
        A mix of versioned and unversioned technologies should be formatted
        correctly: "nginx/1.18.0, WordPress" (version only where available).
        """
        from webinspector.modules.tech_scanner import TechScanner

        mock_wt_instance = MagicMock()
        mock_wt_instance.start_from_url.return_value = {
            "tech": [
                {"name": "nginx", "categories": ["Web servers"], "version": "1.18.0"},
                {"name": "WordPress", "categories": ["CMS"]},
                {"name": "PHP", "categories": ["Programming languages"], "version": "8.1.2"},
            ]
        }
        mock_webtech_mod.WebTech.return_value = mock_wt_instance

        scanner = TechScanner()
        findings = scanner.scan(https_target)

        assert len(findings) == 1
        detail = findings[0].detail
        # Versioned tech should show "name/version"
        assert "nginx/1.18.0" in detail
        assert "PHP/8.1.2" in detail
        # Unversioned tech should show just the name
        assert "WordPress" in detail

    @patch("webinspector.modules.tech_scanner.webtech")
    def test_uses_target_url(self, mock_webtech_mod, https_target):
        """
        The scanner should pass target.url to webtech's start_from_url(),
        because webtech makes its own HTTP requests internally.
        """
        from webinspector.modules.tech_scanner import TechScanner

        mock_wt_instance = MagicMock()
        mock_wt_instance.start_from_url.return_value = {
            "tech": [{"name": "nginx", "categories": ["Web servers"]}]
        }
        mock_webtech_mod.WebTech.return_value = mock_wt_instance

        scanner = TechScanner()
        scanner.scan(https_target)

        # Verify that start_from_url was called with the target's URL
        mock_wt_instance.start_from_url.assert_called_once_with(https_target.url)

    @patch("webinspector.modules.tech_scanner.webtech")
    def test_webtech_options_json(self, mock_webtech_mod, https_target):
        """
        The scanner should instantiate WebTech with json option enabled
        to get structured output.
        """
        from webinspector.modules.tech_scanner import TechScanner

        mock_wt_instance = MagicMock()
        mock_wt_instance.start_from_url.return_value = {"tech": []}
        mock_webtech_mod.WebTech.return_value = mock_wt_instance

        scanner = TechScanner()
        scanner.scan(https_target)

        # Verify WebTech was instantiated with json option
        mock_webtech_mod.WebTech.assert_called_once_with(options={"json": True})


# ===========================================================================
# Tests for no technologies detected
# ===========================================================================

class TestNoTechDetected:
    """Verify behaviour when no technologies are found."""

    @patch("webinspector.modules.tech_scanner.webtech")
    def test_empty_tech_list(self, mock_webtech_mod, https_target):
        """
        When webtech returns an empty tech list, the scanner should
        return an empty findings list (no finding to report).
        """
        from webinspector.modules.tech_scanner import TechScanner

        mock_wt_instance = MagicMock()
        mock_wt_instance.start_from_url.return_value = {"tech": []}
        mock_webtech_mod.WebTech.return_value = mock_wt_instance

        scanner = TechScanner()
        findings = scanner.scan(https_target)

        assert isinstance(findings, list)
        assert len(findings) == 0

    @patch("webinspector.modules.tech_scanner.webtech")
    def test_missing_tech_key(self, mock_webtech_mod, https_target):
        """
        When webtech returns a dict without a 'tech' key, the scanner
        should handle it gracefully and return empty findings.
        """
        from webinspector.modules.tech_scanner import TechScanner

        mock_wt_instance = MagicMock()
        mock_wt_instance.start_from_url.return_value = {}
        mock_webtech_mod.WebTech.return_value = mock_wt_instance

        scanner = TechScanner()
        findings = scanner.scan(https_target)

        assert isinstance(findings, list)
        assert len(findings) == 0


# ===========================================================================
# Tests for finding properties
# ===========================================================================

class TestFindingProperties:
    """Verify that the produced finding has the correct attributes."""

    @patch("webinspector.modules.tech_scanner.webtech")
    def test_finding_module_is_tech(self, mock_webtech_mod, https_target):
        """Every finding should have module='tech'."""
        from webinspector.modules.tech_scanner import TechScanner

        mock_wt_instance = MagicMock()
        mock_wt_instance.start_from_url.return_value = {
            "tech": [{"name": "nginx", "categories": ["Web servers"]}]
        }
        mock_webtech_mod.WebTech.return_value = mock_wt_instance

        scanner = TechScanner()
        findings = scanner.scan(https_target)

        assert len(findings) == 1
        assert findings[0].module == "tech"

    @patch("webinspector.modules.tech_scanner.webtech")
    def test_finding_target_is_correct(self, mock_webtech_mod, https_target):
        """The finding's target should be the same Target object passed to scan()."""
        from webinspector.modules.tech_scanner import TechScanner

        mock_wt_instance = MagicMock()
        mock_wt_instance.start_from_url.return_value = {
            "tech": [{"name": "nginx", "categories": ["Web servers"]}]
        }
        mock_webtech_mod.WebTech.return_value = mock_wt_instance

        scanner = TechScanner()
        findings = scanner.scan(https_target)

        assert len(findings) == 1
        assert findings[0].target is https_target

    @patch("webinspector.modules.tech_scanner.webtech")
    def test_finding_references_empty(self, mock_webtech_mod, https_target):
        """
        Technology detection is informational -- the references list should
        be empty (no CWE or vulnerability reference).
        """
        from webinspector.modules.tech_scanner import TechScanner

        mock_wt_instance = MagicMock()
        mock_wt_instance.start_from_url.return_value = {
            "tech": [{"name": "nginx", "categories": ["Web servers"]}]
        }
        mock_webtech_mod.WebTech.return_value = mock_wt_instance

        scanner = TechScanner()
        findings = scanner.scan(https_target)

        assert len(findings) == 1
        assert findings[0].references == []

    @patch("webinspector.modules.tech_scanner.webtech")
    def test_finding_severity_informational(self, mock_webtech_mod, https_target):
        """The finding severity must be INFORMATIONAL."""
        from webinspector.modules.tech_scanner import TechScanner

        mock_wt_instance = MagicMock()
        mock_wt_instance.start_from_url.return_value = {
            "tech": [{"name": "nginx", "categories": ["Web servers"]}]
        }
        mock_webtech_mod.WebTech.return_value = mock_wt_instance

        scanner = TechScanner()
        findings = scanner.scan(https_target)

        assert len(findings) == 1
        assert findings[0].severity == Severity.INFORMATIONAL

    @patch("webinspector.modules.tech_scanner.webtech")
    def test_finding_has_title(self, mock_webtech_mod, https_target):
        """The finding should have a non-empty, descriptive title."""
        from webinspector.modules.tech_scanner import TechScanner

        mock_wt_instance = MagicMock()
        mock_wt_instance.start_from_url.return_value = {
            "tech": [{"name": "nginx", "categories": ["Web servers"]}]
        }
        mock_webtech_mod.WebTech.return_value = mock_wt_instance

        scanner = TechScanner()
        findings = scanner.scan(https_target)

        assert len(findings) == 1
        assert len(findings[0].title) > 0


# ===========================================================================
# Tests for technology grouping by category
# ===========================================================================

class TestTechGroupingByCategory:
    """Verify that technologies are grouped by category in the detail."""

    @patch("webinspector.modules.tech_scanner.webtech")
    def test_categories_appear_in_detail(self, mock_webtech_mod, https_target):
        """
        When technologies have categories, those categories should appear
        in the finding detail to help the analyst understand the stack.
        """
        from webinspector.modules.tech_scanner import TechScanner

        mock_wt_instance = MagicMock()
        mock_wt_instance.start_from_url.return_value = {
            "tech": [
                {"name": "nginx", "categories": ["Web servers"], "version": "1.18.0"},
                {"name": "PHP", "categories": ["Programming languages"], "version": "8.1.2"},
                {"name": "WordPress", "categories": ["CMS"], "version": "6.4"},
            ]
        }
        mock_webtech_mod.WebTech.return_value = mock_wt_instance

        scanner = TechScanner()
        findings = scanner.scan(https_target)

        assert len(findings) == 1
        detail = findings[0].detail
        # Category names should appear in the detail
        assert "Web servers" in detail
        assert "Programming languages" in detail
        assert "CMS" in detail

    @patch("webinspector.modules.tech_scanner.webtech")
    def test_multiple_techs_same_category(self, mock_webtech_mod, https_target):
        """
        Technologies in the same category should be grouped together
        under one category heading.
        """
        from webinspector.modules.tech_scanner import TechScanner

        mock_wt_instance = MagicMock()
        mock_wt_instance.start_from_url.return_value = {
            "tech": [
                {"name": "nginx", "categories": ["Web servers"], "version": "1.18.0"},
                {"name": "Apache", "categories": ["Web servers"], "version": "2.4.54"},
            ]
        }
        mock_webtech_mod.WebTech.return_value = mock_wt_instance

        scanner = TechScanner()
        findings = scanner.scan(https_target)

        assert len(findings) == 1
        detail = findings[0].detail
        # Both technologies should appear and the category should appear
        assert "nginx/1.18.0" in detail
        assert "Apache/2.4.54" in detail
        assert "Web servers" in detail

    @patch("webinspector.modules.tech_scanner.webtech")
    def test_tech_with_no_categories(self, mock_webtech_mod, https_target):
        """
        Technologies without a categories key should be grouped under
        a fallback 'Other' category.
        """
        from webinspector.modules.tech_scanner import TechScanner

        mock_wt_instance = MagicMock()
        mock_wt_instance.start_from_url.return_value = {
            "tech": [
                {"name": "CustomLib"},
            ]
        }
        mock_webtech_mod.WebTech.return_value = mock_wt_instance

        scanner = TechScanner()
        findings = scanner.scan(https_target)

        assert len(findings) == 1
        detail = findings[0].detail
        assert "CustomLib" in detail
        # Should have a fallback category
        assert "Other" in detail

    @patch("webinspector.modules.tech_scanner.webtech")
    def test_tech_with_empty_categories(self, mock_webtech_mod, https_target):
        """
        Technologies with an empty categories list should be grouped under
        a fallback 'Other' category.
        """
        from webinspector.modules.tech_scanner import TechScanner

        mock_wt_instance = MagicMock()
        mock_wt_instance.start_from_url.return_value = {
            "tech": [
                {"name": "CustomLib", "categories": []},
            ]
        }
        mock_webtech_mod.WebTech.return_value = mock_wt_instance

        scanner = TechScanner()
        findings = scanner.scan(https_target)

        assert len(findings) == 1
        detail = findings[0].detail
        assert "CustomLib" in detail
        assert "Other" in detail


# ===========================================================================
# Tests for error handling and graceful degradation
# ===========================================================================

class TestErrorHandling:
    """Verify graceful handling of errors and missing dependencies."""

    @patch("webinspector.modules.tech_scanner.WEBTECH_AVAILABLE", False)
    def test_webtech_not_installed(self, https_target):
        """
        When webtech is not installed (WEBTECH_AVAILABLE=False), the
        scanner should return an empty list without error.
        """
        from webinspector.modules.tech_scanner import TechScanner

        scanner = TechScanner()
        findings = scanner.scan(https_target)

        assert isinstance(findings, list)
        assert len(findings) == 0

    @patch("webinspector.modules.tech_scanner.webtech")
    def test_webtech_exception_during_scan(self, mock_webtech_mod, https_target):
        """
        When webtech raises an exception during URL analysis, the scanner
        should catch it gracefully and return an empty findings list.
        """
        from webinspector.modules.tech_scanner import TechScanner

        mock_wt_instance = MagicMock()
        mock_wt_instance.start_from_url.side_effect = Exception(
            "Connection refused"
        )
        mock_webtech_mod.WebTech.return_value = mock_wt_instance

        scanner = TechScanner()
        findings = scanner.scan(https_target)

        assert isinstance(findings, list)
        assert len(findings) == 0

    @patch("webinspector.modules.tech_scanner.webtech")
    def test_webtech_init_exception(self, mock_webtech_mod, https_target):
        """
        When WebTech() constructor raises an exception, the scanner
        should catch it gracefully and return an empty findings list.
        """
        from webinspector.modules.tech_scanner import TechScanner

        mock_webtech_mod.WebTech.side_effect = Exception("Init failed")

        scanner = TechScanner()
        findings = scanner.scan(https_target)

        assert isinstance(findings, list)
        assert len(findings) == 0

    @patch("webinspector.modules.tech_scanner.webtech")
    def test_webtech_returns_none(self, mock_webtech_mod, https_target):
        """
        When webtech returns None instead of a dict, the scanner should
        handle it gracefully and return empty findings.
        """
        from webinspector.modules.tech_scanner import TechScanner

        mock_wt_instance = MagicMock()
        mock_wt_instance.start_from_url.return_value = None
        mock_webtech_mod.WebTech.return_value = mock_wt_instance

        scanner = TechScanner()
        findings = scanner.scan(https_target)

        assert isinstance(findings, list)
        assert len(findings) == 0


# ===========================================================================
# Tests for HTTP target scanning
# ===========================================================================

class TestHTTPTarget:
    """Verify scanning works with HTTP targets too."""

    @patch("webinspector.modules.tech_scanner.webtech")
    def test_scan_http_target(self, mock_webtech_mod, http_target):
        """
        The tech scanner should work with HTTP targets (not just HTTPS).
        webtech makes its own requests, so scheme does not matter to us.
        """
        from webinspector.modules.tech_scanner import TechScanner

        mock_wt_instance = MagicMock()
        mock_wt_instance.start_from_url.return_value = {
            "tech": [
                {"name": "Apache", "categories": ["Web servers"], "version": "2.4.54"},
            ]
        }
        mock_webtech_mod.WebTech.return_value = mock_wt_instance

        scanner = TechScanner()
        findings = scanner.scan(http_target)

        assert len(findings) == 1
        assert "Apache" in findings[0].detail
        # Should use the HTTP target's URL
        mock_wt_instance.start_from_url.assert_called_once_with(http_target.url)


# ===========================================================================
# Test module registration
# ===========================================================================

class TestTechScannerRegistration:
    """Verify that importing the module registers it."""

    def test_module_registers(self):
        """
        Importing tech_scanner should call register_module() at the bottom
        of the file, making it discoverable by the module registry.
        """
        from webinspector.modules import _registry
        from webinspector.modules.tech_scanner import TechScanner

        # The module registers itself at import time.
        # Check that an instance of TechScanner is in the registry.
        tech_modules = [m for m in _registry if m.name == "tech"]
        assert len(tech_modules) >= 1
        assert isinstance(tech_modules[0], TechScanner)
