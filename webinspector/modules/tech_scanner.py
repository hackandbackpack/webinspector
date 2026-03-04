"""
webinspector.modules.tech_scanner - Technology fingerprinting module using webtech.

Wraps the webtech library to identify technologies (web servers, frameworks,
CMS platforms, programming languages, JavaScript libraries, etc.) running on a
target.  This is a passive reconnaissance check that helps analysts understand
the target's technology stack without performing any destructive actions.

Technology fingerprinting is valuable for:
    - Identifying outdated software versions with known CVEs
    - Mapping the attack surface (e.g., WordPress plugins, PHP version)
    - Informing later manual testing (e.g., specific CMS exploits)
    - Providing context in the final report for non-technical stakeholders

webtech performs its own HTTP requests internally using the URL we provide.
Unlike other modules that use the pre-fetched http_response object, this module
passes target.url directly to webtech's start_from_url() method.  The
http_response parameter from the orchestrator is ignored.

Module design:
    - name: "tech"
    - Finding type: "technology_detected" (INFORMATIONAL severity)
    - One finding per target containing ALL detected technologies
    - Technologies are grouped by category (Web servers, CMS, etc.)
    - Detail format: "Category: tech1/ver, tech2; Category2: tech3"
    - References: empty (tech detection is informational, not a vulnerability)

webtech API:
    wt = webtech.WebTech(options={'json': True})
    report = wt.start_from_url(url)
    # report = {'tech': [{'name': 'nginx', 'categories': ['Web servers'], 'version': '1.18.0'}, ...]}

Graceful degradation:
    webtech import is wrapped in try/except.  If webtech is not installed, the
    module logs a warning and returns empty findings instead of crashing.  This
    ensures the rest of webinspector still works in environments where webtech
    is not available (e.g., minimal Docker images, CI pipelines).

Author: Red Siege Information Security
"""

import logging
from collections import defaultdict
from typing import Optional

from requests import Response

from webinspector.core.target import Target
from webinspector.core.result import Finding, Severity
from webinspector.modules.base import ScanModule
from webinspector.modules import register_module

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# webtech imports -- wrapped in try/except for graceful degradation
# ---------------------------------------------------------------------------
# webtech is an external library that performs technology fingerprinting via
# HTTP responses, headers, cookies, and HTML content analysis.  If it's not
# installed, the module simply won't produce any findings and will log a
# warning.  The rest of webinspector continues to function normally.

try:
    import webtech  # noqa: F401 — imported for use in scan(), not at module scope

    # WEBTECH_AVAILABLE is checked at scan time to short-circuit gracefully.
    WEBTECH_AVAILABLE = True
except ImportError:
    # webtech is not installed -- set the flag so scan() returns early.
    webtech = None  # type: ignore[assignment]
    WEBTECH_AVAILABLE = False
    logger.warning("webtech not installed - technology scanner will be disabled")

# ---------------------------------------------------------------------------
# Fallback category name for technologies without a category
# ---------------------------------------------------------------------------
# When webtech returns a technology that has no 'categories' key or an
# empty categories list, we group it under this fallback category name.
_FALLBACK_CATEGORY = "Other"


class TechScanner(ScanModule):
    """
    Technology fingerprinting scanner using the webtech library.

    Identifies web servers, CMS platforms, programming languages, JavaScript
    frameworks, and other technologies running on a target.  Produces a single
    INFORMATIONAL finding per target listing all detected technologies grouped
    by category.

    This module does NOT use the pre-fetched http_response from the
    orchestrator because webtech makes its own HTTP requests internally.
    It needs the URL, not a pre-fetched response object.
    """

    # -----------------------------------------------------------------
    # ScanModule interface -- required properties
    # -----------------------------------------------------------------

    @property
    def name(self) -> str:
        """Short identifier used in CLI flags and finding output."""
        return "tech"

    @property
    def description(self) -> str:
        """Human-readable description for --help output."""
        return "Technology fingerprinting and version detection (webtech)"

    # -----------------------------------------------------------------
    # ScanModule interface -- main scan method
    # -----------------------------------------------------------------

    def scan(
        self,
        target: Target,
        http_response: Optional[Response] = None,
    ) -> list[Finding]:
        """
        Run technology fingerprinting against a single target using webtech.

        This method:
            1. Checks that webtech is available (graceful degradation)
            2. Creates a WebTech instance with JSON output enabled
            3. Calls start_from_url() with the target's URL
            4. Parses the response to extract detected technologies
            5. Groups technologies by category
            6. Formats a single INFORMATIONAL finding with the results

        Args:
            target:        The target to fingerprint.
            http_response: Not used by this module.  webtech makes its own
                           HTTP requests internally using the URL we provide.

        Returns:
            List containing zero or one Finding objects.  Empty list means
            either no technologies were detected or webtech is unavailable.
        """
        # Guard: webtech not installed -- return empty instead of crashing.
        if not WEBTECH_AVAILABLE:
            logger.warning(
                "webtech not available, skipping tech scan for %s",
                target.hostport,
            )
            return []

        findings: list[Finding] = []

        try:
            # Create a WebTech instance with JSON output mode enabled.
            # The json option tells webtech to return structured data (dict)
            # instead of formatted text, making it easier to parse.
            wt = webtech.WebTech(options={"json": True})

            # Run the technology analysis.  webtech will make its own HTTP
            # request to the target URL, parse response headers, HTML content,
            # cookies, and JavaScript to identify technologies.
            report = wt.start_from_url(target.url)

            # Guard: webtech might return None on failure
            if report is None:
                logger.debug(
                    "webtech returned None for %s", target.hostport
                )
                return []

            # Extract the technology list from the report.
            # The 'tech' key contains a list of dicts, each with 'name',
            # 'categories', and optionally 'version' keys.
            tech_list = report.get("tech", [])

            # If no technologies were detected, return empty findings.
            # There's nothing informational to report.
            if not tech_list:
                return []

            # Group technologies by category for a well-organized detail string.
            # This makes it easy for analysts to see, for example, all CMS
            # platforms in one group and all web servers in another.
            detail_string = self._format_tech_detail(tech_list)

            # Create a single INFORMATIONAL finding listing all detected
            # technologies.  We use a single finding per target rather than
            # one per technology to keep the report concise -- technology
            # detection is context, not a vulnerability.
            findings.append(Finding(
                module="tech",
                finding_type="technology_detected",
                severity=Severity.INFORMATIONAL,
                target=target,
                title="Detected Technologies",
                detail=detail_string,
                references=[],  # Tech detection is informational -- no CWE refs
            ))

        except Exception as e:
            # Catch-all for webtech errors: connection refused, parse errors,
            # timeout, Content-Type mismatch, etc.  These are expected for
            # non-HTML services (APIs, raw TCP, etc.) so we log at DEBUG
            # to avoid flooding the output during scans with many ports.
            logger.debug(
                "webtech scan skipped for %s: %s", target.hostport, e
            )

        return findings

    # -----------------------------------------------------------------
    # Private helper methods
    # -----------------------------------------------------------------

    def _format_tech_name(self, tech: dict) -> str:
        """
        Format a single technology entry as a display string.

        Includes version information when available.  The format follows
        the convention used by webtech and common in security reports:
            - With version:    "nginx/1.18.0"
            - Without version: "WordPress"

        Args:
            tech: A dict from webtech's 'tech' list with at least a 'name'
                  key and optionally a 'version' key.

        Returns:
            Formatted technology string.
        """
        name = tech.get("name", "Unknown")
        version = tech.get("version", None)

        # Only append version if it's a non-empty string.
        # Some webtech entries have version=None or version="" when the
        # exact version could not be determined.
        if version:
            return f"{name}/{version}"

        return name

    def _format_tech_detail(self, tech_list: list) -> str:
        """
        Format the full technology list grouped by category.

        Technologies are grouped by their first category (or "Other" if
        no category is provided).  Within each category, technologies
        are listed as comma-separated values.  Categories are separated
        by semicolons.

        Example output:
            "Web servers: nginx/1.18.0, Apache/2.4.54; CMS: WordPress/6.4;
             Programming languages: PHP/8.1.2"

        Args:
            tech_list: List of technology dicts from webtech's report.
                       Each dict has 'name', 'categories', and optionally 'version'.

        Returns:
            Formatted detail string with technologies grouped by category.
        """
        # Group technologies by category.  We use defaultdict(list) so
        # appending to a new category automatically creates the list.
        categories: dict[str, list[str]] = defaultdict(list)

        for tech in tech_list:
            # Format the technology name (with optional version).
            tech_display = self._format_tech_name(tech)

            # Get the categories list for this technology.
            # webtech typically provides a list of category strings.
            tech_categories = tech.get("categories", [])

            # If the technology has no categories (missing key or empty list),
            # group it under the fallback "Other" category.
            if not tech_categories:
                categories[_FALLBACK_CATEGORY].append(tech_display)
            else:
                # Add the technology to each of its categories.
                # Most technologies belong to a single category, but some
                # may appear in multiple (e.g., "JavaScript frameworks" and
                # "Web frameworks").  We add it to the first category only
                # to avoid duplicate entries in the output.
                first_category = tech_categories[0]
                categories[first_category].append(tech_display)

        # Build the detail string: "Category: tech1, tech2; Category2: tech3"
        # We sort categories alphabetically for deterministic output.
        parts: list[str] = []
        for category in sorted(categories.keys()):
            techs_in_category = ", ".join(categories[category])
            parts.append(f"{category}: {techs_in_category}")

        return "; ".join(parts)


# ---------------------------------------------------------------------------
# Module registration
# ---------------------------------------------------------------------------
# Instantiate the scanner and register it with the module registry.
# This runs at import time, so importing this file is sufficient to make
# the tech scanner available to the orchestrator.

register_module(TechScanner())
