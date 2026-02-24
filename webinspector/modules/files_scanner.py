"""
webinspector.modules.files_scanner - robots.txt and security.txt scanner module.

Analyses well-known files on a web server to discover sensitive paths and verify
compliance with security reporting standards.  This module makes its OWN HTTP
requests (it does not rely on the orchestrator's pre-fetched response) because
it needs to fetch specific file paths (/robots.txt, /.well-known/security.txt,
/security.txt) that are separate from the target's main page.

Checks performed:

    1. robots.txt analysis:
       - Fetches /robots.txt from the target
       - Parses Disallow and Allow directives
       - Matches each path against a curated list of sensitive path patterns:
         admin, backup, config, api, git, svn, env, database, dump, export,
         internal, private, secret, temp, test, debug, log, wp-admin,
         phpmyadmin, .htaccess, .htpasswd, cgi-bin, server-status, server-info
       - Sensitive paths in robots.txt are flagged as LOW because their
         presence in robots.txt confirms the paths exist on the server and
         provides reconnaissance value to attackers
       - Finding type: "robots_sensitive_paths"

    2. security.txt analysis (RFC 9116):
       - Checks /.well-known/security.txt first (RFC 9116 primary location)
       - Falls back to /security.txt if the primary location returns 404
       - If found, validates required fields per RFC 9116:
         * Contact field (required) -- missing = LOW finding
         * Expires field (required) -- missing = LOW finding
         * Expires date in the past  -- expired = LOW finding
       - If security.txt is missing entirely (both locations return 404):
         INFORMATIONAL finding (finding_type: "missing_security_txt")
       - A valid security.txt with Contact and a future Expires produces
         no finding -- this is the desired state

    Why robots.txt matters for security:
        robots.txt is a plain-text file that tells search engine crawlers which
        paths to avoid.  While it has no enforcement mechanism (crawlers can
        ignore it), it is publicly accessible and effectively serves as a
        directory listing of paths the site owner considers sensitive.  Pentesters
        routinely check robots.txt for paths like /admin, /backup, /config,
        /.git, etc. that reveal the server's internal structure.

    Why security.txt matters (RFC 9116):
        security.txt is a standard that provides security researchers with a
        clear, machine-readable way to find vulnerability disclosure contact
        information.  Without it, researchers who discover vulnerabilities may
        not know how to report them, leading to public disclosure without
        coordination.  The standard requires:
            - Contact: URI (email or web form) for vulnerability reports
            - Expires: ISO 8601 datetime after which the file should be
              re-validated (prevents stale contact info)

CWE References:
    - CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
    - CWE-538: Insertion of Sensitive Information into Externally-Accessible
                File or Directory

Author: Red Siege Information Security
"""

import logging
import re
from datetime import datetime, timezone
from typing import Optional

from requests import Response

from webinspector.core.target import Target
from webinspector.core.result import Finding, Severity
from webinspector.modules.base import ScanModule
from webinspector.modules import register_module
from webinspector.utils.http import create_http_session

# Module-level logger for debug / error messages during file scanning.
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Sensitive path patterns for robots.txt analysis.
# These are substrings that, when found in a Disallow/Allow path, indicate
# the path is security-relevant.  The list covers common categories:
#
#   Administrative interfaces:  admin, wp-admin, phpmyadmin, cgi-bin
#   Configuration / secrets:    config, env, .htaccess, .htpasswd, secret
#   Source code repositories:   git, svn
#   Data / backups:             backup, database, dump, export
#   Internal / private:         internal, private, temp, test, debug, log
#   Server diagnostics:         server-status, server-info
#   API endpoints:              api
#
# Matching is case-insensitive and checks whether the pattern appears
# anywhere in the path string (substring match).
_SENSITIVE_PATH_PATTERNS = [
    "admin",
    "backup",
    "config",
    "api",
    "git",
    "svn",
    "env",
    "database",
    "dump",
    "export",
    "internal",
    "private",
    "secret",
    "temp",
    "test",
    "debug",
    "log",
    "wp-admin",
    "phpmyadmin",
    ".htaccess",
    ".htpasswd",
    "cgi-bin",
    "server-status",
    "server-info",
]


class FilesScanner(ScanModule):
    """
    Scanner for robots.txt and security.txt files.

    Makes its own HTTP requests to fetch /robots.txt and /security.txt
    from the target.  Does NOT use the orchestrator's pre-fetched response
    because these are separate endpoints from the target's main page.

    Accepts both HTTP and HTTPS targets (the default accepts_target
    behaviour from the base class).
    """

    # -----------------------------------------------------------------
    # ScanModule interface -- required properties
    # -----------------------------------------------------------------

    @property
    def name(self) -> str:
        """Short identifier used in CLI flags and finding output."""
        return "files"

    @property
    def description(self) -> str:
        """Human-readable description for --help output."""
        return "robots.txt and security.txt analysis (sensitive paths, RFC 9116 compliance)"

    # -----------------------------------------------------------------
    # ScanModule interface -- main scan method
    # -----------------------------------------------------------------

    def scan(
        self,
        target: Target,
        http_response: Optional[Response] = None,
    ) -> list[Finding]:
        """
        Analyse robots.txt and security.txt for the given target.

        This method:
            1. Creates an HTTP session for making its own requests
            2. Fetches and analyses /robots.txt for sensitive paths
            3. Fetches and analyses security.txt (RFC 9116) for compliance
            4. Returns the combined list of findings

        Args:
            target:        The target to scan.  Uses target.url as the base
                           URL for constructing file paths.
            http_response: Pre-fetched HTTP response from the orchestrator.
                           NOT used by this module -- we make our own requests
                           to specific file paths.

        Returns:
            List of Finding objects.  Empty list means no issues found.
        """
        findings: list[Finding] = []

        # --- Create an HTTP session for our own requests ---
        # We need to fetch /robots.txt and /security.txt independently.
        session, timeout = create_http_session(timeout=10)

        # --- Run robots.txt checks ---
        # Fetch /robots.txt and parse Disallow/Allow directives.
        findings.extend(self._check_robots_txt(session, target, timeout))

        # --- Run security.txt checks ---
        # Check /.well-known/security.txt and /security.txt per RFC 9116.
        findings.extend(self._check_security_txt(session, target, timeout))

        return findings

    # -----------------------------------------------------------------
    # Private methods -- robots.txt analysis
    # -----------------------------------------------------------------

    def _check_robots_txt(
        self,
        session,
        target: Target,
        timeout: int,
    ) -> list[Finding]:
        """
        Fetch and analyse /robots.txt for sensitive path disclosure.

        Parses the robots.txt file line by line, extracting paths from
        Disallow and Allow directives.  Each path is checked against the
        _SENSITIVE_PATH_PATTERNS list (case-insensitive substring match).

        All matching sensitive paths are collected into a single finding
        (not one finding per path) to keep the report concise.

        Args:
            session: The requests.Session for making HTTP requests.
            target:  The target being scanned.
            timeout: Request timeout in seconds.

        Returns:
            List with one Finding if sensitive paths are found, empty
            list otherwise.
        """
        findings: list[Finding] = []

        # Build the robots.txt URL from the target's base URL.
        # target.url gives us "https://example.com:443", so we append /robots.txt.
        robots_url = f"{target.url}/robots.txt"

        # --- Fetch robots.txt ---
        try:
            resp = session.get(robots_url, timeout=timeout, verify=False)
        except Exception as exc:
            # Connection error or timeout -- log and skip robots.txt checks.
            logger.debug(
                "Failed to fetch robots.txt for %s: %s",
                target.hostport,
                exc,
            )
            return findings

        # --- Check if robots.txt exists ---
        # If the server returns 404 or any non-200 status, there is no
        # robots.txt to analyse.  This is not a finding (many sites don't
        # have one and that's fine).
        if resp.status_code != 200:
            logger.debug(
                "robots.txt returned HTTP %d for %s",
                resp.status_code,
                target.hostport,
            )
            return findings

        # --- Parse robots.txt ---
        # Extract paths from Disallow and Allow directives.
        # Format per RFC 9309:
        #   User-agent: <bot-name>
        #   Disallow: /path
        #   Allow: /path
        #
        # We ignore User-agent lines and focus only on the path directives.
        sensitive_paths = self._parse_robots_sensitive_paths(resp.text)

        # --- Produce finding if sensitive paths were found ---
        if sensitive_paths:
            # Join all sensitive paths into a comma-separated string for
            # the finding detail.  This keeps it to one finding per target
            # rather than flooding the report with N findings for N paths.
            paths_str = ", ".join(sorted(sensitive_paths))
            findings.append(Finding(
                module="files",
                finding_type="robots_sensitive_paths",
                severity=Severity.LOW,
                target=target,
                title="Sensitive Paths Disclosed in robots.txt",
                detail=(
                    f"robots.txt contains references to potentially sensitive "
                    f"paths: {paths_str}. These paths may reveal administrative "
                    f"interfaces, backup files, configuration data, or internal "
                    f"endpoints that could aid an attacker in reconnaissance"
                ),
                references=["CWE-200", "CWE-538"],
            ))

        return findings

    def _parse_robots_sensitive_paths(self, robots_text: str) -> list[str]:
        """
        Parse robots.txt content and return a list of sensitive paths found.

        Iterates over each line, looking for Disallow: and Allow: directives.
        For each directive, the path is extracted and checked against the
        _SENSITIVE_PATH_PATTERNS list using case-insensitive substring matching.

        Args:
            robots_text: The full text content of robots.txt.

        Returns:
            List of path strings that matched at least one sensitive pattern.
            Paths are unique (no duplicates) and in the order they were found.
        """
        sensitive_paths: list[str] = []
        seen: set[str] = set()  # Track seen paths to avoid duplicates

        for line in robots_text.splitlines():
            # Strip whitespace and skip empty lines / comments.
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # Extract the path from Disallow: or Allow: directives.
            # The directive format is:  Disallow: /path
            # We use a case-insensitive check for the directive keyword.
            path = None
            line_lower = line.lower()
            if line_lower.startswith("disallow:"):
                path = line.split(":", 1)[1].strip()
            elif line_lower.startswith("allow:"):
                path = line.split(":", 1)[1].strip()

            # Skip if no path was extracted or the path is empty.
            if not path:
                continue

            # Check if the path matches any sensitive pattern.
            # Case-insensitive substring match: /Admin matches "admin",
            # /BACKUP/db matches "backup", /.git/config matches "git".
            path_lower = path.lower()
            for pattern in _SENSITIVE_PATH_PATTERNS:
                if pattern in path_lower:
                    # Avoid adding the same path multiple times (a path
                    # might match multiple patterns, e.g. /admin/config).
                    if path not in seen:
                        sensitive_paths.append(path)
                        seen.add(path)
                    break  # No need to check more patterns for this path

        return sensitive_paths

    # -----------------------------------------------------------------
    # Private methods -- security.txt analysis (RFC 9116)
    # -----------------------------------------------------------------

    def _check_security_txt(
        self,
        session,
        target: Target,
        timeout: int,
    ) -> list[Finding]:
        """
        Fetch and analyse security.txt for RFC 9116 compliance.

        Checks two locations per the RFC:
            1. /.well-known/security.txt  (primary, RFC 9116 recommended)
            2. /security.txt              (legacy fallback)

        If found at either location, validates:
            - Contact field is present (required by RFC 9116)
            - Expires field is present (required by RFC 9116)
            - Expires date is not in the past

        If not found at either location, produces an INFORMATIONAL finding
        suggesting the site owner create one.

        Args:
            session: The requests.Session for making HTTP requests.
            target:  The target being scanned.
            timeout: Request timeout in seconds.

        Returns:
            List of Finding objects for security.txt issues.
        """
        findings: list[Finding] = []

        # --- Try to fetch security.txt from both locations ---
        # Primary location per RFC 9116: /.well-known/security.txt
        well_known_url = f"{target.url}/.well-known/security.txt"
        # Legacy / fallback location: /security.txt
        root_url = f"{target.url}/security.txt"

        security_txt_content = None

        # --- Attempt 1: /.well-known/security.txt (preferred) ---
        try:
            resp = session.get(well_known_url, timeout=timeout, verify=False)
            if resp.status_code == 200:
                security_txt_content = resp.text
                logger.debug(
                    "Found security.txt at %s for %s",
                    well_known_url,
                    target.hostport,
                )
        except Exception as exc:
            logger.debug(
                "Failed to fetch %s: %s",
                well_known_url,
                exc,
            )

        # --- Attempt 2: /security.txt (fallback) ---
        # Only try the fallback if the primary location was not found.
        if security_txt_content is None:
            try:
                resp = session.get(root_url, timeout=timeout, verify=False)
                if resp.status_code == 200:
                    security_txt_content = resp.text
                    logger.debug(
                        "Found security.txt at %s for %s",
                        root_url,
                        target.hostport,
                    )
            except Exception as exc:
                logger.debug(
                    "Failed to fetch %s: %s",
                    root_url,
                    exc,
                )

        # --- If security.txt was not found at either location ---
        if security_txt_content is None:
            findings.append(Finding(
                module="files",
                finding_type="missing_security_txt",
                severity=Severity.INFORMATIONAL,
                target=target,
                title="Missing security.txt (RFC 9116)",
                detail=(
                    "No security.txt file was found at /.well-known/security.txt "
                    "or /security.txt. security.txt (RFC 9116) provides security "
                    "researchers with contact information for responsible "
                    "vulnerability disclosure. Consider creating one at "
                    "/.well-known/security.txt with at minimum Contact and "
                    "Expires fields"
                ),
                references=["CWE-200"],
            ))
            return findings

        # --- Validate security.txt content ---
        # Parse the content and check for required fields.
        findings.extend(
            self._validate_security_txt(target, security_txt_content)
        )

        return findings

    def _validate_security_txt(
        self,
        target: Target,
        content: str,
    ) -> list[Finding]:
        """
        Validate security.txt content against RFC 9116 requirements.

        Checks for:
            1. Contact field is present (required)
            2. Expires field is present (required)
            3. Expires date is not in the past (if parseable)

        Args:
            target:  The target being scanned.
            content: The raw text content of security.txt.

        Returns:
            List of Finding objects for validation issues.
        """
        findings: list[Finding] = []

        # --- Parse fields ---
        # security.txt uses a simple key-value format:
        #   Contact: mailto:security@example.com
        #   Expires: 2025-12-31T23:59:59z
        #   Preferred-Languages: en
        #
        # Fields are case-insensitive per the RFC.  We normalise to
        # lowercase for comparison.
        has_contact = False
        has_expires = False
        expires_value = None

        for line in content.splitlines():
            line = line.strip()

            # Skip empty lines and comments (lines starting with #).
            if not line or line.startswith("#"):
                continue

            # Parse the field name and value.
            # Format: FieldName: Value
            if ":" not in line:
                continue

            field_name, field_value = line.split(":", 1)
            field_name = field_name.strip().lower()
            field_value = field_value.strip()

            # Check for Contact field.
            if field_name == "contact":
                has_contact = True

            # Check for Expires field.
            if field_name == "expires":
                has_expires = True
                expires_value = field_value

        # --- Check 1: Missing Contact ---
        # Contact is required by RFC 9116 so researchers know where to
        # send vulnerability reports.  Without it, the security.txt is
        # incomplete and researchers may not be able to reach the team.
        if not has_contact:
            findings.append(Finding(
                module="files",
                finding_type="security_txt_missing_contact",
                severity=Severity.LOW,
                target=target,
                title="security.txt Missing Contact Field",
                detail=(
                    "The security.txt file does not contain a Contact field. "
                    "Contact is required by RFC 9116 and should be a URI "
                    "(e.g., mailto:security@example.com or "
                    "https://example.com/report) so security researchers know "
                    "where to report vulnerabilities"
                ),
                references=["CWE-200"],
            ))

        # --- Check 2: Missing Expires ---
        # Expires is required by RFC 9116 so security.txt consumers know
        # when the file was last verified and should be re-checked.
        if not has_expires:
            findings.append(Finding(
                module="files",
                finding_type="security_txt_missing_expires",
                severity=Severity.LOW,
                target=target,
                title="security.txt Missing Expires Field",
                detail=(
                    "The security.txt file does not contain an Expires field. "
                    "Expires is required by RFC 9116 and should be an ISO 8601 "
                    "datetime (e.g., 2025-12-31T23:59:59z) indicating when the "
                    "file should be considered stale and re-validated"
                ),
                references=["CWE-200"],
            ))

        # --- Check 3: Expired Expires date ---
        # If the Expires field is present but the date is in the past,
        # the security.txt is stale.  Contact information may no longer
        # be valid, and researchers may not receive vulnerability reports.
        if has_expires and expires_value:
            is_expired = self._is_expired(expires_value)
            if is_expired:
                findings.append(Finding(
                    module="files",
                    finding_type="security_txt_expired",
                    severity=Severity.LOW,
                    target=target,
                    title="security.txt Has Expired",
                    detail=(
                        f"The security.txt Expires field is set to "
                        f"'{expires_value}', which is in the past. An expired "
                        f"security.txt means the contact information may be "
                        f"stale and vulnerability reports may go unanswered. "
                        f"Update the Expires field to a future date"
                    ),
                    references=["CWE-200"],
                ))

        return findings

    def _is_expired(self, expires_value: str) -> bool:
        """
        Check if a security.txt Expires date string is in the past.

        RFC 9116 specifies the Expires field should be in ISO 8601 datetime
        format.  Common formats seen in the wild:
            - 2025-12-31T23:59:59z
            - 2025-12-31T23:59:59Z
            - 2025-12-31T23:59:59+00:00

        We attempt to parse the value with multiple format strategies.
        If parsing fails, we assume the date is NOT expired (conservative
        approach -- don't produce a false positive on an unparseable date).

        Args:
            expires_value: The raw Expires field value from security.txt.

        Returns:
            True if the date is definitely in the past, False if the date
            is in the future or if parsing failed.
        """
        # Clean up the value -- strip whitespace and handle common variants.
        value = expires_value.strip()

        # --- Attempt 1: Parse ISO 8601 with timezone ---
        # Try the standard ISO 8601 format with 'Z' suffix (UTC).
        # Python's datetime.fromisoformat() handles most ISO 8601 variants
        # in Python 3.11+, including trailing 'Z' for UTC.
        try:
            # Replace trailing 'z' (lowercase) with 'Z' for consistency,
            # then replace 'Z' with '+00:00' for fromisoformat() compatibility
            # in older Python versions.
            normalised = value.replace("z", "+00:00").replace("Z", "+00:00")
            # If the value already had +00:00 and we replaced Z, we might
            # get +00:00+00:00 -- handle that edge case.
            normalised = normalised.replace("+00:00+00:00", "+00:00")
            expires_dt = datetime.fromisoformat(normalised)

            # Compare against current UTC time.
            now = datetime.now(timezone.utc)
            return expires_dt < now
        except (ValueError, TypeError):
            pass

        # --- Attempt 2: Manual parsing of common formats ---
        # Try a few common strptime formats as a fallback.
        for fmt in [
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d",
        ]:
            try:
                expires_dt = datetime.strptime(value, fmt)
                # If the parsed datetime is naive (no timezone), assume UTC.
                if expires_dt.tzinfo is None:
                    expires_dt = expires_dt.replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)
                return expires_dt < now
            except (ValueError, TypeError):
                continue

        # --- Parsing failed -- assume not expired ---
        # If we can't parse the date, we err on the side of caution
        # and don't flag it as expired (avoid false positives).
        logger.debug(
            "Could not parse security.txt Expires value: %s",
            expires_value,
        )
        return False


# ---------------------------------------------------------------------------
# Module registration
# ---------------------------------------------------------------------------
# Instantiate the scanner and register it with the module registry.
# This runs at import time, so importing this file is sufficient to make
# the files scanner available to the orchestrator.

register_module(FilesScanner())
