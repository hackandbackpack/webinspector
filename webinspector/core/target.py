"""
webinspector.core.target - Target definition and input parsing for webinspector.

This module defines the Target dataclass — the universal representation of a
scan target used by every scanner module, the output renderers, and the
orchestration engine.  It also provides helper functions for parsing user-supplied
target strings (bare hosts, URLs, CIDR ranges, host:port pairs) into concrete
Target objects ready for scanning.

Why this module matters:
    Every other component in webinspector receives or produces Target objects.
    Getting the parsing and normalization right here means downstream modules
    can trust that ``target.host`` is always a clean hostname / IP and
    ``target.port`` is always an integer — no ad-hoc parsing needed elsewhere.

Key public API:
    Target               - Dataclass representing a single scan endpoint
    parse_target_string() - Convert one raw string into a list of Targets
    expand_targets()      - Batch convert + deduplicate a list of raw strings
    parse_target_file()   - Read a target file from disk into raw strings

Author: Red Siege Information Security
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

# netaddr gives us IP network math (CIDR expansion) and IP validation.
# It is listed in requirements.txt / setup.py as a runtime dependency.
from netaddr import IPNetwork, valid_ipv4


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Default port used when the user doesn't specify one.
# 443 (HTTPS) is the most common port we scan during engagements.
DEFAULT_PORT = 443

# The two schemes we support.  We expand bare targets to *both* so that
# scanning covers the case where a server answers on HTTP vs HTTPS.
SCHEMES = ("http", "https")

# Default ports for each scheme — used when parsing full URLs that omit the port.
SCHEME_DEFAULT_PORTS = {
    "http": 80,
    "https": 443,
}

# Simple regex for detecting a CIDR notation string like "10.0.0.0/24".
# We look for digits-and-dots followed by a slash and a prefix length.
CIDR_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$")


# ---------------------------------------------------------------------------
# Target dataclass
# ---------------------------------------------------------------------------

@dataclass
class Target:
    """
    Represents a single scan target — one (scheme, host, port) triple.

    Scanner modules receive a Target and use ``target.url`` to make HTTP
    requests, ``target.hostport`` for display in findings, and ``target.ip``
    for numeric sorting in reports.

    Attributes:
        host   : The hostname or IP address to scan (e.g. "example.com" or "10.0.0.1").
        port   : TCP port number (e.g. 443, 8080).
        scheme : Protocol scheme — either "http" or "https".
        ip     : The resolved IPv4 address for hostname targets, populated during the
                 DNS pre-resolution phase.  None until resolution is performed.
        rdns   : Reverse DNS hostname for IP-address targets, populated during the
                 DNS pre-resolution phase.  None until resolution is performed.
        source : Where this target originated.  Useful for audit trails and debugging.
                 Common values: "cli" (command-line argument), "file" (target file),
                 "nmap" (imported from Nmap XML).
    """

    host: str           # Hostname or IP address
    port: int           # Port number (default 443)
    scheme: str         # 'http' or 'https'
    ip: str | None = None       # Resolved IP (populated during DNS pre-resolution)
    rdns: str | None = None     # Reverse DNS name (populated for IP targets)
    source: str = "cli"         # Where target came from: 'cli', 'file', 'nmap'

    # ----- Computed properties -----

    @property
    def url(self) -> str:
        """
        Full URL suitable for HTTP requests.

        Returns a string like ``"https://example.com:443"``.  The port is
        always included explicitly so that non-standard ports work correctly
        with the requests library.
        """
        return f"{self.scheme}://{self.host}:{self.port}"

    @property
    def hostport(self) -> str:
        """
        ``host:port`` string for display in findings and reports.

        Example: ``"example.com:443"``
        """
        return f"{self.host}:{self.port}"

    @property
    def display(self) -> str:
        """
        Human-friendly display string that includes supplemental DNS info.

        The goal is to give the analyst maximum context at a glance:
        - If the target is a hostname and we resolved an IP  -> ``"example.com:443 (10.0.0.1)"``
        - If the target is an IP and we have reverse DNS     -> ``"10.0.0.1:443 (server.corp.com)"``
        - If no extra info is available, or the extra info is
          redundant (ip == host), just return ``"host:port"``
        """
        base = self.hostport

        # Case 1: Target is a hostname and we have a resolved IP that differs from the host.
        # (If host == ip, showing both would be redundant.)
        if self.ip and self.ip != self.host:
            return f"{base} ({self.ip})"

        # Case 2: Target is an IP address and we have reverse DNS.
        if self.rdns:
            return f"{base} ({self.rdns})"

        # Case 3: No supplemental info available.
        return base


# ---------------------------------------------------------------------------
# Target parsing helpers
# ---------------------------------------------------------------------------

def _is_cidr(raw: str) -> bool:
    """
    Return True if *raw* looks like a CIDR range (e.g. ``"10.0.0.0/24"``).

    We use a simple regex check rather than relying on netaddr directly so
    that we can distinguish CIDR from bare IPs before attempting expansion.
    """
    return bool(CIDR_RE.match(raw))


def _is_url(raw: str) -> bool:
    """
    Return True if *raw* starts with ``http://`` or ``https://``.

    This tells us the user specified an explicit scheme, which means we
    should NOT expand the target to both http and https.
    """
    return raw.startswith("http://") or raw.startswith("https://")


def _is_host_port(raw: str) -> bool:
    """
    Return True if *raw* looks like ``host:port`` (but NOT a URL).

    We check for exactly one colon where the part after the colon is numeric.
    IPv6 addresses are not currently supported (they contain multiple colons).
    """
    # Ensure there is exactly one colon and the right-hand side is a port number.
    if ":" not in raw:
        return False
    parts = raw.rsplit(":", 1)
    return parts[1].isdigit()


def _make_targets(
    host: str,
    ports: list[int],
    schemes: tuple[str, ...],
    source: str = "cli",
) -> list[Target]:
    """
    Internal helper: create Target objects for every combination of
    (scheme, host, port).

    Args:
        host:    The hostname or IP string.
        ports:   List of port numbers to use.
        schemes: Tuple of schemes to generate (e.g. ("http", "https")).
        source:  Origin tag for the targets.

    Returns:
        A list of Target instances — one per (scheme x port) combination.
    """
    targets: list[Target] = []
    for port in ports:
        for scheme in schemes:
            targets.append(
                Target(host=host, port=port, scheme=scheme, source=source)
            )
    return targets


def parse_target_string(raw: str, ports: list[int] | None = None) -> list[Target]:
    """
    Parse a single user-supplied target string into one or more Target objects.

    Supported formats and their behaviour:

    +--------------------------+-------------------------------------------------+
    | Input format             | Result                                          |
    +--------------------------+-------------------------------------------------+
    | https://host:8443        | 1 Target (explicit scheme & port)               |
    | http://host              | 1 Target (explicit scheme, default port 80)     |
    | host:port                | 2 Targets (http + https on that port)           |
    | bare hostname            | 2+ Targets (both schemes, default or given port)|
    | bare IP                  | 2+ Targets (same as bare hostname)              |
    | CIDR (10.0.0.0/30)      | N*2 Targets (each IP * both schemes)            |
    +--------------------------+-------------------------------------------------+

    Args:
        raw:   The raw target string from the user (URL, host, IP, CIDR, etc.).
        ports: Optional list of ports to scan.  When provided, bare hosts/IPs
               are expanded to every port in this list.  Ignored when the raw
               string already specifies a port explicitly.

    Returns:
        A list of Target objects (never empty for valid input).
    """
    # Strip whitespace to handle sloppy input gracefully.
    raw = raw.strip()

    # ---- Full URL (explicit scheme) ----
    # When the user gives us a URL we honour the scheme and port exactly.
    # We do NOT expand to both http and https — the user was explicit.
    if _is_url(raw):
        parsed = urlparse(raw)
        scheme = parsed.scheme                   # "http" or "https"
        host = parsed.hostname or parsed.netloc  # strip port & path
        # If the URL contained an explicit port, use it; otherwise fall back
        # to the well-known default for the scheme (80 for http, 443 for https).
        port = parsed.port or SCHEME_DEFAULT_PORTS.get(scheme, DEFAULT_PORT)
        return [Target(host=host, port=port, scheme=scheme)]

    # ---- CIDR range (e.g. "10.0.0.0/24") ----
    # Expand the network into individual IP addresses and create targets
    # for each IP on the requested ports (or default port 443).
    if _is_cidr(raw):
        # netaddr.IPNetwork iterates over every address in the range,
        # including the network and broadcast addresses (for /30 that's
        # 10.0.0.0, 10.0.0.1, 10.0.0.2, 10.0.0.3 — all four).
        network = IPNetwork(raw)
        # Determine which ports to use: caller-supplied list, or default.
        effective_ports = ports if ports else [DEFAULT_PORT]
        targets: list[Target] = []
        for ip_addr in network:
            # Convert netaddr IP object to a plain string like "10.0.0.1".
            ip_str = str(ip_addr)
            targets.extend(
                _make_targets(ip_str, effective_ports, SCHEMES)
            )
        return targets

    # ---- host:port pair (no scheme) ----
    # When the user specifies a port but no scheme, we expand to both
    # http and https because we don't know what the server speaks.
    if _is_host_port(raw):
        host, port_str = raw.rsplit(":", 1)
        port = int(port_str)
        return _make_targets(host, [port], SCHEMES)

    # ---- Bare hostname or IP ----
    # No scheme, no port, no CIDR slash.  Expand to both schemes on
    # the default port (443), or on every port in the ports list.
    host = raw
    effective_ports = ports if ports else [DEFAULT_PORT]
    return _make_targets(host, effective_ports, SCHEMES)


def expand_targets(
    raw_strings: list[str],
    ports: list[int] | None = None,
) -> list[Target]:
    """
    Batch-parse a list of raw target strings, deduplicate, and sort.

    This is the main entry point for the CLI and file-based target loading.
    It handles comment lines (starting with ``#``), blank lines, and
    duplicate targets that arise when the same host appears multiple times
    or in different notations (e.g. ``https://host`` and ``https://host:443``).

    Args:
        raw_strings: List of raw strings — each is a URL, host, IP, or CIDR.
        ports:       Optional list of ports forwarded to parse_target_string().

    Returns:
        A deduplicated, sorted list of Target objects.
    """
    targets: list[Target] = []

    for raw in raw_strings:
        # Strip leading/trailing whitespace for clean comparison.
        stripped = raw.strip()

        # Skip blank lines.
        if not stripped:
            continue

        # Skip comment lines (lines whose first non-whitespace character is '#').
        if stripped.startswith("#"):
            continue

        # Parse the line and accumulate the resulting targets.
        targets.extend(parse_target_string(stripped, ports=ports))

    # --- Deduplication ---
    # Two targets are considered duplicates if they share the same
    # (scheme, host, port) tuple.  We use a dict keyed on that tuple
    # to preserve insertion order while eliminating duplicates.
    seen: dict[tuple[str, str, int], Target] = {}
    for t in targets:
        key = (t.scheme, t.host, t.port)
        if key not in seen:
            seen[key] = t

    # --- Sort ---
    # Sort by (host, port, scheme) for deterministic, readable output.
    # This keeps related targets (same host, different ports/schemes) together.
    unique_targets = sorted(
        seen.values(),
        key=lambda t: (t.host, t.port, t.scheme),
    )

    return unique_targets


def parse_target_file(filepath: str) -> list[str]:
    """
    Read a target file from disk and return a list of raw target strings.

    The file is expected to contain one target per line.  Comment lines
    (starting with ``#``) and blank lines are preserved in the output so
    that ``expand_targets`` can handle them uniformly.

    This function only performs I/O; all parsing and validation happens
    downstream in ``expand_targets`` / ``parse_target_string``.

    Args:
        filepath: Path to the target file (absolute or relative).

    Returns:
        List of raw line strings (whitespace-stripped, but comments/blanks
        are retained for downstream filtering).

    Raises:
        FileNotFoundError: If the file does not exist.
    """
    path = Path(filepath)
    # Read the file, strip each line of leading/trailing whitespace,
    # and return all non-empty lines.  We keep comment lines so that
    # expand_targets() can log/skip them consistently.
    lines: list[str] = []
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            stripped = line.strip()
            if stripped:
                lines.append(stripped)
    return lines
