"""
webinspector.utils.nmap_parser - Parse nmap XML output to extract web service targets.

This module reads nmap's XML output format (produced by ``nmap -oX``) and extracts
hosts with open web service ports.  It is a critical part of the pentest team's
workflow: the team runs nmap to discover live services across the target network,
then feeds the resulting XML into webinspector to perform web-specific security
checks (SSL config, headers, cookies, CORS, etc.).

Why lxml instead of xmlstarlet:
    The original bash-based tool shelled out to ``xmlstarlet`` for XML parsing.
    Using lxml's etree gives us the same XPath power without an external binary
    dependency, and it's significantly faster for large scan results.

Supported service detection patterns:
    nmap identifies web services in several ways.  We look for:
    - Service names:  https, ssl, http, http-proxy, http-alt, https-alt, oracleas-https
    - Tunnel attribute:  tunnel="ssl" on any service (indicates SSL-wrapped HTTP)

    Only ports with state="open" are included.  Closed, filtered, or
    unresponsive ports are excluded.

Key public API:
    parse_nmap_xml(filepath) - Parse an nmap XML file and return Target objects

Author: Red Siege Information Security
"""

from __future__ import annotations

import logging
from pathlib import Path

# lxml is our fast XML parser — listed in requirements.txt.
# We use it instead of the standard library's xml.etree.ElementTree because
# lxml handles malformed XML more gracefully and supports full XPath 1.0.
from lxml import etree

# Import the Target dataclass that every scanner module understands.
from webinspector.core.target import Target


# ---------------------------------------------------------------------------
# Module-level logger
# ---------------------------------------------------------------------------

# Set up a logger for this module.  Messages go to the root logger which
# the CLI configures with the appropriate handler and level.
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants — nmap service names that indicate web services
# ---------------------------------------------------------------------------

# Service names that nmap uses for SSL/TLS-based web services.
# When we see any of these, the target scheme should be "https".
HTTPS_SERVICE_NAMES = frozenset({
    "https",          # Standard HTTPS
    "ssl",            # Generic SSL — often wraps HTTP
    "https-alt",      # HTTPS on non-standard ports
    "oracleas-https", # Oracle Application Server HTTPS
})

# Service names that nmap uses for plain (unencrypted) HTTP services.
# When we see any of these (without an SSL tunnel), scheme should be "http".
HTTP_SERVICE_NAMES = frozenset({
    "http",           # Standard HTTP
    "http-proxy",     # HTTP proxy servers (still web-accessible)
    "http-alt",       # HTTP on non-standard ports (e.g. 8080)
})

# Combined set of all web service names we recognise — used for quick
# membership testing when deciding whether to include a port.
ALL_WEB_SERVICE_NAMES = HTTPS_SERVICE_NAMES | HTTP_SERVICE_NAMES


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def parse_nmap_xml(filepath: str) -> list[Target]:
    """
    Parse an nmap XML output file and extract web service targets.

    Reads the XML produced by ``nmap -oX``, iterates over every host/port
    combination, and builds Target objects for open ports running web services.

    The logic for deciding scheme:
        1. If the service name is in HTTPS_SERVICE_NAMES -> "https"
        2. If the service has tunnel="ssl"               -> "https"
        3. If the service name is in HTTP_SERVICE_NAMES  -> "http"
        4. Otherwise, skip this port entirely.

    Args:
        filepath: Path to the nmap XML file (absolute or relative).

    Returns:
        A list of Target objects, one per open web service port.
        Returns an empty list if the file is missing, empty, or malformed.
        All returned targets have source="nmap".

    Example::

        targets = parse_nmap_xml("/tmp/scan_results.xml")
        for t in targets:
            print(f"{t.scheme}://{t.host}:{t.port}")
    """
    # --- Validate the file path ---
    path = Path(filepath)
    if not path.exists():
        # File not found — log a warning and return empty.
        # The pentest team may have a typo in their path; we don't want
        # the entire scan to crash because of a missing nmap file.
        logger.warning("Nmap XML file not found: %s", filepath)
        return []

    if path.stat().st_size == 0:
        # Empty file — nothing to parse.
        logger.warning("Nmap XML file is empty: %s", filepath)
        return []

    # --- Parse the XML ---
    try:
        # Parse the XML file.  We use lxml's etree.parse() which returns
        # an ElementTree object.  recover=True tells the parser to try to
        # handle minor XML errors gracefully.
        parser = etree.XMLParser(recover=True)
        tree = etree.parse(str(path), parser)
        root = tree.getroot()
    except (etree.XMLSyntaxError, etree.Error, OSError) as exc:
        # Malformed XML or I/O error — log and return empty.
        logger.error("Failed to parse nmap XML '%s': %s", filepath, exc)
        return []

    # If the parser returned None (can happen with extremely broken XML),
    # bail out with an empty list.
    if root is None:
        logger.error("Nmap XML root element is None: %s", filepath)
        return []

    # --- Extract targets from the XML structure ---
    targets: list[Target] = []

    # Iterate over every <host> element in the nmap output.
    # Each <host> represents one scanned IP address / hostname.
    for host_elem in root.findall(".//host"):
        # Extract the IP address from the <address> element.
        # nmap always includes at least one <address> with addrtype="ipv4".
        ip_address = _extract_ip_address(host_elem)
        if ip_address is None:
            # No IP address found for this host — skip it.
            # This shouldn't happen with valid nmap output, but we
            # handle it defensively.
            logger.debug("Skipping host with no IP address in nmap XML")
            continue

        # Iterate over every <port> element within this host.
        # Each <port> represents one scanned port.
        for port_elem in host_elem.findall(".//port"):
            # Extract the target from this port element (if it's a web service).
            target = _process_port_element(port_elem, ip_address)
            if target is not None:
                targets.append(target)

    logger.info(
        "Parsed %d web targets from nmap XML: %s",
        len(targets),
        filepath,
    )
    return targets


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _extract_ip_address(host_elem) -> str | None:
    """
    Extract the IPv4 address from an nmap <host> element.

    nmap includes one or more <address> child elements.  We look for the
    one with addrtype="ipv4" and return its addr attribute.

    Args:
        host_elem: An lxml Element representing an nmap <host>.

    Returns:
        The IPv4 address string (e.g. "10.0.0.1"), or None if not found.
    """
    # Look through all <address> children for the IPv4 one.
    for addr_elem in host_elem.findall("address"):
        if addr_elem.get("addrtype") == "ipv4":
            return addr_elem.get("addr")

    # Fallback: if no addrtype="ipv4" found, try the first <address>.
    # Some nmap output might not specify addrtype explicitly.
    first_addr = host_elem.find("address")
    if first_addr is not None:
        return first_addr.get("addr")

    # No address element at all — shouldn't happen, but handle gracefully.
    return None


def _process_port_element(port_elem, ip_address: str) -> Target | None:
    """
    Examine a single nmap <port> element and return a Target if it's
    an open web service, or None if it should be skipped.

    Decision logic:
        1. Check the <state> child — only include ports with state="open".
        2. Check the <service> child for a web-related service name.
        3. Determine the scheme (http vs https) based on service name
           and the tunnel attribute.

    Args:
        port_elem:  An lxml Element representing an nmap <port>.
        ip_address: The IP address of the host this port belongs to.

    Returns:
        A Target object if this port is an open web service, or None.
    """
    # --- Check port state ---
    # Only include ports that are definitively "open".
    # Closed, filtered, and unresponsive ports are excluded.
    state_elem = port_elem.find("state")
    if state_elem is None:
        # No <state> element — shouldn't happen in valid nmap XML, skip.
        return None

    port_state = state_elem.get("state", "")
    if port_state != "open":
        # Port is not open — skip it.
        return None

    # --- Extract port number ---
    # The portid attribute contains the port number as a string.
    try:
        port_number = int(port_elem.get("portid", "0"))
    except ValueError:
        # Non-numeric port ID — shouldn't happen, but skip gracefully.
        logger.debug("Skipping port with non-numeric portid: %s", port_elem.get("portid"))
        return None

    # --- Check service type ---
    # The <service> child element tells us what service is running.
    service_elem = port_elem.find("service")
    if service_elem is None:
        # No service identification — nmap couldn't determine the service.
        # We can't tell if it's a web service, so skip it.
        return None

    service_name = service_elem.get("name", "").lower()
    tunnel = service_elem.get("tunnel", "").lower()

    # --- Determine if this is a web service and what scheme to use ---
    scheme = _determine_scheme(service_name, tunnel)
    if scheme is None:
        # Not a web service — skip this port.
        return None

    # --- Build and return the Target ---
    # All nmap-sourced targets get source="nmap" for provenance tracking.
    return Target(
        host=ip_address,
        port=port_number,
        scheme=scheme,
        source="nmap",
    )


def _determine_scheme(service_name: str, tunnel: str) -> str | None:
    """
    Determine the URL scheme (http or https) for an nmap-detected service.

    Decision order:
        1. If the service has tunnel="ssl", it's always HTTPS regardless
           of the service name (SSL wrapping means encrypted).
        2. If the service name is in HTTPS_SERVICE_NAMES, it's HTTPS.
        3. If the service name is in HTTP_SERVICE_NAMES, it's HTTP.
        4. Otherwise, it's not a web service — return None.

    Args:
        service_name: The nmap service name (e.g. "http", "https", "ssh").
        tunnel:       The tunnel attribute value (e.g. "ssl" or "").

    Returns:
        "https", "http", or None (not a web service).
    """
    # Check for SSL tunnel first — this overrides the service name.
    # nmap uses tunnel="ssl" to indicate that a service is wrapped in
    # SSL/TLS, even if the underlying service name is "http".
    if tunnel == "ssl":
        return "https"

    # Check if the service name indicates HTTPS.
    if service_name in HTTPS_SERVICE_NAMES:
        return "https"

    # Check if the service name indicates plain HTTP.
    if service_name in HTTP_SERVICE_NAMES:
        return "http"

    # Not a web service — return None to signal that this port should
    # be skipped by the caller.
    return None
