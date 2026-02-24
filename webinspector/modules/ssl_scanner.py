"""
webinspector.modules.ssl_scanner - SSL/TLS scanner module using sslyze.

Wraps the sslyze library to perform comprehensive SSL/TLS security checks
including protocol version support, cipher suite analysis, and vulnerability
detection (Heartbleed, ROBOT, CCS injection, TLS compression, renegotiation).

This module checks for:
    - Deprecated protocols: SSLv2, SSLv3, TLSv1.0, TLSv1.1
    - Weak ciphers: NULL, EXP (export-grade), ADH, AECDH, key_size <= 64 bits
    - Medium ciphers: DES (not 3DES), RC4, 64 < key_size <= 112 bits
    - Heartbleed vulnerability (CVE-2014-0160)
    - ROBOT vulnerability (Return Of Bleichenbacher's Oracle Threat)
    - CCS injection vulnerability (CVE-2014-0224)
    - TLS compression (CRIME attack, CVE-2012-4929)
    - Insecure client-initiated renegotiation (DoS risk)
    - Missing TLS_FALLBACK_SCSV (protocol downgrade protection)
    - TLS 1.3 early data / 0-RTT (replay attack risk)

The module only runs against HTTPS targets (accepts_target returns False
for http:// targets).  When sslyze is not installed, the module degrades
gracefully and logs a warning instead of crashing.

sslyze API reference (v6.x):
    - Scanner() creates a scanner instance
    - scanner.queue_scans([ServerScanRequest(...)]) queues scan jobs
    - scanner.get_results() yields ServerScanResult objects
    - Each ServerScanResult.scan_result has typed attributes for each
      scan command (e.g., ssl_2_0_cipher_suites, heartbleed, robot)
    - Each attribute is a ScanCommandAttempt with .status and .result
    - Cipher results: .accepted_cipher_suites list of CipherSuiteAcceptedByServer
    - Each accepted cipher: .cipher_suite.name, .cipher_suite.key_size

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
# sslyze imports — wrapped in try/except for graceful degradation
# ---------------------------------------------------------------------------
# sslyze is a large dependency with C extensions (nassl).  If it's not
# installed (e.g., in a minimal Docker image or during development), the
# rest of webinspector should still work — this module simply won't
# produce any findings and will log a warning.

try:
    from sslyze import (
        Scanner,
        ServerScanRequest,
        ServerNetworkLocation,
        ScanCommand,
    )
    from sslyze.errors import ServerHostnameCouldNotBeResolved

    # SSLYZE_AVAILABLE is checked at scan time to short-circuit gracefully.
    SSLYZE_AVAILABLE = True
except ImportError:
    SSLYZE_AVAILABLE = False
    logger.warning("sslyze not installed - SSL scanner will be disabled")


# ---------------------------------------------------------------------------
# Cipher classification constants
# ---------------------------------------------------------------------------

# Weak cipher name patterns.  Any cipher whose name contains one of these
# substrings is considered weak (HIGH severity) regardless of key size.
# These patterns catch:
#   NULL  — no encryption at all (plaintext)
#   EXP   — export-grade, intentionally weakened (FREAK attack)
#   ADH   — anonymous Diffie-Hellman (no authentication, MITM-vulnerable)
#   AECDH — anonymous EC Diffie-Hellman (same as ADH but elliptic curve)
_WEAK_CIPHER_PATTERNS = ("NULL", "EXP", "ADH", "AECDH")

# Maximum key size (in bits) that is considered trivially breakable.
# Anything at or below this is flagged as weak (HIGH severity).
# 64 bits can be brute-forced with modest hardware.
_WEAK_KEY_SIZE_MAX = 64

# Medium cipher name patterns.  Ciphers matching these are not immediately
# breakable but are considered deprecated / insecure for modern use.
#   DES — single DES (56-bit key), but we must exclude 3DES
#   RC4 — stream cipher with known statistical biases (RFC 7465)
_MEDIUM_CIPHER_NAME_DES = "DES"
_MEDIUM_CIPHER_NAME_RC4 = "RC4"

# Key size range for medium-strength classification.
# Ciphers with key_size in (64, 112] are flagged as medium.
_MEDIUM_KEY_SIZE_MIN = 64   # exclusive lower bound
_MEDIUM_KEY_SIZE_MAX = 112  # inclusive upper bound


class SSLScanner(ScanModule):
    """
    SSL/TLS configuration and vulnerability scanner.

    Uses sslyze to perform a comprehensive analysis of a target's TLS
    stack.  Checks for deprecated protocols, weak/medium ciphers, and
    known vulnerabilities (Heartbleed, ROBOT, CCS injection, etc.).

    Only runs against HTTPS targets — the accepts_target() override
    returns False for http:// targets.
    """

    # -----------------------------------------------------------------
    # ScanModule interface — required properties
    # -----------------------------------------------------------------

    @property
    def name(self) -> str:
        """Short identifier used in CLI flags and finding output."""
        return "ssl"

    @property
    def description(self) -> str:
        """Human-readable description for --help output."""
        return "SSL/TLS protocol, cipher, and vulnerability analysis (sslyze)"

    # -----------------------------------------------------------------
    # ScanModule interface — accepts_target override
    # -----------------------------------------------------------------

    def accepts_target(self, target: Target) -> bool:
        """
        Only scan HTTPS targets.

        SSL/TLS checks are meaningless against plain HTTP targets because
        there is no TLS handshake to analyse.  The orchestrator calls this
        before scan() so we can skip HTTP targets efficiently.
        """
        return target.scheme == "https"

    # -----------------------------------------------------------------
    # ScanModule interface — main scan method
    # -----------------------------------------------------------------

    def scan(
        self,
        target: Target,
        http_response: Optional[Response] = None,
    ) -> list[Finding]:
        """
        Run SSL/TLS checks against a single target using sslyze.

        This method:
            1. Checks that sslyze is available (graceful degradation)
            2. Creates a ServerScanRequest with all relevant scan commands
            3. Runs the scan via sslyze's Scanner
            4. Processes results through three check categories:
               a. Deprecated protocol detection
               b. Cipher suite analysis (weak + medium)
               c. Vulnerability detection (Heartbleed, ROBOT, CCS, etc.)

        Args:
            target:        The HTTPS target to scan.
            http_response: Not used by this module (SSL checks use their
                           own TLS connections via sslyze, not HTTP).

        Returns:
            List of Finding objects.  Empty list means no issues found or
            sslyze is unavailable / encountered an error.
        """
        # Guard: sslyze not installed — return empty instead of crashing.
        if not SSLYZE_AVAILABLE:
            logger.warning(
                "sslyze not available, skipping SSL scan for %s",
                target.hostport,
            )
            return []

        findings: list[Finding] = []

        try:
            # Create sslyze server location from our Target's host and port.
            location = ServerNetworkLocation(
                hostname=target.host,
                port=target.port,
            )

            # Queue all relevant scan commands.  sslyze runs them in parallel
            # using its own thread pool, so queuing everything at once is
            # more efficient than running them sequentially.
            scan_request = ServerScanRequest(
                server_location=location,
                scan_commands={
                    # Protocol version checks — detect deprecated versions
                    ScanCommand.SSL_2_0_CIPHER_SUITES,
                    ScanCommand.SSL_3_0_CIPHER_SUITES,
                    ScanCommand.TLS_1_0_CIPHER_SUITES,
                    ScanCommand.TLS_1_1_CIPHER_SUITES,
                    # Cipher analysis for modern protocols
                    ScanCommand.TLS_1_2_CIPHER_SUITES,
                    ScanCommand.TLS_1_3_CIPHER_SUITES,
                    # Vulnerability checks
                    ScanCommand.HEARTBLEED,
                    ScanCommand.ROBOT,
                    ScanCommand.OPENSSL_CCS_INJECTION,
                    ScanCommand.TLS_COMPRESSION,
                    ScanCommand.SESSION_RENEGOTIATION,
                    ScanCommand.TLS_FALLBACK_SCSV,
                    ScanCommand.TLS_1_3_EARLY_DATA,
                },
            )

            # Run the scan.  Scanner() creates a new scanner instance that
            # manages its own thread pool for parallel scan execution.
            scanner = Scanner()
            scanner.queue_scans([scan_request])

            # Process results.  get_results() is a generator that yields
            # one ServerScanResult per queued request.  Since we only
            # queued one request, we expect exactly one result.
            for server_scan_result in scanner.get_results():
                # Each check category is handled by a dedicated method
                # that returns a list of Finding objects.
                findings.extend(
                    self._check_deprecated_protocols(target, server_scan_result)
                )
                findings.extend(
                    self._check_cipher_suites(target, server_scan_result)
                )
                findings.extend(
                    self._check_vulnerabilities(target, server_scan_result)
                )

        except Exception as e:
            # Catch-all for sslyze errors: connection refused, DNS failure,
            # TLS handshake error, etc.  We log the error and return
            # whatever findings we've collected so far (usually empty).
            logger.error(
                "sslyze scan failed for %s: %s", target.hostport, e
            )

        return findings

    # -----------------------------------------------------------------
    # Private check methods
    # -----------------------------------------------------------------

    def _check_deprecated_protocols(
        self, target: Target, scan_result
    ) -> list[Finding]:
        """
        Check for deprecated SSL/TLS protocol versions.

        A protocol is considered "supported" if sslyze found at least one
        cipher suite accepted by the server for that protocol version.

        Severity logic:
            - SSLv2 or SSLv3 present -> HIGH (critically broken protocols)
            - TLSv1.0 or TLSv1.1 only -> MEDIUM (deprecated but less severe)

        Returns:
            A single Finding listing all deprecated protocols found, or
            an empty list if none are detected.
        """
        findings: list[Finding] = []
        deprecated: list[str] = []

        # Map sslyze scan_result attribute names to human-readable protocol
        # names.  We iterate through these in order from oldest to newest.
        protocol_checks = [
            ("ssl_2_0_cipher_suites", "SSLv2"),
            ("ssl_3_0_cipher_suites", "SSLv3"),
            ("tls_1_0_cipher_suites", "TLSv1.0"),
            ("tls_1_1_cipher_suites", "TLSv1.1"),
        ]

        for attr_name, proto_name in protocol_checks:
            try:
                # Access the scan attempt for this protocol version.
                # scan_result.scan_result is the AllScanCommandsAttempts object.
                attempt = getattr(scan_result.scan_result, attr_name)

                # Skip if the scan command did not complete successfully.
                # The attempt.status is a string or enum; we check the
                # result object directly — if it's None, the scan failed.
                if attempt.result is None:
                    continue

                # If there are accepted cipher suites, the server supports
                # this deprecated protocol version.
                if attempt.result.accepted_cipher_suites:
                    deprecated.append(proto_name)

            except (AttributeError, Exception) as e:
                # If we can't access the result (e.g., scan error, missing
                # attribute on a mocked object), skip this protocol check
                # and continue with the others.
                logger.debug(
                    "Could not check %s for %s: %s",
                    proto_name, target.hostport, e,
                )
                continue

        # If we found any deprecated protocols, create a single finding
        # that lists all of them.
        if deprecated:
            # Determine severity: SSLv2 and SSLv3 are critically broken
            # protocols with known exploits (DROWN for SSLv2, POODLE for
            # SSLv3).  TLSv1.0/1.1 are deprecated but less severe.
            has_ssl = any(p.startswith("SSL") for p in deprecated)
            severity = Severity.HIGH if has_ssl else Severity.MEDIUM

            findings.append(Finding(
                module="ssl",
                finding_type="deprecated_protocols",
                severity=severity,
                target=target,
                title="Deprecated SSL/TLS Protocols",
                detail=", ".join(deprecated),
                references=["CWE-326"],
            ))

        return findings

    def _check_cipher_suites(
        self, target: Target, scan_result
    ) -> list[Finding]:
        """
        Analyse cipher suites for weak and medium-strength configurations.

        Scans TLS 1.2 and TLS 1.3 cipher suite results for:
            - Weak ciphers (HIGH severity):
                * NULL, EXP, ADH, AECDH in cipher name
                * key_size <= 64 bits
            - Medium ciphers (MEDIUM severity):
                * DES (excluding 3DES) or RC4 in cipher name
                * 64 < key_size <= 112 bits

        We only check TLS 1.2 and TLS 1.3 here because deprecated protocols
        (SSLv2, SSLv3, TLSv1.0, TLSv1.1) are already flagged as a separate
        finding by _check_deprecated_protocols().  Listing individual ciphers
        for deprecated protocols would create noise — the protocol itself is
        the problem, not the specific ciphers.

        Returns:
            List of Findings — up to two (one for weak, one for medium).
        """
        findings: list[Finding] = []
        weak_names: list[str] = []
        medium_names: list[str] = []

        # Collect accepted ciphers from TLS 1.2 and TLS 1.3.
        # These are the modern protocols where cipher choice matters
        # (deprecated protocols are covered by the protocol check).
        cipher_attrs = ["tls_1_2_cipher_suites", "tls_1_3_cipher_suites"]

        for attr_name in cipher_attrs:
            try:
                attempt = getattr(scan_result.scan_result, attr_name)

                # Skip if the scan command did not complete successfully.
                if attempt.result is None:
                    continue

                # Iterate through each cipher suite accepted by the server.
                for accepted in attempt.result.accepted_cipher_suites:
                    cipher_name = accepted.cipher_suite.name
                    key_size = accepted.cipher_suite.key_size

                    # --- Weak cipher checks (HIGH severity) ---
                    # Check for known-weak cipher patterns in the name.
                    if self._is_weak_cipher(cipher_name, key_size):
                        weak_names.append(
                            f"{cipher_name} ({key_size}-bit)"
                        )
                    # --- Medium cipher checks (MEDIUM severity) ---
                    # Only flag as medium if it wasn't already flagged as weak.
                    elif self._is_medium_cipher(cipher_name, key_size):
                        medium_names.append(
                            f"{cipher_name} ({key_size}-bit)"
                        )

            except (AttributeError, Exception) as e:
                logger.debug(
                    "Could not check cipher suites (%s) for %s: %s",
                    attr_name, target.hostport, e,
                )
                continue

        # --- Create findings ---
        # We produce at most two cipher-related findings per target:
        # one for weak ciphers (if any) and one for medium ciphers (if any).

        if weak_names:
            findings.append(Finding(
                module="ssl",
                finding_type="weak_ciphers",
                severity=Severity.HIGH,
                target=target,
                title="Weak Cipher Suites",
                detail="; ".join(weak_names),
                references=["CWE-326", "CWE-327"],
            ))

        if medium_names:
            findings.append(Finding(
                module="ssl",
                finding_type="medium_ciphers",
                severity=Severity.MEDIUM,
                target=target,
                title="Medium-Strength Cipher Suites",
                detail="; ".join(medium_names),
                references=["CWE-326"],
            ))

        return findings

    def _is_weak_cipher(self, cipher_name: str, key_size: int) -> bool:
        """
        Determine if a cipher suite is weak (HIGH severity).

        A cipher is considered weak if:
            1. Its name contains NULL, EXP, ADH, or AECDH — these patterns
               indicate no encryption, export-grade, or no authentication.
            2. Its key size is <= 64 bits — trivially brute-forceable.

        Args:
            cipher_name: The RFC name of the cipher suite.
            key_size:    The symmetric key size in bits.

        Returns:
            True if the cipher should be flagged as weak.
        """
        # Check for known-weak name patterns (case-sensitive because
        # cipher names use uppercase consistently in sslyze).
        for pattern in _WEAK_CIPHER_PATTERNS:
            if pattern in cipher_name:
                return True

        # Check for trivially small key sizes.
        if key_size <= _WEAK_KEY_SIZE_MAX:
            return True

        return False

    def _is_medium_cipher(self, cipher_name: str, key_size: int) -> bool:
        """
        Determine if a cipher suite is medium-strength (MEDIUM severity).

        A cipher is considered medium if:
            1. Its name contains "DES" (but NOT "3DES") — single DES is
               deprecated but not as catastrophically weak as NULL/EXP.
            2. Its name contains "RC4" — known statistical biases.
            3. Its key size is in the range (64, 112] — too weak for long-
               term security but not trivially breakable today.

        This check is only called for ciphers that did NOT match the weak
        check, so there's no risk of double-counting.

        Args:
            cipher_name: The RFC name of the cipher suite.
            key_size:    The symmetric key size in bits.

        Returns:
            True if the cipher should be flagged as medium-strength.
        """
        # Check for DES (but not 3DES).  We check that "DES" appears in
        # the name but "3DES" does not, to avoid false positives on
        # Triple DES cipher suites.
        if _MEDIUM_CIPHER_NAME_DES in cipher_name and "3DES" not in cipher_name:
            return True

        # Check for RC4 — prohibited by RFC 7465 for use in TLS.
        if _MEDIUM_CIPHER_NAME_RC4 in cipher_name:
            return True

        # Check for medium key size range: 64 < key_size <= 112.
        if _MEDIUM_KEY_SIZE_MIN < key_size <= _MEDIUM_KEY_SIZE_MAX:
            return True

        return False

    def _check_vulnerabilities(
        self, target: Target, scan_result
    ) -> list[Finding]:
        """
        Check for specific known TLS vulnerabilities.

        Each check accesses a specific attribute on the scan_result and
        examines a boolean or enum flag.  Individual check failures are
        caught and logged so that one broken check doesn't prevent the
        others from running.

        Vulnerabilities checked:
            1. Heartbleed (CVE-2014-0160)         - CRITICAL
            2. ROBOT (Bleichenbacher oracle)       - HIGH
            3. CCS Injection (CVE-2014-0224)       - HIGH
            4. TLS Compression / CRIME             - MEDIUM
            5. Insecure Renegotiation              - MEDIUM
            6. Missing Fallback SCSV               - LOW
            7. TLS 1.3 Early Data / 0-RTT          - LOW

        Returns:
            List of Finding objects for each detected vulnerability.
        """
        findings: list[Finding] = []

        # --- 1. Heartbleed (CVE-2014-0160) ---
        # Buffer over-read in OpenSSL's heartbeat extension.  Allows
        # remote attackers to read server memory (private keys, session
        # data, user credentials).  CRITICAL because it's remotely
        # exploitable with no authentication required.
        try:
            attempt = scan_result.scan_result.heartbleed
            if (
                attempt.result is not None
                and attempt.result.is_vulnerable_to_heartbleed
            ):
                findings.append(Finding(
                    module="ssl",
                    finding_type="heartbleed",
                    severity=Severity.CRITICAL,
                    target=target,
                    title="Heartbleed Vulnerability (CVE-2014-0160)",
                    detail="Server is vulnerable to the Heartbleed attack",
                    references=["CVE-2014-0160", "CWE-126"],
                ))
        except (AttributeError, Exception) as e:
            logger.debug(
                "Could not check Heartbleed for %s: %s",
                target.hostport, e,
            )

        # --- 2. ROBOT (Return Of Bleichenbacher's Oracle Threat) ---
        # Allows decryption of RSA key exchanges by exploiting subtle
        # differences in server responses during PKCS#1 v1.5 padding
        # validation.  HIGH severity because it enables passive decryption.
        try:
            attempt = scan_result.scan_result.robot
            if attempt.result is not None:
                # ROBOT result is an enum — vulnerable states contain
                # "VULNERABLE" in their name.
                robot_name = attempt.result.robot_result.name
                if "VULNERABLE" in robot_name:
                    findings.append(Finding(
                        module="ssl",
                        finding_type="robot",
                        severity=Severity.HIGH,
                        target=target,
                        title="ROBOT Vulnerability",
                        detail=f"Server is vulnerable to ROBOT attack ({robot_name})",
                        references=["CWE-203"],
                    ))
        except (AttributeError, Exception) as e:
            logger.debug(
                "Could not check ROBOT for %s: %s",
                target.hostport, e,
            )

        # --- 3. CCS Injection (CVE-2014-0224) ---
        # Allows an active MITM attacker to force the use of weak keys
        # during the TLS handshake by sending a ChangeCipherSpec message
        # at the wrong time.  HIGH severity because it enables active
        # traffic interception.
        try:
            attempt = scan_result.scan_result.openssl_ccs_injection
            if (
                attempt.result is not None
                and attempt.result.is_vulnerable_to_ccs_injection
            ):
                findings.append(Finding(
                    module="ssl",
                    finding_type="ccs_injection",
                    severity=Severity.HIGH,
                    target=target,
                    title="OpenSSL CCS Injection (CVE-2014-0224)",
                    detail="Server is vulnerable to CCS injection attack",
                    references=["CVE-2014-0224", "CWE-310"],
                ))
        except (AttributeError, Exception) as e:
            logger.debug(
                "Could not check CCS injection for %s: %s",
                target.hostport, e,
            )

        # --- 4. TLS Compression (CRIME) ---
        # When TLS-level compression is enabled, an attacker can use
        # CRIME (Compression Ratio Info-leak Made Easy) to recover
        # secrets from encrypted traffic.  MEDIUM because it requires
        # the attacker to observe and inject traffic.
        try:
            attempt = scan_result.scan_result.tls_compression
            if (
                attempt.result is not None
                and attempt.result.supports_compression
            ):
                findings.append(Finding(
                    module="ssl",
                    finding_type="tls_compression",
                    severity=Severity.MEDIUM,
                    target=target,
                    title="TLS Compression Enabled (CRIME)",
                    detail="TLS compression is enabled, making the server "
                           "vulnerable to the CRIME attack",
                    references=["CVE-2012-4929", "CWE-310"],
                ))
        except (AttributeError, Exception) as e:
            logger.debug(
                "Could not check TLS compression for %s: %s",
                target.hostport, e,
            )

        # --- 5. Insecure Renegotiation ---
        # Client-initiated renegotiation can be abused for DoS attacks
        # (each renegotiation is CPU-expensive for the server) and
        # insecure renegotiation can enable request injection.
        # MEDIUM severity as exploitation requires active MITM or
        # sustained connection to the target.
        try:
            attempt = scan_result.scan_result.session_renegotiation
            if attempt.result is not None:
                is_vuln = attempt.result.is_vulnerable_to_client_renegotiation_dos
                if is_vuln:
                    findings.append(Finding(
                        module="ssl",
                        finding_type="insecure_renegotiation",
                        severity=Severity.MEDIUM,
                        target=target,
                        title="Insecure TLS Renegotiation",
                        detail="Server is vulnerable to client-initiated "
                               "renegotiation DoS",
                        references=["CVE-2009-3555", "CWE-310"],
                    ))
        except (AttributeError, Exception) as e:
            logger.debug(
                "Could not check renegotiation for %s: %s",
                target.hostport, e,
            )

        # --- 6. Missing TLS_FALLBACK_SCSV ---
        # TLS_FALLBACK_SCSV (RFC 7507) prevents protocol downgrade attacks
        # where an attacker forces a client to fall back to a weaker TLS
        # version.  LOW severity because modern clients rarely fall back
        # and the attack requires an active MITM position.
        try:
            attempt = scan_result.scan_result.tls_fallback_scsv
            if (
                attempt.result is not None
                and not attempt.result.supports_fallback_scsv
            ):
                findings.append(Finding(
                    module="ssl",
                    finding_type="missing_fallback_scsv",
                    severity=Severity.LOW,
                    target=target,
                    title="Missing TLS Fallback SCSV",
                    detail="Server does not support TLS_FALLBACK_SCSV "
                           "(vulnerable to protocol downgrade attacks)",
                    references=["RFC 7507", "CWE-757"],
                ))
        except (AttributeError, Exception) as e:
            logger.debug(
                "Could not check fallback SCSV for %s: %s",
                target.hostport, e,
            )

        # --- 7. TLS 1.3 Early Data (0-RTT) ---
        # TLS 1.3 early data allows sending application data before the
        # handshake completes, reducing latency.  However, early data is
        # not protected against replay attacks — an attacker who captures
        # the initial ClientHello can re-send it to replay the request.
        # LOW severity because exploitation requires capturing the initial
        # handshake and the application must be vulnerable to replays.
        try:
            attempt = scan_result.scan_result.tls_1_3_early_data
            if (
                attempt.result is not None
                and attempt.result.supports_early_data
            ):
                findings.append(Finding(
                    module="ssl",
                    finding_type="early_data",
                    severity=Severity.LOW,
                    target=target,
                    title="TLS 1.3 Early Data (0-RTT) Supported",
                    detail="Server accepts TLS 1.3 early data, which is "
                           "vulnerable to replay attacks",
                    references=["CWE-294"],
                ))
        except (AttributeError, Exception) as e:
            logger.debug(
                "Could not check early data for %s: %s",
                target.hostport, e,
            )

        return findings


# ---------------------------------------------------------------------------
# Module registration
# ---------------------------------------------------------------------------
# Instantiate the scanner and register it with the module registry.
# This runs at import time, so importing this file is sufficient to make
# the SSL scanner available to the orchestrator.

register_module(SSLScanner())
