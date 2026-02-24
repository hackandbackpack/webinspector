"""
webinspector.modules.cert_scanner - Certificate scanner module using sslyze.

Wraps the sslyze library to perform comprehensive X.509 certificate security
checks using the CERTIFICATE_INFO scan command.  This module examines the
server's leaf certificate for common misconfigurations and weaknesses.

This module checks for:
    - Self-signed / untrusted certificates (verified_certificate_chain is None)
    - Expired certificates (not_valid_after_utc in the past)
    - Not-yet-valid certificates (not_valid_before_utc in the future)
    - Weak signature algorithms:
        * SHA1 — collision attacks demonstrated (SHAttered, 2017)
        * MD5  — broken since 2004, practical certificate forgery possible
    - Weak RSA keys (key_size < 2048 bits)
    - Weak ECC keys (curve key_size < 256 bits)
    - Hostname mismatch (leaf cert subject/SAN doesn't match target hostname)

The module only runs against HTTPS targets (accepts_target returns False
for http:// targets).  When sslyze is not installed, the module degrades
gracefully and logs a warning instead of crashing.

sslyze certificate_info API reference (v6.x):
    - Scanner() creates a scanner instance
    - scanner.queue_scans([ServerScanRequest(...)]) queues scan jobs
    - scanner.get_results() yields ServerScanResult objects
    - Each ServerScanResult.scan_result.certificate_info is a ScanCommandAttempt
    - The attempt's .result has a .certificate_deployments list
    - Each deployment (CertificateDeploymentAnalysisResult) has:
        * received_certificate_chain[0] — the leaf certificate
          (cryptography.x509.Certificate)
        * leaf_certificate_subject_matches_hostname — bool
        * verified_certificate_chain — None if untrusted/self-signed
        * path_validation_results — list of PathValidationResult
    - The leaf certificate (cryptography.x509.Certificate) provides:
        * not_valid_before_utc / not_valid_after_utc — datetime objects
        * signature_hash_algorithm — instance with .name (e.g., "sha256")
        * public_key() — RSAPublicKey or EllipticCurvePublicKey
            - RSAPublicKey.key_size — int (bits)
            - EllipticCurvePublicKey.curve.key_size — int (bits)

Author: Red Siege Information Security
"""

import logging
from datetime import datetime, timezone
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
    logger.warning("sslyze not installed - certificate scanner will be disabled")


# ---------------------------------------------------------------------------
# Weak signature algorithm constants
# ---------------------------------------------------------------------------
# These hash algorithm names (as reported by cryptography's
# signature_hash_algorithm.name) are considered weak for certificate signing.
# The mapping is: algorithm name -> severity level.
#
# MD5:  Broken since 2004.  Chosen-prefix collision attacks have been
#       demonstrated against X.509 certificates (Sotirov et al., 2008).
#       HIGH severity because practical forgery is feasible.
#
# SHA1: Collision resistance broken (SHAttered, 2017).  Theoretical
#       certificate forgery is possible but requires significant compute.
#       MEDIUM severity — deprecated but less immediately exploitable.

_WEAK_SIGNATURE_ALGORITHMS = {
    "md5": Severity.HIGH,
    "sha1": Severity.MEDIUM,
}

# ---------------------------------------------------------------------------
# Minimum key size constants
# ---------------------------------------------------------------------------
# These define the minimum acceptable key sizes for RSA and ECC keys.
# Keys smaller than these values are flagged as weak (MEDIUM severity).

# NIST SP 800-131A Rev.2 requires RSA keys >= 2048 bits for all uses
# after 2013.  Keys below this threshold are considered easily factorable
# by well-resourced attackers.
_MIN_RSA_KEY_SIZE = 2048

# NIST recommends ECC keys >= 256 bits (P-256 / secp256r1) as the minimum.
# Smaller curves (e.g., P-192) provide insufficient security margin.
_MIN_ECC_KEY_SIZE = 256


class CertScanner(ScanModule):
    """
    X.509 certificate security scanner.

    Uses sslyze's CERTIFICATE_INFO scan command to analyse a target's
    certificate deployments.  Checks for trust issues, expiration,
    weak cryptographic primitives, and hostname mismatches.

    Only runs against HTTPS targets — the accepts_target() override
    returns False for http:// targets.
    """

    # -----------------------------------------------------------------
    # ScanModule interface — required properties
    # -----------------------------------------------------------------

    @property
    def name(self) -> str:
        """Short identifier used in CLI flags and finding output."""
        return "certs"

    @property
    def description(self) -> str:
        """Human-readable description for --help output."""
        return "Certificate chain, expiry, and trust analysis (sslyze)"

    # -----------------------------------------------------------------
    # ScanModule interface — accepts_target override
    # -----------------------------------------------------------------

    def accepts_target(self, target: Target) -> bool:
        """
        Only scan HTTPS targets.

        Certificate checks are meaningless against plain HTTP targets
        because there is no TLS handshake to obtain a certificate from.
        The orchestrator calls this before scan() so we can skip HTTP
        targets efficiently.
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
        Run certificate checks against a single target using sslyze.

        This method:
            1. Checks that sslyze is available (graceful degradation)
            2. Creates a ServerScanRequest with CERTIFICATE_INFO command
            3. Runs the scan via sslyze's Scanner
            4. Iterates over each certificate deployment and checks:
               a. Trust / self-signed status
               b. Expiration
               c. Not-yet-valid
               d. Signature algorithm strength
               e. Public key strength (RSA and ECC)
               f. Hostname matching

        Args:
            target:        The HTTPS target to scan.
            http_response: Not used by this module (certificate checks use
                           their own TLS connections via sslyze, not HTTP).

        Returns:
            List of Finding objects.  Empty list means no issues found or
            sslyze is unavailable / encountered an error.
        """
        # Guard: sslyze not installed — return empty instead of crashing.
        if not SSLYZE_AVAILABLE:
            logger.warning(
                "sslyze not available, skipping certificate scan for %s",
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

            # Queue the CERTIFICATE_INFO scan command.  This tells sslyze to
            # connect, retrieve the certificate chain, and analyse it against
            # multiple trust stores (Mozilla, Apple, Microsoft, etc.).
            scan_request = ServerScanRequest(
                server_location=location,
                scan_commands={
                    ScanCommand.CERTIFICATE_INFO,
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
                findings.extend(
                    self._check_certificate_info(target, server_scan_result)
                )

        except Exception as e:
            # Catch-all for sslyze errors: connection refused, DNS failure,
            # TLS handshake error, etc.  We log the error and return
            # whatever findings we've collected so far (usually empty).
            logger.error(
                "sslyze certificate scan failed for %s: %s",
                target.hostport, e,
            )

        return findings

    # -----------------------------------------------------------------
    # Private check methods
    # -----------------------------------------------------------------

    def _check_certificate_info(
        self, target: Target, scan_result
    ) -> list[Finding]:
        """
        Process the certificate_info scan result.

        Extracts the certificate_info attempt from the scan result,
        then iterates over each certificate deployment and delegates
        to individual check methods.

        Args:
            target:      The HTTPS target being scanned.
            scan_result: The sslyze ServerScanResult object.

        Returns:
            List of Finding objects from all deployments.
        """
        findings: list[Finding] = []

        try:
            # Access the certificate_info scan attempt.
            cert_attempt = scan_result.scan_result.certificate_info

            # If the scan command did not complete, skip it.
            if cert_attempt.result is None:
                logger.debug(
                    "Certificate info scan did not complete for %s",
                    target.hostport,
                )
                return findings

            # Iterate over each certificate deployment.  Most servers have
            # a single deployment, but some serve different certificates
            # for RSA vs. ECC key exchanges.
            for deployment in cert_attempt.result.certificate_deployments:
                findings.extend(
                    self._check_deployment(target, deployment)
                )

        except (AttributeError, Exception) as e:
            logger.debug(
                "Could not process certificate info for %s: %s",
                target.hostport, e,
            )

        return findings

    def _check_deployment(
        self, target: Target, deployment
    ) -> list[Finding]:
        """
        Check a single certificate deployment for issues.

        A deployment represents one certificate chain served by the server.
        This method extracts the leaf certificate and runs each individual
        check against it.

        Args:
            target:     The HTTPS target being scanned.
            deployment: A CertificateDeploymentAnalysisResult object.

        Returns:
            List of Finding objects for issues found in this deployment.
        """
        findings: list[Finding] = []

        # Extract the leaf certificate (first in the received chain).
        # If the chain is empty, we can't analyse anything.
        if not deployment.received_certificate_chain:
            logger.debug(
                "Empty certificate chain for %s, skipping deployment",
                target.hostport,
            )
            return findings

        leaf_cert = deployment.received_certificate_chain[0]

        # --- Check 1: Self-signed / untrusted certificate ---
        findings.extend(self._check_trust(target, deployment))

        # --- Check 2: Expired certificate ---
        findings.extend(self._check_expiration(target, leaf_cert))

        # --- Check 3: Not-yet-valid certificate ---
        findings.extend(self._check_not_yet_valid(target, leaf_cert))

        # --- Check 4: Weak signature algorithm ---
        findings.extend(self._check_signature_algorithm(target, leaf_cert))

        # --- Check 5: Weak public key ---
        findings.extend(self._check_key_strength(target, leaf_cert))

        # --- Check 6: Hostname mismatch ---
        findings.extend(self._check_hostname_match(target, deployment))

        return findings

    def _check_trust(
        self, target: Target, deployment
    ) -> list[Finding]:
        """
        Check if the certificate chain is trusted.

        A certificate is considered untrusted (self-signed or signed by
        an untrusted CA) when the verified_certificate_chain is None.
        This means sslyze could not build a valid chain to any trust
        store root.

        Severity: HIGH — an untrusted certificate provides no identity
        assurance and will cause browser warnings for all visitors.

        Args:
            target:     The HTTPS target being scanned.
            deployment: The certificate deployment to check.

        Returns:
            A list with one Finding if untrusted, empty list otherwise.
        """
        findings: list[Finding] = []

        try:
            if deployment.verified_certificate_chain is None:
                findings.append(Finding(
                    module="certs",
                    finding_type="untrusted_certificate",
                    severity=Severity.HIGH,
                    target=target,
                    title="Self-Signed or Untrusted Certificate",
                    detail="The certificate chain could not be verified "
                           "against any trusted root certificate authority",
                    references=["CWE-295"],
                ))
        except (AttributeError, Exception) as e:
            logger.debug(
                "Could not check certificate trust for %s: %s",
                target.hostport, e,
            )

        return findings

    def _check_expiration(
        self, target: Target, leaf_cert
    ) -> list[Finding]:
        """
        Check if the certificate has expired.

        Compares the certificate's not_valid_after_utc field against the
        current UTC time.  Expired certificates cause browser warnings and
        indicate the server operator has not maintained proper certificate
        lifecycle management.

        Severity: HIGH — expired certificates break trust for all clients
        and often indicate an operational failure.

        Args:
            target:    The HTTPS target being scanned.
            leaf_cert: The leaf certificate (cryptography.x509.Certificate).

        Returns:
            A list with one Finding if expired, empty list otherwise.
        """
        findings: list[Finding] = []

        try:
            now = datetime.now(timezone.utc)
            if leaf_cert.not_valid_after_utc < now:
                # Format the expiration date for human-readable detail.
                expiry_str = leaf_cert.not_valid_after_utc.strftime(
                    "%Y-%m-%d %H:%M:%S UTC"
                )
                findings.append(Finding(
                    module="certs",
                    finding_type="expired_certificate",
                    severity=Severity.HIGH,
                    target=target,
                    title="Expired Certificate",
                    detail=f"Certificate expired on {expiry_str}",
                    references=["CWE-298"],
                ))
        except (AttributeError, Exception) as e:
            logger.debug(
                "Could not check certificate expiration for %s: %s",
                target.hostport, e,
            )

        return findings

    def _check_not_yet_valid(
        self, target: Target, leaf_cert
    ) -> list[Finding]:
        """
        Check if the certificate is not yet valid.

        Compares the certificate's not_valid_before_utc field against the
        current UTC time.  A certificate with a future start date indicates
        it was installed before its intended validity period — typically a
        configuration error.

        Severity: HIGH — a not-yet-valid certificate will cause the same
        trust failures as an expired certificate.

        Args:
            target:    The HTTPS target being scanned.
            leaf_cert: The leaf certificate (cryptography.x509.Certificate).

        Returns:
            A list with one Finding if not yet valid, empty list otherwise.
        """
        findings: list[Finding] = []

        try:
            now = datetime.now(timezone.utc)
            if leaf_cert.not_valid_before_utc > now:
                # Format the start date for human-readable detail.
                start_str = leaf_cert.not_valid_before_utc.strftime(
                    "%Y-%m-%d %H:%M:%S UTC"
                )
                findings.append(Finding(
                    module="certs",
                    finding_type="not_yet_valid_certificate",
                    severity=Severity.HIGH,
                    target=target,
                    title="Certificate Not Yet Valid",
                    detail=f"Certificate is not valid until {start_str}",
                    references=["CWE-298"],
                ))
        except (AttributeError, Exception) as e:
            logger.debug(
                "Could not check certificate validity start for %s: %s",
                target.hostport, e,
            )

        return findings

    def _check_signature_algorithm(
        self, target: Target, leaf_cert
    ) -> list[Finding]:
        """
        Check if the certificate uses a weak signature hash algorithm.

        Examines the leaf certificate's signature_hash_algorithm.name to
        detect deprecated algorithms:

            - MD5: Broken since 2004.  Chosen-prefix collision attacks
              demonstrated against X.509 certificates.  HIGH severity.
            - SHA1: Collision resistance broken (SHAttered, 2017).
              MEDIUM severity — deprecated but less immediately exploitable.

        Modern certificates should use SHA-256 or stronger (SHA-384, SHA-512).

        Args:
            target:    The HTTPS target being scanned.
            leaf_cert: The leaf certificate (cryptography.x509.Certificate).

        Returns:
            A list with one Finding if weak algorithm, empty list otherwise.
        """
        findings: list[Finding] = []

        try:
            # Get the hash algorithm name, normalised to lowercase for
            # consistent comparison.
            algo = leaf_cert.signature_hash_algorithm
            if algo is None:
                # Some certificates (e.g., Ed25519) have no hash algorithm.
                # These are modern and not weak.
                return findings

            algo_name = algo.name.lower()

            # Check against our known-weak algorithms map.
            if algo_name in _WEAK_SIGNATURE_ALGORITHMS:
                severity = _WEAK_SIGNATURE_ALGORITHMS[algo_name]
                findings.append(Finding(
                    module="certs",
                    finding_type="weak_signature_algorithm",
                    severity=severity,
                    target=target,
                    title="Weak Certificate Signature Algorithm",
                    detail=f"Certificate is signed with {algo_name.upper()}, "
                           f"which is considered cryptographically weak",
                    references=["CWE-328"],
                ))
        except (AttributeError, Exception) as e:
            logger.debug(
                "Could not check signature algorithm for %s: %s",
                target.hostport, e,
            )

        return findings

    def _check_key_strength(
        self, target: Target, leaf_cert
    ) -> list[Finding]:
        """
        Check if the certificate's public key is too small.

        Examines the leaf certificate's public key to determine its type
        and size:

            - RSA keys < 2048 bits: MEDIUM severity.  NIST SP 800-131A
              Rev.2 requires >= 2048 bits.  1024-bit RSA is factorizable
              by well-resourced attackers.
            - ECC keys < 256 bits: MEDIUM severity.  NIST recommends
              P-256 as the minimum curve.  Smaller curves like P-192
              provide insufficient security margin.

        The method uses duck typing to detect whether the key is RSA
        (has key_size directly) or ECC (has curve.key_size), which avoids
        importing the specific cryptography key type classes.

        Args:
            target:    The HTTPS target being scanned.
            leaf_cert: The leaf certificate (cryptography.x509.Certificate).

        Returns:
            A list with one Finding if weak key, empty list otherwise.
        """
        findings: list[Finding] = []

        try:
            pub_key = leaf_cert.public_key()

            # --- RSA key size check ---
            # RSA public keys have a direct key_size attribute.
            # We check for RSA first by looking for key_size without a
            # curve attribute (ECC keys also have key_size but always
            # have a curve attribute).
            if hasattr(pub_key, 'key_size') and not hasattr(pub_key, 'curve'):
                # This is an RSA (or DSA) key — check against minimum size.
                if pub_key.key_size < _MIN_RSA_KEY_SIZE:
                    findings.append(Finding(
                        module="certs",
                        finding_type="weak_key",
                        severity=Severity.MEDIUM,
                        target=target,
                        title="Weak RSA Key",
                        detail=f"RSA key size is {pub_key.key_size} bits "
                               f"(minimum recommended: {_MIN_RSA_KEY_SIZE})",
                        references=["CWE-326"],
                    ))

            # --- ECC key size check ---
            # ECC public keys have a curve attribute with key_size.
            elif hasattr(pub_key, 'curve'):
                curve_size = pub_key.curve.key_size
                if curve_size < _MIN_ECC_KEY_SIZE:
                    findings.append(Finding(
                        module="certs",
                        finding_type="weak_key",
                        severity=Severity.MEDIUM,
                        target=target,
                        title="Weak ECC Key",
                        detail=f"ECC key size is {curve_size} bits "
                               f"(minimum recommended: {_MIN_ECC_KEY_SIZE})",
                        references=["CWE-326"],
                    ))

        except (AttributeError, Exception) as e:
            logger.debug(
                "Could not check key strength for %s: %s",
                target.hostport, e,
            )

        return findings

    def _check_hostname_match(
        self, target: Target, deployment
    ) -> list[Finding]:
        """
        Check if the certificate's subject matches the target hostname.

        sslyze's CertificateDeploymentAnalysisResult provides a boolean
        leaf_certificate_subject_matches_hostname that is True when the
        leaf cert's Common Name or Subject Alternative Names include the
        target hostname.

        A mismatch means the certificate was issued for a different
        domain — browsers will show a warning and the connection provides
        no meaningful identity assurance.

        Severity: HIGH — hostname mismatches break TLS identity validation
        and are a common misconfiguration on shared hosting or after
        domain changes.

        Args:
            target:     The HTTPS target being scanned.
            deployment: The certificate deployment to check.

        Returns:
            A list with one Finding if hostname mismatch, empty list otherwise.
        """
        findings: list[Finding] = []

        try:
            if not deployment.leaf_certificate_subject_matches_hostname:
                findings.append(Finding(
                    module="certs",
                    finding_type="hostname_mismatch",
                    severity=Severity.HIGH,
                    target=target,
                    title="Certificate Hostname Mismatch",
                    detail=f"The certificate's subject does not match "
                           f"the target hostname '{target.host}'",
                    references=["CWE-297"],
                ))
        except (AttributeError, Exception) as e:
            logger.debug(
                "Could not check hostname match for %s: %s",
                target.hostport, e,
            )

        return findings


# ---------------------------------------------------------------------------
# Module registration
# ---------------------------------------------------------------------------
# Instantiate the scanner and register it with the module registry.
# This runs at import time, so importing this file is sufficient to make
# the certificate scanner available to the orchestrator.

register_module(CertScanner())
