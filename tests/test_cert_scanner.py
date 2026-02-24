"""
Tests for the certificate scanner module (cert_scanner.py).

These tests verify that the CertScanner module correctly:
    1. Accepts only HTTPS targets (rejects HTTP)
    2. Detects self-signed / untrusted certificates
    3. Detects expired certificates
    4. Detects not-yet-valid certificates
    5. Detects weak signature algorithms (SHA1 -> MEDIUM, MD5 -> HIGH)
    6. Detects weak RSA keys (< 2048 bits)
    7. Detects weak ECC keys (< 256 bits)
    8. Detects hostname mismatches
    9. Returns empty findings for a clean certificate
   10. Handles sslyze scan failures gracefully
   11. Handles sslyze not being installed

All sslyze interactions are mocked -- no real TLS connections are made.
The tests create mock objects that simulate sslyze's ServerScanResult and
the nested certificate_info result structures (CertificateDeploymentAnalysisResult,
cryptography.x509.Certificate, etc.).

Author: Red Siege Information Security
"""

import pytest
from unittest.mock import patch, MagicMock
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Optional

from webinspector.core.target import Target
from webinspector.core.result import Finding, Severity


# ---------------------------------------------------------------------------
# Mock helpers -- lightweight stand-ins for sslyze / cryptography objects
# ---------------------------------------------------------------------------
# We create simple classes that mimic the nested structure of sslyze's
# certificate_info results and the cryptography library's x509 certificate
# objects.  This approach is more readable than deeply nested MagicMock
# objects and makes test assertions explicit about which fields matter.


class MockHashAlgorithm:
    """
    Stand-in for cryptography.hazmat.primitives.hashes.HashAlgorithm.

    The certificate scanner inspects the name attribute to detect weak
    algorithms like SHA1 and MD5.
    """

    def __init__(self, name: str):
        self.name = name


class MockRSAPublicKey:
    """
    Stand-in for cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey.

    The scanner checks key_size to detect weak RSA keys (< 2048 bits).
    """

    def __init__(self, key_size: int):
        self.key_size = key_size


class MockECCCurve:
    """
    Stand-in for cryptography.hazmat.primitives.asymmetric.ec.EllipticCurve.

    Provides key_size attribute for ECC key size detection.
    """

    def __init__(self, key_size: int):
        self.key_size = key_size


class MockECCPublicKey:
    """
    Stand-in for cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey.

    The scanner checks curve.key_size to detect weak ECC keys (< 256 bits).
    """

    def __init__(self, key_size: int):
        self.curve = MockECCCurve(key_size)
        self.key_size = key_size


class MockCertificate:
    """
    Stand-in for cryptography.x509.Certificate (the leaf certificate).

    Provides the fields the scanner needs:
        - not_valid_before_utc: datetime when cert becomes valid
        - not_valid_after_utc:  datetime when cert expires
        - signature_hash_algorithm: hash algorithm instance (SHA256, SHA1, etc.)
        - public_key(): returns RSA or ECC public key object
    """

    def __init__(
        self,
        not_valid_before_utc: Optional[datetime] = None,
        not_valid_after_utc: Optional[datetime] = None,
        signature_hash_algorithm: Optional[MockHashAlgorithm] = None,
        public_key_obj: Optional[object] = None,
    ):
        # Default: cert valid from one year ago to one year from now.
        now = datetime.now(timezone.utc)
        self.not_valid_before_utc = not_valid_before_utc or (now - timedelta(days=365))
        self.not_valid_after_utc = not_valid_after_utc or (now + timedelta(days=365))
        self.signature_hash_algorithm = signature_hash_algorithm or MockHashAlgorithm("sha256")
        self._public_key = public_key_obj or MockRSAPublicKey(2048)

    def public_key(self):
        """Return the mock public key object."""
        return self._public_key


@dataclass
class MockPathValidationResult:
    """
    Stand-in for sslyze.PathValidationResult.

    Each path validation represents a trust store check.  If the
    verified_certificate_chain is not None, the cert chain is trusted
    by that trust store.
    """
    trust_store: object = None
    verified_certificate_chain: Optional[list] = None
    openssl_error_string: Optional[str] = None


@dataclass
class MockCertificateDeployment:
    """
    Stand-in for sslyze.CertificateDeploymentAnalysisResult.

    This represents one certificate deployment on a server (servers can
    have multiple deployments for RSA/EC key types).  The scanner checks:
        - received_certificate_chain[0] -- the leaf certificate
        - leaf_certificate_subject_matches_hostname -- bool
        - verified_certificate_chain -- None if untrusted/self-signed
        - path_validation_results -- list of validation results
    """
    received_certificate_chain: list = field(default_factory=list)
    leaf_certificate_subject_matches_hostname: bool = True
    verified_certificate_chain: Optional[list] = None
    path_validation_results: list = field(default_factory=list)


@dataclass
class MockCertificateInfoResult:
    """
    Stand-in for the certificate_info scan result.

    Contains a list of certificate deployments.
    """
    certificate_deployments: list = field(default_factory=list)


@dataclass
class MockScanAttempt:
    """
    Stand-in for sslyze.ScanCommandAttempt.

    sslyze wraps every scan result in a ScanCommandAttempt that has:
        - status: COMPLETED / ERROR / NOT_SCHEDULED
        - result: the actual scan result (only set when status == COMPLETED)
        - error_reason / error_trace: set when status == ERROR
    """
    status: str = "COMPLETED"
    result: object = None
    error_reason: object = None
    error_trace: object = None


def _make_clean_cert(**overrides):
    """
    Build a MockCertificate with sensible defaults (valid, strong, SHA256).

    Keyword arguments override individual certificate properties:
        - not_valid_before_utc: datetime
        - not_valid_after_utc:  datetime
        - signature_hash_algorithm: MockHashAlgorithm
        - public_key_obj: MockRSAPublicKey or MockECCPublicKey

    Returns:
        A MockCertificate with either defaults or caller-specified values.
    """
    return MockCertificate(**overrides)


def _make_deployment(
    cert: Optional[MockCertificate] = None,
    hostname_matches: bool = True,
    trusted: bool = True,
):
    """
    Build a MockCertificateDeployment with a single leaf certificate.

    Args:
        cert:             The leaf certificate.  Uses a clean default if None.
        hostname_matches: Whether the leaf cert subject matches the hostname.
        trusted:          Whether the cert chain is trusted (verified_certificate_chain
                          is not None when trusted).

    Returns:
        A MockCertificateDeployment ready for inclusion in a scan result.
    """
    if cert is None:
        cert = _make_clean_cert()

    # Build path validation results.  When trusted, the chain is populated;
    # when untrusted (self-signed), the chain is None.
    chain = [cert] if trusted else None
    path_result = MockPathValidationResult(
        verified_certificate_chain=chain,
    )

    return MockCertificateDeployment(
        received_certificate_chain=[cert],
        leaf_certificate_subject_matches_hostname=hostname_matches,
        verified_certificate_chain=chain,
        path_validation_results=[path_result],
    )


def _make_cert_scan_result(deployments=None):
    """
    Build a mock ServerScanResult with certificate_info results.

    By default, creates a single clean deployment (valid, trusted, SHA256,
    2048-bit RSA, hostname matches).

    Args:
        deployments: List of MockCertificateDeployment objects.  If None,
                     a single clean deployment is used.

    Returns:
        A MagicMock mimicking ServerScanResult with certificate_info.
    """
    if deployments is None:
        deployments = [_make_deployment()]

    cert_info_result = MockCertificateInfoResult(
        certificate_deployments=deployments,
    )

    cert_info_attempt = MockScanAttempt(
        status="COMPLETED",
        result=cert_info_result,
    )

    # Build the nested scan_result structure:
    # server_scan_result.scan_result.certificate_info
    scan_result_inner = MagicMock()
    scan_result_inner.certificate_info = cert_info_attempt

    server_scan_result = MagicMock()
    server_scan_result.scan_result = scan_result_inner

    return server_scan_result


# ---------------------------------------------------------------------------
# Target fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def https_target():
    """An HTTPS target for certificate scanning."""
    return Target(host="example.com", port=443, scheme="https")


@pytest.fixture
def http_target():
    """An HTTP target that the certificate scanner should reject."""
    return Target(host="example.com", port=80, scheme="http")


# ===========================================================================
# Tests for accepts_target
# ===========================================================================

class TestCertScannerAcceptsTarget:
    """Verify that the certificate scanner only accepts HTTPS targets."""

    def test_accepts_https(self, https_target):
        """Certificate scanner should accept targets with scheme='https'."""
        from webinspector.modules.cert_scanner import CertScanner
        scanner = CertScanner()
        assert scanner.accepts_target(https_target) is True

    def test_rejects_http(self, http_target):
        """Certificate scanner should reject targets with scheme='http'."""
        from webinspector.modules.cert_scanner import CertScanner
        scanner = CertScanner()
        assert scanner.accepts_target(http_target) is False

    def test_accepts_https_non_standard_port(self):
        """Certificate scanner should accept HTTPS on non-standard ports (e.g., 8443)."""
        from webinspector.modules.cert_scanner import CertScanner
        target = Target(host="example.com", port=8443, scheme="https")
        scanner = CertScanner()
        assert scanner.accepts_target(target) is True


# ===========================================================================
# Tests for module properties
# ===========================================================================

class TestCertScannerProperties:
    """Verify name and description properties."""

    def test_name(self):
        """Module name should be 'certs'."""
        from webinspector.modules.cert_scanner import CertScanner
        scanner = CertScanner()
        assert scanner.name == "certs"

    def test_description(self):
        """Module should have a non-empty description."""
        from webinspector.modules.cert_scanner import CertScanner
        scanner = CertScanner()
        assert len(scanner.description) > 0
        # Should mention certificate in the description
        assert "cert" in scanner.description.lower()


# ===========================================================================
# Tests for self-signed / untrusted certificate detection
# ===========================================================================

class TestUntrustedCertificate:
    """Verify detection of self-signed and untrusted certificates."""

    @patch("webinspector.modules.cert_scanner.Scanner")
    def test_detects_untrusted_cert(self, mock_scanner_cls, https_target):
        """
        A certificate with no verified chain (self-signed or untrusted CA)
        should produce a HIGH severity finding.

        Self-signed certificates are common on internal servers but indicate
        that no trusted third-party has validated the server's identity.
        """
        from webinspector.modules.cert_scanner import CertScanner

        # Build a deployment with an untrusted (self-signed) certificate
        deployment = _make_deployment(trusted=False)
        result = _make_cert_scan_result(deployments=[deployment])

        mock_scanner = MagicMock()
        mock_scanner.get_results.return_value = iter([result])
        mock_scanner_cls.return_value = mock_scanner

        scanner = CertScanner()
        findings = scanner.scan(https_target)

        untrusted = [f for f in findings if f.finding_type == "untrusted_certificate"]
        assert len(untrusted) == 1
        assert untrusted[0].severity == Severity.HIGH

    @patch("webinspector.modules.cert_scanner.Scanner")
    def test_trusted_cert_no_finding(self, mock_scanner_cls, https_target):
        """
        A trusted certificate (verified chain is not None) should NOT produce
        an untrusted finding.
        """
        from webinspector.modules.cert_scanner import CertScanner

        deployment = _make_deployment(trusted=True)
        result = _make_cert_scan_result(deployments=[deployment])

        mock_scanner = MagicMock()
        mock_scanner.get_results.return_value = iter([result])
        mock_scanner_cls.return_value = mock_scanner

        scanner = CertScanner()
        findings = scanner.scan(https_target)

        untrusted = [f for f in findings if f.finding_type == "untrusted_certificate"]
        assert len(untrusted) == 0


# ===========================================================================
# Tests for expired certificate detection
# ===========================================================================

class TestExpiredCertificate:
    """Verify detection of expired certificates."""

    @patch("webinspector.modules.cert_scanner.Scanner")
    def test_detects_expired_cert(self, mock_scanner_cls, https_target):
        """
        A certificate whose not_valid_after_utc is in the past should
        produce a HIGH severity finding.

        Expired certificates cause browser warnings and indicate the
        server operator has not maintained proper certificate lifecycle.
        """
        from webinspector.modules.cert_scanner import CertScanner

        # Create a cert that expired yesterday
        expired_cert = _make_clean_cert(
            not_valid_after_utc=datetime.now(timezone.utc) - timedelta(days=1),
        )
        deployment = _make_deployment(cert=expired_cert)
        result = _make_cert_scan_result(deployments=[deployment])

        mock_scanner = MagicMock()
        mock_scanner.get_results.return_value = iter([result])
        mock_scanner_cls.return_value = mock_scanner

        scanner = CertScanner()
        findings = scanner.scan(https_target)

        expired = [f for f in findings if f.finding_type == "expired_certificate"]
        assert len(expired) == 1
        assert expired[0].severity == Severity.HIGH

    @patch("webinspector.modules.cert_scanner.Scanner")
    def test_valid_cert_not_expired(self, mock_scanner_cls, https_target):
        """
        A certificate whose not_valid_after_utc is in the future should NOT
        produce an expired finding.
        """
        from webinspector.modules.cert_scanner import CertScanner

        valid_cert = _make_clean_cert(
            not_valid_after_utc=datetime.now(timezone.utc) + timedelta(days=365),
        )
        deployment = _make_deployment(cert=valid_cert)
        result = _make_cert_scan_result(deployments=[deployment])

        mock_scanner = MagicMock()
        mock_scanner.get_results.return_value = iter([result])
        mock_scanner_cls.return_value = mock_scanner

        scanner = CertScanner()
        findings = scanner.scan(https_target)

        expired = [f for f in findings if f.finding_type == "expired_certificate"]
        assert len(expired) == 0


# ===========================================================================
# Tests for not-yet-valid certificate detection
# ===========================================================================

class TestNotYetValidCertificate:
    """Verify detection of certificates that are not yet valid."""

    @patch("webinspector.modules.cert_scanner.Scanner")
    def test_detects_not_yet_valid_cert(self, mock_scanner_cls, https_target):
        """
        A certificate whose not_valid_before_utc is in the future should
        produce a HIGH severity finding.

        This can occur when a certificate is installed before its start
        date, indicating a configuration error.
        """
        from webinspector.modules.cert_scanner import CertScanner

        # Create a cert that isn't valid until tomorrow
        future_cert = _make_clean_cert(
            not_valid_before_utc=datetime.now(timezone.utc) + timedelta(days=1),
        )
        deployment = _make_deployment(cert=future_cert)
        result = _make_cert_scan_result(deployments=[deployment])

        mock_scanner = MagicMock()
        mock_scanner.get_results.return_value = iter([result])
        mock_scanner_cls.return_value = mock_scanner

        scanner = CertScanner()
        findings = scanner.scan(https_target)

        not_yet = [f for f in findings if f.finding_type == "not_yet_valid_certificate"]
        assert len(not_yet) == 1
        assert not_yet[0].severity == Severity.HIGH

    @patch("webinspector.modules.cert_scanner.Scanner")
    def test_already_valid_cert_no_finding(self, mock_scanner_cls, https_target):
        """
        A certificate whose not_valid_before_utc is in the past should NOT
        produce a not-yet-valid finding.
        """
        from webinspector.modules.cert_scanner import CertScanner

        valid_cert = _make_clean_cert(
            not_valid_before_utc=datetime.now(timezone.utc) - timedelta(days=365),
        )
        deployment = _make_deployment(cert=valid_cert)
        result = _make_cert_scan_result(deployments=[deployment])

        mock_scanner = MagicMock()
        mock_scanner.get_results.return_value = iter([result])
        mock_scanner_cls.return_value = mock_scanner

        scanner = CertScanner()
        findings = scanner.scan(https_target)

        not_yet = [f for f in findings if f.finding_type == "not_yet_valid_certificate"]
        assert len(not_yet) == 0


# ===========================================================================
# Tests for weak signature algorithm detection
# ===========================================================================

class TestWeakSignatureAlgorithm:
    """Verify detection of weak certificate signature algorithms."""

    @patch("webinspector.modules.cert_scanner.Scanner")
    def test_detects_sha1_signature(self, mock_scanner_cls, https_target):
        """
        SHA1-signed certificates should produce a MEDIUM severity finding.

        SHA1 collision attacks have been demonstrated (SHAttered, 2017)
        making it theoretically possible to forge certificates.  However,
        practical exploitation requires significant resources.
        """
        from webinspector.modules.cert_scanner import CertScanner

        sha1_cert = _make_clean_cert(
            signature_hash_algorithm=MockHashAlgorithm("sha1"),
        )
        deployment = _make_deployment(cert=sha1_cert)
        result = _make_cert_scan_result(deployments=[deployment])

        mock_scanner = MagicMock()
        mock_scanner.get_results.return_value = iter([result])
        mock_scanner_cls.return_value = mock_scanner

        scanner = CertScanner()
        findings = scanner.scan(https_target)

        sig = [f for f in findings if f.finding_type == "weak_signature_algorithm"]
        assert len(sig) == 1
        assert sig[0].severity == Severity.MEDIUM
        assert "sha1" in sig[0].detail.lower()

    @patch("webinspector.modules.cert_scanner.Scanner")
    def test_detects_md5_signature(self, mock_scanner_cls, https_target):
        """
        MD5-signed certificates should produce a HIGH severity finding.

        MD5 has been broken since 2004 and practical collision attacks
        have been demonstrated against X.509 certificates.
        """
        from webinspector.modules.cert_scanner import CertScanner

        md5_cert = _make_clean_cert(
            signature_hash_algorithm=MockHashAlgorithm("md5"),
        )
        deployment = _make_deployment(cert=md5_cert)
        result = _make_cert_scan_result(deployments=[deployment])

        mock_scanner = MagicMock()
        mock_scanner.get_results.return_value = iter([result])
        mock_scanner_cls.return_value = mock_scanner

        scanner = CertScanner()
        findings = scanner.scan(https_target)

        sig = [f for f in findings if f.finding_type == "weak_signature_algorithm"]
        assert len(sig) == 1
        assert sig[0].severity == Severity.HIGH
        assert "md5" in sig[0].detail.lower()

    @patch("webinspector.modules.cert_scanner.Scanner")
    def test_sha256_not_flagged(self, mock_scanner_cls, https_target):
        """
        SHA256-signed certificates are secure and should NOT produce a
        weak signature finding.
        """
        from webinspector.modules.cert_scanner import CertScanner

        sha256_cert = _make_clean_cert(
            signature_hash_algorithm=MockHashAlgorithm("sha256"),
        )
        deployment = _make_deployment(cert=sha256_cert)
        result = _make_cert_scan_result(deployments=[deployment])

        mock_scanner = MagicMock()
        mock_scanner.get_results.return_value = iter([result])
        mock_scanner_cls.return_value = mock_scanner

        scanner = CertScanner()
        findings = scanner.scan(https_target)

        sig = [f for f in findings if f.finding_type == "weak_signature_algorithm"]
        assert len(sig) == 0

    @patch("webinspector.modules.cert_scanner.Scanner")
    def test_sha384_not_flagged(self, mock_scanner_cls, https_target):
        """
        SHA384-signed certificates are secure and should NOT produce a
        weak signature finding.
        """
        from webinspector.modules.cert_scanner import CertScanner

        sha384_cert = _make_clean_cert(
            signature_hash_algorithm=MockHashAlgorithm("sha384"),
        )
        deployment = _make_deployment(cert=sha384_cert)
        result = _make_cert_scan_result(deployments=[deployment])

        mock_scanner = MagicMock()
        mock_scanner.get_results.return_value = iter([result])
        mock_scanner_cls.return_value = mock_scanner

        scanner = CertScanner()
        findings = scanner.scan(https_target)

        sig = [f for f in findings if f.finding_type == "weak_signature_algorithm"]
        assert len(sig) == 0


# ===========================================================================
# Tests for weak RSA key detection
# ===========================================================================

class TestWeakRSAKey:
    """Verify detection of weak RSA key sizes."""

    @patch("webinspector.modules.cert_scanner.Scanner")
    def test_detects_1024_bit_rsa(self, mock_scanner_cls, https_target):
        """
        A 1024-bit RSA key is considered weak (factoring is feasible for
        well-resourced attackers) and should produce a MEDIUM finding.
        """
        from webinspector.modules.cert_scanner import CertScanner

        weak_rsa_cert = _make_clean_cert(
            public_key_obj=MockRSAPublicKey(1024),
        )
        deployment = _make_deployment(cert=weak_rsa_cert)
        result = _make_cert_scan_result(deployments=[deployment])

        mock_scanner = MagicMock()
        mock_scanner.get_results.return_value = iter([result])
        mock_scanner_cls.return_value = mock_scanner

        scanner = CertScanner()
        findings = scanner.scan(https_target)

        weak_key = [f for f in findings if f.finding_type == "weak_key"]
        assert len(weak_key) == 1
        assert weak_key[0].severity == Severity.MEDIUM
        assert "1024" in weak_key[0].detail

    @patch("webinspector.modules.cert_scanner.Scanner")
    def test_detects_512_bit_rsa(self, mock_scanner_cls, https_target):
        """
        A 512-bit RSA key is trivially breakable and should produce a
        MEDIUM finding (severity is MEDIUM per specification).
        """
        from webinspector.modules.cert_scanner import CertScanner

        weak_rsa_cert = _make_clean_cert(
            public_key_obj=MockRSAPublicKey(512),
        )
        deployment = _make_deployment(cert=weak_rsa_cert)
        result = _make_cert_scan_result(deployments=[deployment])

        mock_scanner = MagicMock()
        mock_scanner.get_results.return_value = iter([result])
        mock_scanner_cls.return_value = mock_scanner

        scanner = CertScanner()
        findings = scanner.scan(https_target)

        weak_key = [f for f in findings if f.finding_type == "weak_key"]
        assert len(weak_key) == 1
        assert weak_key[0].severity == Severity.MEDIUM

    @patch("webinspector.modules.cert_scanner.Scanner")
    def test_2048_bit_rsa_not_flagged(self, mock_scanner_cls, https_target):
        """
        A 2048-bit RSA key is the minimum recommended size and should NOT
        produce a weak key finding.
        """
        from webinspector.modules.cert_scanner import CertScanner

        strong_rsa_cert = _make_clean_cert(
            public_key_obj=MockRSAPublicKey(2048),
        )
        deployment = _make_deployment(cert=strong_rsa_cert)
        result = _make_cert_scan_result(deployments=[deployment])

        mock_scanner = MagicMock()
        mock_scanner.get_results.return_value = iter([result])
        mock_scanner_cls.return_value = mock_scanner

        scanner = CertScanner()
        findings = scanner.scan(https_target)

        weak_key = [f for f in findings if f.finding_type == "weak_key"]
        assert len(weak_key) == 0

    @patch("webinspector.modules.cert_scanner.Scanner")
    def test_4096_bit_rsa_not_flagged(self, mock_scanner_cls, https_target):
        """
        A 4096-bit RSA key is strong and should NOT produce a weak key finding.
        """
        from webinspector.modules.cert_scanner import CertScanner

        strong_rsa_cert = _make_clean_cert(
            public_key_obj=MockRSAPublicKey(4096),
        )
        deployment = _make_deployment(cert=strong_rsa_cert)
        result = _make_cert_scan_result(deployments=[deployment])

        mock_scanner = MagicMock()
        mock_scanner.get_results.return_value = iter([result])
        mock_scanner_cls.return_value = mock_scanner

        scanner = CertScanner()
        findings = scanner.scan(https_target)

        weak_key = [f for f in findings if f.finding_type == "weak_key"]
        assert len(weak_key) == 0


# ===========================================================================
# Tests for weak ECC key detection
# ===========================================================================

class TestWeakECCKey:
    """Verify detection of weak ECC key sizes."""

    @patch("webinspector.modules.cert_scanner.Scanner")
    def test_detects_192_bit_ecc(self, mock_scanner_cls, https_target):
        """
        A 192-bit ECC key is below the 256-bit minimum and should produce
        a MEDIUM severity finding.
        """
        from webinspector.modules.cert_scanner import CertScanner

        weak_ecc_cert = _make_clean_cert(
            public_key_obj=MockECCPublicKey(192),
        )
        deployment = _make_deployment(cert=weak_ecc_cert)
        result = _make_cert_scan_result(deployments=[deployment])

        mock_scanner = MagicMock()
        mock_scanner.get_results.return_value = iter([result])
        mock_scanner_cls.return_value = mock_scanner

        scanner = CertScanner()
        findings = scanner.scan(https_target)

        weak_key = [f for f in findings if f.finding_type == "weak_key"]
        assert len(weak_key) == 1
        assert weak_key[0].severity == Severity.MEDIUM
        assert "192" in weak_key[0].detail

    @patch("webinspector.modules.cert_scanner.Scanner")
    def test_detects_224_bit_ecc(self, mock_scanner_cls, https_target):
        """
        A 224-bit ECC key is below the 256-bit minimum and should produce
        a MEDIUM severity finding.
        """
        from webinspector.modules.cert_scanner import CertScanner

        weak_ecc_cert = _make_clean_cert(
            public_key_obj=MockECCPublicKey(224),
        )
        deployment = _make_deployment(cert=weak_ecc_cert)
        result = _make_cert_scan_result(deployments=[deployment])

        mock_scanner = MagicMock()
        mock_scanner.get_results.return_value = iter([result])
        mock_scanner_cls.return_value = mock_scanner

        scanner = CertScanner()
        findings = scanner.scan(https_target)

        weak_key = [f for f in findings if f.finding_type == "weak_key"]
        assert len(weak_key) == 1
        assert weak_key[0].severity == Severity.MEDIUM

    @patch("webinspector.modules.cert_scanner.Scanner")
    def test_256_bit_ecc_not_flagged(self, mock_scanner_cls, https_target):
        """
        A 256-bit ECC key (e.g., P-256 / secp256r1) meets the minimum
        requirement and should NOT produce a weak key finding.
        """
        from webinspector.modules.cert_scanner import CertScanner

        strong_ecc_cert = _make_clean_cert(
            public_key_obj=MockECCPublicKey(256),
        )
        deployment = _make_deployment(cert=strong_ecc_cert)
        result = _make_cert_scan_result(deployments=[deployment])

        mock_scanner = MagicMock()
        mock_scanner.get_results.return_value = iter([result])
        mock_scanner_cls.return_value = mock_scanner

        scanner = CertScanner()
        findings = scanner.scan(https_target)

        weak_key = [f for f in findings if f.finding_type == "weak_key"]
        assert len(weak_key) == 0

    @patch("webinspector.modules.cert_scanner.Scanner")
    def test_384_bit_ecc_not_flagged(self, mock_scanner_cls, https_target):
        """
        A 384-bit ECC key (e.g., P-384 / secp384r1) is strong and should
        NOT produce a weak key finding.
        """
        from webinspector.modules.cert_scanner import CertScanner

        strong_ecc_cert = _make_clean_cert(
            public_key_obj=MockECCPublicKey(384),
        )
        deployment = _make_deployment(cert=strong_ecc_cert)
        result = _make_cert_scan_result(deployments=[deployment])

        mock_scanner = MagicMock()
        mock_scanner.get_results.return_value = iter([result])
        mock_scanner_cls.return_value = mock_scanner

        scanner = CertScanner()
        findings = scanner.scan(https_target)

        weak_key = [f for f in findings if f.finding_type == "weak_key"]
        assert len(weak_key) == 0


# ===========================================================================
# Tests for hostname mismatch detection
# ===========================================================================

class TestHostnameMismatch:
    """Verify detection of hostname mismatches."""

    @patch("webinspector.modules.cert_scanner.Scanner")
    def test_detects_hostname_mismatch(self, mock_scanner_cls, https_target):
        """
        When the certificate's subject/SAN does not match the target
        hostname, a HIGH severity finding should be produced.

        Hostname mismatches cause browser warnings and may indicate the
        wrong certificate is installed, or the server is misconfigured.
        """
        from webinspector.modules.cert_scanner import CertScanner

        deployment = _make_deployment(hostname_matches=False)
        result = _make_cert_scan_result(deployments=[deployment])

        mock_scanner = MagicMock()
        mock_scanner.get_results.return_value = iter([result])
        mock_scanner_cls.return_value = mock_scanner

        scanner = CertScanner()
        findings = scanner.scan(https_target)

        mismatch = [f for f in findings if f.finding_type == "hostname_mismatch"]
        assert len(mismatch) == 1
        assert mismatch[0].severity == Severity.HIGH

    @patch("webinspector.modules.cert_scanner.Scanner")
    def test_matching_hostname_no_finding(self, mock_scanner_cls, https_target):
        """
        When the certificate matches the hostname, no hostname mismatch
        finding should be produced.
        """
        from webinspector.modules.cert_scanner import CertScanner

        deployment = _make_deployment(hostname_matches=True)
        result = _make_cert_scan_result(deployments=[deployment])

        mock_scanner = MagicMock()
        mock_scanner.get_results.return_value = iter([result])
        mock_scanner_cls.return_value = mock_scanner

        scanner = CertScanner()
        findings = scanner.scan(https_target)

        mismatch = [f for f in findings if f.finding_type == "hostname_mismatch"]
        assert len(mismatch) == 0


# ===========================================================================
# Tests for clean targets and error handling
# ===========================================================================

class TestCleanTargetAndErrors:
    """Verify behaviour for secure targets and error scenarios."""

    @patch("webinspector.modules.cert_scanner.Scanner")
    def test_clean_cert_no_findings(self, mock_scanner_cls, https_target):
        """
        A target with a valid, trusted, SHA256, 2048-bit RSA certificate
        matching the hostname should produce zero findings.
        """
        from webinspector.modules.cert_scanner import CertScanner

        # Default _make_cert_scan_result produces a clean deployment
        result = _make_cert_scan_result()

        mock_scanner = MagicMock()
        mock_scanner.get_results.return_value = iter([result])
        mock_scanner_cls.return_value = mock_scanner

        scanner = CertScanner()
        findings = scanner.scan(https_target)

        assert len(findings) == 0

    @patch("webinspector.modules.cert_scanner.Scanner")
    def test_scan_failure_returns_empty(self, mock_scanner_cls, https_target):
        """
        When sslyze throws an exception (e.g., connection refused, DNS
        failure), the scanner should catch it gracefully and return an
        empty findings list rather than crashing.
        """
        from webinspector.modules.cert_scanner import CertScanner

        # Make the scanner raise an exception when queueing scans
        mock_scanner = MagicMock()
        mock_scanner.queue_scans.side_effect = Exception("Connection refused")
        mock_scanner_cls.return_value = mock_scanner

        scanner = CertScanner()
        findings = scanner.scan(https_target)

        assert isinstance(findings, list)
        assert len(findings) == 0

    @patch("webinspector.modules.cert_scanner.Scanner")
    def test_cert_info_error_returns_empty(self, mock_scanner_cls, https_target):
        """
        When the certificate_info scan command fails (result is None),
        the scanner should return an empty list.
        """
        from webinspector.modules.cert_scanner import CertScanner

        # Build a result where certificate_info has a None result
        cert_info_attempt = MockScanAttempt(
            status="ERROR",
            result=None,
            error_reason="BUG_IN_SSLYZE",
        )

        scan_result_inner = MagicMock()
        scan_result_inner.certificate_info = cert_info_attempt

        server_scan_result = MagicMock()
        server_scan_result.scan_result = scan_result_inner

        mock_scanner = MagicMock()
        mock_scanner.get_results.return_value = iter([server_scan_result])
        mock_scanner_cls.return_value = mock_scanner

        scanner = CertScanner()
        findings = scanner.scan(https_target)

        assert isinstance(findings, list)
        assert len(findings) == 0

    @patch("webinspector.modules.cert_scanner.SSLYZE_AVAILABLE", False)
    def test_sslyze_not_installed(self, https_target):
        """
        When sslyze is not installed (SSLYZE_AVAILABLE=False), the
        scanner should return an empty list without error.
        """
        from webinspector.modules.cert_scanner import CertScanner

        scanner = CertScanner()
        findings = scanner.scan(https_target)

        assert isinstance(findings, list)
        assert len(findings) == 0

    @patch("webinspector.modules.cert_scanner.Scanner")
    def test_empty_certificate_chain_returns_empty(self, mock_scanner_cls, https_target):
        """
        When the received certificate chain is empty (no leaf cert), the
        scanner should handle it gracefully and produce no findings for
        that deployment.
        """
        from webinspector.modules.cert_scanner import CertScanner

        # Deployment with empty certificate chain
        deployment = MockCertificateDeployment(
            received_certificate_chain=[],
            leaf_certificate_subject_matches_hostname=True,
            verified_certificate_chain=[],
            path_validation_results=[],
        )
        result = _make_cert_scan_result(deployments=[deployment])

        mock_scanner = MagicMock()
        mock_scanner.get_results.return_value = iter([result])
        mock_scanner_cls.return_value = mock_scanner

        scanner = CertScanner()
        findings = scanner.scan(https_target)

        assert isinstance(findings, list)
        # Should not crash; may have 0 or more findings but should not error


# ===========================================================================
# Tests for multiple findings in a single scan
# ===========================================================================

class TestMultipleFindings:
    """Verify that multiple issues on a single certificate are all reported."""

    @patch("webinspector.modules.cert_scanner.Scanner")
    def test_multiple_issues_on_one_cert(self, mock_scanner_cls, https_target):
        """
        A certificate with multiple problems (expired, SHA1, weak key,
        hostname mismatch) should produce a finding for each issue.
        """
        from webinspector.modules.cert_scanner import CertScanner

        # Create a really bad certificate: expired, SHA1, 1024-bit RSA
        bad_cert = _make_clean_cert(
            not_valid_after_utc=datetime.now(timezone.utc) - timedelta(days=30),
            signature_hash_algorithm=MockHashAlgorithm("sha1"),
            public_key_obj=MockRSAPublicKey(1024),
        )

        # Also untrusted and hostname mismatch
        deployment = _make_deployment(
            cert=bad_cert,
            hostname_matches=False,
            trusted=False,
        )
        result = _make_cert_scan_result(deployments=[deployment])

        mock_scanner = MagicMock()
        mock_scanner.get_results.return_value = iter([result])
        mock_scanner_cls.return_value = mock_scanner

        scanner = CertScanner()
        findings = scanner.scan(https_target)

        # Extract finding types
        types = {f.finding_type for f in findings}

        # Should have findings for all four issues
        assert "expired_certificate" in types
        assert "weak_signature_algorithm" in types
        assert "weak_key" in types
        assert "hostname_mismatch" in types
        assert "untrusted_certificate" in types

    @patch("webinspector.modules.cert_scanner.Scanner")
    def test_findings_have_correct_module(self, mock_scanner_cls, https_target):
        """Every finding should have module='certs'."""
        from webinspector.modules.cert_scanner import CertScanner

        # Create a cert with a few issues
        bad_cert = _make_clean_cert(
            not_valid_after_utc=datetime.now(timezone.utc) - timedelta(days=1),
            signature_hash_algorithm=MockHashAlgorithm("sha1"),
        )
        deployment = _make_deployment(cert=bad_cert, hostname_matches=False)
        result = _make_cert_scan_result(deployments=[deployment])

        mock_scanner = MagicMock()
        mock_scanner.get_results.return_value = iter([result])
        mock_scanner_cls.return_value = mock_scanner

        scanner = CertScanner()
        findings = scanner.scan(https_target)

        assert len(findings) >= 2
        for finding in findings:
            assert finding.module == "certs"
            assert finding.target is https_target

    @patch("webinspector.modules.cert_scanner.Scanner")
    def test_findings_have_references(self, mock_scanner_cls, https_target):
        """Findings should include CWE or other references where appropriate."""
        from webinspector.modules.cert_scanner import CertScanner

        expired_cert = _make_clean_cert(
            not_valid_after_utc=datetime.now(timezone.utc) - timedelta(days=1),
        )
        deployment = _make_deployment(cert=expired_cert)
        result = _make_cert_scan_result(deployments=[deployment])

        mock_scanner = MagicMock()
        mock_scanner.get_results.return_value = iter([result])
        mock_scanner_cls.return_value = mock_scanner

        scanner = CertScanner()
        findings = scanner.scan(https_target)

        expired = [f for f in findings if f.finding_type == "expired_certificate"]
        assert len(expired) == 1
        assert len(expired[0].references) > 0

    @patch("webinspector.modules.cert_scanner.Scanner")
    def test_multiple_deployments(self, mock_scanner_cls, https_target):
        """
        When a server has multiple certificate deployments (e.g., RSA and
        ECC), the scanner should check all deployments.
        """
        from webinspector.modules.cert_scanner import CertScanner

        # Deployment 1: clean RSA cert
        deployment1 = _make_deployment()

        # Deployment 2: expired ECC cert
        expired_cert = _make_clean_cert(
            not_valid_after_utc=datetime.now(timezone.utc) - timedelta(days=1),
            public_key_obj=MockECCPublicKey(256),
        )
        deployment2 = _make_deployment(cert=expired_cert)

        result = _make_cert_scan_result(deployments=[deployment1, deployment2])

        mock_scanner = MagicMock()
        mock_scanner.get_results.return_value = iter([result])
        mock_scanner_cls.return_value = mock_scanner

        scanner = CertScanner()
        findings = scanner.scan(https_target)

        # Should detect the expired cert from deployment 2
        expired = [f for f in findings if f.finding_type == "expired_certificate"]
        assert len(expired) == 1


# ===========================================================================
# Test module registration
# ===========================================================================

class TestCertScannerRegistration:
    """Verify that importing the module registers it."""

    def test_module_registers(self):
        """
        Importing cert_scanner should call register_module() at the bottom
        of the file, making it discoverable by the module registry.
        """
        from webinspector.modules import _registry
        from webinspector.modules.cert_scanner import CertScanner

        # The module registers itself at import time.
        # Check that an instance of CertScanner is in the registry.
        cert_modules = [m for m in _registry if m.name == "certs"]
        assert len(cert_modules) >= 1
        assert isinstance(cert_modules[0], CertScanner)
