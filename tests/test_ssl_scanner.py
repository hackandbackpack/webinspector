"""
Tests for the SSL/TLS scanner module (ssl_scanner.py).

These tests verify that the SSLScanner module correctly:
    1. Accepts only HTTPS targets (rejects HTTP)
    2. Detects deprecated SSL/TLS protocols (SSLv2, SSLv3, TLSv1.0, TLSv1.1)
    3. Detects weak cipher suites (NULL, EXP, ADH, AECDH, key_size <= 64)
    4. Detects medium-strength cipher suites (DES, RC4, 64 < key_size <= 112)
    5. Detects Heartbleed vulnerability
    6. Detects ROBOT vulnerability
    7. Detects CCS injection vulnerability
    8. Detects TLS compression (CRIME attack)
    9. Detects insecure renegotiation
   10. Detects missing TLS fallback SCSV
   11. Detects TLS 1.3 early data (0-RTT)
   12. Returns empty findings for a clean target
   13. Handles sslyze scan failures gracefully

All sslyze interactions are mocked — no real TLS connections are made.
The tests create mock objects that simulate sslyze's ServerScanResult and
its nested scan attempt / result dataclasses.

Author: Red Siege Information Security
"""

import pytest
from unittest.mock import patch, MagicMock, PropertyMock
from dataclasses import dataclass
from typing import Optional, List

from webinspector.core.target import Target
from webinspector.core.result import Finding, Severity


# ---------------------------------------------------------------------------
# Mock helpers — lightweight stand-ins for sslyze dataclasses
# ---------------------------------------------------------------------------
# We create simple dataclass stand-ins for sslyze's deeply nested result
# structures.  This approach is more readable than building nested MagicMock
# objects, and makes the test assertions explicit about which fields matter.

@dataclass
class MockCipherSuite:
    """Stand-in for sslyze.CipherSuite."""
    name: str
    is_anonymous: bool = False
    key_size: int = 128
    openssl_name: str = ""


@dataclass
class MockCipherSuiteAccepted:
    """Stand-in for sslyze.CipherSuiteAcceptedByServer."""
    cipher_suite: MockCipherSuite
    ephemeral_key: Optional[object] = None


@dataclass
class MockCipherSuitesScanResult:
    """Stand-in for sslyze.CipherSuitesScanResult."""
    accepted_cipher_suites: list
    rejected_cipher_suites: list = None
    tls_version_used: str = "TLS_1_2"

    def __post_init__(self):
        if self.rejected_cipher_suites is None:
            self.rejected_cipher_suites = []


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


def _make_cipher_attempt(accepted_ciphers=None):
    """
    Build a MockScanAttempt containing a cipher suites result.

    Args:
        accepted_ciphers: List of (name, key_size) tuples for accepted ciphers.
                          If None, creates an empty (no accepted ciphers) result.

    Returns:
        MockScanAttempt with a MockCipherSuitesScanResult inside.
    """
    if accepted_ciphers is None:
        accepted_ciphers = []

    accepted = [
        MockCipherSuiteAccepted(
            cipher_suite=MockCipherSuite(name=name, key_size=key_size)
        )
        for name, key_size in accepted_ciphers
    ]
    return MockScanAttempt(
        status="COMPLETED",
        result=MockCipherSuitesScanResult(accepted_cipher_suites=accepted),
    )


def _empty_cipher_attempt():
    """Build a cipher attempt with zero accepted cipher suites (protocol not supported)."""
    return _make_cipher_attempt(accepted_ciphers=[])


def _make_scan_result(**overrides):
    """
    Build a mock ServerScanResult.scan_result (AllScanCommandsAttempts).

    By default, every check returns a "clean" result (no vulnerabilities).
    Pass keyword arguments to override specific scan attempts.

    Returns:
        A MagicMock mimicking AllScanCommandsAttempts with sensible defaults.
    """
    # Default: all protocols have no accepted ciphers (not supported)
    defaults = {
        "ssl_2_0_cipher_suites": _empty_cipher_attempt(),
        "ssl_3_0_cipher_suites": _empty_cipher_attempt(),
        "tls_1_0_cipher_suites": _empty_cipher_attempt(),
        "tls_1_1_cipher_suites": _empty_cipher_attempt(),
        "tls_1_2_cipher_suites": _make_cipher_attempt([
            ("TLS_AES_256_GCM_SHA384", 256),
        ]),
        "tls_1_3_cipher_suites": _make_cipher_attempt([
            ("TLS_AES_128_GCM_SHA256", 128),
        ]),
        # Vulnerability checks — all clean by default
        "heartbleed": MockScanAttempt(
            status="COMPLETED",
            result=MagicMock(is_vulnerable_to_heartbleed=False),
        ),
        "robot": MockScanAttempt(
            status="COMPLETED",
            result=MagicMock(robot_result=MagicMock(
                name="NOT_VULNERABLE_NO_ORACLE"
            )),
        ),
        "openssl_ccs_injection": MockScanAttempt(
            status="COMPLETED",
            result=MagicMock(is_vulnerable_to_ccs_injection=False),
        ),
        "tls_compression": MockScanAttempt(
            status="COMPLETED",
            result=MagicMock(supports_compression=False),
        ),
        "session_renegotiation": MockScanAttempt(
            status="COMPLETED",
            result=MagicMock(
                is_vulnerable_to_client_renegotiation_dos=False,
                supports_secure_renegotiation=True,
            ),
        ),
        "tls_fallback_scsv": MockScanAttempt(
            status="COMPLETED",
            result=MagicMock(supports_fallback_scsv=True),
        ),
        "tls_1_3_early_data": MockScanAttempt(
            status="COMPLETED",
            result=MagicMock(supports_early_data=False),
        ),
    }

    # Apply overrides — caller can replace any default with a custom attempt
    defaults.update(overrides)

    # Build the top-level ServerScanResult mock
    scan_result_inner = MagicMock()
    for attr_name, value in defaults.items():
        setattr(scan_result_inner, attr_name, value)

    server_scan_result = MagicMock()
    server_scan_result.scan_result = scan_result_inner

    return server_scan_result


# ---------------------------------------------------------------------------
# Target fixture
# ---------------------------------------------------------------------------

@pytest.fixture
def https_target():
    """An HTTPS target for SSL scanning."""
    return Target(host="example.com", port=443, scheme="https")


@pytest.fixture
def http_target():
    """An HTTP target that the SSL scanner should reject."""
    return Target(host="example.com", port=80, scheme="http")


# ===========================================================================
# Tests for accepts_target
# ===========================================================================

class TestSSLScannerAcceptsTarget:
    """Verify that the SSL scanner only accepts HTTPS targets."""

    def test_accepts_https(self, https_target):
        """SSL scanner should accept targets with scheme='https'."""
        from webinspector.modules.ssl_scanner import SSLScanner
        scanner = SSLScanner()
        assert scanner.accepts_target(https_target) is True

    def test_rejects_http(self, http_target):
        """SSL scanner should reject targets with scheme='http'."""
        from webinspector.modules.ssl_scanner import SSLScanner
        scanner = SSLScanner()
        assert scanner.accepts_target(http_target) is False

    def test_accepts_https_non_standard_port(self):
        """SSL scanner should accept HTTPS on non-standard ports (e.g., 8443)."""
        from webinspector.modules.ssl_scanner import SSLScanner
        target = Target(host="example.com", port=8443, scheme="https")
        scanner = SSLScanner()
        assert scanner.accepts_target(target) is True


# ===========================================================================
# Tests for module properties
# ===========================================================================

class TestSSLScannerProperties:
    """Verify name and description properties."""

    def test_name(self):
        """Module name should be 'ssl'."""
        from webinspector.modules.ssl_scanner import SSLScanner
        scanner = SSLScanner()
        assert scanner.name == "ssl"

    def test_description(self):
        """Module should have a non-empty description."""
        from webinspector.modules.ssl_scanner import SSLScanner
        scanner = SSLScanner()
        assert len(scanner.description) > 0
        # Should mention SSL/TLS in the description
        assert "ssl" in scanner.description.lower() or "tls" in scanner.description.lower()


# ===========================================================================
# Tests for deprecated protocol detection
# ===========================================================================

class TestDeprecatedProtocols:
    """Verify detection of deprecated SSL/TLS protocol versions."""

    @patch("webinspector.modules.ssl_scanner.Scanner")
    def test_detects_sslv2(self, mock_scanner_cls, https_target):
        """
        SSLv2 support should produce a HIGH severity finding.

        SSLv2 has critical design flaws (no integrity protection, weak MAC)
        and has been deprecated since 2011 (RFC 6176).
        """
        from webinspector.modules.ssl_scanner import SSLScanner

        # Build a scan result where SSLv2 has accepted ciphers
        result = _make_scan_result(
            ssl_2_0_cipher_suites=_make_cipher_attempt([
                ("SSL_CK_RC4_128_WITH_MD5", 128),
            ]),
        )

        # Wire up the mock scanner to return our crafted result
        mock_scanner = MagicMock()
        mock_scanner.get_results.return_value = iter([result])
        mock_scanner_cls.return_value = mock_scanner

        scanner = SSLScanner()
        findings = scanner.scan(https_target)

        # Should find at least one deprecated protocol finding
        deprecated = [f for f in findings if f.finding_type == "deprecated_protocols"]
        assert len(deprecated) >= 1
        assert deprecated[0].severity == Severity.HIGH
        assert "SSLv2" in deprecated[0].detail

    @patch("webinspector.modules.ssl_scanner.Scanner")
    def test_detects_sslv3(self, mock_scanner_cls, https_target):
        """
        SSLv3 support should produce a HIGH severity finding.

        SSLv3 is vulnerable to the POODLE attack (CVE-2014-3566) and was
        deprecated by RFC 7568.
        """
        from webinspector.modules.ssl_scanner import SSLScanner

        result = _make_scan_result(
            ssl_3_0_cipher_suites=_make_cipher_attempt([
                ("TLS_RSA_WITH_AES_128_CBC_SHA", 128),
            ]),
        )

        mock_scanner = MagicMock()
        mock_scanner.get_results.return_value = iter([result])
        mock_scanner_cls.return_value = mock_scanner

        scanner = SSLScanner()
        findings = scanner.scan(https_target)

        deprecated = [f for f in findings if f.finding_type == "deprecated_protocols"]
        assert len(deprecated) >= 1
        assert deprecated[0].severity == Severity.HIGH
        assert "SSLv3" in deprecated[0].detail

    @patch("webinspector.modules.ssl_scanner.Scanner")
    def test_detects_tls10(self, mock_scanner_cls, https_target):
        """
        TLS 1.0 support should produce a MEDIUM severity finding.

        TLS 1.0 was deprecated by RFC 8996 (March 2021).  It is vulnerable
        to BEAST and other attacks but is less severe than SSLv2/SSLv3.
        """
        from webinspector.modules.ssl_scanner import SSLScanner

        result = _make_scan_result(
            tls_1_0_cipher_suites=_make_cipher_attempt([
                ("TLS_RSA_WITH_AES_128_CBC_SHA", 128),
            ]),
        )

        mock_scanner = MagicMock()
        mock_scanner.get_results.return_value = iter([result])
        mock_scanner_cls.return_value = mock_scanner

        scanner = SSLScanner()
        findings = scanner.scan(https_target)

        deprecated = [f for f in findings if f.finding_type == "deprecated_protocols"]
        assert len(deprecated) >= 1
        assert deprecated[0].severity == Severity.MEDIUM
        assert "TLSv1.0" in deprecated[0].detail

    @patch("webinspector.modules.ssl_scanner.Scanner")
    def test_detects_tls11(self, mock_scanner_cls, https_target):
        """
        TLS 1.1 support should produce a MEDIUM severity finding.

        TLS 1.1 was deprecated alongside TLS 1.0 by RFC 8996.
        """
        from webinspector.modules.ssl_scanner import SSLScanner

        result = _make_scan_result(
            tls_1_1_cipher_suites=_make_cipher_attempt([
                ("TLS_RSA_WITH_AES_256_CBC_SHA", 256),
            ]),
        )

        mock_scanner = MagicMock()
        mock_scanner.get_results.return_value = iter([result])
        mock_scanner_cls.return_value = mock_scanner

        scanner = SSLScanner()
        findings = scanner.scan(https_target)

        deprecated = [f for f in findings if f.finding_type == "deprecated_protocols"]
        assert len(deprecated) >= 1
        assert deprecated[0].severity == Severity.MEDIUM
        assert "TLSv1.1" in deprecated[0].detail

    @patch("webinspector.modules.ssl_scanner.Scanner")
    def test_mixed_ssl_and_tls_is_high(self, mock_scanner_cls, https_target):
        """
        When both SSLv3 and TLSv1.0 are supported, the severity should be
        HIGH (driven by the presence of SSLv3).
        """
        from webinspector.modules.ssl_scanner import SSLScanner

        result = _make_scan_result(
            ssl_3_0_cipher_suites=_make_cipher_attempt([
                ("TLS_RSA_WITH_RC4_128_SHA", 128),
            ]),
            tls_1_0_cipher_suites=_make_cipher_attempt([
                ("TLS_RSA_WITH_AES_128_CBC_SHA", 128),
            ]),
        )

        mock_scanner = MagicMock()
        mock_scanner.get_results.return_value = iter([result])
        mock_scanner_cls.return_value = mock_scanner

        scanner = SSLScanner()
        findings = scanner.scan(https_target)

        deprecated = [f for f in findings if f.finding_type == "deprecated_protocols"]
        assert len(deprecated) >= 1
        # Should be HIGH because SSLv3 is present
        assert deprecated[0].severity == Severity.HIGH
        assert "SSLv3" in deprecated[0].detail
        assert "TLSv1.0" in deprecated[0].detail


# ===========================================================================
# Tests for cipher suite analysis
# ===========================================================================

class TestCipherSuiteAnalysis:
    """Verify detection of weak and medium-strength cipher suites."""

    @patch("webinspector.modules.ssl_scanner.Scanner")
    def test_detects_null_cipher(self, mock_scanner_cls, https_target):
        """
        NULL cipher suites provide no encryption and should produce a
        HIGH severity finding.
        """
        from webinspector.modules.ssl_scanner import SSLScanner

        result = _make_scan_result(
            tls_1_2_cipher_suites=_make_cipher_attempt([
                ("TLS_RSA_WITH_NULL_SHA256", 0),
                ("TLS_AES_256_GCM_SHA384", 256),  # Also has a good cipher
            ]),
        )

        mock_scanner = MagicMock()
        mock_scanner.get_results.return_value = iter([result])
        mock_scanner_cls.return_value = mock_scanner

        scanner = SSLScanner()
        findings = scanner.scan(https_target)

        weak = [f for f in findings if f.finding_type == "weak_ciphers"]
        assert len(weak) >= 1
        assert weak[0].severity == Severity.HIGH
        assert "NULL" in weak[0].detail

    @patch("webinspector.modules.ssl_scanner.Scanner")
    def test_detects_export_cipher(self, mock_scanner_cls, https_target):
        """
        Export-grade ciphers (EXP) use intentionally weakened keys and
        should produce a HIGH severity finding (cf. FREAK attack).
        """
        from webinspector.modules.ssl_scanner import SSLScanner

        result = _make_scan_result(
            tls_1_2_cipher_suites=_make_cipher_attempt([
                ("TLS_RSA_EXP_WITH_RC4_40_MD5", 40),
            ]),
        )

        mock_scanner = MagicMock()
        mock_scanner.get_results.return_value = iter([result])
        mock_scanner_cls.return_value = mock_scanner

        scanner = SSLScanner()
        findings = scanner.scan(https_target)

        weak = [f for f in findings if f.finding_type == "weak_ciphers"]
        assert len(weak) >= 1
        assert weak[0].severity == Severity.HIGH

    @patch("webinspector.modules.ssl_scanner.Scanner")
    def test_detects_anon_dh_cipher(self, mock_scanner_cls, https_target):
        """
        Anonymous Diffie-Hellman (ADH) ciphers provide no authentication
        and are vulnerable to man-in-the-middle attacks.
        """
        from webinspector.modules.ssl_scanner import SSLScanner

        result = _make_scan_result(
            tls_1_2_cipher_suites=_make_cipher_attempt([
                ("TLS_ADH_WITH_AES_128_CBC_SHA", 128),
            ]),
        )

        mock_scanner = MagicMock()
        mock_scanner.get_results.return_value = iter([result])
        mock_scanner_cls.return_value = mock_scanner

        scanner = SSLScanner()
        findings = scanner.scan(https_target)

        weak = [f for f in findings if f.finding_type == "weak_ciphers"]
        assert len(weak) >= 1
        assert weak[0].severity == Severity.HIGH

    @patch("webinspector.modules.ssl_scanner.Scanner")
    def test_detects_aecdh_cipher(self, mock_scanner_cls, https_target):
        """
        Anonymous Elliptic Curve Diffie-Hellman (AECDH) ciphers lack
        authentication, similar to ADH.
        """
        from webinspector.modules.ssl_scanner import SSLScanner

        result = _make_scan_result(
            tls_1_2_cipher_suites=_make_cipher_attempt([
                ("TLS_AECDH_WITH_AES_128_CBC_SHA", 128),
            ]),
        )

        mock_scanner = MagicMock()
        mock_scanner.get_results.return_value = iter([result])
        mock_scanner_cls.return_value = mock_scanner

        scanner = SSLScanner()
        findings = scanner.scan(https_target)

        weak = [f for f in findings if f.finding_type == "weak_ciphers"]
        assert len(weak) >= 1
        assert weak[0].severity == Severity.HIGH

    @patch("webinspector.modules.ssl_scanner.Scanner")
    def test_detects_small_key_size(self, mock_scanner_cls, https_target):
        """
        Cipher suites with key_size <= 64 bits are trivially breakable
        and should be flagged as weak (HIGH severity).
        """
        from webinspector.modules.ssl_scanner import SSLScanner

        result = _make_scan_result(
            tls_1_2_cipher_suites=_make_cipher_attempt([
                ("TLS_RSA_WITH_DES_CBC_SHA", 56),  # 56-bit DES
            ]),
        )

        mock_scanner = MagicMock()
        mock_scanner.get_results.return_value = iter([result])
        mock_scanner_cls.return_value = mock_scanner

        scanner = SSLScanner()
        findings = scanner.scan(https_target)

        weak = [f for f in findings if f.finding_type == "weak_ciphers"]
        assert len(weak) >= 1
        assert weak[0].severity == Severity.HIGH

    @patch("webinspector.modules.ssl_scanner.Scanner")
    def test_detects_rc4_cipher(self, mock_scanner_cls, https_target):
        """
        RC4 ciphers have known statistical biases and should produce a
        MEDIUM severity finding (RFC 7465 prohibits RC4 in TLS).
        """
        from webinspector.modules.ssl_scanner import SSLScanner

        result = _make_scan_result(
            tls_1_2_cipher_suites=_make_cipher_attempt([
                ("TLS_RSA_WITH_RC4_128_SHA", 128),
            ]),
        )

        mock_scanner = MagicMock()
        mock_scanner.get_results.return_value = iter([result])
        mock_scanner_cls.return_value = mock_scanner

        scanner = SSLScanner()
        findings = scanner.scan(https_target)

        medium = [f for f in findings if f.finding_type == "medium_ciphers"]
        assert len(medium) >= 1
        assert medium[0].severity == Severity.MEDIUM

    @patch("webinspector.modules.ssl_scanner.Scanner")
    def test_detects_des_cipher(self, mock_scanner_cls, https_target):
        """
        Single DES (not 3DES) should produce a MEDIUM severity finding.

        Note: The check specifically looks for "DES" in the cipher name
        but excludes "3DES" to avoid false positives on Triple DES.
        """
        from webinspector.modules.ssl_scanner import SSLScanner

        # A cipher with DES in the name and key_size 112 (medium range)
        result = _make_scan_result(
            tls_1_2_cipher_suites=_make_cipher_attempt([
                ("TLS_RSA_WITH_DES_CBC_SHA", 112),
            ]),
        )

        mock_scanner = MagicMock()
        mock_scanner.get_results.return_value = iter([result])
        mock_scanner_cls.return_value = mock_scanner

        scanner = SSLScanner()
        findings = scanner.scan(https_target)

        medium = [f for f in findings if f.finding_type == "medium_ciphers"]
        assert len(medium) >= 1
        assert medium[0].severity == Severity.MEDIUM

    @patch("webinspector.modules.ssl_scanner.Scanner")
    def test_detects_medium_key_size(self, mock_scanner_cls, https_target):
        """
        Cipher suites with 64 < key_size <= 112 bits are medium-strength
        and should produce a MEDIUM severity finding.
        """
        from webinspector.modules.ssl_scanner import SSLScanner

        result = _make_scan_result(
            tls_1_2_cipher_suites=_make_cipher_attempt([
                ("TLS_RSA_WITH_3DES_EDE_CBC_SHA", 112),
            ]),
        )

        mock_scanner = MagicMock()
        mock_scanner.get_results.return_value = iter([result])
        mock_scanner_cls.return_value = mock_scanner

        scanner = SSLScanner()
        findings = scanner.scan(https_target)

        medium = [f for f in findings if f.finding_type == "medium_ciphers"]
        assert len(medium) >= 1
        assert medium[0].severity == Severity.MEDIUM

    @patch("webinspector.modules.ssl_scanner.Scanner")
    def test_3des_not_flagged_as_des(self, mock_scanner_cls, https_target):
        """
        Triple DES (3DES) with key_size 168 should NOT be flagged as a
        medium cipher due to the DES name check.  However, it may still
        be flagged by key_size if key_size <= 112.
        """
        from webinspector.modules.ssl_scanner import SSLScanner

        # 3DES with 168-bit key — should NOT produce a medium finding
        result = _make_scan_result(
            tls_1_2_cipher_suites=_make_cipher_attempt([
                ("TLS_RSA_WITH_3DES_EDE_CBC_SHA", 168),
            ]),
        )

        mock_scanner = MagicMock()
        mock_scanner.get_results.return_value = iter([result])
        mock_scanner_cls.return_value = mock_scanner

        scanner = SSLScanner()
        findings = scanner.scan(https_target)

        # 168-bit 3DES should not be flagged as medium (key_size > 112 and
        # the cipher name check should not match 3DES as DES)
        medium = [f for f in findings if f.finding_type == "medium_ciphers"]
        weak = [f for f in findings if f.finding_type == "weak_ciphers"]
        assert len(medium) == 0
        assert len(weak) == 0


# ===========================================================================
# Tests for vulnerability detection
# ===========================================================================

class TestVulnerabilityDetection:
    """Verify detection of specific TLS vulnerabilities."""

    @patch("webinspector.modules.ssl_scanner.Scanner")
    def test_detects_heartbleed(self, mock_scanner_cls, https_target):
        """
        Heartbleed (CVE-2014-0160) should produce a CRITICAL severity
        finding since it allows remote memory disclosure.
        """
        from webinspector.modules.ssl_scanner import SSLScanner

        result = _make_scan_result(
            heartbleed=MockScanAttempt(
                status="COMPLETED",
                result=MagicMock(is_vulnerable_to_heartbleed=True),
            ),
        )

        mock_scanner = MagicMock()
        mock_scanner.get_results.return_value = iter([result])
        mock_scanner_cls.return_value = mock_scanner

        scanner = SSLScanner()
        findings = scanner.scan(https_target)

        heartbleed = [f for f in findings if f.finding_type == "heartbleed"]
        assert len(heartbleed) == 1
        assert heartbleed[0].severity == Severity.CRITICAL
        assert "heartbleed" in heartbleed[0].title.lower()

    @patch("webinspector.modules.ssl_scanner.Scanner")
    def test_detects_robot_weak_oracle(self, mock_scanner_cls, https_target):
        """
        ROBOT vulnerability (weak oracle) should produce a HIGH severity
        finding.  ROBOT allows decryption of RSA key exchanges.
        """
        from webinspector.modules.ssl_scanner import SSLScanner

        robot_result = MagicMock()
        robot_result.robot_result.name = "VULNERABLE_WEAK_ORACLE"

        result = _make_scan_result(
            robot=MockScanAttempt(
                status="COMPLETED",
                result=robot_result,
            ),
        )

        mock_scanner = MagicMock()
        mock_scanner.get_results.return_value = iter([result])
        mock_scanner_cls.return_value = mock_scanner

        scanner = SSLScanner()
        findings = scanner.scan(https_target)

        robot = [f for f in findings if f.finding_type == "robot"]
        assert len(robot) == 1
        assert robot[0].severity == Severity.HIGH

    @patch("webinspector.modules.ssl_scanner.Scanner")
    def test_detects_robot_strong_oracle(self, mock_scanner_cls, https_target):
        """
        ROBOT vulnerability (strong oracle) should also produce a HIGH
        severity finding.
        """
        from webinspector.modules.ssl_scanner import SSLScanner

        robot_result = MagicMock()
        robot_result.robot_result.name = "VULNERABLE_STRONG_ORACLE"

        result = _make_scan_result(
            robot=MockScanAttempt(
                status="COMPLETED",
                result=robot_result,
            ),
        )

        mock_scanner = MagicMock()
        mock_scanner.get_results.return_value = iter([result])
        mock_scanner_cls.return_value = mock_scanner

        scanner = SSLScanner()
        findings = scanner.scan(https_target)

        robot = [f for f in findings if f.finding_type == "robot"]
        assert len(robot) == 1
        assert robot[0].severity == Severity.HIGH

    @patch("webinspector.modules.ssl_scanner.Scanner")
    def test_detects_ccs_injection(self, mock_scanner_cls, https_target):
        """
        OpenSSL CCS injection (CVE-2014-0224) should produce a HIGH
        severity finding.
        """
        from webinspector.modules.ssl_scanner import SSLScanner

        result = _make_scan_result(
            openssl_ccs_injection=MockScanAttempt(
                status="COMPLETED",
                result=MagicMock(is_vulnerable_to_ccs_injection=True),
            ),
        )

        mock_scanner = MagicMock()
        mock_scanner.get_results.return_value = iter([result])
        mock_scanner_cls.return_value = mock_scanner

        scanner = SSLScanner()
        findings = scanner.scan(https_target)

        ccs = [f for f in findings if f.finding_type == "ccs_injection"]
        assert len(ccs) == 1
        assert ccs[0].severity == Severity.HIGH

    @patch("webinspector.modules.ssl_scanner.Scanner")
    def test_detects_tls_compression(self, mock_scanner_cls, https_target):
        """
        TLS compression enables the CRIME attack (CVE-2012-4929) and
        should produce a MEDIUM severity finding.
        """
        from webinspector.modules.ssl_scanner import SSLScanner

        result = _make_scan_result(
            tls_compression=MockScanAttempt(
                status="COMPLETED",
                result=MagicMock(supports_compression=True),
            ),
        )

        mock_scanner = MagicMock()
        mock_scanner.get_results.return_value = iter([result])
        mock_scanner_cls.return_value = mock_scanner

        scanner = SSLScanner()
        findings = scanner.scan(https_target)

        compression = [f for f in findings if f.finding_type == "tls_compression"]
        assert len(compression) == 1
        assert compression[0].severity == Severity.MEDIUM

    @patch("webinspector.modules.ssl_scanner.Scanner")
    def test_detects_insecure_renegotiation(self, mock_scanner_cls, https_target):
        """
        Insecure client-initiated renegotiation enables DoS attacks and
        should produce a MEDIUM severity finding.
        """
        from webinspector.modules.ssl_scanner import SSLScanner

        result = _make_scan_result(
            session_renegotiation=MockScanAttempt(
                status="COMPLETED",
                result=MagicMock(
                    is_vulnerable_to_client_renegotiation_dos=True,
                    supports_secure_renegotiation=False,
                ),
            ),
        )

        mock_scanner = MagicMock()
        mock_scanner.get_results.return_value = iter([result])
        mock_scanner_cls.return_value = mock_scanner

        scanner = SSLScanner()
        findings = scanner.scan(https_target)

        reneg = [f for f in findings if f.finding_type == "insecure_renegotiation"]
        assert len(reneg) == 1
        assert reneg[0].severity == Severity.MEDIUM

    @patch("webinspector.modules.ssl_scanner.Scanner")
    def test_detects_missing_fallback_scsv(self, mock_scanner_cls, https_target):
        """
        Missing TLS_FALLBACK_SCSV allows protocol downgrade attacks and
        should produce a LOW severity finding.
        """
        from webinspector.modules.ssl_scanner import SSLScanner

        result = _make_scan_result(
            tls_fallback_scsv=MockScanAttempt(
                status="COMPLETED",
                result=MagicMock(supports_fallback_scsv=False),
            ),
        )

        mock_scanner = MagicMock()
        mock_scanner.get_results.return_value = iter([result])
        mock_scanner_cls.return_value = mock_scanner

        scanner = SSLScanner()
        findings = scanner.scan(https_target)

        scsv = [f for f in findings if f.finding_type == "missing_fallback_scsv"]
        assert len(scsv) == 1
        assert scsv[0].severity == Severity.LOW

    @patch("webinspector.modules.ssl_scanner.Scanner")
    def test_detects_early_data(self, mock_scanner_cls, https_target):
        """
        TLS 1.3 early data (0-RTT) is vulnerable to replay attacks and
        should produce a LOW severity finding.
        """
        from webinspector.modules.ssl_scanner import SSLScanner

        result = _make_scan_result(
            tls_1_3_early_data=MockScanAttempt(
                status="COMPLETED",
                result=MagicMock(supports_early_data=True),
            ),
        )

        mock_scanner = MagicMock()
        mock_scanner.get_results.return_value = iter([result])
        mock_scanner_cls.return_value = mock_scanner

        scanner = SSLScanner()
        findings = scanner.scan(https_target)

        early = [f for f in findings if f.finding_type == "early_data"]
        assert len(early) == 1
        assert early[0].severity == Severity.LOW


# ===========================================================================
# Tests for clean targets and error handling
# ===========================================================================

class TestCleanTargetAndErrors:
    """Verify behaviour for secure targets and error scenarios."""

    @patch("webinspector.modules.ssl_scanner.Scanner")
    def test_clean_target_no_findings(self, mock_scanner_cls, https_target):
        """
        A target with modern TLS configuration and no vulnerabilities
        should produce zero findings.
        """
        from webinspector.modules.ssl_scanner import SSLScanner

        # Default _make_scan_result produces a clean target
        result = _make_scan_result()

        mock_scanner = MagicMock()
        mock_scanner.get_results.return_value = iter([result])
        mock_scanner_cls.return_value = mock_scanner

        scanner = SSLScanner()
        findings = scanner.scan(https_target)

        assert len(findings) == 0

    @patch("webinspector.modules.ssl_scanner.Scanner")
    def test_scan_failure_returns_empty(self, mock_scanner_cls, https_target):
        """
        When sslyze throws an exception (e.g., connection refused, DNS
        failure), the scanner should catch it gracefully and return an
        empty findings list rather than crashing.
        """
        from webinspector.modules.ssl_scanner import SSLScanner

        # Make the scanner raise an exception when queueing scans
        mock_scanner = MagicMock()
        mock_scanner.queue_scans.side_effect = Exception("Connection refused")
        mock_scanner_cls.return_value = mock_scanner

        scanner = SSLScanner()
        findings = scanner.scan(https_target)

        assert isinstance(findings, list)
        assert len(findings) == 0

    @patch("webinspector.modules.ssl_scanner.Scanner")
    def test_individual_check_failure_doesnt_crash(self, mock_scanner_cls, https_target):
        """
        If one scan command fails (ERROR status) but others succeed,
        the scanner should still return findings from the successful
        commands without crashing.
        """
        from webinspector.modules.ssl_scanner import SSLScanner

        # Set heartbleed to error state, but compression to a finding
        result = _make_scan_result(
            heartbleed=MockScanAttempt(
                status="ERROR",
                result=None,
                error_reason="BUG_IN_SSLYZE",
            ),
            tls_compression=MockScanAttempt(
                status="COMPLETED",
                result=MagicMock(supports_compression=True),
            ),
        )

        mock_scanner = MagicMock()
        mock_scanner.get_results.return_value = iter([result])
        mock_scanner_cls.return_value = mock_scanner

        scanner = SSLScanner()
        findings = scanner.scan(https_target)

        # Should still detect the compression issue despite heartbleed error
        compression = [f for f in findings if f.finding_type == "tls_compression"]
        assert len(compression) == 1

    @patch("webinspector.modules.ssl_scanner.SSLYZE_AVAILABLE", False)
    def test_sslyze_not_installed(self, https_target):
        """
        When sslyze is not installed (SSLYZE_AVAILABLE=False), the
        scanner should return an empty list without error.
        """
        from webinspector.modules.ssl_scanner import SSLScanner

        scanner = SSLScanner()
        findings = scanner.scan(https_target)

        assert isinstance(findings, list)
        assert len(findings) == 0


# ===========================================================================
# Tests for multiple findings in a single scan
# ===========================================================================

class TestMultipleFindings:
    """Verify that multiple issues on a single target are all reported."""

    @patch("webinspector.modules.ssl_scanner.Scanner")
    def test_multiple_vulnerabilities(self, mock_scanner_cls, https_target):
        """
        A target with multiple vulnerabilities should produce a finding
        for each one (not stop after the first issue).
        """
        from webinspector.modules.ssl_scanner import SSLScanner

        result = _make_scan_result(
            # Deprecated protocol
            tls_1_0_cipher_suites=_make_cipher_attempt([
                ("TLS_RSA_WITH_AES_128_CBC_SHA", 128),
            ]),
            # Weak cipher on TLS 1.2
            tls_1_2_cipher_suites=_make_cipher_attempt([
                ("TLS_RSA_WITH_NULL_SHA256", 0),
                ("TLS_AES_256_GCM_SHA384", 256),
            ]),
            # Heartbleed
            heartbleed=MockScanAttempt(
                status="COMPLETED",
                result=MagicMock(is_vulnerable_to_heartbleed=True),
            ),
            # TLS compression
            tls_compression=MockScanAttempt(
                status="COMPLETED",
                result=MagicMock(supports_compression=True),
            ),
        )

        mock_scanner = MagicMock()
        mock_scanner.get_results.return_value = iter([result])
        mock_scanner_cls.return_value = mock_scanner

        scanner = SSLScanner()
        findings = scanner.scan(https_target)

        # Extract finding types
        types = {f.finding_type for f in findings}

        # Should have at least four distinct finding types
        assert "deprecated_protocols" in types
        assert "weak_ciphers" in types
        assert "heartbleed" in types
        assert "tls_compression" in types

    @patch("webinspector.modules.ssl_scanner.Scanner")
    def test_findings_have_correct_module(self, mock_scanner_cls, https_target):
        """Every finding should have module='ssl'."""
        from webinspector.modules.ssl_scanner import SSLScanner

        result = _make_scan_result(
            tls_1_0_cipher_suites=_make_cipher_attempt([
                ("TLS_RSA_WITH_AES_128_CBC_SHA", 128),
            ]),
            heartbleed=MockScanAttempt(
                status="COMPLETED",
                result=MagicMock(is_vulnerable_to_heartbleed=True),
            ),
        )

        mock_scanner = MagicMock()
        mock_scanner.get_results.return_value = iter([result])
        mock_scanner_cls.return_value = mock_scanner

        scanner = SSLScanner()
        findings = scanner.scan(https_target)

        assert len(findings) >= 2
        for finding in findings:
            assert finding.module == "ssl"
            assert finding.target is https_target

    @patch("webinspector.modules.ssl_scanner.Scanner")
    def test_findings_have_references(self, mock_scanner_cls, https_target):
        """Findings should include CWE or other references where appropriate."""
        from webinspector.modules.ssl_scanner import SSLScanner

        result = _make_scan_result(
            heartbleed=MockScanAttempt(
                status="COMPLETED",
                result=MagicMock(is_vulnerable_to_heartbleed=True),
            ),
        )

        mock_scanner = MagicMock()
        mock_scanner.get_results.return_value = iter([result])
        mock_scanner_cls.return_value = mock_scanner

        scanner = SSLScanner()
        findings = scanner.scan(https_target)

        heartbleed = [f for f in findings if f.finding_type == "heartbleed"]
        assert len(heartbleed) == 1
        # Heartbleed should have a CVE reference
        assert len(heartbleed[0].references) > 0


# ===========================================================================
# Test module registration
# ===========================================================================

class TestSSLScannerRegistration:
    """Verify that importing the module registers it."""

    def test_module_registers(self):
        """
        Importing ssl_scanner should call register_module() at the bottom
        of the file, making it discoverable by the module registry.
        """
        from webinspector.modules import _registry, register_module
        from webinspector.modules.ssl_scanner import SSLScanner

        # The module registers itself at import time.
        # Check that an instance of SSLScanner is in the registry.
        ssl_modules = [m for m in _registry if m.name == "ssl"]
        assert len(ssl_modules) >= 1
        assert isinstance(ssl_modules[0], SSLScanner)
