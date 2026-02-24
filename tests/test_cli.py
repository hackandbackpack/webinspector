"""
tests/test_cli.py - Unit tests for the CLI argument parser.

Tests the parse_args() function which converts command-line arguments into a
ScanConfig dataclass that the scanner orchestrator consumes. Covers all argument
types: target input (-t, -iL, -x), module selection (--only, --no), output
options (-o, --json), scanning tweaks (--timeout, --proxy, -p, --threads),
and verbosity flags (-v, -q).

Author: Red Siege Information Security
"""

import pytest

# Import the CLI module under test.
from webinspector.cli import parse_args, ScanConfig


# ---------------------------------------------------------------------------
# Target input tests
# ---------------------------------------------------------------------------

class TestTargetInputs:
    """Tests for the three target input methods: -t, -iL, -x."""

    def test_single_target(self):
        """
        -t example.com should produce a ScanConfig with one target string
        in the targets list.
        """
        config = parse_args(["-t", "example.com"])
        assert config.targets == ["example.com"]

    def test_multiple_targets(self):
        """
        -t 10.0.0.1 10.0.0.2 example.com should produce a ScanConfig with
        all three target strings in the targets list, in order.
        """
        config = parse_args(["-t", "10.0.0.1", "10.0.0.2", "example.com"])
        assert config.targets == ["10.0.0.1", "10.0.0.2", "example.com"]

    def test_target_file(self):
        """
        -iL file.txt should set target_file to the file path string.
        """
        config = parse_args(["-iL", "file.txt"])
        assert config.target_file == "file.txt"

    def test_nmap_file(self):
        """
        -x nmap.xml should set nmap_files to a list containing the file path.
        """
        config = parse_args(["-x", "nmap.xml"])
        assert config.nmap_files == ["nmap.xml"]

    def test_multiple_nmap_files(self):
        """
        -x scan1.xml scan2.xml should set nmap_files to a list of both paths.
        """
        config = parse_args(["-x", "scan1.xml", "scan2.xml"])
        assert config.nmap_files == ["scan1.xml", "scan2.xml"]

    def test_combined_inputs(self):
        """
        Combining -t, -iL, and -x should populate all three fields.
        """
        config = parse_args([
            "-t", "10.0.0.5",
            "-iL", "extras.txt",
            "-x", "scan.xml",
        ])
        assert config.targets == ["10.0.0.5"]
        assert config.target_file == "extras.txt"
        assert config.nmap_files == ["scan.xml"]

    def test_no_targets_raises_error(self):
        """
        When no target source is provided (-t, -iL, or -x), parse_args
        should raise SystemExit because at least one target is required.
        """
        with pytest.raises(SystemExit):
            parse_args([])


# ---------------------------------------------------------------------------
# Port specification tests
# ---------------------------------------------------------------------------

class TestPortSpecification:
    """Tests for the -p (port) argument."""

    def test_single_port(self):
        """
        -p 443 should produce a ports list with one integer.
        """
        config = parse_args(["-t", "example.com", "-p", "443"])
        assert config.ports == [443]

    def test_multiple_ports(self):
        """
        -p 443 8443 8080 should produce a ports list with all three integers.
        """
        config = parse_args(["-t", "example.com", "-p", "443", "8443", "8080"])
        assert config.ports == [443, 8443, 8080]

    def test_no_ports_defaults_to_empty(self):
        """
        When -p is not specified, ports should default to an empty list.
        The downstream target parser will apply its own default port (443).
        """
        config = parse_args(["-t", "example.com"])
        assert config.ports == []


# ---------------------------------------------------------------------------
# Module selection tests
# ---------------------------------------------------------------------------

class TestModuleSelection:
    """Tests for --only and --no module selection flags."""

    def test_only_modules(self):
        """
        --only ssl,headers should produce an only_modules list of ['ssl', 'headers'].
        """
        config = parse_args(["-t", "example.com", "--only", "ssl,headers"])
        assert config.only_modules == ["ssl", "headers"]

    def test_no_modules(self):
        """
        --no tech should produce an exclude_modules list of ['tech'].
        """
        config = parse_args(["-t", "example.com", "--no", "tech"])
        assert config.exclude_modules == ["tech"]

    def test_no_modules_comma_separated(self):
        """
        --no tech,content should produce an exclude_modules list of ['tech', 'content'].
        """
        config = parse_args(["-t", "example.com", "--no", "tech,content"])
        assert config.exclude_modules == ["tech", "content"]

    def test_only_and_no_mutually_exclusive(self):
        """
        Providing both --only and --no should raise SystemExit because
        they are mutually exclusive options.
        """
        with pytest.raises(SystemExit):
            parse_args(["-t", "example.com", "--only", "ssl", "--no", "tech"])

    def test_no_module_selection_defaults_to_none(self):
        """
        When neither --only nor --no is specified, both only_modules
        and exclude_modules should be None (meaning run all modules).
        """
        config = parse_args(["-t", "example.com"])
        assert config.only_modules is None
        assert config.exclude_modules is None


# ---------------------------------------------------------------------------
# Timeout and threads tests
# ---------------------------------------------------------------------------

class TestTimeoutAndThreads:
    """Tests for --timeout and --threads arguments."""

    def test_timeout(self):
        """
        --timeout 30 should set the timeout field to 30.
        """
        config = parse_args(["-t", "example.com", "--timeout", "30"])
        assert config.timeout == 30

    def test_timeout_default(self):
        """
        When --timeout is not specified, it should default to 10 seconds.
        """
        config = parse_args(["-t", "example.com"])
        assert config.timeout == 10

    def test_threads_default(self):
        """
        When --threads is not specified, it should default to 10.
        """
        config = parse_args(["-t", "example.com"])
        assert config.threads == 10

    def test_threads_custom(self):
        """
        --threads 20 should set the threads field to 20.
        """
        config = parse_args(["-t", "example.com", "--threads", "20"])
        assert config.threads == 20


# ---------------------------------------------------------------------------
# Proxy tests
# ---------------------------------------------------------------------------

class TestProxy:
    """Tests for the --proxy argument."""

    def test_proxy(self):
        """
        --proxy socks5://127.0.0.1:9050 should set the proxy field.
        """
        config = parse_args([
            "-t", "example.com",
            "--proxy", "socks5://127.0.0.1:9050",
        ])
        assert config.proxy == "socks5://127.0.0.1:9050"

    def test_proxy_default_none(self):
        """
        When --proxy is not specified, proxy should be None.
        """
        config = parse_args(["-t", "example.com"])
        assert config.proxy is None


# ---------------------------------------------------------------------------
# Output option tests
# ---------------------------------------------------------------------------

class TestOutputOptions:
    """Tests for -o (text output) and --json (JSON output) arguments."""

    def test_output_file(self):
        """
        -o results.txt should set the output_file field.
        """
        config = parse_args(["-t", "example.com", "-o", "results.txt"])
        assert config.output_file == "results.txt"

    def test_json_file(self):
        """
        --json results.json should set the json_file field.
        """
        config = parse_args(["-t", "example.com", "--json", "results.json"])
        assert config.json_file == "results.json"

    def test_output_defaults_none(self):
        """
        When neither -o nor --json is specified, both should be None
        (output goes to stdout only).
        """
        config = parse_args(["-t", "example.com"])
        assert config.output_file is None
        assert config.json_file is None

    def test_both_output_files(self):
        """
        -o report.txt --json report.json should set both output fields.
        These are NOT mutually exclusive — analysts often want both formats.
        """
        config = parse_args([
            "-t", "example.com",
            "-o", "report.txt",
            "--json", "report.json",
        ])
        assert config.output_file == "report.txt"
        assert config.json_file == "report.json"


# ---------------------------------------------------------------------------
# Verbosity tests
# ---------------------------------------------------------------------------

class TestVerbosity:
    """Tests for -v (verbose) and -q (quiet) flags."""

    def test_verbose(self):
        """
        -v should set verbose=True and quiet=False.
        """
        config = parse_args(["-t", "example.com", "-v"])
        assert config.verbose is True
        assert config.quiet is False

    def test_quiet(self):
        """
        -q should set quiet=True and verbose=False.
        """
        config = parse_args(["-t", "example.com", "-q"])
        assert config.quiet is True
        assert config.verbose is False

    def test_verbose_and_quiet_mutually_exclusive(self):
        """
        Providing both -v and -q should raise SystemExit because
        they are mutually exclusive options.
        """
        with pytest.raises(SystemExit):
            parse_args(["-t", "example.com", "-v", "-q"])

    def test_default_neither_verbose_nor_quiet(self):
        """
        By default, both verbose and quiet should be False.
        """
        config = parse_args(["-t", "example.com"])
        assert config.verbose is False
        assert config.quiet is False


# ---------------------------------------------------------------------------
# Input validation tests
# ---------------------------------------------------------------------------

class TestModuleNameValidation:
    """Tests that --only and --no reject unknown module names."""

    def test_only_unknown_module_raises_error(self):
        """
        --only nonexistent_module should raise SystemExit because the module
        name is not in ALL_MODULE_NAMES.
        """
        with pytest.raises(SystemExit):
            parse_args(["-t", "example.com", "--only", "nonexistent_module"])

    def test_no_unknown_module_raises_error(self):
        """
        --no nonexistent_module should raise SystemExit because the module
        name is not in ALL_MODULE_NAMES.
        """
        with pytest.raises(SystemExit):
            parse_args(["-t", "example.com", "--no", "nonexistent_module"])


class TestTimeoutAndThreadsValidation:
    """Tests that --timeout and --threads reject non-positive values."""

    def test_timeout_zero_raises_error(self):
        """
        --timeout 0 should raise SystemExit because timeout must be
        a positive integer (> 0).
        """
        with pytest.raises(SystemExit):
            parse_args(["-t", "example.com", "--timeout", "0"])

    def test_threads_negative_raises_error(self):
        """
        --threads -1 should raise SystemExit because threads must be
        a positive integer (> 0).
        """
        with pytest.raises(SystemExit):
            parse_args(["-t", "example.com", "--threads", "-1"])


class TestPortValidation:
    """Tests that -p rejects port numbers outside the valid range 1-65535."""

    def test_port_zero_raises_error(self):
        """
        -p 0 should raise SystemExit because port 0 is reserved and
        falls outside the valid TCP port range (1-65535).
        """
        with pytest.raises(SystemExit):
            parse_args(["-t", "example.com", "-p", "0"])

    def test_port_above_max_raises_error(self):
        """
        -p 99999 should raise SystemExit because 99999 exceeds the
        maximum TCP port number (65535).
        """
        with pytest.raises(SystemExit):
            parse_args(["-t", "example.com", "-p", "99999"])

    def test_valid_ports_accepted(self):
        """
        Ports 1, 443, and 65535 are all within the valid TCP range
        (1-65535) and should be accepted without error.
        """
        config = parse_args(["-t", "example.com", "-p", "1", "443", "65535"])
        assert config.ports == [1, 443, 65535]


# ---------------------------------------------------------------------------
# ScanConfig dataclass tests
# ---------------------------------------------------------------------------

class TestScanConfig:
    """Tests that ScanConfig is a proper dataclass with correct defaults."""

    def test_scanconfig_is_dataclass(self):
        """
        ScanConfig should be a dataclass (has __dataclass_fields__).
        """
        import dataclasses
        assert dataclasses.is_dataclass(ScanConfig)

    def test_scanconfig_defaults(self):
        """
        ScanConfig created with minimal arguments should have sensible
        defaults for all optional fields.
        """
        config = ScanConfig(
            targets=["example.com"],
            target_file=None,
            nmap_files=[],
            ports=[],
            only_modules=None,
            exclude_modules=None,
            timeout=10,
            threads=10,
            proxy=None,
            output_file=None,
            json_file=None,
            verbose=False,
            quiet=False,
        )
        assert config.targets == ["example.com"]
        assert config.timeout == 10
        assert config.threads == 10
        assert config.proxy is None


# ---------------------------------------------------------------------------
# Full command-line integration tests
# ---------------------------------------------------------------------------

class TestFullCommandLine:
    """End-to-end tests simulating realistic CLI invocations."""

    def test_full_command_line(self):
        """
        A full command line combining all options should correctly populate
        every field in ScanConfig.

        Simulates:
            webinspector -x scan.xml -iL extras.txt -t 10.0.0.5 \
                --no dns --timeout 30 -o report.txt --json report.json -v
        """
        config = parse_args([
            "-x", "scan.xml",
            "-iL", "extras.txt",
            "-t", "10.0.0.5",
            "--no", "dns",
            "--timeout", "30",
            "-o", "report.txt",
            "--json", "report.json",
            "-v",
        ])
        assert config.targets == ["10.0.0.5"]
        assert config.target_file == "extras.txt"
        assert config.nmap_files == ["scan.xml"]
        assert config.exclude_modules == ["dns"]
        assert config.timeout == 30
        assert config.output_file == "report.txt"
        assert config.json_file == "report.json"
        assert config.verbose is True
        assert config.quiet is False

    def test_target_with_ports_and_proxy(self):
        """
        Simulates:
            webinspector -t 10.0.0.1 -p 443 8443 --proxy socks5://127.0.0.1:9050 -q
        """
        config = parse_args([
            "-t", "10.0.0.1",
            "-p", "443", "8443",
            "--proxy", "socks5://127.0.0.1:9050",
            "-q",
        ])
        assert config.targets == ["10.0.0.1"]
        assert config.ports == [443, 8443]
        assert config.proxy == "socks5://127.0.0.1:9050"
        assert config.quiet is True
        assert config.verbose is False

    def test_only_nmap_input(self):
        """
        Using only -x (no -t or -iL) should be valid — nmap files
        are a legitimate sole target source.
        """
        config = parse_args(["-x", "scan1.xml", "scan2.xml"])
        assert config.targets == []
        assert config.target_file is None
        assert config.nmap_files == ["scan1.xml", "scan2.xml"]

    def test_only_target_file_input(self):
        """
        Using only -iL (no -t or -x) should be valid — a target file
        is a legitimate sole target source.
        """
        config = parse_args(["-iL", "targets.txt"])
        assert config.targets == []
        assert config.target_file == "targets.txt"
        assert config.nmap_files == []
