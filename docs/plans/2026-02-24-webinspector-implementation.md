# WebInspector Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a production-ready Python CLI tool that combines SSL/TLS scanning, HTTP security header analysis, cookie checks, CORS detection, tech fingerprinting, and passive web app analysis into a single tool for penetration testing engagements.

**Architecture:** Modular scanner with pluggable modules, ThreadPoolExecutor for HTTP concurrency, sslyze's own Scanner for TLS concurrency. Shared HTTP response per target avoids duplicate requests. Results aggregated by finding type for report-ready output.

**Tech Stack:** Python 3.11, sslyze (TLS), webtech (tech fingerprinting), requests (HTTP), dnspython (DNS), rich (progress/output), lxml (nmap XML), netaddr (CIDR)

**Environment:** Windows 11, Python 3.11.9, bash shell. All paths use forward slashes. sslyze and webtech already installed.

---

## Phase 1: Project Skeleton and Core Data Structures

### Task 1: Create project structure and packaging files

**Files:**
- Create: `webinspector/__init__.py`
- Create: `webinspector/__main__.py`
- Create: `webinspector/core/__init__.py`
- Create: `webinspector/modules/__init__.py`
- Create: `webinspector/output/__init__.py`
- Create: `webinspector/utils/__init__.py`
- Create: `requirements.txt`
- Create: `setup.py`
- Create: `tests/__init__.py`

**Step 1: Create all directories and package init files**

```
webinspector/
├── webinspector/
│   ├── __init__.py          # VERSION = "1.0.0"
│   ├── __main__.py          # stub: print("webinspector")
│   ├── core/__init__.py     # empty
│   ├── modules/__init__.py  # empty
│   ├── output/__init__.py   # empty
│   └── utils/__init__.py    # empty
├── tests/__init__.py        # empty
├── requirements.txt
└── setup.py
```

`webinspector/__init__.py`:
```python
"""
WebInspector - Web Application Security Scanner for Penetration Testing.

Combines SSL/TLS scanning, HTTP security header analysis, cookie checks,
CORS misconfiguration detection, technology fingerprinting, and passive
web application security analysis into a single unified CLI tool.
"""

VERSION = "1.0.0"
```

`webinspector/__main__.py`:
```python
"""
Entry point for running webinspector as a module: python -m webinspector
"""

def main():
    """Main entry point - will be replaced with CLI parsing in Task 3."""
    print("webinspector v1.0.0 - stub")

if __name__ == "__main__":
    main()
```

`requirements.txt`:
```
sslyze>=6.0,<7.0
webtech>=1.3
requests>=2.31
dnspython>=2.4
rich>=13.0
lxml>=4.9
netaddr>=0.9
pytest>=7.0
```

`setup.py`:
```python
"""
Setup script for webinspector package.
Allows installation via: pip install -e .
"""

from setuptools import setup, find_packages

setup(
    name="webinspector",
    version="1.0.0",
    description="Web Application Security Scanner for Penetration Testing",
    author="Red Siege",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=[
        "sslyze>=6.0,<7.0",
        "webtech>=1.3",
        "requests>=2.31",
        "dnspython>=2.4",
        "rich>=13.0",
        "lxml>=4.9",
        "netaddr>=0.9",
    ],
    entry_points={
        "console_scripts": [
            "webinspector=webinspector.__main__:main",
        ],
    },
)
```

**Step 2: Verify the package runs**

Run: `cd ~/webinspector && python -m webinspector`
Expected: `webinspector v1.0.0 - stub`

**Step 3: Install in editable mode**

Run: `cd ~/webinspector && pip install -e .`
Expected: Successfully installed webinspector-1.0.0

**Step 4: Commit**

```bash
git add webinspector/ tests/ requirements.txt setup.py
git commit -m "feat: create project skeleton with packaging files"
```

---

### Task 2: Core data structures - Target and Finding

**Files:**
- Create: `webinspector/core/target.py`
- Create: `webinspector/core/result.py`
- Create: `tests/test_target.py`
- Create: `tests/test_result.py`

**Step 1: Write failing tests for Target**

`tests/test_target.py`:
```python
"""
Tests for the Target dataclass and target parsing utilities.

Covers: URL parsing, host:port parsing, bare hostname expansion,
CIDR range expansion, target list file parsing, and deduplication.
"""

import pytest
from webinspector.core.target import Target, parse_target_string, expand_targets


class TestTarget:
    """Tests for the Target dataclass."""

    def test_url_property_https(self):
        """Target with https scheme should produce correct URL."""
        t = Target(host="example.com", port=443, scheme="https")
        assert t.url == "https://example.com:443"

    def test_url_property_http(self):
        """Target with http scheme should produce correct URL."""
        t = Target(host="10.0.0.1", port=8080, scheme="http")
        assert t.url == "http://10.0.0.1:8080"

    def test_hostport_property(self):
        """hostport should return host:port string."""
        t = Target(host="10.0.0.1", port=443, scheme="https")
        assert t.hostport == "10.0.0.1:443"

    def test_display_with_rdns(self):
        """display should include reverse DNS when available."""
        t = Target(host="10.0.0.1", port=443, scheme="https", rdns="server.corp.com")
        assert "server.corp.com" in t.display


class TestParseTargetString:
    """Tests for parsing individual target strings."""

    def test_full_url(self):
        """Full URL with protocol should be parsed correctly."""
        targets = parse_target_string("https://example.com:8443")
        assert len(targets) == 1
        assert targets[0].host == "example.com"
        assert targets[0].port == 8443
        assert targets[0].scheme == "https"

    def test_host_port(self):
        """host:port without protocol should expand to http + https."""
        targets = parse_target_string("10.0.0.1:443")
        # Should produce both http and https variants
        assert len(targets) == 2
        schemes = {t.scheme for t in targets}
        assert schemes == {"http", "https"}

    def test_bare_hostname(self):
        """Bare hostname should expand to http:443 + https:443."""
        targets = parse_target_string("example.com")
        assert len(targets) == 2
        assert all(t.port == 443 for t in targets)

    def test_bare_ip(self):
        """Bare IP should expand to http:443 + https:443."""
        targets = parse_target_string("10.0.0.1")
        assert len(targets) == 2
        assert all(t.host == "10.0.0.1" for t in targets)

    def test_bare_hostname_with_port_override(self):
        """Bare hostname with port list should expand correctly."""
        targets = parse_target_string("10.0.0.1", ports=[443, 8443])
        assert len(targets) == 4  # 2 ports * 2 schemes

    def test_http_url_no_expand(self):
        """Explicit http:// URL should NOT expand to https."""
        targets = parse_target_string("http://10.0.0.1:80")
        assert len(targets) == 1
        assert targets[0].scheme == "http"

    def test_cidr_expansion(self):
        """CIDR range should expand to individual IPs."""
        targets = parse_target_string("10.0.0.0/30")
        # /30 = 4 IPs, 2 usable, but we expand all 4 for scanning
        # Each IP gets http + https = 8 targets
        assert len(targets) == 8  # 4 IPs * 2 schemes


class TestExpandTargets:
    """Tests for deduplication and merging of targets."""

    def test_dedup_same_target(self):
        """Duplicate targets should be deduplicated."""
        raw = ["example.com", "example.com"]
        targets = expand_targets(raw)
        # example.com expands to http+https, but dupes removed
        assert len(targets) == 2  # http + https, not 4

    def test_comment_lines_ignored(self):
        """Lines starting with # should be ignored in target lists."""
        raw = ["# this is a comment", "example.com"]
        targets = expand_targets(raw)
        assert len(targets) == 2  # only example.com expanded
```

**Step 2: Run tests to verify they fail**

Run: `cd ~/webinspector && python -m pytest tests/test_target.py -v`
Expected: FAIL (ImportError - module doesn't exist yet)

**Step 3: Implement Target and parsing functions**

`webinspector/core/target.py` — full implementation with:
- Target dataclass with url, hostport, display properties
- parse_target_string() — handles URLs, host:port, bare hosts, CIDR
- expand_targets() — takes list of raw strings, returns deduplicated Target list
- parse_target_file() — reads file with one target per line, skips comments
- Heavily commented explaining every decision

**Step 4: Run tests to verify they pass**

Run: `cd ~/webinspector && python -m pytest tests/test_target.py -v`
Expected: All PASS

**Step 5: Write failing tests for Finding/Result**

`tests/test_result.py`:
```python
"""
Tests for Finding dataclass and result aggregation.
"""

import pytest
from webinspector.core.result import Finding, Severity, group_findings, sort_findings_by_ip
from webinspector.core.target import Target


class TestSeverity:
    """Tests for Severity enum ordering."""

    def test_severity_ordering(self):
        """Severities should be orderable from Critical to Informational."""
        assert Severity.CRITICAL.weight > Severity.HIGH.weight
        assert Severity.HIGH.weight > Severity.MEDIUM.weight
        assert Severity.MEDIUM.weight > Severity.LOW.weight
        assert Severity.LOW.weight > Severity.INFORMATIONAL.weight


class TestFinding:
    """Tests for the Finding dataclass."""

    def test_finding_creation(self):
        """Finding should store all fields correctly."""
        t = Target(host="10.0.0.1", port=443, scheme="https")
        f = Finding(
            module="ssl",
            finding_type="deprecated_protocols",
            severity=Severity.MEDIUM,
            target=t,
            title="Deprecated Protocols",
            detail="TLSv1.0, TLSv1.1",
        )
        assert f.module == "ssl"
        assert f.severity == Severity.MEDIUM
        assert f.detail == "TLSv1.0, TLSv1.1"


class TestGroupFindings:
    """Tests for grouping and sorting findings."""

    def test_group_by_type(self):
        """Findings should be grouped by (module, finding_type)."""
        t1 = Target(host="10.0.0.1", port=443, scheme="https", ip="10.0.0.1")
        t2 = Target(host="10.0.0.2", port=443, scheme="https", ip="10.0.0.2")
        findings = [
            Finding("ssl", "deprecated_protocols", Severity.MEDIUM, t1,
                    "Deprecated Protocols", "TLSv1.0"),
            Finding("ssl", "deprecated_protocols", Severity.MEDIUM, t2,
                    "Deprecated Protocols", "TLSv1.1"),
            Finding("headers", "missing_csp", Severity.LOW, t1,
                    "Missing CSP", ""),
        ]
        grouped = group_findings(findings)
        assert ("ssl", "deprecated_protocols") in grouped
        assert len(grouped[("ssl", "deprecated_protocols")]) == 2
        assert ("headers", "missing_csp") in grouped
        assert len(grouped[("headers", "missing_csp")]) == 1

    def test_sort_by_ip(self):
        """Findings within a group should sort numerically by IP."""
        t1 = Target(host="10.0.0.10", port=443, scheme="https", ip="10.0.0.10")
        t2 = Target(host="10.0.0.2", port=443, scheme="https", ip="10.0.0.2")
        findings = [
            Finding("ssl", "expired", Severity.MEDIUM, t1, "Expired", ""),
            Finding("ssl", "expired", Severity.MEDIUM, t2, "Expired", ""),
        ]
        sorted_f = sort_findings_by_ip(findings)
        # 10.0.0.2 should come before 10.0.0.10 (numerical sort)
        assert sorted_f[0].target.ip == "10.0.0.2"
        assert sorted_f[1].target.ip == "10.0.0.10"
```

**Step 6: Implement Finding and result aggregation**

`webinspector/core/result.py` — full implementation with:
- Severity enum with weight property for ordering
- Finding dataclass
- group_findings() — groups by (module, finding_type)
- sort_findings_by_ip() — numerical IP sort within groups
- ScanSummary dataclass for statistics

**Step 7: Run all tests**

Run: `cd ~/webinspector && python -m pytest tests/ -v`
Expected: All PASS

**Step 8: Commit**

```bash
git add webinspector/core/ tests/test_target.py tests/test_result.py
git commit -m "feat: add Target and Finding core data structures with tests"
```

---

### Task 3: Utilities - HTTP client, DNS, Nmap parser

**Files:**
- Create: `webinspector/utils/http.py`
- Create: `webinspector/utils/network.py`
- Create: `webinspector/utils/nmap_parser.py`
- Create: `tests/test_nmap_parser.py`
- Create: `tests/test_network.py`
- Create: `tests/fixtures/sample_nmap.xml`

**Step 1: Write tests for nmap parser**

`tests/fixtures/sample_nmap.xml` — a minimal valid nmap XML with 3 hosts:
one with HTTPS on 443, one with HTTP on 80 + SSL on 8443, one with no web services.

`tests/test_nmap_parser.py`:
```python
"""
Tests for nmap XML parsing.

Uses a sample nmap XML fixture that includes:
- Host 10.0.0.1: HTTPS on port 443 (open)
- Host 10.0.0.2: HTTP on port 80 (open), SSL on port 8443 (open)
- Host 10.0.0.3: SSH on port 22 (open) — should be excluded
"""

import pytest
import os
from webinspector.utils.nmap_parser import parse_nmap_xml

FIXTURE_DIR = os.path.join(os.path.dirname(__file__), "fixtures")


class TestNmapParser:
    def test_extracts_https_services(self):
        """Should extract hosts with HTTPS/SSL services."""
        targets = parse_nmap_xml(os.path.join(FIXTURE_DIR, "sample_nmap.xml"))
        hostports = {(t.host, t.port) for t in targets}
        assert ("10.0.0.1", 443) in hostports

    def test_extracts_ssl_tunnel(self):
        """Should extract services with tunnel='ssl'."""
        targets = parse_nmap_xml(os.path.join(FIXTURE_DIR, "sample_nmap.xml"))
        hostports = {(t.host, t.port) for t in targets}
        assert ("10.0.0.2", 8443) in hostports

    def test_extracts_http_services(self):
        """Should extract plain HTTP services too."""
        targets = parse_nmap_xml(os.path.join(FIXTURE_DIR, "sample_nmap.xml"))
        hostports = {(t.host, t.port) for t in targets}
        assert ("10.0.0.2", 80) in hostports

    def test_excludes_non_web_services(self):
        """Should NOT extract SSH or other non-web services."""
        targets = parse_nmap_xml(os.path.join(FIXTURE_DIR, "sample_nmap.xml"))
        hostports = {(t.host, t.port) for t in targets}
        assert ("10.0.0.3", 22) not in hostports

    def test_skips_closed_ports(self):
        """Should only include ports with state='open'."""
        targets = parse_nmap_xml(os.path.join(FIXTURE_DIR, "sample_nmap.xml"))
        # All returned targets should have been from open ports
        assert len(targets) >= 3  # 10.0.0.1:443, 10.0.0.2:80, 10.0.0.2:8443
```

**Step 2: Run tests to verify they fail**

Run: `cd ~/webinspector && python -m pytest tests/test_nmap_parser.py -v`
Expected: FAIL

**Step 3: Create nmap XML fixture and implement parser**

`tests/fixtures/sample_nmap.xml` — valid nmap XML with the hosts described above.

`webinspector/utils/nmap_parser.py` — parse using lxml, extract hosts with
web service names (https, ssl, http, http-proxy, http-alt, https-alt,
oracleas-https) or tunnel="ssl". Only include open ports. Return list of Targets.

**Step 4: Implement HTTP client utility**

`webinspector/utils/http.py`:
- create_http_session() — returns a requests.Session with retry adapter,
  configurable timeout, user-agent, proxy support, SSL verify=False
- fetch_url() — GET with retry, exponential backoff, returns (response, error)
- DEFAULT_USER_AGENT constant (Firefox on Windows)
- Heavily commented

**Step 5: Implement network utilities**

`webinspector/utils/network.py`:
- batch_resolve_dns() — resolve all hostnames, return dict of host->ip
- reverse_dns_lookup() — IP to hostname
- check_caa_records() — query CAA records for a domain via dnspython
- is_ip_address() — check if string is an IP
- ip_sort_key() — convert IP string to sortable tuple
- Heavily commented

`tests/test_network.py` — basic tests for is_ip_address(), ip_sort_key()

**Step 6: Run all tests**

Run: `cd ~/webinspector && python -m pytest tests/ -v`
Expected: All PASS

**Step 7: Commit**

```bash
git add webinspector/utils/ tests/test_nmap_parser.py tests/test_network.py tests/fixtures/
git commit -m "feat: add HTTP client, DNS utilities, and nmap XML parser"
```

---

### Task 4: Module base class and module registry

**Files:**
- Create: `webinspector/modules/base.py`
- Modify: `webinspector/modules/__init__.py`
- Create: `tests/test_module_registry.py`

**Step 1: Write failing test for module registry**

`tests/test_module_registry.py`:
```python
"""
Tests for the module base class and registry system.
"""

import pytest
from webinspector.modules.base import ScanModule
from webinspector.modules import get_all_modules, get_module_by_name


class TestModuleRegistry:
    def test_get_all_modules_returns_list(self):
        """get_all_modules should return a list of ScanModule subclasses."""
        modules = get_all_modules()
        assert isinstance(modules, list)
        assert all(isinstance(m, ScanModule) for m in modules)

    def test_get_module_by_name(self):
        """Should find module by its name string."""
        # After modules are implemented, this will find real modules
        # For now we just test the registry mechanism
        modules = get_all_modules()
        if modules:
            first = modules[0]
            found = get_module_by_name(first.name)
            assert found is not None
            assert found.name == first.name

    def test_unknown_module_returns_none(self):
        """Unknown module name should return None."""
        found = get_module_by_name("nonexistent_module_xyz")
        assert found is None
```

**Step 2: Implement base class and registry**

`webinspector/modules/base.py`:
```python
"""
Abstract base class for all scanner modules.

Every scanner module (SSL, headers, cookies, etc.) inherits from ScanModule
and implements the scan() method. The module registry in __init__.py
discovers and loads all available modules.
"""

from abc import ABC, abstractmethod
from typing import Optional
from requests import Response
from webinspector.core.target import Target
from webinspector.core.result import Finding


class ScanModule(ABC):
    """
    Abstract base class for scanner modules.

    Each module performs a specific category of security checks against
    a target. Modules receive a pre-fetched HTTP response to avoid
    duplicate requests (multiple modules examining the same response).
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Short identifier for this module (e.g., 'ssl', 'headers')."""
        ...

    @property
    @abstractmethod
    def description(self) -> str:
        """Human-readable description shown in help text."""
        ...

    @abstractmethod
    def scan(self, target: Target, http_response: Optional[Response] = None) -> list[Finding]:
        """
        Run this module's security checks against a single target.

        Args:
            target: The target to scan (host, port, scheme, resolved IP).
            http_response: Pre-fetched HTTP response. Shared across all
                          HTTP-based modules for this target to avoid
                          duplicate requests. May be None if the target
                          was unreachable or if this module doesn't need it
                          (e.g., SSL module does its own connections).

        Returns:
            List of Finding objects. Empty list means no issues found.
        """
        ...

    def accepts_target(self, target: Target) -> bool:
        """
        Check whether this module should run against a given target.

        Override in subclasses to skip targets that don't apply.
        For example, the SSL module should skip http:// targets,
        and the HTTPS enforcement module should skip https:// targets.

        Default: accept all targets.
        """
        return True
```

`webinspector/modules/__init__.py`:
```python
"""
Module registry — discovers and manages scanner modules.
"""

# ... imports of all module classes once they exist
# Registry pattern: list of module instances

ALL_MODULE_NAMES = [
    "ssl", "certs", "headers", "cookies", "cors",
    "tech", "disclosure", "https", "files", "content", "dns",
]

def get_all_modules():
    # Returns instances of all registered ScanModule subclasses
    ...

def get_module_by_name(name):
    # Find a module instance by its name string
    ...

def get_modules_for_selection(only=None, exclude=None):
    # Filter modules based on --only and --no flags
    ...
```

**Step 3: Run tests, verify pass**

Run: `cd ~/webinspector && python -m pytest tests/test_module_registry.py -v`

**Step 4: Commit**

```bash
git add webinspector/modules/ tests/test_module_registry.py
git commit -m "feat: add ScanModule base class and module registry"
```

---

## Phase 2: CLI and Scanner Orchestration

### Task 5: CLI argument parser

**Files:**
- Create: `webinspector/cli.py`
- Modify: `webinspector/__main__.py`
- Create: `tests/test_cli.py`

**Step 1: Write failing tests for CLI**

`tests/test_cli.py` — tests for parse_args() covering:
- `-t example.com` produces target list
- `-iL file.txt` reads file path
- `-x nmap.xml` reads nmap path
- `-p 443 8443` produces port list
- `--only ssl,headers` produces module include list
- `--no tech` produces module exclude list
- `--only` and `--no` together raises error
- `--timeout 30` sets timeout
- `--proxy socks5://...` sets proxy
- `-o results.txt` sets output file
- `--json results.json` sets json file
- `-v` sets verbose, `-q` sets quiet
- No targets provided raises error

**Step 2: Implement CLI parser**

`webinspector/cli.py` — argparse-based with:
- All argument groups from the design doc
- Validation: at least one target source required, --only/--no mutually exclusive
- Returns a ScanConfig dataclass with all parsed options
- Heavily commented with examples for each argument

**Step 3: Wire up __main__.py**

`webinspector/__main__.py` — call parse_args(), print config summary, exit.
Will be extended in Task 6 to actually run the scanner.

**Step 4: Run tests, verify pass, commit**

```bash
git add webinspector/cli.py webinspector/__main__.py tests/test_cli.py
git commit -m "feat: add CLI argument parser with validation"
```

---

### Task 6: Scanner orchestrator

**Files:**
- Create: `webinspector/core/scanner.py`
- Modify: `webinspector/__main__.py`

**Step 1: Implement scanner orchestrator**

`webinspector/core/scanner.py`:
- WebInspectorScanner class with run(config, targets, modules) method
- DNS pre-resolution phase (batch)
- ThreadPoolExecutor for HTTP-based module scanning
- Separate sslyze scanning thread/phase for SSL/cert modules
- Rich progress bar integration
- Per-target error handling (catch, log, continue)
- Keyboard interrupt handling (graceful shutdown, output partial results)
- delay support between requests
- Returns list of all Findings + ScanSummary

**Step 2: Wire up __main__.py end-to-end**

`webinspector/__main__.py`:
1. Parse CLI args
2. Resolve targets from all input sources
3. Select modules based on --only/--no
4. Print banner (unless --quiet)
5. Run scanner
6. Render output (console, and optionally text/json)

At this point the tool should run end-to-end, but with no modules
implemented yet it will just scan targets with an empty finding list.

**Step 3: Test manually**

Run: `cd ~/webinspector && python -m webinspector -t example.com -v`
Expected: Banner, progress bar, 0 findings, summary

**Step 4: Commit**

```bash
git add webinspector/core/scanner.py webinspector/__main__.py
git commit -m "feat: add scanner orchestrator with concurrency and progress bars"
```

---

## Phase 3: Output Renderers

### Task 7: Console, text, and JSON output

**Files:**
- Create: `webinspector/output/console.py`
- Create: `webinspector/output/text.py`
- Create: `webinspector/output/json_output.py`
- Create: `tests/test_output.py`

**Step 1: Write tests for output formatting**

`tests/test_output.py`:
- Test that console formatter groups findings by type
- Test that text output contains no ANSI codes
- Test that JSON output is valid JSON with expected schema
- Test that summary stats are calculated correctly
- Test empty findings produces clean output

**Step 2: Implement all three renderers**

`webinspector/output/console.py` — Rich-based:
- Banner with version, target count, module list
- Progress bar during scanning (called from scanner.py)
- Grouped findings with colored severity
- Disclosure headers in categorized sections
- Tech fingerprinting results
- Summary statistics table

`webinspector/output/text.py`:
- Same layout as console but plain text (no ANSI)
- Write to file specified by -o flag

`webinspector/output/json_output.py`:
- Structured JSON matching the schema in the design doc
- scan_info, findings, failed_targets, summary sections

**Step 3: Run tests, commit**

```bash
git add webinspector/output/ tests/test_output.py
git commit -m "feat: add console, text, and JSON output renderers"
```

---

## Phase 4: Scanner Modules (each task is one module)

### Task 8: SSL scanner module

**Files:**
- Create: `webinspector/modules/ssl_scanner.py`
- Create: `tests/test_ssl_scanner.py`

Wraps sslyze Scanner API. Queues ServerScanRequests for all HTTPS targets.
Checks: deprecated protocols (SSL2, SSL3, TLS1.0, TLS1.1), weak ciphers
(NULL, EXP, ADH, AECDH, key_size<=64), medium ciphers (DES, RC4, 64<key_size<=112),
Heartbleed, ROBOT, CCS injection, TLS compression, insecure renegotiation,
missing fallback SCSV, TLS 1.3 early data.

Only runs against targets with scheme="https" (accepts_target override).

Tests use mocked sslyze results (don't make real TLS connections in tests).

**Commit:** `git commit -m "feat: add SSL/TLS scanner module (sslyze wrapper)"`

---

### Task 9: Certificate scanner module

**Files:**
- Create: `webinspector/modules/cert_scanner.py`
- Create: `tests/test_cert_scanner.py`

Uses sslyze's certificate_info results (shared with SSL scanner — the scanner
orchestrator runs sslyze once and passes results to both ssl_scanner and
cert_scanner). Checks: self-signed/untrusted, expired, not-yet-valid, weak
signature algorithm (SHA1, MD5), weak RSA key (<2048 bits), weak ECC key
(<256 bits), hostname mismatch.

**Commit:** `git commit -m "feat: add certificate scanner module"`

---

### Task 10: Header scanner module

**Files:**
- Create: `webinspector/modules/header_scanner.py`
- Create: `tests/test_header_scanner.py`

Checks HTTP response for missing security headers:
- Content-Security-Policy (+ quality analysis: unsafe-inline, unsafe-eval, wildcard, data:, missing default-src, missing object-src, missing base-uri, report-only)
- X-Frame-Options (+ CSP frame-ancestors for clickjacking)
- X-Content-Type-Options (must be "nosniff")
- Referrer-Policy (flag unsafe-url, no-referrer-when-downgrade)
- Permissions-Policy (flag missing, flag wildcard on sensitive features)
- Deprecated headers (X-XSS-Protection, Public-Key-Pins, Expect-CT)

Tests mock HTTP responses with various header combinations.

**Commit:** `git commit -m "feat: add security header scanner module"`

---

### Task 11: Cookie scanner module

**Files:**
- Create: `webinspector/modules/cookie_scanner.py`
- Create: `tests/test_cookie_scanner.py`

Checks Set-Cookie headers for:
- Missing Secure flag (Medium if session cookie, Low otherwise)
- Missing HttpOnly flag (Medium if session cookie, Low otherwise)
- Missing SameSite attribute
- SameSite=None without Secure
- Persistent session cookie (has Expires/Max-Age on a session cookie)

Session cookie detection via name pattern matching (JSESSIONID, PHPSESSID,
ASP.NET_SessionId, connect.sid, laravel_session, etc.)

Parses raw Set-Cookie headers since requests' cookiejar doesn't expose SameSite.

**Commit:** `git commit -m "feat: add cookie security scanner module"`

---

### Task 12: CORS scanner module

**Files:**
- Create: `webinspector/modules/cors_scanner.py`
- Create: `tests/test_cors_scanner.py`

Sends requests with crafted Origin headers:
- evil.com (arbitrary origin)
- null (null origin attack)
- evil.{target_domain} (subdomain hijack)
- {target_domain}.evil.com (post-domain bypass)

Checks if Access-Control-Allow-Origin reflects the crafted origin,
and whether Access-Control-Allow-Credentials is true.

Severity: High with credentials, Medium without.

**Commit:** `git commit -m "feat: add CORS misconfiguration scanner module"`

---

### Task 13: Technology fingerprinting module

**Files:**
- Create: `webinspector/modules/tech_scanner.py`
- Create: `tests/test_tech_scanner.py`

Wraps webtech library. Passes the URL to webtech.WebTech for analysis.
Groups detected technologies by category. Handles DB update via --update-db.
Formats output as: host  tech1, tech2, tech3 (with versions where available).

**Commit:** `git commit -m "feat: add technology fingerprinting module (webtech)"`

---

### Task 14: Information disclosure scanner module

**Files:**
- Create: `webinspector/modules/disclosure_scanner.py`
- Create: `tests/test_disclosure_scanner.py`

Checks ~90+ headers across 8 categories (ported from headerinspect's
INFO_DISCLOSURE_HEADERS dict):
- Technology Stack (X-Powered-By, Server, X-AspNet-Version, etc.)
- Debugging/Development (X-Debug-Token, X-Trace-Id, etc.)
- Infrastructure/Proxy (Via, X-Backend-Server, etc.)
- Caching/CDN (X-Varnish, CF-Ray, etc.)
- Container/Orchestration (X-Kubernetes-*, X-Docker-*, etc.)
- Load Balancer (X-Haproxy-*, X-LB-Server, etc.)
- Authentication (X-Auth-Server, X-OAuth-Scopes, etc.)
- Miscellaneous (X-Hostname, X-Instance-ID, etc.)

Groups findings by category and header value (URLs sharing the same
Server: nginx/1.18.0 are grouped together, matching headerinspect's output).

**Commit:** `git commit -m "feat: add information disclosure header scanner module"`

---

### Task 15: HTTPS enforcement scanner module

**Files:**
- Create: `webinspector/modules/https_scanner.py`
- Create: `tests/test_https_scanner.py`

Checks:
- HTTP-to-HTTPS redirect (request http:// version, check for 301/302 to https://)
- No redirect = Medium finding
- Non-301 redirect = Informational
- Redirect chain length >2 = Low
- HSTS header analysis: missing = Medium, max-age < 1 year = Low,
  missing includeSubDomains = Low, missing preload = Informational

Only runs against http:// targets for redirect checks, https:// for HSTS.

**Commit:** `git commit -m "feat: add HTTPS enforcement scanner module"`

---

### Task 16: Files scanner module (robots.txt, security.txt)

**Files:**
- Create: `webinspector/modules/files_scanner.py`
- Create: `tests/test_files_scanner.py`

robots.txt checks:
- Fetch /robots.txt, parse Disallow/Allow lines
- Match against sensitive path patterns (admin, backup, config, api, git, etc.)
- Flag interesting paths as Low finding

security.txt checks (RFC 9116):
- Check /.well-known/security.txt and /security.txt
- Validate required fields: Contact, Expires
- Check if Expires is in the past
- Check for PGP signature
- Missing entirely = Informational

**Commit:** `git commit -m "feat: add robots.txt and security.txt scanner module"`

---

### Task 17: Content scanner module

**Files:**
- Create: `webinspector/modules/content_scanner.py`
- Create: `tests/test_content_scanner.py`

Parses the HTML response body to check:
- Mixed content: <script>, <link>, <iframe> loading http:// resources on https page
  (active mixed content = Medium, passive = Low)
- Missing SRI: external <script>/<link> without integrity attribute (Low)
- Internal IP disclosure: RFC 1918 addresses in response body (Low)
- Email address disclosure (Informational)
- Sensitive HTML comments: containing TODO, FIXME, password, key, version (Informational)
- Error page detection: Java stacktrace, Python traceback, PHP error, ASP.NET error,
  Django debug, Laravel debug, SQL error, directory listing patterns (Medium-High)
- Default server pages: Apache, nginx, IIS default pages (Low)

Uses html.parser (stdlib) for HTML parsing. No beautifulsoup dependency.

**Commit:** `git commit -m "feat: add content analysis scanner module"`

---

### Task 18: DNS scanner module

**Files:**
- Create: `webinspector/modules/dns_scanner.py`
- Create: `tests/test_dns_scanner.py`

Checks:
- CAA records: query domain for CAA DNS records. Missing = Low finding.
  Present = Informational (log the records).
- Reverse DNS: for IP targets, populate rdns field. Report hostname for context.

Uses dnspython for DNS queries.
Only runs once per unique domain (not per URL).

**Commit:** `git commit -m "feat: add DNS security scanner module (CAA, reverse DNS)"`

---

## Phase 5: Integration and Polish

### Task 19: Wire all modules into the registry

**Files:**
- Modify: `webinspector/modules/__init__.py`
- Modify: `webinspector/core/scanner.py`

**Step 1: Register all 11 modules in __init__.py**

Import all module classes, instantiate them, add to registry list.

**Step 2: Update scanner to share sslyze results**

The scanner orchestrator needs to:
1. Run sslyze once for all HTTPS targets
2. Pass the sslyze results dict to both ssl_scanner and cert_scanner
3. Pass HTTP response to all HTTP-based modules

**Step 3: Integration test**

Run: `cd ~/webinspector && python -m webinspector -t example.com -v`
Expected: Real findings from all modules, proper output formatting

**Step 4: Commit**

```bash
git add webinspector/modules/__init__.py webinspector/core/scanner.py
git commit -m "feat: wire all scanner modules into registry and orchestrator"
```

---

### Task 20: Install scripts

**Files:**
- Create: `install.sh`
- Create: `install.ps1`

**Step 1: Write install.sh (Linux/macOS/WSL/Git Bash)**

```bash
#!/bin/bash
# WebInspector Install Script
# 1. Check Python 3.10+
# 2. Create venv
# 3. Install requirements
# 4. Install package in editable mode
# 5. Download webtech DB
# 6. Run tests
# 7. Smoke test against example.com
# 8. Print usage instructions
```

**Step 2: Write install.ps1 (Windows PowerShell)**

Same logic adapted for PowerShell.

**Step 3: Test install script**

Run: `cd ~/webinspector && bash install.sh`
Expected: All steps pass, smoke test produces findings

**Step 4: Commit**

```bash
git add install.sh install.ps1
git commit -m "feat: add install scripts for Linux/macOS and Windows"
```

---

### Task 21: README and final polish

**Files:**
- Create: `README.md`
- Review all files for comments and documentation

**Step 1: Write README.md**

Cover: what it does, installation, quick start examples, all CLI flags,
module descriptions, output formats, input formats, examples of each,
dependencies, contributing notes.

**Step 2: Review all source files**

Verify every file has:
- Module docstring explaining what it does
- Comments on non-obvious logic
- Type hints on function signatures
- Consistent formatting

**Step 3: Final integration test**

Run: `cd ~/webinspector && python -m webinspector -t example.com -o /tmp/test_results.txt --json /tmp/test_results.json`
Verify: Console output looks correct, text file is clean, JSON is valid.

Run: `cd ~/webinspector && python -m webinspector --only ssl,headers -t example.com`
Verify: Only SSL and header modules run.

Run: `cd ~/webinspector && python -m pytest tests/ -v`
Verify: All tests pass.

**Step 4: Commit**

```bash
git add README.md
git commit -m "docs: add README with usage instructions and examples"
```

---

## Task Dependency Map

```
Phase 1 (Foundation):
  Task 1 (skeleton) → Task 2 (data structures) → Task 3 (utilities) → Task 4 (module base)

Phase 2 (CLI + Orchestration):
  Task 4 → Task 5 (CLI) → Task 6 (scanner orchestrator)

Phase 3 (Output):
  Task 6 → Task 7 (output renderers)

Phase 4 (Modules — all depend on Tasks 4+6+7, but are independent of each other):
  Task 7 → Task 8  (SSL)
  Task 7 → Task 9  (Certs)
  Task 7 → Task 10 (Headers)
  Task 7 → Task 11 (Cookies)
  Task 7 → Task 12 (CORS)
  Task 7 → Task 13 (Tech)
  Task 7 → Task 14 (Disclosure)
  Task 7 → Task 15 (HTTPS)
  Task 7 → Task 16 (Files)
  Task 7 → Task 17 (Content)
  Task 7 → Task 18 (DNS)

Phase 5 (Integration):
  Tasks 8-18 → Task 19 (wire up)
  Task 19 → Task 20 (install scripts)
  Task 20 → Task 21 (README + polish)
```

**Note:** Tasks 8-18 (the scanner modules) are independent of each other and
CAN be implemented in parallel by multiple agents. Each produces its own
findings and only depends on the base module class and core data structures.
