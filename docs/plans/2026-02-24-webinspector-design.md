# WebInspector Design Document

**Date:** 2026-02-24
**Author:** Jason Downey / Claude
**Status:** Approved

## Overview

WebInspector is a production-ready Python CLI tool for penetration testing engagements
that combines SSL/TLS configuration scanning, HTTP security header analysis, cookie
security checks, CORS misconfiguration detection, technology fingerprinting, and
passive web application security analysis into a single unified tool.

It replaces the need to run multiple separate tools (sslyze-scan.py, sslscan scripts,
header-scan.py, headerinspect, webtech) by consolidating all functionality with
improved error handling, progress reporting, and report-ready output.

## Goals

1. **Single tool** — replaces 5+ separate scripts with one CLI
2. **Report-ready output** — grouped by finding type for direct copy-paste into pentest reports
3. **Flexible input** — accepts URLs, IPs, host:port, target lists, and nmap XML files
4. **Modular** — all checks run by default, each module can be run individually or excluded
5. **Production-ready** — progress bars, error handling, retry logic, reverse DNS, concurrency
6. **Well-documented** — heavily commented Python code so the team can follow and extend it
7. **Easy install** — single install script that handles dependencies and runs basic tests

## Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| TLS scanning engine | sslyze (library) | Battle-tested, covers Heartbleed/ROBOT/CCS, team already uses it |
| Tech fingerprinting | webtech | Lightweight (only requests), 7,500+ tech DB, auto-updates from enthec fork |
| HTTP client | requests | Standard, team is familiar, headerinspect already uses it |
| Progress bars | rich | Modern, handles concurrent progress well, colored output |
| XML parsing | lxml | Fast nmap XML parsing, no external xmlstarlet dependency |
| DNS lookups | dnspython | CAA records, reverse DNS, pure Python |
| Concurrency | ThreadPoolExecutor | I/O bound workload, sslyze manages its own threads internally |
| Output format | Console + text file + JSON | Console for interactive use, text for reports, JSON for automation |
| WAF detection | Excluded | Not needed for team's workflow |
| Open redirect probing | Excluded | Not needed for team's workflow |
| JARM fingerprinting | Excluded | Not needed for typical engagements |
| CT log lookups | Excluded | Not needed for typical engagements |

## Input Handling

### Supported Input Formats

```bash
# Single target (defaults to port 443)
webinspector -t example.com

# Host:port
webinspector -t 10.0.0.1:8443

# Multiple targets
webinspector -t 10.0.0.1 10.0.0.2 example.com

# Host with multiple ports
webinspector -t 10.0.0.1 -p 443 8443 8080

# Target list file (one host or host:port per line)
webinspector -iL targets.txt

# Nmap XML file (auto-extracts HTTPS/SSL services)
webinspector -x nmap_output.xml

# Multiple nmap XML files
webinspector -x scan1.xml scan2.xml

# Combine all input types
webinspector -x scan.xml -iL extras.txt -t 10.0.0.5
```

### Target Expansion Rules

- Bare hostnames/IPs without protocol: expand to both `http://` and `https://`
- Targets with explicit protocol: use as-is
- Nmap XML: extract hosts with services tagged `https`, `ssl`, `http`, `tunnel="ssl"`,
  `http-proxy`, `http-alt`, `https-alt`, `oracleas-https`
- Port flag (`-p`): applies to all `-t` targets that don't already specify a port
- Deduplication: targets resolving to the same IP:port are scanned once

### Target List File Format

```
# Comments supported (lines starting with #)
example.com
10.0.0.1:8443
https://internal.corp.com
192.168.1.0/24:443    # CIDR ranges supported
```

## Module System

### Available Modules

| Module | Flag | What It Checks |
|--------|------|----------------|
| `ssl` | `--only ssl` / `--no ssl` | Deprecated protocols, weak/medium ciphers, Heartbleed, ROBOT, CCS injection, TLS compression, renegotiation, fallback SCSV, early data |
| `certs` | `--only certs` / `--no certs` | Self-signed, expired, weak signature (SHA1/MD5), weak RSA (<2048), weak ECC (<256), untrusted chains, hostname mismatch |
| `headers` | `--only headers` / `--no headers` | Missing CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy. CSP quality analysis (unsafe-inline, unsafe-eval, wildcards) |
| `cookies` | `--only cookies` / `--no cookies` | Missing Secure, HttpOnly, SameSite flags. Session cookie detection. Persistent session cookies |
| `cors` | `--only cors` / `--no cors` | Origin reflection with/without credentials, null origin, subdomain bypass patterns |
| `tech` | `--only tech` / `--no tech` | Technology fingerprinting via webtech (CMS, frameworks, CDN, analytics, servers, languages) |
| `disclosure` | `--only disclosure` / `--no disclosure` | Info disclosure headers (~90+ across 8 categories: tech stack, debug, infrastructure, caching, container, load balancer, auth, misc) |
| `https` | `--only https` / `--no https` | HTTP-to-HTTPS redirect, redirect chain analysis, HSTS max-age/includeSubDomains/preload |
| `files` | `--only files` / `--no files` | robots.txt sensitive path disclosure, security.txt validation (RFC 9116) |
| `content` | `--only content` / `--no content` | Mixed content (active/passive), missing SRI on external scripts, internal IP disclosure, sensitive HTML comments, error page detection (stack traces, debug pages, default pages, directory listings) |
| `dns` | `--only dns` / `--no dns` | CAA record presence/validation, reverse DNS lookups |

### Module Selection

```bash
# Run everything (default)
webinspector -t example.com

# Run only specific modules
webinspector -t example.com --only ssl,certs

# Run everything except specific modules
webinspector -t example.com --no tech,content

# --only and --no are mutually exclusive
```

## Output

### Console Output (Default)

Results grouped by finding type, with targets sorted by IP within each group.
Uses rich for colored severity indicators and progress bars during scanning.

```
[*] WebInspector v1.0.0
[*] Targets: 5 hosts, 8 URLs
[*] Modules: ssl, certs, headers, cookies, cors, tech, disclosure, https, files, content, dns

Scanning ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 8/8 targets

================================================================================
RESULTS
================================================================================

SSL/TLS - Deprecated Protocols:
------------------------------
10.0.0.1:443        TLSv1.0, TLSv1.1
10.0.0.5:8443       SSLv3, TLSv1.0
Count: 2

SSL/TLS - Weak Ciphers:
------------------------------
10.0.0.1:443        TLS_RSA_WITH_3DES_EDE_CBC_SHA
Count: 1

SSL/TLS - Self-Signed Certificates:
------------------------------
10.0.0.5:8443
Count: 1

SSL/TLS - Expired Certificates:
------------------------------
10.0.0.1:443        Expired: Jan 15, 2025
Count: 1

Missing Content-Security-Policy:
------------------------------
http://10.0.0.1
https://10.0.0.1:443
https://10.0.0.5:8443
Count: 3

Missing Strict-Transport-Security:
------------------------------
https://10.0.0.1:443
https://10.0.0.5:8443
Count: 2

Clickjacking - No Protection:
------------------------------
https://10.0.0.1:443   Neither X-Frame-Options nor CSP frame-ancestors set
Count: 1

Cookie Security - Missing Secure Flag:
------------------------------
https://10.0.0.1:443   JSESSIONID
Count: 1

CORS - Origin Reflection with Credentials:
------------------------------
https://10.0.0.1:443   Reflects arbitrary Origin with Access-Control-Allow-Credentials: true
Count: 1

INFORMATION DISCLOSURE HEADERS:
========================================

[Technology Stack]

Server: nginx/1.18.0
  https://10.0.0.1:443
  https://10.0.0.5:8443

X-Powered-By: PHP/8.1.2
  https://10.0.0.1:443

[Infrastructure/Proxy]

X-Backend-Server: app-node-03.internal
  https://10.0.0.1:443

TECHNOLOGY FINGERPRINTING:
========================================
10.0.0.1:443         nginx, PHP, WordPress 6.4, jQuery 3.7.1, Google Analytics
10.0.0.5:8443        Apache, Tomcat, Java

DNS - Missing CAA Records:
------------------------------
example.com
Count: 1

robots.txt - Sensitive Paths Disclosed:
------------------------------
https://10.0.0.1:443   /admin/, /backup/, /api/internal/
Count: 1

================================================================================
SCAN SUMMARY
================================================================================
Total targets scanned: 5
Successful checks:     4
Failed connections:    1 (10.0.0.3:443 - Connection refused)
Scan duration:         47.2s

Security Header Analysis:
  Content-Security-Policy:        3/4 missing (75.0%)
  Strict-Transport-Security:      2/4 missing (50.0%)
  X-Content-Type-Options:         1/4 missing (25.0%)
  X-Frame-Options:                1/4 missing (25.0%)

SSL/TLS Summary:
  Deprecated protocols:           2 hosts
  Weak ciphers:                   1 host
  Certificate issues:             2 hosts
```

### Text File Output (-o)

Same format as console but without color codes. Suitable for copy-paste into reports.

```bash
webinspector -t example.com -o results.txt
```

### JSON Output (--json)

Structured JSON for automation and programmatic processing.

```bash
webinspector -t example.com --json results.json
```

```json
{
  "scan_info": {
    "version": "1.0.0",
    "timestamp": "2026-02-24T10:30:00Z",
    "targets_scanned": 5,
    "modules_run": ["ssl", "certs", "headers", "cookies", "cors", "tech", "disclosure", "https", "files", "content", "dns"],
    "duration_seconds": 47.2
  },
  "findings": [
    {
      "module": "ssl",
      "finding_type": "deprecated_protocols",
      "severity": "Medium",
      "targets": [
        {"host": "10.0.0.1", "port": 443, "ip": "10.0.0.1", "detail": "TLSv1.0, TLSv1.1"},
        {"host": "10.0.0.5", "port": 8443, "ip": "10.0.0.5", "detail": "SSLv3, TLSv1.0"}
      ],
      "count": 2
    }
  ],
  "failed_targets": [
    {"host": "10.0.0.3", "port": 443, "error": "Connection refused"}
  ],
  "summary": {
    "total_findings": 15,
    "by_severity": {"High": 1, "Medium": 6, "Low": 5, "Informational": 3}
  }
}
```

## Architecture

### Directory Structure

```
webinspector/
├── install.sh                   # Install script: deps, tests, PATH setup
├── install.ps1                  # Windows install script
├── requirements.txt             # Python dependencies
├── setup.py                     # Package setup for pip install -e .
├── README.md                    # Usage documentation
├── tests/
│   ├── test_target_parser.py    # Input parsing tests
│   ├── test_nmap_parser.py      # Nmap XML parsing tests
│   ├── test_modules.py          # Module unit tests
│   └── test_output.py           # Output formatting tests
├── webinspector/
│   ├── __init__.py              # Package init, version
│   ├── __main__.py              # Entry point: python -m webinspector
│   ├── cli.py                   # Argument parser, module selection, validation
│   ├── core/
│   │   ├── __init__.py
│   │   ├── target.py            # Target dataclass, input parsing, URL expansion,
│   │   │                        # CIDR expansion, deduplication
│   │   ├── scanner.py           # Main orchestrator: thread pool, progress bars,
│   │   │                        # module dispatch, result collection
│   │   └── result.py            # Finding dataclass with severity enum,
│   │                            # result aggregation, sorting by IP
│   ├── modules/
│   │   ├── __init__.py          # Module registry, discovery
│   │   ├── base.py              # Abstract base class: ScanModule with
│   │   │                        # name, description, scan(target) -> [Finding]
│   │   ├── ssl_scanner.py       # sslyze wrapper: cipher suites, protocol versions,
│   │   │                        # vulnerability checks (Heartbleed, ROBOT, CCS),
│   │   │                        # compression, renegotiation, fallback SCSV, early data
│   │   ├── cert_scanner.py      # Certificate analysis: self-signed, expired, weak sig,
│   │   │                        # weak key, untrusted chain, hostname mismatch.
│   │   │                        # Uses sslyze certificate_info results
│   │   ├── header_scanner.py    # Security headers: CSP (with quality analysis),
│   │   │                        # X-Frame-Options, X-Content-Type-Options,
│   │   │                        # Referrer-Policy, Permissions-Policy, clickjacking
│   │   ├── cookie_scanner.py    # Cookie flags: Secure, HttpOnly, SameSite.
│   │   │                        # Session cookie detection via name patterns.
│   │   │                        # Persistent session cookie detection
│   │   ├── cors_scanner.py      # CORS: test with crafted Origin headers.
│   │   │                        # Detect reflection, null origin, subdomain bypass.
│   │   │                        # Check Access-Control-Allow-Credentials
│   │   ├── tech_scanner.py      # webtech wrapper: technology fingerprinting.
│   │   │                        # DB update support. Category grouping
│   │   ├── disclosure_scanner.py # Info disclosure headers: ~90+ headers across
│   │   │                        # 8 categories (tech stack, debug, infra, cache,
│   │   │                        # container, LB, auth, misc)
│   │   ├── https_scanner.py     # HTTPS enforcement: HTTP->HTTPS redirect check,
│   │   │                        # redirect chain analysis, HSTS max-age,
│   │   │                        # includeSubDomains, preload
│   │   ├── files_scanner.py     # robots.txt: sensitive path detection.
│   │   │                        # security.txt: RFC 9116 validation (contact,
│   │   │                        # expires, signature, canonical)
│   │   ├── content_scanner.py   # Mixed content (active/passive), SRI on external
│   │   │                        # scripts/styles, internal IP leakage, email
│   │   │                        # disclosure, sensitive HTML comments, error page
│   │   │                        # detection (stack traces, debug, defaults, dir listing)
│   │   └── dns_scanner.py       # CAA records, reverse DNS lookups
│   ├── output/
│   │   ├── __init__.py
│   │   ├── console.py           # Rich-based console output: colored severity,
│   │   │                        # progress bars, grouped findings, summary stats
│   │   ├── text.py              # Plain text file output (no ANSI codes)
│   │   └── json_output.py       # Structured JSON output
│   └── utils/
│       ├── __init__.py
│       ├── network.py           # DNS resolution cache, reverse DNS, IP validation,
│       │                        # CIDR expansion
│       ├── nmap_parser.py       # Nmap XML parsing with lxml: extract hosts,
│       │                        # ports, service names. No xmlstarlet dependency
│       └── http.py              # Shared requests.Session with retry logic,
│                                # exponential backoff, configurable timeout,
│                                # user-agent, proxy support, LRU response cache
```

### Key Classes

```python
# --- core/target.py ---

@dataclass
class Target:
    """Represents a single scan target."""
    host: str           # Hostname or IP
    port: int           # Port number
    scheme: str         # 'http' or 'https'
    ip: str | None      # Resolved IP address (populated during DNS pre-resolution)
    rdns: str | None    # Reverse DNS name (populated if IP target)
    source: str         # Where this target came from: 'cli', 'file', 'nmap'

    @property
    def url(self) -> str:
        """Full URL for HTTP requests."""
        ...

    @property
    def hostport(self) -> str:
        """host:port string for display."""
        ...


# --- core/result.py ---

class Severity(Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFORMATIONAL = "Informational"

@dataclass
class Finding:
    """A single security finding."""
    module: str         # Which module produced this (e.g., 'ssl', 'headers')
    finding_type: str   # Category within module (e.g., 'deprecated_protocols')
    severity: Severity  # Finding severity
    target: Target      # Which target this applies to
    title: str          # Human-readable title (e.g., 'Deprecated Protocols')
    detail: str         # Specific detail (e.g., 'TLSv1.0, TLSv1.1')
    references: list[str] = field(default_factory=list)  # CWE/OWASP refs


# --- modules/base.py ---

class ScanModule(ABC):
    """Abstract base class for all scanner modules."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Module identifier (e.g., 'ssl', 'headers')."""
        ...

    @property
    @abstractmethod
    def description(self) -> str:
        """Human-readable description."""
        ...

    @abstractmethod
    def scan(self, target: Target, http_response: Response | None = None) -> list[Finding]:
        """
        Run this module's checks against a target.

        Args:
            target: The target to scan.
            http_response: Pre-fetched HTTP response (shared across modules
                          to avoid duplicate requests). May be None if the
                          target is not reachable over HTTP.

        Returns:
            List of Finding objects for any issues detected.
        """
        ...
```

### Execution Flow

```
1. CLI PARSING
   cli.py parses arguments -> list of raw target strings + options

2. TARGET RESOLUTION
   target.py expands all inputs:
   - Parse URLs, host:port, bare hosts
   - Expand CIDR ranges
   - Parse nmap XML files
   - Apply port flag (-p) to portless targets
   - Expand bare hosts to http:// + https://
   - Deduplicate by resolved IP:port

3. DNS PRE-RESOLUTION
   network.py batch-resolves all unique hostnames
   Populates Target.ip for each target
   Populates Target.rdns for IP-only targets (reverse DNS)

4. MODULE INITIALIZATION
   scanner.py loads requested modules based on --only / --no flags
   Each module validates it can run (e.g., ssl module skips http:// targets)

5. CONCURRENT SCANNING
   For each target (via ThreadPoolExecutor):
     a. Fetch HTTP response (shared across HTTP-based modules)
     b. Run each enabled module's scan() method
     c. SSL module runs sslyze Scanner separately (it manages own threads)
     d. Collect Finding objects from all modules

6. RESULT AGGREGATION
   result.py groups findings by (module, finding_type)
   Sorts targets within each group by IP address (numerical sort)
   Calculates summary statistics

7. OUTPUT
   console.py / text.py / json_output.py render the grouped results
```

### Concurrency Design

```
Main Thread
  │
  ├─ DNS Pre-resolution (batch, before scanning starts)
  │
  ├─ ThreadPoolExecutor (adaptive: 3-20 workers based on target count)
  │   ├─ Worker 1: Target A
  │   │   ├─ HTTP GET (shared response)
  │   │   ├─ header_scanner.scan(target, response)
  │   │   ├─ cookie_scanner.scan(target, response)
  │   │   ├─ cors_scanner.scan(target, response)
  │   │   ├─ ... (all HTTP-based modules, sequential per target)
  │   │   └─ Results queued
  │   ├─ Worker 2: Target B
  │   │   └─ ... (same)
  │   └─ Worker N: Target N
  │       └─ ...
  │
  ├─ sslyze Scanner (separate, manages its own thread pool)
  │   ├─ Queue all HTTPS targets as ServerScanRequests
  │   ├─ sslyze runs scans with its own concurrency limits
  │   │   (default: 5 connections/server, 10 concurrent servers)
  │   └─ Results collected via scanner.get_results() generator
  │
  └─ Result aggregation + output (main thread, after all scanning complete)
```

The HTTP module scanning and sslyze scanning run concurrently with each other,
since they use independent thread pools. This maximizes throughput — HTTP checks
are fast (single request per target) while SSL checks are slower (multiple TLS
handshakes per target).

## CLI Interface

```
usage: webinspector [-h] [-t TARGET [TARGET ...]] [-iL FILE] [-x NMAP_XML [NMAP_XML ...]]
                    [-p PORT [PORT ...]] [-o OUTPUT] [--json JSON_FILE]
                    [--only MODULES] [--no MODULES]
                    [--timeout SECONDS] [--ssl-timeout SECONDS]
                    [--threads THREADS] [--delay SECONDS]
                    [--proxy PROXY_URL] [--user-agent USER_AGENT]
                    [--no-color] [-v] [-q]
                    [--update-db] [--version]

WebInspector - Web Application Security Scanner for Penetration Testing

Target Specification:
  -t, --target TARGET     Target hostname, IP, URL, or CIDR range (can specify multiple)
  -iL FILE                File containing targets (one per line)
  -x, --nmap-xml FILE     Nmap XML output file(s) to parse for targets
  -p, --port PORT         Port(s) to scan (applies to targets without explicit port)

Output:
  -o, --output FILE       Write results to text file
  --json FILE             Write results to JSON file
  --no-color              Disable colored console output

Module Selection:
  --only MODULES          Only run these modules (comma-separated)
  --no MODULES            Skip these modules (comma-separated)
                          Modules: ssl, certs, headers, cookies, cors, tech,
                                   disclosure, https, files, content, dns

Performance:
  --timeout SECONDS       HTTP request timeout (default: 10)
  --ssl-timeout SECONDS   SSL scan timeout per target (default: 30)
  --threads THREADS       Max concurrent threads (default: auto)
  --delay SECONDS         Delay between requests to same host (default: 0)

Connection:
  --proxy PROXY_URL       Proxy URL (e.g., socks5://127.0.0.1:1080, http://proxy:8080)
  --user-agent UA         Custom User-Agent string (default: Firefox UA)

Misc:
  --update-db             Update the webtech technology database and exit
  -v, --verbose           Verbose output (show per-target progress, debug info)
  -q, --quiet             Quiet mode (suppress banner, only show findings)
  --version               Show version and exit
  -h, --help              Show this help message
```

## Install Script

### install.sh (Linux/macOS/WSL)

```bash
#!/bin/bash
# 1. Check Python 3.10+ is available
# 2. Create virtual environment in ./venv
# 3. pip install -r requirements.txt
# 4. pip install -e . (editable install)
# 5. Run webtech DB download
# 6. Run basic test suite (pytest tests/)
# 7. Verify sslyze import works
# 8. Print success message with usage examples
```

### install.ps1 (Windows PowerShell)

Same steps adapted for Windows/PowerShell.

## Dependencies

```
# requirements.txt
sslyze>=6.0,<7.0       # TLS scanning engine (brings nassl, cryptography, pydantic, tls-parser)
webtech>=1.3            # Technology fingerprinting
requests>=2.31          # HTTP client
dnspython>=2.4          # DNS queries (CAA, reverse DNS)
rich>=13.0              # Progress bars, colored console output, tables
lxml>=4.9               # Fast nmap XML parsing
netaddr>=0.9            # CIDR range expansion, IP manipulation
pytest>=7.0             # Test framework (dev dependency)
```

## Error Handling Strategy

- **Connection refused/timeout:** Log warning, add to failed targets list, continue scanning
- **SSL handshake failure:** Log warning, skip SSL module for that target, HTTP modules still run
- **DNS resolution failure:** Log warning, skip target entirely
- **Module crash:** Catch exception, log error with traceback in verbose mode, continue with other modules
- **Keyboard interrupt (Ctrl+C):** Graceful shutdown, output results collected so far
- **Retry logic:** 3 attempts with exponential backoff (0.5s, 1s, 2s) for HTTP requests
- **Rate limiting:** Optional --delay flag adds sleep between requests to same host

## Testing Strategy

### Unit Tests

- **test_target_parser.py:** Parse URLs, IPs, host:port, CIDR ranges, nmap XML. Verify expansion rules.
- **test_nmap_parser.py:** Parse sample nmap XML files. Verify service detection and host extraction.
- **test_modules.py:** Each module tested with mocked HTTP responses. Verify findings are produced for known-bad headers, cookies, certs, etc.
- **test_output.py:** Verify console, text, and JSON output formatting.

### Integration Test (in install script)

Quick smoke test: scan a known public target (e.g., example.com) with --only headers,tech to verify the tool works end-to-end.

## Security Considerations

- Tool ignores SSL certificate verification for scanning (this is intentional — we're testing the certs, not trusting them)
- User-Agent defaults to Firefox to avoid appearing as a scanner to basic WAF rules
- No credentials are stored or transmitted
- Proxy support does not log proxy credentials
- CORS checks send crafted Origin headers but do not submit forms or modify data

## Future Considerations (Not In Scope)

These are explicitly excluded from v1.0 but could be added later:

- WAF detection and fingerprinting
- Open redirect probing
- JARM TLS fingerprinting
- Certificate Transparency log lookups
- HTML report generation
- Scheduled/continuous scanning
- API mode (run as a service)
- Plugin system for custom modules
