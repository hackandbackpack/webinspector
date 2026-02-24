# WebInspector

A production-ready Python CLI tool for penetration testing engagements that combines SSL/TLS configuration scanning, HTTP security header analysis, cookie security checks, CORS misconfiguration detection, technology fingerprinting, and passive web application security analysis into a single unified tool.

**Author:** Red Siege Information Security

## Overview

WebInspector runs 11 security scanning modules against web targets and produces consolidated findings with severity ratings. It accepts targets as hostnames, IPs, URLs, CIDR ranges, target list files, or Nmap XML output -- making it easy to integrate into existing pentest workflows.

Key design goals:

- **Single command, full coverage** -- one tool replaces a handful of separate scripts
- **Pentest-ready output** -- findings grouped by type with severity ratings for direct inclusion in reports
- **Flexible input** -- feed it Nmap XML, a target list, or bare hostnames
- **Selective scanning** -- run only the modules you need or exclude the ones you don't

## Installation

### Automated (recommended)

**Linux / macOS / WSL / Git Bash:**

```bash
chmod +x install.sh
./install.sh
```

**Windows (PowerShell):**

```powershell
# If you get an execution policy error, run this first:
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

.\install.ps1
```

Both install scripts will:

1. Verify Python 3.10+ is available
2. Create a virtual environment in `./venv`
3. Install all dependencies from `requirements.txt`
4. Install webinspector in editable/development mode
5. Update the webtech technology fingerprint database
6. Run the full test suite to confirm everything works

### Manual

```bash
python3 -m venv venv
source venv/bin/activate        # Linux/macOS
# .\venv\Scripts\Activate.ps1  # Windows PowerShell

pip install -r requirements.txt
pip install -e .
```

After installation, the `webinspector` command is available in the virtual environment.

## Quick Start

```bash
# Scan a single target (defaults to port 443)
webinspector -t example.com

# Scan multiple targets on specific ports
webinspector -t 10.0.0.1 10.0.0.2 -p 443 8443

# Import targets from an Nmap XML scan
webinspector -x nmap_scan.xml

# Read targets from a file (one per line)
webinspector -iL targets.txt

# Combine input sources
webinspector -x scan.xml -iL extras.txt -t 10.0.0.5

# Run only SSL and header checks
webinspector -t example.com --only ssl,headers

# Run everything except DNS and tech fingerprinting
webinspector -t example.com --no dns,tech

# Save text report and JSON output
webinspector -t example.com -o report.txt --json report.json

# Verbose output with proxy and rate limiting
webinspector -t example.com -v --proxy socks5://127.0.0.1:9050 --delay 0.5

# Quiet mode (findings only, no banner or progress)
webinspector -t example.com -q
```

## CLI Reference

```
webinspector [-h] [-t TARGET ...] [-iL FILE] [-x NMAP_XML ...]
             [-p PORT ...] [-o OUTPUT] [--json JSON_FILE]
             [--only MODULES] [--no MODULES]
             [--timeout SECONDS] [--threads THREADS] [--delay SECONDS]
             [--proxy PROXY_URL]
             [-v] [-q] [--version]
```

### Target Specification

| Flag | Description | Example |
|------|-------------|---------|
| `-t TARGET [...]` | Direct target(s): hostnames, IPs, CIDRs, or URLs | `-t example.com 10.0.0.1` |
| `-iL FILE` | Target list file (one target per line, `#` comments allowed) | `-iL targets.txt` |
| `-x FILE [...]` | Nmap XML output file(s) -- HTTPS/SSL services extracted automatically | `-x scan.xml` |
| `-p PORT [...]` | Override default port (443) for bare hostname/IP targets | `-p 443 8443 8080` |

At least one of `-t`, `-iL`, or `-x` is required. They can be combined -- targets from all sources are merged and deduplicated.

### Output Options

| Flag | Description | Example |
|------|-------------|---------|
| `-o FILE` | Write plain text report to a file (in addition to console output) | `-o results.txt` |
| `--json FILE` | Write structured JSON report to a file | `--json results.json` |

Both `-o` and `--json` can be used together in the same scan.

### Module Selection

| Flag | Description | Example |
|------|-------------|---------|
| `--only MODULES` | Run ONLY the listed modules (comma-separated) | `--only ssl,headers,certs` |
| `--no MODULES` | Run all modules EXCEPT the listed ones (comma-separated) | `--no tech,dns` |

`--only` and `--no` are mutually exclusive.

### Performance / Connection

| Flag | Description | Default | Example |
|------|-------------|---------|---------|
| `--timeout SECONDS` | HTTP request timeout | 10 | `--timeout 30` |
| `--threads N` | Max concurrent scan threads | 10 | `--threads 20` |
| `--delay SECONDS` | Delay between requests to the same host (avoids rate limiting) | 0 | `--delay 0.5` |
| `--proxy URL` | Route all HTTP traffic through a proxy (HTTP, HTTPS, SOCKS5) | None | `--proxy socks5://127.0.0.1:9050` |

### Miscellaneous

| Flag | Description |
|------|-------------|
| `-v`, `--verbose` | Show extra diagnostic output (DNS resolution, HTTP status codes, timing) |
| `-q`, `--quiet` | Suppress everything except findings (useful for scripting) |
| `--version` | Print version and exit |
| `-h`, `--help` | Show help message and exit |

`-v` and `-q` are mutually exclusive.

## Modules

WebInspector includes 11 scanner modules. Each module produces findings with severity ratings (Critical, High, Medium, Low, Informational).

| Module | What It Checks |
|--------|----------------|
| `ssl` | Deprecated protocols (SSLv2, SSLv3, TLS 1.0, TLS 1.1), weak and medium-strength ciphers, Heartbleed, ROBOT, CCS injection, TLS compression (CRIME), insecure renegotiation, missing fallback SCSV, early data (0-RTT) |
| `certs` | Self-signed certificates, expired certificates, weak signature algorithms (SHA-1, MD5), weak RSA key sizes (<2048-bit), weak ECC key sizes (<256-bit), hostname mismatch |
| `headers` | Content-Security-Policy analysis, X-Frame-Options, X-Content-Type-Options, Strict-Transport-Security (HSTS), Referrer-Policy, Permissions-Policy, deprecated/removed headers |
| `cookies` | Missing Secure flag, missing HttpOnly flag, missing SameSite attribute, SameSite=None without Secure flag, persistent session cookies |
| `cors` | Origin reflection (reflects arbitrary origins), null origin acceptance, subdomain-based bypass, post-domain bypass patterns |
| `tech` | Technology fingerprinting via webtech library -- identifies CMS platforms, web frameworks, JavaScript libraries, CDNs, analytics tools, and server software |
| `disclosure` | ~90+ information disclosure headers across 8 categories (server identity, framework details, caching internals, debug headers, infrastructure, CDN/proxy, custom application headers, deprecated headers) |
| `https` | HTTP-to-HTTPS redirect behavior, redirect chain analysis, HSTS quality analysis (max-age value, includeSubDomains, preload directives) |
| `files` | robots.txt sensitive path detection, security.txt presence and RFC 9116 validation (required fields, expiry, HTTPS enforcement) |
| `content` | Mixed content (HTTP resources on HTTPS pages), missing Subresource Integrity (SRI), internal IP address disclosure, error page information leakage, sensitive HTML comments |
| `dns` | CAA (Certificate Authority Authorization) records, reverse DNS lookups |

## Input Formats

WebInspector accepts targets in several formats:

| Format | Example | Notes |
|--------|---------|-------|
| Hostname | `example.com` | Scans on default port 443 (or ports specified with `-p`) |
| IP address | `10.0.0.1` | Scans on default port 443 (or ports specified with `-p`) |
| Host:port | `example.com:8443` | Explicit port overrides `-p` |
| Full URL | `https://example.com:8443` | Scheme and port taken from URL |
| CIDR range | `192.168.1.0/24` | Expands to all IPs in the range |
| Target file (`-iL`) | One target per line | Blank lines and `#` comments are ignored |
| Nmap XML (`-x`) | Nmap `-oX` output | Automatically extracts hosts with HTTPS/SSL services |

## Output Formats

### Console (default)

Colored terminal output using the Rich library. Findings are grouped by module and type, with severity-coded colors:

- **Critical** -- bold red
- **High** -- red
- **Medium** -- yellow
- **Low** -- blue
- **Informational** -- grey/dim

### Text file (`-o`)

Plain text report with no ANSI escape codes, suitable for including in pentest reports or emailing to clients.

```bash
webinspector -t example.com -o report.txt
```

### JSON (`--json`)

Structured JSON output for machine consumption, integration with SIEM platforms, or automated report generation.

```bash
webinspector -t example.com --json results.json
```

Example JSON structure:

```json
{
  "scan_info": {
    "version": "1.0.0",
    "timestamp": "2026-02-24T10:30:00Z",
    "targets_scanned": 5,
    "modules_run": ["ssl", "headers"],
    "duration_seconds": 47.2
  },
  "findings": [
    {
      "module": "ssl",
      "finding_type": "deprecated_protocols",
      "severity": "Medium",
      "targets": [
        {
          "host": "10.0.0.1",
          "port": 443,
          "ip": "10.0.0.1",
          "detail": "TLSv1.0, TLSv1.1"
        }
      ],
      "count": 1
    }
  ],
  "failed_targets": [],
  "summary": {
    "total_findings": 7,
    "by_severity": {
      "High": 1,
      "Medium": 4,
      "Low": 1,
      "Informational": 1
    }
  }
}
```

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| sslyze | >= 6.0 | SSL/TLS configuration analysis |
| webtech | >= 1.3 | Web technology fingerprinting |
| requests | >= 2.31 | HTTP requests |
| dnspython | >= 2.4 | DNS record lookups |
| rich | >= 13.0 | Colored terminal output |
| lxml | >= 4.9 | XML/HTML parsing |
| netaddr | >= 0.9 | IP address and CIDR range handling |
| pytest | >= 7.0 | Testing (development only) |

Requires **Python 3.10** or newer.

## Running Tests

```bash
python -m pytest tests/ -v --tb=short
```

## License

Proprietary -- Red Siege Information Security
