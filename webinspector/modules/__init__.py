"""
webinspector.modules - Individual security scanning modules.

This sub-package contains one module per scanning capability. Each module
implements a consistent interface so the core scanner can invoke them uniformly.

Planned modules:
    - ssl_analyzer.py: SSL/TLS configuration analysis using sslyze
    - header_analyzer.py: HTTP security header evaluation
    - cookie_analyzer.py: Cookie security attribute checking
    - cors_analyzer.py: CORS misconfiguration detection
    - tech_fingerprint.py: Technology fingerprinting using webtech

Author: Red Siege Information Security
"""
