"""
webinspector.output - Output formatting and report generation.

This sub-package handles all output rendering, including terminal-friendly
rich console output, plain text file reports, and structured data export
(JSON) suitable for inclusion in penetration testing reports.

Modules:
    - console.py     : Rich-based terminal output with colored severity indicators
    - text.py        : Plain text file output (no ANSI escape codes)
    - json_output.py : Structured JSON export matching the design doc schema

Author: Red Siege Information Security
"""
