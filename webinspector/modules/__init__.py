"""
webinspector.modules - Module registry: discovers and manages scanner modules.

This sub-package contains one module per scanning capability (SSL, headers,
cookies, CORS, etc.).  Each module implements the ScanModule ABC defined in
base.py so the core scanner orchestrator can invoke them uniformly.

The registry system here provides:
    - A central list of all available modules (ALL_MODULE_NAMES)
    - Functions to register, retrieve, and filter modules at runtime
    - Lazy loading so modules are only imported when first needed

How it works:
    1. Each scanner module file (e.g., ssl_scanner.py) defines a class that
       inherits from ScanModule and implements scan().
    2. When the orchestrator calls get_all_modules() for the first time,
       _load_modules() imports each module file.  Each file calls
       register_module() at the bottom, so the import alone is sufficient.
    3. The CLI uses get_modules_for_selection() to apply --only / --no-<module>
       flags, returning just the modules the user wants to run.

Key public API:
    ALL_MODULE_NAMES            - Canonical list of module name strings
    register_module(instance)   - Add a module instance to the registry
    get_all_modules()           - Get all registered module instances
    get_module_by_name(name)    - Look up a single module by its name string
    get_modules_for_selection() - Filter modules based on CLI flags

Scanner modules (one file each):
    - ssl_scanner.py         : SSL/TLS configuration analysis using sslyze
    - cert_scanner.py        : Certificate chain and expiry checks
    - header_scanner.py      : HTTP security header evaluation
    - cookie_scanner.py      : Cookie security attribute checking
    - cors_scanner.py        : CORS misconfiguration detection
    - tech_scanner.py        : Technology fingerprinting using webtech
    - disclosure_scanner.py  : Information disclosure checks (server headers, etc.)
    - https_scanner.py       : HTTPS enforcement and redirect checks
    - files_scanner.py       : robots.txt, security.txt analysis
    - content_scanner.py     : Content-type, X-Content-Type-Options checks
    - dns_scanner.py         : DNS record and configuration checks

Author: Red Siege Information Security
"""

import logging

# ---------------------------------------------------------------------------
# Module-level logger
# ---------------------------------------------------------------------------
# Used by _load_modules() to report which modules loaded successfully and
# which failed due to missing dependencies (e.g., sslyze not installed).
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Canonical module name list
# ---------------------------------------------------------------------------
# This list defines ALL valid module names in the order they are displayed
# in --help output and the order they execute during a scan.  Adding a new
# module to webinspector means adding its name here first.
#
# The names correspond to the ScanModule.name property on each module class.
# They are short, lowercase, and used as CLI flag values:
#     webinspector --only ssl,headers target.com
#     webinspector --no-cookies target.com
ALL_MODULE_NAMES = [
    "ssl",         # SSL/TLS protocol and cipher suite analysis
    "certs",       # Certificate chain, expiry, and trust checks
    "headers",     # HTTP security headers (CSP, HSTS, X-Frame-Options, etc.)
    "cookies",     # Cookie attributes (Secure, HttpOnly, SameSite)
    "cors",        # Cross-Origin Resource Sharing misconfigurations
    "tech",        # Technology fingerprinting (server software, frameworks)
    "disclosure",  # Information disclosure (stack traces, version strings)
    "https",       # HTTPS enforcement and redirect checks
    "files",       # robots.txt, security.txt, sitemap.xml analysis
    "content",     # Content-type headers and sniffing protections
    "dns",         # DNS record checks (SPF, DMARC, DNSSEC, zone transfer)
]


# ---------------------------------------------------------------------------
# Registry storage (module-level singletons)
# ---------------------------------------------------------------------------

# _registry holds the actual ScanModule instances that have been registered.
# It is populated by register_module() calls, either from _load_modules()
# or from individual module files calling register_module() at import time.
_registry: list = []

# _loaded tracks whether _load_modules() has been called yet.  This flag
# enables lazy loading: we don't import the heavy scanner modules until
# someone actually asks for the module list (typically at scan start time).
_loaded: bool = False


# ---------------------------------------------------------------------------
# Registry functions
# ---------------------------------------------------------------------------

def register_module(module_instance) -> None:
    """
    Register a ScanModule instance in the global registry.

    This is called either by _load_modules() during lazy initialization or
    by individual module files at import time.  Each module instance must
    have a unique .name property — duplicates are silently ignored to support
    safe re-importing.

    Args:
        module_instance: An instance of a ScanModule subclass.  Must have
                         .name, .description, and .scan() implemented.

    Example:
        # In ssl_analyzer.py:
        from webinspector.modules import register_module
        from webinspector.modules.base import ScanModule

        class SSLAnalyzer(ScanModule):
            ...

        register_module(SSLAnalyzer())
    """
    # Check if a module with this name is already registered.
    # This prevents duplicate entries if a module file is imported twice
    # or if _load_modules() and manual registration both fire.
    for existing in _registry:
        if existing.name == module_instance.name:
            # Already registered — skip to avoid duplicates.
            return

    # Add the new module instance to the global registry list.
    _registry.append(module_instance)


def _load_modules() -> None:
    """
    Import all scanner modules, triggering their self-registration.

    Called lazily on first access to get_all_modules().  This deferred import
    pattern has two benefits:

    1. Avoids circular imports -- the registry module can be imported by
       scanner modules that also need to register themselves.
    2. Graceful degradation -- if a module has a missing dependency (e.g.,
       sslyze not installed), only that module fails to load.  The rest
       of the scanner still works.

    Each module file calls register_module() at the bottom of the file, so
    simply importing the file is sufficient to register the module.  Every
    import is wrapped in try/except ImportError so that a missing third-party
    dependency (sslyze, webtech, dnspython, etc.) only disables the one
    module that needs it, not the entire tool.

    Author: Red Siege Information Security
    """
    global _loaded

    # Mark as loaded BEFORE importing to prevent infinite recursion if a
    # module file imports something from this package during its own load.
    _loaded = True

    # ---------------------------------------------------------------
    # SSL/TLS configuration analysis (requires sslyze).
    # Checks for deprecated protocols, weak ciphers, and known
    # vulnerabilities like Heartbleed and ROBOT.
    # ---------------------------------------------------------------
    try:
        from webinspector.modules import ssl_scanner      # noqa: F401
    except ImportError as exc:
        logger.warning("SSL module not available: %s", exc)

    # ---------------------------------------------------------------
    # Certificate chain and expiry checks (requires sslyze).
    # Validates trust chains, expiration dates, signature algorithms,
    # key sizes, and hostname matching.
    # ---------------------------------------------------------------
    try:
        from webinspector.modules import cert_scanner     # noqa: F401
    except ImportError as exc:
        logger.warning("Certificate module not available: %s", exc)

    # ---------------------------------------------------------------
    # HTTP security header evaluation.
    # Checks for CSP, HSTS, X-Frame-Options, X-Content-Type-Options,
    # Referrer-Policy, Permissions-Policy, and more.
    # ---------------------------------------------------------------
    try:
        from webinspector.modules import header_scanner   # noqa: F401
    except ImportError as exc:
        logger.warning("Header module not available: %s", exc)

    # ---------------------------------------------------------------
    # Cookie security attribute checking.
    # Validates Secure, HttpOnly, SameSite, Path, and Domain settings
    # on all cookies returned by the target.
    # ---------------------------------------------------------------
    try:
        from webinspector.modules import cookie_scanner   # noqa: F401
    except ImportError as exc:
        logger.warning("Cookie module not available: %s", exc)

    # ---------------------------------------------------------------
    # CORS misconfiguration detection.
    # Tests for overly permissive Access-Control-Allow-Origin headers,
    # wildcard origins, and credential exposure.
    # ---------------------------------------------------------------
    try:
        from webinspector.modules import cors_scanner     # noqa: F401
    except ImportError as exc:
        logger.warning("CORS module not available: %s", exc)

    # ---------------------------------------------------------------
    # Technology fingerprinting (may require webtech).
    # Identifies server software, frameworks, CMS platforms, and other
    # technologies from response headers and body content.
    # ---------------------------------------------------------------
    try:
        from webinspector.modules import tech_scanner     # noqa: F401
    except ImportError as exc:
        logger.warning("Tech fingerprinting module not available: %s", exc)

    # ---------------------------------------------------------------
    # Information disclosure checks.
    # Detects server version strings, debug headers, stack traces,
    # and other sensitive data leaks in HTTP responses.
    # ---------------------------------------------------------------
    try:
        from webinspector.modules import disclosure_scanner  # noqa: F401
    except ImportError as exc:
        logger.warning("Disclosure module not available: %s", exc)

    # ---------------------------------------------------------------
    # HTTPS enforcement and redirect checks.
    # Verifies that HTTP requests are properly redirected to HTTPS,
    # checks for mixed content issues and HSTS preloading.
    # ---------------------------------------------------------------
    try:
        from webinspector.modules import https_scanner    # noqa: F401
    except ImportError as exc:
        logger.warning("HTTPS enforcement module not available: %s", exc)

    # ---------------------------------------------------------------
    # robots.txt, security.txt, and sitemap.xml analysis.
    # Checks for missing security.txt, overly permissive robots.txt,
    # and information leakage through sitemap files.
    # ---------------------------------------------------------------
    try:
        from webinspector.modules import files_scanner    # noqa: F401
    except ImportError as exc:
        logger.warning("Files module not available: %s", exc)

    # ---------------------------------------------------------------
    # Content-type headers and sniffing protections.
    # Validates Content-Type correctness, X-Content-Type-Options,
    # and content sniffing attack surfaces.
    # ---------------------------------------------------------------
    try:
        from webinspector.modules import content_scanner  # noqa: F401
    except ImportError as exc:
        logger.warning("Content module not available: %s", exc)

    # ---------------------------------------------------------------
    # DNS record and configuration checks (requires dnspython).
    # Examines SPF, DMARC, DNSSEC, MX records, zone transfer
    # vulnerabilities, and other DNS security settings.
    # ---------------------------------------------------------------
    try:
        from webinspector.modules import dns_scanner      # noqa: F401
    except ImportError as exc:
        logger.warning("DNS module not available: %s", exc)

    # Log the final count of successfully loaded modules.
    logger.info(
        "Module registry loaded: %d of %d modules available",
        len(_registry),
        len(ALL_MODULE_NAMES),
    )


def get_all_modules() -> list:
    """
    Get instances of all registered scanner modules.

    On the first call, this triggers _load_modules() which imports all
    scanner module files and populates the registry.  Subsequent calls
    return the cached list directly.

    Returns:
        List of ScanModule subclass instances, in registration order.
        May be empty if no modules have been registered yet (e.g., in
        early development or when all module imports fail).

    Example:
        for module in get_all_modules():
            print(f"{module.name}: {module.description}")
    """
    global _loaded

    # Lazy-load modules on first access.  The _loaded flag ensures we only
    # run the import logic once, even if get_all_modules() is called many times.
    if not _loaded:
        _load_modules()

    # Return a copy of the registry list to prevent callers from accidentally
    # mutating the global state (e.g., list.pop() would remove a module).
    return list(_registry)


def get_module_by_name(name: str):
    """
    Find a module instance by its name string.

    This is used by the CLI to validate --only and --no-<module> arguments
    and by any code that needs to reference a specific module directly.

    Args:
        name: The module name to look up (e.g., "ssl", "headers").
              Must match the .name property of a registered module exactly.

    Returns:
        The ScanModule instance with the matching name, or None if no
        module with that name is registered.

    Example:
        ssl_mod = get_module_by_name("ssl")
        if ssl_mod:
            findings = ssl_mod.scan(target)
    """
    # Ensure modules are loaded before searching.  This handles the case
    # where get_module_by_name() is called before get_all_modules().
    modules = get_all_modules()

    # Linear search through the registry.  With ~11 modules this is
    # effectively O(1) and simpler than maintaining a separate dict.
    for module in modules:
        if module.name == name:
            return module

    # No module with this name found — return None so the caller can
    # decide how to handle it (e.g., print an error, skip, etc.).
    return None


def get_modules_for_selection(only=None, exclude=None) -> list:
    """
    Filter modules based on --only and --no-<module> CLI flags.

    This is the main function the orchestrator calls to determine which
    modules to run for a given scan.  It supports two mutually exclusive
    filtering modes:

    1. Inclusive (--only): Run ONLY the named modules.  Everything else
       is skipped.  Used when the analyst wants to focus on specific checks:
           webinspector --only ssl,headers target.com

    2. Exclusive (--no-X): Run ALL modules EXCEPT the named ones.  Used
       when the analyst wants to skip slow or irrelevant checks:
           webinspector --no-ssl --no-dns target.com

    The CLI parser ensures that --only and --no-X are mutually exclusive,
    so this function doesn't need to handle the case where both are set.

    Args:
        only:    List of module name strings to include.  If provided,
                 ONLY these modules are returned.  Pass None to include all.
        exclude: List of module name strings to exclude.  If provided,
                 all modules EXCEPT these are returned.  Pass None to
                 exclude nothing.

    Returns:
        List of ScanModule instances matching the selection criteria.
        May be empty if the selection filters out everything.

    Examples:
        # Run only SSL and header checks:
        mods = get_modules_for_selection(only=["ssl", "headers"])

        # Run everything except DNS:
        mods = get_modules_for_selection(exclude=["dns"])

        # Run all modules (default):
        mods = get_modules_for_selection()
    """
    # Start with the full list of registered modules.
    modules = get_all_modules()

    # --- Inclusive mode: keep ONLY the specified modules ---
    if only is not None:
        # Filter: keep modules whose .name appears in the 'only' list.
        # We convert 'only' to a set for O(1) membership tests (minor
        # optimization, but good practice).
        only_set = set(only)
        return [m for m in modules if m.name in only_set]

    # --- Exclusive mode: remove the specified modules ---
    if exclude is not None:
        # Filter: keep modules whose .name does NOT appear in the 'exclude' list.
        exclude_set = set(exclude)
        return [m for m in modules if m.name not in exclude_set]

    # --- No filter: return all modules ---
    # Neither --only nor --no-X was specified, so the user wants everything.
    return modules
