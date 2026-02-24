"""
webinspector.core.scanner - Main scanning orchestrator for webinspector.

This module implements the WebInspectorScanner class, which is the heart of
the scanning pipeline.  It coordinates DNS pre-resolution, HTTP fetching,
module execution, and (in future tasks) sslyze TLS scanning across multiple
targets using concurrent threads.

The orchestrator's job is to:
    1. Resolve DNS for all targets (forward lookup for hostnames, reverse
       for IP addresses) so reports can show both hostnames and IPs.
    2. Fetch the HTTP response for each target once, then share it across
       all HTTP-based scanner modules to avoid duplicate requests.
    3. Run all applicable scanner modules against each target, collecting
       Finding objects from each module.
    4. (Future) Run sslyze separately for SSL/cert modules that need raw
       TLS socket access instead of HTTP responses.
    5. Aggregate results into a ScanSummary and return them to the caller.

Concurrency model:
    The scanner uses a ThreadPoolExecutor to scan multiple targets in parallel.
    Each worker thread handles one target at a time: it fetches the HTTP
    response, then runs all HTTP-based modules sequentially against that
    response.  This means:
        - N targets run in parallel (up to config.threads workers)
        - Modules within a single target run sequentially (they share one response)
        - sslyze runs in its own separate phase (it has its own thread pool)

    Thread safety: each worker returns its findings list from the future.
    The main thread collects all results after the executor completes, so
    there is no concurrent mutation of shared state.  Failed targets are
    tracked per-worker and merged in the main thread as well.

Error handling:
    - Per-target: if a target fails (connection error, timeout, DNS failure),
      the error is logged and the scan continues with the next target.
    - Per-module: if a module raises an exception for a target, the error is
      logged and the next module runs.  One buggy module should never crash
      the entire scan.
    - KeyboardInterrupt: if the user presses Ctrl+C, the executor shuts down
      gracefully and partial results are returned so the user still gets
      whatever was collected before the interrupt.

Key public API:
    WebInspectorScanner(config)  - Create a scanner with the given ScanConfig
    scanner.run(targets, modules) - Execute the scan, returns (findings, summary)

Author: Red Siege Information Security
"""

from __future__ import annotations

import logging
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# Import the ScanConfig dataclass that holds all user-supplied CLI options.
from webinspector.cli import ScanConfig

# Import the core data structures this module produces.
from webinspector.core.result import Finding, ScanSummary, Severity

# Import the Target dataclass that represents a single scan endpoint.
from webinspector.core.target import Target

# Import HTTP utilities for creating sessions and fetching URLs.
from webinspector.utils.http import create_http_session, fetch_url

# Import DNS utilities for batch resolution and reverse lookups.
from webinspector.utils.network import batch_resolve_dns, is_ip_address, reverse_dns_lookup

# Import the ScanModule ABC for type hints.
from webinspector.modules.base import ScanModule

# ---------------------------------------------------------------------------
# Rich progress bar — imported conditionally
# ---------------------------------------------------------------------------
# Rich is listed in requirements.txt, but we guard the import with try/except
# so the scanner still works if rich is not installed (e.g., in minimal
# Docker containers or CI environments).  When rich is unavailable, we fall
# back to simple print-based progress reporting.

try:
    from rich.progress import (
        Progress,
        SpinnerColumn,
        BarColumn,
        TextColumn,
        TimeElapsedColumn,
        MofNCompleteColumn,
    )
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False


# ---------------------------------------------------------------------------
# Module-level logger
# ---------------------------------------------------------------------------

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# SSL/cert module names
# ---------------------------------------------------------------------------
# These module names identify the SSL and certificate scanner modules that
# require sslyze (raw TLS socket access) instead of an HTTP response.
# They are handled in a separate scanning phase from the HTTP-based modules.

SSL_MODULE_NAMES = frozenset({"ssl", "certs"})


# ---------------------------------------------------------------------------
# WebInspectorScanner class
# ---------------------------------------------------------------------------

class WebInspectorScanner:
    """
    Main scanning orchestrator.

    Coordinates DNS resolution, HTTP fetching, module execution,
    and sslyze TLS scanning across multiple targets.

    Usage::

        scanner = WebInspectorScanner(config)
        findings, summary = scanner.run(targets, modules)

    The scanner is designed to be instantiated once per scan run.  It creates
    a shared HTTP session (with retry logic, proxy settings, etc.) that all
    worker threads use for their requests.

    Attributes:
        config:         The ScanConfig with all user-supplied options.
        session:        A pre-configured requests.Session shared across threads.
        timeout:        HTTP request timeout from create_http_session.
    """

    def __init__(self, config: ScanConfig):
        """
        Initialize the scanner with the given configuration.

        Creates a shared HTTP session configured with the user's timeout,
        proxy, and retry settings.  The session is thread-safe (requests.Session
        uses urllib3's connection pool which handles thread safety internally).

        Args:
            config: ScanConfig dataclass with all CLI options.
        """
        self.config = config

        # Create a shared HTTP session for all worker threads.
        # create_http_session returns a (session, timeout) tuple.
        self.session, self.timeout = create_http_session(
            timeout=config.timeout,
            proxy=config.proxy,
        )

        # Instance-level accumulators for partial results during HTTP scanning.
        # These are written to by the as_completed() loops in the sub-methods
        # (_run_http_scan_with_progress / _run_http_scan_simple) so that
        # _run_http_scan() can read whatever was collected if a
        # KeyboardInterrupt fires before the sub-method returns.
        self._http_findings: list[Finding] = []
        self._http_failed: list[tuple[Target, str]] = []

    def run(
        self,
        targets: list[Target],
        modules: list[ScanModule],
    ) -> tuple[list[Finding], ScanSummary]:
        """
        Run the full scan pipeline.

        This is the main entry point for a scan.  It performs DNS pre-resolution,
        splits modules into HTTP-based and SSL-based groups, runs the HTTP
        scanning phase with a thread pool, runs the sslyze phase (stub for now),
        and aggregates results into a ScanSummary.

        Args:
            targets: List of Target objects to scan.
            modules: List of ScanModule instances to run against each target.

        Returns:
            A tuple of (findings, summary):
            - findings: List of all Finding objects from all targets and modules.
            - summary:  A ScanSummary with aggregate metrics for the scan.
        """
        start_time = time.time()

        # These lists are populated by the scanning phases below.
        # They are NOT shared across threads — each phase collects results
        # in the main thread after workers complete.
        all_findings: list[Finding] = []
        failed_targets: list[tuple[Target, str]] = []

        # --- Phase 1: DNS pre-resolution ---
        # Resolve hostnames to IPs and do reverse DNS for IP targets.
        # This populates Target.ip and Target.rdns fields used in reports.
        if not self.config.quiet:
            print("[*] Resolving DNS for targets...")
        self._resolve_dns(targets)

        # --- Phase 2: Split modules into HTTP-based and SSL-based ---
        # SSL/cert modules use sslyze's raw TLS socket connections, not HTTP.
        # They are handled in a separate phase with their own concurrency model.
        ssl_modules = [m for m in modules if m.name in SSL_MODULE_NAMES]
        http_modules = [m for m in modules if m.name not in SSL_MODULE_NAMES]

        # --- Phase 3: HTTP-based module scanning with ThreadPoolExecutor ---
        # Each worker thread handles one target: fetch HTTP response, then run
        # all HTTP-based modules against that response sequentially.
        if http_modules:
            http_findings, http_failures = self._run_http_scan(
                targets, http_modules
            )
            all_findings.extend(http_findings)
            failed_targets.extend(http_failures)
        elif not ssl_modules:
            # No modules at all — nothing to do.  This happens when all modules
            # have been filtered out via --only/--no, or when no modules are
            # registered yet (early development).
            logger.info("No scanner modules to run")

        # --- Phase 4: sslyze scanning for SSL/cert modules ---
        # This is a separate phase because sslyze manages its own thread pool
        # and uses raw TLS connections instead of HTTP.
        if ssl_modules:
            ssl_findings = self._scan_sslyze(targets, ssl_modules)
            all_findings.extend(ssl_findings)

        # --- Phase 5: Calculate summary ---
        duration = time.time() - start_time

        # Count findings by severity for the summary.
        findings_by_severity: dict[str, int] = {}
        for severity in Severity:
            count = sum(
                1 for f in all_findings if f.severity == severity
            )
            if count > 0:
                findings_by_severity[severity.value] = count

        # A target is "successful" if it did NOT appear in the failed list.
        # Note: a target can be in the failed list (HTTP error) but still
        # produce sslyze findings.  For simplicity, we count HTTP failures
        # as the "failed" count since that's the primary scanning path.
        failed_hosts = set()
        for target, _error in failed_targets:
            failed_hosts.add((target.scheme, target.host, target.port))

        num_failed = len(failed_hosts)
        num_successful = len(targets) - num_failed

        summary = ScanSummary(
            total_targets=len(targets),
            successful=num_successful,
            failed=num_failed,
            duration_seconds=round(duration, 2),
            findings_by_severity=findings_by_severity,
            failed_targets=failed_targets,
        )

        return all_findings, summary

    # -----------------------------------------------------------------
    # DNS resolution
    # -----------------------------------------------------------------

    def _resolve_dns(self, targets: list[Target]) -> None:
        """
        Batch DNS resolution + reverse DNS for IP targets.

        For hostname targets:
            Performs forward DNS lookups (hostname -> IP address) and stores
            the result in target.ip.  This gives reports the IP for each
            hostname, enabling numeric sorting and network context.

        For IP-address targets:
            Performs reverse DNS lookups (IP -> hostname) and stores the
            result in target.rdns.  This gives analysts the server name
            associated with each IP address.

        All DNS errors are handled gracefully — a failed lookup simply
        leaves the target.ip or target.rdns as None.

        Args:
            targets: List of Target objects to resolve.  Modified in place.
        """
        # Collect unique hostnames that need forward DNS resolution.
        # We skip IP addresses — they don't need forward resolution.
        hostnames_to_resolve: list[str] = []
        ip_targets: list[Target] = []

        for target in targets:
            if is_ip_address(target.host):
                # This target is already an IP — needs reverse DNS instead.
                ip_targets.append(target)
            else:
                # This target is a hostname — needs forward DNS.
                hostnames_to_resolve.append(target.host)

        # Deduplicate hostnames before batch resolution.
        # Multiple targets can share the same hostname (different ports/schemes).
        unique_hostnames = list(set(hostnames_to_resolve))

        # --- Forward DNS: hostname -> IP ---
        if unique_hostnames:
            logger.info(
                "Resolving %d unique hostnames...", len(unique_hostnames)
            )
            dns_results = batch_resolve_dns(unique_hostnames)

            # Apply resolved IPs to all targets that share each hostname.
            for target in targets:
                if not is_ip_address(target.host) and target.host in dns_results:
                    target.ip = dns_results[target.host]

        # --- Reverse DNS: IP -> hostname ---
        # Deduplicate IPs before doing reverse lookups.
        unique_ips = list(set(t.host for t in ip_targets))
        if unique_ips:
            logger.info(
                "Performing reverse DNS for %d unique IPs...", len(unique_ips)
            )
            rdns_results: dict[str, str | None] = {}
            for ip in unique_ips:
                rdns_results[ip] = reverse_dns_lookup(ip)

            # Apply reverse DNS results to all targets that share each IP.
            for target in ip_targets:
                if target.host in rdns_results:
                    target.rdns = rdns_results[target.host]
                    # Also set target.ip to the host itself for consistency,
                    # so that target.ip is always populated for IP targets.
                    target.ip = target.host

    # -----------------------------------------------------------------
    # HTTP-based scanning
    # -----------------------------------------------------------------

    def _run_http_scan(
        self,
        targets: list[Target],
        modules: list[ScanModule],
    ) -> tuple[list[Finding], list[tuple[Target, str]]]:
        """
        Run all HTTP-based modules against all targets using a thread pool.

        Each worker thread processes one target at a time:
            1. Fetch the HTTP response (one GET request per target)
            2. Run all HTTP modules sequentially against that response
            3. Return the findings list and any failure info

        The main thread collects results from all workers after they complete.

        Uses Rich progress bars when available, falls back to simple print
        statements otherwise.

        Args:
            targets: List of Target objects to scan.
            modules: List of HTTP-based ScanModule instances.

        Returns:
            A tuple of (findings, failed_targets):
            - findings: All Finding objects from all targets.
            - failed_targets: List of (Target, error_message) for failures.
        """
        # Reset the instance-level accumulators so that each call to
        # _run_http_scan starts fresh.  The sub-methods append to these
        # lists as each future completes, which allows the KeyboardInterrupt
        # handler below to read partial results even though the sub-method
        # was interrupted before it could return.
        self._http_findings = []
        self._http_failed = []

        # Determine whether to show progress bars.
        show_progress = not self.config.quiet and RICH_AVAILABLE

        try:
            if show_progress:
                # Use Rich progress bars for a polished scanning experience.
                self._run_http_scan_with_progress(targets, modules)
            else:
                # Fallback: simple output without Rich.
                self._run_http_scan_simple(targets, modules)

        except KeyboardInterrupt:
            # Graceful shutdown on Ctrl+C.
            # The user wants to stop the scan, but we should still output
            # whatever partial results we've collected so far.
            print(
                "\n[!] Scan interrupted by user. Outputting partial results...",
                file=sys.stderr,
            )
            logger.warning("Scan interrupted by user (KeyboardInterrupt)")
            # self._http_findings and self._http_failed already contain
            # results from futures that completed before the interrupt.

        return self._http_findings, self._http_failed

    def _run_http_scan_with_progress(
        self,
        targets: list[Target],
        modules: list[ScanModule],
    ) -> None:
        """
        HTTP scanning phase with Rich progress bar integration.

        Creates a Rich Progress context that shows a live progress bar
        as targets are scanned.  Each completed target advances the bar.

        Results are appended to ``self._http_findings`` and
        ``self._http_failed`` as each future completes, so that partial
        results are available if a KeyboardInterrupt is raised.

        Args:
            targets: Targets to scan.
            modules: HTTP-based modules to run.
        """
        # Build the Rich progress bar with informative columns.
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            transient=False,  # Keep the progress bar visible after completion
        ) as progress:
            # Create a progress task to track scanning completion.
            scan_task = progress.add_task(
                "Scanning targets...", total=len(targets)
            )

            # Submit all targets to the thread pool.
            with ThreadPoolExecutor(
                max_workers=self.config.threads
            ) as executor:
                # Map futures back to their targets for error reporting.
                future_to_target = {}
                for target in targets:
                    future = executor.submit(
                        self._scan_target_http, target, modules
                    )
                    future_to_target[future] = target

                # Collect results as they complete (in any order).
                # as_completed yields futures as they finish, which lets us
                # update the progress bar in real time.
                for future in as_completed(future_to_target):
                    target = future_to_target[future]
                    try:
                        findings, failure = future.result()
                        self._http_findings.extend(findings)
                        if failure is not None:
                            self._http_failed.append(failure)
                    except Exception as exc:
                        # Unexpected exception from the worker thread.
                        # This should not happen because _scan_target_http
                        # catches all exceptions internally, but we handle
                        # it defensively just in case.
                        error_msg = f"Unexpected error: {exc}"
                        self._http_failed.append((target, error_msg))
                        logger.error(
                            "Unexpected error scanning %s: %s",
                            target.display, exc,
                        )
                    finally:
                        # Always advance the progress bar, even on failure.
                        progress.advance(scan_task)

    def _run_http_scan_simple(
        self,
        targets: list[Target],
        modules: list[ScanModule],
    ) -> None:
        """
        HTTP scanning phase without Rich (simple print-based progress).

        Used when Rich is not installed or when running in quiet mode.
        Falls back to printing a dot per completed target for minimal
        progress indication.

        Results are appended to ``self._http_findings`` and
        ``self._http_failed`` as each future completes, so that partial
        results are available if a KeyboardInterrupt is raised.

        Args:
            targets: Targets to scan.
            modules: HTTP-based modules to run.
        """
        completed = 0

        with ThreadPoolExecutor(
            max_workers=self.config.threads
        ) as executor:
            future_to_target = {}
            for target in targets:
                future = executor.submit(
                    self._scan_target_http, target, modules
                )
                future_to_target[future] = target

            for future in as_completed(future_to_target):
                target = future_to_target[future]
                try:
                    findings, failure = future.result()
                    self._http_findings.extend(findings)
                    if failure is not None:
                        self._http_failed.append(failure)
                except Exception as exc:
                    error_msg = f"Unexpected error: {exc}"
                    self._http_failed.append((target, error_msg))
                    logger.error(
                        "Unexpected error scanning %s: %s",
                        target.display, exc,
                    )
                finally:
                    completed += 1
                    # Print minimal progress for non-quiet, non-rich mode.
                    if not self.config.quiet:
                        print(
                            f"\r[*] Scanned {completed}/{len(targets)} targets",
                            end="",
                            flush=True,
                        )

        # Print newline after the progress counter.
        if not self.config.quiet:
            print()

    def _scan_target_http(
        self,
        target: Target,
        modules: list[ScanModule],
    ) -> tuple[list[Finding], tuple[Target, str] | None]:
        """
        Scan a single target with all HTTP-based modules.

        This is the worker function submitted to the ThreadPoolExecutor.
        It runs in a worker thread and must be thread-safe.

        The function:
            1. Fetches the HTTP response for the target (one GET request).
            2. Iterates through all HTTP modules, running each one against
               the response.
            3. Returns the collected findings and any failure info.

        Per-module error handling:
            If a module raises an exception, the error is logged and the
            scan continues with the next module.  One buggy module should
            never prevent other modules from running.

        Args:
            target:  The Target to scan.
            modules: List of HTTP-based ScanModule instances.

        Returns:
            A tuple of (findings, failure):
            - findings: List of Finding objects from all modules.
            - failure:  A (Target, error_message) tuple if the HTTP fetch
                        failed, or None if the fetch succeeded.
        """
        findings: list[Finding] = []

        # --- Step 1: Fetch the HTTP response ---
        # One GET request per target, shared across all modules.
        logger.debug("Fetching %s", target.url)
        response, error = fetch_url(self.session, target.url, self.timeout)

        if error:
            # HTTP fetch failed — log it and return the failure.
            # We still return an empty findings list (not None) so the caller
            # can always extend() without checking.
            logger.info(
                "Failed to fetch %s: %s", target.display, error
            )
            return findings, (target, error)

        # --- Step 2: Run all HTTP modules against the response ---
        for module in modules:
            # Check if this module wants to scan this target.
            # Some modules skip targets based on scheme (e.g., HTTPS-only).
            if not module.accepts_target(target):
                logger.debug(
                    "Module '%s' skipped target %s (accepts_target=False)",
                    module.name, target.display,
                )
                continue

            try:
                # Run the module's scan method with the pre-fetched response.
                module_findings = module.scan(target, response)
                findings.extend(module_findings)

                if module_findings:
                    logger.debug(
                        "Module '%s' found %d findings for %s",
                        module.name, len(module_findings), target.display,
                    )
            except Exception as exc:
                # Per-module error handling: log and continue.
                # This catches any unexpected exception from a scanner module.
                # We log the full exception for debugging but don't crash.
                logger.warning(
                    "Module '%s' raised an exception for %s: %s",
                    module.name, target.display, exc,
                )

        return findings, None

    # -----------------------------------------------------------------
    # sslyze scanning (stub for future Tasks 8-9)
    # -----------------------------------------------------------------

    def _scan_sslyze(
        self,
        targets: list[Target],
        ssl_modules: list[ScanModule],
    ) -> list[Finding]:
        """
        Run sslyze Scanner for SSL/cert modules.

        This method handles the separate sslyze scanning phase for modules
        that need raw TLS socket connections (ssl_analyzer, cert_analyzer)
        instead of HTTP responses.

        sslyze has its own internal thread pool and connection management,
        so we don't wrap it in our ThreadPoolExecutor.  Instead, we:
            1. Filter targets to HTTPS-only (SSL scanning on HTTP is meaningless)
            2. Queue all HTTPS targets as sslyze ServerScanRequests
            3. Collect results via sslyze's scanner.get_results() generator
            4. Pass each result to the SSL/cert modules for analysis

        NOTE: This is currently a stub.  The full sslyze integration will be
        implemented in Tasks 8 (SSL scanner) and 9 (Certificate scanner).
        The structure is in place so those tasks just need to fill in the
        sslyze-specific code.

        Args:
            targets:     All targets (will be filtered to HTTPS only).
            ssl_modules: The SSL/cert ScanModule instances.

        Returns:
            List of Finding objects from SSL/cert analysis.
            Currently returns an empty list (stub).
        """
        # Filter to HTTPS targets only — SSL scanning on HTTP makes no sense.
        https_targets = [t for t in targets if t.scheme == "https"]

        if not https_targets:
            logger.info("No HTTPS targets for SSL/cert scanning")
            return []

        logger.info(
            "SSL/cert scanning: %d HTTPS targets, %d modules (stub — not yet implemented)",
            len(https_targets),
            len(ssl_modules),
        )

        # ---------------------------------------------------------------
        # TODO (Tasks 8-9): Implement sslyze integration here.
        #
        # The implementation will look approximately like this:
        #
        #   try:
        #       from sslyze import (
        #           Scanner,
        #           ServerScanRequest,
        #           ServerNetworkLocation,
        #           ScanCommand,
        #       )
        #   except ImportError:
        #       logger.warning("sslyze not installed — skipping SSL/cert scanning")
        #       return []
        #
        #   scanner = Scanner()
        #   for target in https_targets:
        #       location = ServerNetworkLocation(
        #           hostname=target.host, port=target.port
        #       )
        #       request = ServerScanRequest(
        #           server_location=location,
        #           scan_commands={
        #               ScanCommand.SSL_2_0_CIPHER_SUITES,
        #               ScanCommand.SSL_3_0_CIPHER_SUITES,
        #               ScanCommand.TLS_1_0_CIPHER_SUITES,
        #               ScanCommand.TLS_1_1_CIPHER_SUITES,
        #               ScanCommand.TLS_1_2_CIPHER_SUITES,
        #               ScanCommand.TLS_1_3_CIPHER_SUITES,
        #               ScanCommand.CERTIFICATE_INFO,
        #               ScanCommand.HEARTBLEED,
        #           },
        #       )
        #       scanner.queue_scans([request])
        #
        #   findings = []
        #   for result in scanner.get_results():
        #       for module in ssl_modules:
        #           if module.accepts_target(target):
        #               findings.extend(module.scan(target, sslyze_result=result))
        #
        #   return findings
        # ---------------------------------------------------------------

        return []
