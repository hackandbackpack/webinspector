"""
Tests for the module base class and registry system.

These tests verify that:
    1. ScanModule ABC cannot be instantiated directly (enforces the contract)
    2. Concrete subclasses work when all abstract methods are implemented
    3. The module registry can store, retrieve, and filter modules
    4. The ALL_MODULE_NAMES constant matches the expected module list

The tests use lightweight DummyModule/DummyModule2 stubs that implement the
required interface without performing any actual scanning, keeping the test
suite fast and free of network dependencies.

Author: Red Siege Information Security
"""
import pytest

from webinspector.modules.base import ScanModule
from webinspector.modules import (
    get_all_modules,
    get_module_by_name,
    get_modules_for_selection,
    register_module,
    ALL_MODULE_NAMES,
    _registry,
)
from webinspector.core.target import Target
from webinspector.core.result import Finding, Severity


# ---------------------------------------------------------------------------
# Concrete test modules — minimal implementations of the ScanModule ABC
# ---------------------------------------------------------------------------

class DummyModule(ScanModule):
    """
    A minimal concrete ScanModule for testing purposes.

    Returns an empty findings list from scan(), which is the "no issues found"
    case.  All abstract methods/properties are implemented with trivial values.
    """

    @property
    def name(self):
        return "dummy"

    @property
    def description(self):
        return "A test module"

    def scan(self, target, http_response=None):
        # No findings — represents a clean target with no issues detected.
        return []


class DummyModule2(ScanModule):
    """
    A second concrete ScanModule for testing multi-module registry scenarios.

    Having two distinct modules lets us verify filtering (only/exclude) and
    lookup-by-name logic.
    """

    @property
    def name(self):
        return "dummy2"

    @property
    def description(self):
        return "Another test module"

    def scan(self, target, http_response=None):
        return []


# ===========================================================================
# Tests for the ScanModule abstract base class
# ===========================================================================

class TestScanModule:
    """
    Verify the ScanModule ABC enforces the contract correctly.
    """

    def test_cannot_instantiate_abc(self):
        """
        ScanModule itself cannot be instantiated.

        Python's ABC machinery raises TypeError when you try to create an
        instance of a class that has unimplemented abstract methods.  This
        ensures every scanner module is forced to implement name, description,
        and scan().
        """
        with pytest.raises(TypeError):
            ScanModule()

    def test_concrete_module_works(self):
        """
        A concrete subclass that implements all abstract methods can be
        instantiated and its properties return the expected values.
        """
        m = DummyModule()
        assert m.name == "dummy"
        assert m.description == "A test module"

    def test_scan_returns_list(self):
        """
        The scan() method must return a list (even if empty).

        This verifies the return type contract that the orchestrator relies
        on when it does ``all_findings.extend(module.scan(target, response))``.
        """
        m = DummyModule()
        # Create a minimal target for the scan call.
        t = Target(host="example.com", port=443, scheme="https")
        result = m.scan(t)
        assert isinstance(result, list)

    def test_accepts_target_default_true(self):
        """
        The default accepts_target() implementation returns True for all
        targets.  Subclasses override this to skip irrelevant targets.
        """
        m = DummyModule()
        t = Target(host="example.com", port=443, scheme="https")
        assert m.accepts_target(t) is True


# ===========================================================================
# Tests for the module registry
# ===========================================================================

class TestModuleRegistry:
    """
    Verify that the registry can store, look up, and filter scanner modules.

    IMPORTANT: Each test that mutates _registry saves and restores the
    original contents to avoid cross-contamination between tests.  The
    registry is a module-level singleton, so mutations persist across tests
    unless explicitly cleaned up.  We save/restore instead of just clearing
    because real modules may have already been loaded by _load_modules()
    and cannot be re-registered after a clear (Python caches imports).

    Author: Red Siege Information Security
    """

    def test_get_all_modules_returns_list(self):
        """get_all_modules() always returns a list, even if empty."""
        modules = get_all_modules()
        assert isinstance(modules, list)

    def test_get_module_by_name_unknown(self):
        """Looking up a name that doesn't exist returns None (not an error)."""
        found = get_module_by_name("nonexistent_module_xyz")
        assert found is None

    def test_register_and_retrieve(self):
        """
        Modules registered via register_module() are retrievable by name
        through get_module_by_name() and appear in get_all_modules().
        """
        # Save the original registry contents so we can restore them after
        # this test.  This prevents wiping out real modules that other tests
        # depend on (e.g., TestSSLScannerRegistration.test_module_registers).
        saved = list(_registry)
        _registry.clear()

        m1 = DummyModule()
        m2 = DummyModule2()
        register_module(m1)
        register_module(m2)

        # Both modules should be in the global list.
        assert len(get_all_modules()) >= 2

        # Both modules should be findable by name.
        assert get_module_by_name("dummy") is not None
        assert get_module_by_name("dummy2") is not None

        # Restore the original registry contents.
        _registry.clear()
        _registry.extend(saved)

    def test_get_modules_for_selection_only(self):
        """
        When 'only' is provided, ONLY modules whose names are in that list
        are returned.  This supports the CLI --only flag.
        """
        # Save and restore the registry around test mutations.
        saved = list(_registry)
        _registry.clear()
        register_module(DummyModule())
        register_module(DummyModule2())

        # Select only "dummy" — should exclude "dummy2".
        selected = get_modules_for_selection(only=["dummy"])
        assert len(selected) == 1
        assert selected[0].name == "dummy"

        # Restore original registry.
        _registry.clear()
        _registry.extend(saved)

    def test_get_modules_for_selection_exclude(self):
        """
        When 'exclude' is provided, all modules EXCEPT those named are
        returned.  This supports the CLI --no-<module> flags.
        """
        # Save and restore the registry around test mutations.
        saved = list(_registry)
        _registry.clear()
        register_module(DummyModule())
        register_module(DummyModule2())

        # Exclude "dummy" — should return only "dummy2".
        selected = get_modules_for_selection(exclude=["dummy"])
        assert len(selected) == 1
        assert selected[0].name == "dummy2"

        # Restore original registry.
        _registry.clear()
        _registry.extend(saved)

    def test_all_module_names_is_list(self):
        """
        ALL_MODULE_NAMES is a list containing exactly 11 module name strings,
        including the core modules 'ssl' and 'headers'.

        This constant defines the canonical set of modules that webinspector
        supports and the order they appear in help text and execution.
        """
        assert isinstance(ALL_MODULE_NAMES, list)
        assert "ssl" in ALL_MODULE_NAMES
        assert "headers" in ALL_MODULE_NAMES
        assert len(ALL_MODULE_NAMES) == 11
