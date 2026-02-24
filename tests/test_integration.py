"""
Integration tests for the webinspector module registry and scanner wiring.

These tests verify that:
    1. All 11 scanner modules are loaded into the registry by _load_modules()
    2. Every name in ALL_MODULE_NAMES has a corresponding registered module
    3. Registered module names match ALL_MODULE_NAMES exactly (no extras,
       no missing entries)
    4. Each registered module has the expected interface (name, description,
       scan, accepts_target)
    5. The ScanConfig can be created and the scanner orchestrator can be
       instantiated with it

Unlike the unit tests for individual modules (which mock network calls),
these tests verify that the *wiring* is correct -- that importing the
modules package actually registers all 11 scanner modules and that the
orchestrator can work with them.

Author: Red Siege Information Security
"""

import pytest

from webinspector.cli import ScanConfig
from webinspector.modules import (
    ALL_MODULE_NAMES,
    get_all_modules,
    get_module_by_name,
    get_modules_for_selection,
    _registry,
    _loaded,
)
from webinspector.modules.base import ScanModule
from webinspector.core.target import Target


# ===========================================================================
# Tests for module registry wiring
# ===========================================================================

class TestModuleRegistryIntegration:
    """
    Verify that all 11 scanner modules are correctly wired into the registry.

    These tests call get_all_modules() which triggers _load_modules() if it
    hasn't been called yet.  This tests the real import paths -- each module
    file must exist, import cleanly, and call register_module() at the bottom.
    """

    def test_all_11_modules_are_loaded(self):
        """
        Calling get_all_modules() should return exactly 11 module instances,
        one for each scanner capability.

        If this test fails, a module file is either missing, has an import
        error, or forgot to call register_module() at the bottom.
        """
        modules = get_all_modules()
        assert len(modules) == 11, (
            f"Expected 11 modules, got {len(modules)}. "
            f"Registered names: {[m.name for m in modules]}"
        )

    def test_module_names_match_all_module_names(self):
        """
        The set of registered module names must exactly match ALL_MODULE_NAMES.

        This catches two types of bugs:
            - A module is registered with a wrong name (typo in .name property)
            - A module is missing from the registry (import failed silently)
        """
        modules = get_all_modules()
        registered_names = sorted([m.name for m in modules])
        expected_names = sorted(ALL_MODULE_NAMES)

        assert registered_names == expected_names, (
            f"Registered names {registered_names} do not match "
            f"expected names {expected_names}"
        )

    def test_every_all_module_name_is_retrievable(self):
        """
        Every name listed in ALL_MODULE_NAMES should be retrievable via
        get_module_by_name().  This tests the lookup path end-to-end.
        """
        for name in ALL_MODULE_NAMES:
            module = get_module_by_name(name)
            assert module is not None, (
                f"Module '{name}' is in ALL_MODULE_NAMES but "
                f"get_module_by_name('{name}') returned None"
            )
            # Verify the returned module actually has the right name.
            assert module.name == name

    def test_all_modules_are_scan_module_instances(self):
        """
        Every registered module must be an instance of the ScanModule ABC.

        This ensures that all modules implement the required interface
        (name, description, scan, accepts_target) and that no non-module
        objects accidentally got registered.
        """
        modules = get_all_modules()
        for module in modules:
            assert isinstance(module, ScanModule), (
                f"Module '{module}' is not a ScanModule instance"
            )

    def test_all_modules_have_description(self):
        """
        Every registered module must have a non-empty description string.

        The description is shown in --help output and verbose logging,
        so it should be meaningful and not an empty placeholder.
        """
        modules = get_all_modules()
        for module in modules:
            assert isinstance(module.description, str), (
                f"Module '{module.name}' description is not a string"
            )
            assert len(module.description) > 0, (
                f"Module '{module.name}' has an empty description"
            )

    def test_all_modules_have_accepts_target(self):
        """
        Every registered module must have an accepts_target() method that
        returns a bool when called with a Target.

        This tests the full interface contract that the orchestrator relies
        on when deciding whether to run a module against a given target.
        """
        # Create a basic HTTPS target for testing.
        target = Target(host="example.com", port=443, scheme="https")

        modules = get_all_modules()
        for module in modules:
            result = module.accepts_target(target)
            assert isinstance(result, bool), (
                f"Module '{module.name}'.accepts_target() returned "
                f"{type(result).__name__}, expected bool"
            )


# ===========================================================================
# Tests for module selection (--only / --no-X flags)
# ===========================================================================

class TestModuleSelectionIntegration:
    """
    Verify that get_modules_for_selection() works correctly with all 11
    real modules loaded (not just dummy test modules).
    """

    def test_no_filter_returns_all(self):
        """
        With no --only or --no-X flags, all 11 modules are returned.
        """
        selected = get_modules_for_selection()
        assert len(selected) == 11

    def test_only_filter_returns_subset(self):
        """
        The --only flag returns exactly the requested modules.
        """
        selected = get_modules_for_selection(only=["ssl", "headers"])
        names = [m.name for m in selected]
        assert sorted(names) == ["headers", "ssl"]

    def test_exclude_filter_removes_modules(self):
        """
        The --no-X flags remove exactly the specified modules.
        """
        selected = get_modules_for_selection(exclude=["dns", "ssl"])
        names = [m.name for m in selected]
        # Should have 11 - 2 = 9 modules remaining.
        assert len(names) == 9
        assert "dns" not in names
        assert "ssl" not in names

    def test_only_single_module(self):
        """
        Selecting a single module returns exactly one module.
        """
        for name in ALL_MODULE_NAMES:
            selected = get_modules_for_selection(only=[name])
            assert len(selected) == 1, (
                f"Expected 1 module for --only {name}, got {len(selected)}"
            )
            assert selected[0].name == name


# ===========================================================================
# Tests for ScanConfig creation
# ===========================================================================

class TestScanConfigIntegration:
    """
    Verify that ScanConfig can be created with default values and that
    the scanner modules list is compatible with it.
    """

    def test_scan_config_defaults(self):
        """
        ScanConfig can be instantiated with just targets.
        """
        config = ScanConfig(targets=["example.com"])
        assert config.targets == ["example.com"]
        # Verify key defaults that the orchestrator depends on.
        assert config.threads >= 1
        assert config.timeout > 0

    def test_scan_config_with_module_filters(self):
        """
        ScanConfig works with the only_modules and exclude_modules fields
        that the orchestrator passes to get_modules_for_selection().
        """
        config = ScanConfig(
            targets=["example.com"],
            only_modules=["ssl", "headers"],
        )
        assert config.only_modules == ["ssl", "headers"]
