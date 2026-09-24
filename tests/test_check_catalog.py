"""Tests for the combined NightRecon assessment-check catalog."""

import unittest
from unittest.mock import patch

from nightrecon.assessment_engine import (
    AssessmentCheckMetadata,
    CheckIntrusiveness,
)
from nightrecon.check_catalog import load_check_catalog
from nightrecon.check_plugins import CheckDiscoveryResult


class _Check:
    def __init__(self, check_id):
        self.metadata = AssessmentCheckMetadata(
            check_id=check_id,
            name=check_id,
            family="test",
            description="Test check.",
            intrusiveness=CheckIntrusiveness.PASSIVE,
        )

    def run(self, context):
        return ()


class CheckCatalogTests(unittest.TestCase):
    def test_catalog_combines_builtin_and_installed_checks(self):
        with patch(
            "nightrecon.check_catalog.builtin_checks",
            return_value=(
                _Check("builtin.one"),
            ),
        ):
            with patch(
                "nightrecon.check_catalog.discover_installed_checks",
                return_value=CheckDiscoveryResult(
                    checks=(
                        _Check("plugin.one"),
                    ),
                ),
            ):
                result = load_check_catalog()

        self.assertEqual(
            tuple(
                check.metadata.check_id
                for check in result.checks
            ),
            (
                "builtin.one",
                "plugin.one",
            ),
        )
        self.assertEqual(result.errors, ())

    def test_builtin_check_wins_duplicate_id(self):
        with patch(
            "nightrecon.check_catalog.builtin_checks",
            return_value=(
                _Check("shared.id"),
            ),
        ):
            with patch(
                "nightrecon.check_catalog.discover_installed_checks",
                return_value=CheckDiscoveryResult(
                    checks=(
                        _Check("shared.id"),
                    ),
                ),
            ):
                result = load_check_catalog()

        self.assertEqual(
            tuple(
                check.metadata.check_id
                for check in result.checks
            ),
            ("shared.id",),
        )
        self.assertEqual(
            result.errors,
            (
                "Duplicate assessment check id: shared.id",
            ),
        )

    def test_catalog_preserves_plugin_discovery_errors(self):
        with patch(
            "nightrecon.check_catalog.builtin_checks",
            return_value=(),
        ):
            with patch(
                "nightrecon.check_catalog.discover_installed_checks",
                return_value=CheckDiscoveryResult(
                    checks=(),
                    errors=("broken: failed",),
                ),
            ):
                result = load_check_catalog()

        self.assertEqual(result.checks, ())
        self.assertEqual(
            result.errors,
            ("broken: failed",),
        )


if __name__ == "__main__":
    unittest.main()
