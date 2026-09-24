"""Tests for NightRecon installed assessment-check discovery."""

import unittest
from unittest.mock import MagicMock, patch

from nightrecon.assessment_engine import (
    AssessmentCheckMetadata,
    CheckIntrusiveness,
)
from nightrecon.check_plugins import discover_installed_checks


class _Check:
    def __init__(self, check_id):
        self.metadata = AssessmentCheckMetadata(
            check_id=check_id,
            name=check_id,
            family="test",
            description="Test plugin check.",
            intrusiveness=CheckIntrusiveness.PASSIVE,
        )

    def run(self, context):
        return ()


class CheckPluginDiscoveryTests(unittest.TestCase):
    def test_installed_entrypoint_check_is_discovered(self):
        entrypoint = MagicMock()
        entrypoint.name = "example"
        entrypoint.load.return_value = _Check(
            "plugin.example"
        )

        entrypoints = MagicMock()
        entrypoints.select.return_value = (
            entrypoint,
        )

        with patch(
            "nightrecon.check_plugins.entry_points",
            return_value=entrypoints,
        ):
            result = discover_installed_checks()

        self.assertEqual(
            tuple(
                check.metadata.check_id
                for check in result.checks
            ),
            ("plugin.example",),
        )
        self.assertEqual(result.errors, ())
        entrypoints.select.assert_called_once_with(
            group="nightrecon.checks"
        )

    def test_plugin_factory_can_return_multiple_checks(self):
        entrypoint = MagicMock()
        entrypoint.name = "pack"
        entrypoint.load.return_value = lambda: (
            _Check("pack.one"),
            _Check("pack.two"),
        )

        entrypoints = MagicMock()
        entrypoints.select.return_value = (
            entrypoint,
        )

        with patch(
            "nightrecon.check_plugins.entry_points",
            return_value=entrypoints,
        ):
            result = discover_installed_checks()

        self.assertEqual(
            tuple(
                check.metadata.check_id
                for check in result.checks
            ),
            ("pack.one", "pack.two"),
        )
        self.assertEqual(result.errors, ())

    def test_plugin_load_failure_is_fail_soft(self):
        good = MagicMock()
        good.name = "good"
        good.load.return_value = _Check(
            "plugin.good"
        )

        bad = MagicMock()
        bad.name = "bad"
        bad.load.side_effect = RuntimeError(
            "broken plugin"
        )

        entrypoints = MagicMock()
        entrypoints.select.return_value = (
            bad,
            good,
        )

        with patch(
            "nightrecon.check_plugins.entry_points",
            return_value=entrypoints,
        ):
            result = discover_installed_checks()

        self.assertEqual(
            tuple(
                check.metadata.check_id
                for check in result.checks
            ),
            ("plugin.good",),
        )
        self.assertEqual(
            result.errors,
            ("bad: broken plugin",),
        )

    def test_invalid_plugin_object_is_reported(self):
        entrypoint = MagicMock()
        entrypoint.name = "invalid"
        entrypoint.load.return_value = object()

        entrypoints = MagicMock()
        entrypoints.select.return_value = (
            entrypoint,
        )

        with patch(
            "nightrecon.check_plugins.entry_points",
            return_value=entrypoints,
        ):
            result = discover_installed_checks()

        self.assertEqual(result.checks, ())
        self.assertEqual(
            result.errors,
            ("invalid: plugin did not provide assessment checks",),
        )


if __name__ == "__main__":
    unittest.main()
