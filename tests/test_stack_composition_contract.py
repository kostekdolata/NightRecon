"""NightRecon v0.44 Batch 5 stack-composition contract tests."""

from __future__ import annotations

import json
from pathlib import Path
import sys
import tomllib
import unittest


ROOT = Path(__file__).resolve().parents[1]
SHARED_CORE_ROOT = ROOT / "packages" / "shared-core"
if str(SHARED_CORE_ROOT) not in sys.path:
    sys.path.insert(0, str(SHARED_CORE_ROOT))

from nightrecon_shared_core.composition import (  # noqa: E402
    RED_WHITE_PROFILE,
    SHARED_CORE_DISTRIBUTION,
    composition_profile,
    validate_stack_composition_contract,
)


class StackCompositionContractTests(unittest.TestCase):
    def test_red_white_profile_uses_one_shared_core_and_both_night_package_sets(self):
        self.assertEqual(RED_WHITE_PROFILE.profile_id, "red-white")
        self.assertEqual(RED_WHITE_PROFILE.nights, ("red", "white"))
        self.assertEqual(
            RED_WHITE_PROFILE.required_distributions,
            (
                "nightrecon-shared-core",
                "nightrecon-red-engine",
                "nightrecon-red-night",
                "nightrecon-white-engine",
                "nightrecon-white-night",
            ),
        )
        self.assertEqual(
            RED_WHITE_PROFILE.required_distributions.count(
                SHARED_CORE_DISTRIBUTION
            ),
            1,
        )

    def test_composition_preserves_privilege_and_never_authorizes(self):
        self.assertTrue(RED_WHITE_PROFILE.offline_capable)
        self.assertEqual(
            RED_WHITE_PROFILE.os_privilege_policy,
            "required-platform-privileged",
        )
        self.assertEqual(
            RED_WHITE_PROFILE.host_disk_policy,
            "no-automatic-mount",
        )
        self.assertEqual(RED_WHITE_PROFILE.authorization_effect, "none")
        self.assertFalse(RED_WHITE_PROFILE.direct_night_runtime_dependencies)

    def test_profile_lookup_and_validation_are_deterministic(self):
        self.assertIs(composition_profile("red-white"), RED_WHITE_PROFILE)
        validate_stack_composition_contract()
        with self.assertRaises(ValueError):
            composition_profile("full-stack")

    def test_live_profile_manifest_matches_shared_core_contract(self):
        path = ROOT / "live" / "compositions" / "red-white" / "profile.json"
        payload = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(payload["schema_version"], 1)
        expected = RED_WHITE_PROFILE.to_dict()
        for key, value in expected.items():
            self.assertEqual(payload[key], value)

    def test_red_and_white_packages_do_not_depend_on_each_other(self):
        red_projects = (
            ROOT / "packages" / "red-engine" / "pyproject.toml",
            ROOT / "packages" / "red-night" / "pyproject.toml",
        )
        white_projects = (
            ROOT / "packages" / "white-engine" / "pyproject.toml",
            ROOT / "packages" / "white-night" / "pyproject.toml",
        )

        for path in red_projects:
            data = tomllib.loads(path.read_text(encoding="utf-8"))
            dependencies = "\n".join(data["project"].get("dependencies", ()))
            self.assertNotIn("nightrecon-white", dependencies)

        for path in white_projects:
            data = tomllib.loads(path.read_text(encoding="utf-8"))
            dependencies = "\n".join(data["project"].get("dependencies", ()))
            self.assertNotIn("nightrecon-red", dependencies)

    def test_red_and_white_runtime_sources_have_no_cross_night_imports(self):
        red_roots = (
            ROOT / "packages" / "red-engine",
            ROOT / "packages" / "red-night",
        )
        white_roots = (
            ROOT / "packages" / "white-engine",
            ROOT / "packages" / "white-night",
        )

        for root in red_roots:
            for path in root.rglob("*.py"):
                source = path.read_text(encoding="utf-8")
                self.assertNotIn("nightrecon_white_engine", source, path)
                self.assertNotIn("white_night_app", source, path)

        for root in white_roots:
            for path in root.rglob("*.py"):
                source = path.read_text(encoding="utf-8")
                self.assertNotIn("nightrecon_red_engine", source, path)
                self.assertNotIn("red_night_app", source, path)


if __name__ == "__main__":
    unittest.main()
