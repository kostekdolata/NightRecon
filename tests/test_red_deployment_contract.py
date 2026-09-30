"""Red Night v0.44 deployment-profile contract tests."""

from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
RED_APP_ROOT = ROOT / "packages" / "red-night"
if str(RED_APP_ROOT) not in sys.path:
    sys.path.insert(0, str(RED_APP_ROOT))

from red_night_app.deployment import (  # noqa: E402
    FORBIDDEN_NIGHT_RUNTIME_PREFIXES,
    OTHER_NIGHT_SLUGS,
    RED_COMPOSED_PROFILE,
    RED_DEPLOYMENT_PROFILES,
    RED_LIVE_USB_PROFILE,
    RED_REQUIRED_DISTRIBUTIONS,
    RED_STANDALONE_PROFILE,
    RedDeploymentMode,
    deployment_profile,
    validate_red_deployment_contract,
)


class RedDeploymentContractTests(unittest.TestCase):
    def test_all_profiles_use_the_same_red_package_set(self):
        validate_red_deployment_contract()
        self.assertEqual(
            tuple(item.mode for item in RED_DEPLOYMENT_PROFILES),
            (
                RedDeploymentMode.STANDALONE,
                RedDeploymentMode.COMPOSED,
                RedDeploymentMode.LIVE_USB,
            ),
        )
        for profile in RED_DEPLOYMENT_PROFILES:
            self.assertEqual(
                profile.required_distributions,
                RED_REQUIRED_DISTRIBUTIONS,
            )
            self.assertTrue(profile.offline_capable)
            self.assertEqual(profile.host_disk_policy, "no-automatic-mount")
            self.assertEqual(
                profile.dependency_rule,
                "red-app->red-engine->shared-core",
            )

    def test_standalone_and_live_require_no_peer_night(self):
        self.assertEqual(RED_STANDALONE_PROFILE.optional_peer_nights, ())
        self.assertEqual(RED_LIVE_USB_PROFILE.optional_peer_nights, ())
        self.assertFalse(RED_STANDALONE_PROFILE.bootable_media)
        self.assertTrue(RED_LIVE_USB_PROFILE.bootable_media)
        self.assertEqual(
            RED_LIVE_USB_PROFILE.workspace_modes,
            (
                "secure-workspace",
                "ephemeral-session",
                "recovery-integrity",
            ),
        )

    def test_composed_profile_marks_peers_optional_not_required(self):
        self.assertEqual(
            RED_COMPOSED_PROFILE.optional_peer_nights,
            OTHER_NIGHT_SLUGS,
        )
        self.assertEqual(
            RED_COMPOSED_PROFILE.required_distributions,
            RED_REQUIRED_DISTRIBUTIONS,
        )
        self.assertFalse(RED_COMPOSED_PROFILE.bootable_media)

    def test_profile_lookup_is_deterministic(self):
        self.assertIs(
            deployment_profile("live-usb"),
            RED_LIVE_USB_PROFILE,
        )
        self.assertIs(
            deployment_profile(RedDeploymentMode.COMPOSED),
            RED_COMPOSED_PROFILE,
        )

    def test_red_python_sources_do_not_import_other_night_runtimes(self):
        roots = (
            ROOT / "packages" / "red-night",
            ROOT / "packages" / "red-engine",
        )
        offenders = []
        for source_root in roots:
            for path in source_root.rglob("*.py"):
                text = path.read_text(encoding="utf-8")
                for prefix in FORBIDDEN_NIGHT_RUNTIME_PREFIXES:
                    if prefix in text:
                        offenders.append(f"{path.relative_to(ROOT)}:{prefix}")
        self.assertEqual(offenders, [])

    def test_red_app_dependencies_do_not_require_peer_nights(self):
        pyproject = (
            ROOT / "packages" / "red-night" / "pyproject.toml"
        ).read_text(encoding="utf-8")
        for slug in OTHER_NIGHT_SLUGS:
            self.assertNotIn(f"nightrecon-{slug}-", pyproject)


if __name__ == "__main__":
    unittest.main()
