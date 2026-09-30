"""Static safety and deployment-contract tests for White Night Live Batch 1."""

from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
LIVE = ROOT / "live" / "white-night"


class WhiteLiveBuildTests(unittest.TestCase):
    def test_batch_one_files_exist(self) -> None:
        required = (
            LIVE / "README.md",
            LIVE / "auto" / "config",
            LIVE / "build.sh",
            LIVE / "config" / "package-lists" / "white-night.list.chroot",
            LIVE
            / "config"
            / "includes.chroot"
            / "etc"
            / "systemd"
            / "system"
            / "white-night-live-readiness.service",
            LIVE
            / "config"
            / "includes.chroot"
            / "usr"
            / "local"
            / "sbin"
            / "white-night-live-readiness",
            LIVE
            / "config"
            / "hooks"
            / "live"
            / "0100-enable-white-readiness.hook.chroot",
            ROOT / "tests" / "white_live_vm_smoke.sh",
        )
        self.assertTrue(all(path.is_file() for path in required))

    def test_live_build_is_amd64_uefi_debian_trixie(self) -> None:
        config = (LIVE / "auto" / "config").read_text(encoding="utf-8")
        self.assertIn("--mode debian", config)
        self.assertIn("--distribution trixie", config)
        self.assertIn("--architecture amd64", config)
        self.assertIn("--binary-image iso-hybrid", config)
        self.assertIn("--bootloaders grub-efi", config)
        self.assertIn("--debian-installer none", config)
        self.assertIn("--uefi-secure-boot disable", config)
        self.assertIn("console=ttyS0,115200n8", config)

    def test_image_stages_exact_current_white_package_artifacts(self) -> None:
        build = (LIVE / "build.sh").read_text(encoding="utf-8")
        readiness = (
            LIVE
            / "config"
            / "includes.chroot"
            / "usr"
            / "local"
            / "sbin"
            / "white-night-live-readiness"
        ).read_text(encoding="utf-8")
        for expected in (
            "nightrecon_shared_core-0.43.0-*.whl",
            "nightrecon_white_engine-0.1.0a6-*.whl",
            "nightrecon_white_night-0.1.0a6-*.whl",
        ):
            self.assertIn(expected, readiness)
        self.assertIn("SHARED_CORE_VERSION=0.43.0", build)
        self.assertIn("WHITE_VERSION=0.1.0a6", build)
        self.assertNotIn("packages/white-engine/nightrecon_white_engine", build)
        self.assertNotIn("packages/white-night/white_night_app", build)

    def test_batch_one_does_not_claim_later_live_capabilities(self) -> None:
        combined = "\n".join(
            path.read_text(encoding="utf-8")
            for path in (
                LIVE / "auto" / "config",
                LIVE / "build.sh",
                LIVE
                / "config"
                / "includes.chroot"
                / "usr"
                / "local"
                / "sbin"
                / "white-night-live-readiness",
            )
        ).lower()
        for forbidden in (
            "cryptsetup",
            "luksformat",
            "mount /dev/",
            "white-night-app",
            "secure boot enabled",
        ):
            self.assertNotIn(forbidden, combined)

    def test_vm_smoke_is_uefi_and_has_no_network_interface(self) -> None:
        smoke = (ROOT / "tests" / "white_live_vm_smoke.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("OVMF_CODE", smoke)
        self.assertIn("-nic none", smoke)
        self.assertIn("WHITE_NIGHT_LIVE_BOOT_OK", smoke)
        self.assertNotIn("-net user", smoke)
        self.assertNotIn("-nic user", smoke)

    def test_profile_is_non_authoritative_and_nonpersistent(self) -> None:
        profile = (
            LIVE
            / "config"
            / "includes.chroot"
            / "etc"
            / "nightrecon-live-profile.json"
        ).read_text(encoding="utf-8")
        self.assertIn('"authorization_effect": "none"', profile)
        self.assertIn('"host_disk_policy": "no-automatic-mount"', profile)
        self.assertIn('"persistence": false', profile)
        self.assertIn('"application_auto_launch": false', profile)


if __name__ == "__main__":
    unittest.main()
