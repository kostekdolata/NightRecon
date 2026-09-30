"""Red Night v0.44 Batch 2 Live build skeleton source tests."""

from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
LIVE = ROOT / "live" / "red-night"


class RedLiveBuildSkeletonTests(unittest.TestCase):
    def test_source_controlled_live_build_shape_exists(self):
        required = (
            "auto/config",
            "auto/build",
            "auto/clean",
            "config/package-lists/red-night.list.chroot",
            "config/hooks/live/0100-install-red-night.hook.chroot",
            "config/hooks/live/0900-serial-grub.hook.binary",
            "config/includes.chroot/etc/systemd/system/red-night-live-smoke.service",
            "config/includes.chroot/usr/local/sbin/red-night-live-boot-smoke",
            "build.sh",
            "tests/uefi_boot_smoke.sh",
            "tests/artifact_smoke.py",
            "README.md",
        )
        for relative in required:
            with self.subTest(relative=relative):
                self.assertTrue((LIVE / relative).is_file())

    def test_live_build_is_amd64_uefi_trixie_and_no_persistence(self):
        config = (LIVE / "auto" / "config").read_text(encoding="utf-8")
        for required in (
            "--architecture amd64",
            "--distribution trixie",
            "--binary-image iso-hybrid",
            "--bootloaders grub-efi",
            "--uefi-secure-boot disable",
            "console=ttyS0,115200n8",
        ):
            self.assertIn(required, config)
        self.assertNotIn("persistence", config.lower())

    def test_headless_uefi_grub_is_serial_and_noninteractive(self):
        grub_hook = (
            LIVE / "config" / "hooks" / "live" /
            "0900-serial-grub.hook.binary"
        ).read_text(encoding="utf-8")
        self.assertIn("set timeout=0", grub_hook)
        self.assertIn("terminal_input serial", grub_hook)
        self.assertIn("terminal_output serial", grub_hook)
        self.assertIn("linux /live/vmlinuz", grub_hook)
        self.assertIn("initrd /live/initrd.img", grub_hook)
        self.assertIn("console=ttyS0,115200n8", grub_hook)

    def test_image_installs_built_red_wheels_offline(self):
        build = (LIVE / "build.sh").read_text(encoding="utf-8")
        hook = (
            LIVE / "config" / "hooks" / "live" /
            "0100-install-red-night.hook.chroot"
        ).read_text(encoding="utf-8")

        for package_path in (
            "packages/shared-core",
            "packages/red-engine",
            "packages/red-night",
        ):
            self.assertIn(package_path, build)
        self.assertIn("--python-version 3.13", build)
        self.assertIn("cryptography>=50.0.1,<51", build)
        self.assertIn("WHEELHOUSE.sha256", build)

        self.assertIn("--no-index", hook)
        self.assertIn("--find-links=", hook)
        self.assertIn("nightrecon-shared-core==", hook)
        self.assertIn("nightrecon-red-engine==", hook)
        self.assertIn("nightrecon-red-night==", hook)
        self.assertIn("pip check", hook)
        self.assertNotIn("curl ", hook)
        self.assertNotIn("wget ", hook)

    def test_boot_smoke_is_non_networked_and_validates_guest_marker(self):
        smoke = (
            LIVE / "tests" / "uefi_boot_smoke.sh"
        ).read_text(encoding="utf-8")
        marker = (
            LIVE / "config" / "includes.chroot" / "usr" / "local" /
            "sbin" / "red-night-live-boot-smoke"
        ).read_text(encoding="utf-8")

        self.assertIn("OVMF", smoke)
        self.assertIn("qemu-system-x86_64", smoke)
        self.assertIn("-nic none", smoke)
        self.assertIn("RED_NIGHT_LIVE_BOOT_OK", smoke)
        self.assertIn("validate_red_deployment_contract", marker)
        self.assertIn("red-night-app --help", marker)

    def test_batch2_does_not_define_encrypted_or_host_disk_setup(self):
        texts = "\n".join(
            path.read_text(encoding="utf-8")
            for path in LIVE.rglob("*")
            if path.is_file()
        ).lower()
        self.assertNotIn("cryptsetup luksformat", texts)
        self.assertNotIn("mount /dev/sd", texts)
        self.assertNotIn("mkfs.", texts)


if __name__ == "__main__":
    unittest.main()
