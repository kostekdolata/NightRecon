"""Static acceptance tests for the Red Night v0.44 Batch 2 Live skeleton."""

from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
LIVE_ROOT = ROOT / "live" / "red-night"


class RedLiveBuildSkeletonTests(unittest.TestCase):
    def read(self, relative: str) -> str:
        return (LIVE_ROOT / relative).read_text(encoding="utf-8")

    def test_live_build_targets_trixie_amd64_uefi_hybrid_iso(self):
        config = self.read("auto/config")
        self.assertIn("--architecture amd64", config)
        self.assertIn("--distribution trixie", config)
        self.assertIn("--binary-image iso-hybrid", config)
        self.assertIn('--bootloaders "grub-efi"', config)
        self.assertNotIn("--architectures ", config)
        self.assertNotIn("--binary-images ", config)
        self.assertIn("console=ttyS0,115200n8", config)

    def test_grub_default_entry_has_bounded_autoboot_timeout(self):
        grub = self.read("config/bootloaders/grub-pc/config.cfg")
        self.assertIn("set default=0", grub)
        self.assertIn("set timeout_style=menu", grub)
        self.assertIn("set timeout=3", grub)

    def test_image_stages_only_required_red_wheels(self):
        build = self.read("build-image.sh")
        hook = self.read(
            "config/hooks/live/010-install-red-night.hook.chroot"
        )
        required = (
            "nightrecon_shared_core-*.whl",
            "nightrecon_red_engine-*.whl",
            "nightrecon_red_night-*.whl",
        )
        for pattern in required:
            self.assertIn(pattern, build)
            self.assertIn(pattern, hook)
        for peer in ("white", "blue", "purple", "black"):
            self.assertNotIn(f"nightrecon_{peer}", build.lower())
            self.assertNotIn(f"nightrecon_{peer}", hook.lower())

    def test_batch_two_scripts_do_not_create_persistence_or_touch_host_disks(self):
        paths = (
            "auto/config",
            "build-image.sh",
            "config/hooks/live/010-install-red-night.hook.chroot",
            "config/hooks/live/020-enable-boot-smoke.hook.chroot",
            "config/includes.chroot/usr/local/sbin/red-night-live-boot-smoke",
        )
        combined = "\n".join(self.read(path).lower() for path in paths)
        forbidden = (
            "cryptsetup",
            "luksformat",
            "mkfs.",
            "/dev/sda",
            "/dev/nvme",
            "mount /dev/",
        )
        for token in forbidden:
            self.assertNotIn(token, combined)

    def test_runtime_boot_smoke_is_networkless_and_validates_live_contract(self):
        smoke = self.read("ci/uefi_boot_smoke.sh")
        marker = self.read(
            "config/includes.chroot/usr/local/sbin/red-night-live-boot-smoke"
        )
        self.assertIn("-nic none", smoke)
        self.assertIn("if=pflash", smoke)
        self.assertIn("OVMF_CODE_4M.fd", smoke)
        self.assertIn("OVMF_VARS_4M.fd", smoke)
        self.assertNotIn("-bios", smoke)
        self.assertIn("RED_NIGHT_LIVE_BOOT_OK", smoke)
        self.assertIn("validate_red_deployment_contract", marker)
        self.assertIn("no-automatic-mount", marker)

    def test_batch_three_appliance_service_is_explicit_and_non_root(self):
        install_hook = self.read(
            "config/hooks/live/010-install-red-night.hook.chroot"
        )
        enable_hook = self.read(
            "config/hooks/live/020-enable-boot-smoke.hook.chroot"
        )
        service = self.read(
            "config/includes.chroot/etc/systemd/system/"
            "red-night-live-appliance.service"
        )
        marker = self.read(
            "config/includes.chroot/usr/local/sbin/red-night-live-boot-smoke"
        )

        self.assertIn("red-night-appliance", install_hook)
        self.assertIn(
            "systemctl enable red-night-live-appliance.service",
            enable_hook,
        )
        self.assertIn("User=rednight", service)
        self.assertIn("Group=rednight", service)
        self.assertIn("TTYPath=/dev/tty1", service)
        self.assertIn("StandardInput=tty-force", service)
        self.assertNotIn("User=root", service)
        self.assertIn("systemctl is-active --quiet red-night-live-appliance.service", marker)
        for mode in (
            "secure-workspace",
            "ephemeral-session",
            "recovery-integrity",
        ):
            self.assertIn(f"--mode {mode} --dry-run", marker)
        self.assertIn("authorization_effect", marker)

    def test_live_package_list_contains_only_base_appliance_dependencies(self):
        packages = {
            line.strip()
            for line in self.read(
                "config/package-lists/red-night.list.chroot"
            ).splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        }
        self.assertEqual(
            packages,
            {
                "live-boot",
                "live-config",
                "python3",
                "python3-pip",
                "python3-venv",
                "ca-certificates",
                "iproute2",
                "iputils-ping",
                "network-manager",
            },
        )


if __name__ == "__main__":
    unittest.main()
