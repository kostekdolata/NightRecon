"""Static safety and deployment-contract tests for White Night Live Batch 3."""

from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
LIVE = ROOT / "live" / "white-night"


class WhiteLiveBuildTests(unittest.TestCase):
    def read(self, relative: str) -> str:
        return (LIVE / relative).read_text(encoding="utf-8")

    def test_live_files_exist(self) -> None:
        required = (
            LIVE / "README.md",
            LIVE / "auto" / "config",
            LIVE / "build.sh",
            LIVE / "config" / "package-lists" / "white-night.list.chroot",
            LIVE / "config" / "bootloaders" / "grub-pc" / "config.cfg",
            LIVE / "config" / "bootloaders" / "grub-pc" / "grub.cfg",
            LIVE / "config" / "hooks" / "live" / "0100-enable-white-readiness.hook.chroot",
            LIVE / "config" / "hooks" / "live" / "0200-install-white-runtime.hook.chroot",
            LIVE / "config" / "hooks" / "live" / "0300-enable-white-app.hook.chroot",
            LIVE / "config" / "hooks" / "live" / "0400-enable-white-mode.hook.chroot",
            LIVE / "config" / "includes.chroot" / "etc" / "systemd" / "system" / "white-night-live-readiness.service",
            LIVE / "config" / "includes.chroot" / "etc" / "systemd" / "system" / "white-night-live-app.service",
            LIVE / "config" / "includes.chroot" / "etc" / "systemd" / "system" / "white-night-live-mode.service",
            LIVE / "config" / "includes.chroot" / "usr" / "local" / "sbin" / "white-night-live-readiness",
            LIVE / "config" / "includes.chroot" / "usr" / "local" / "sbin" / "white-night-live-app-start",
            LIVE / "config" / "includes.chroot" / "usr" / "local" / "sbin" / "white-night-live-mode-select",
            ROOT / "tests" / "white_live_vm_smoke.sh",
            ROOT / "tests" / "test_white_live_modes.py",
        )
        self.assertTrue(all(path.is_file() for path in required))

    def test_live_build_is_amd64_uefi_debian_trixie(self) -> None:
        config = self.read("auto/config")
        self.assertIn("--mode debian", config)
        self.assertIn("--distribution trixie", config)
        self.assertIn("--architecture amd64", config)
        self.assertIn("--binary-image iso-hybrid", config)
        self.assertIn("--bootloaders grub-efi", config)
        self.assertIn("--debian-installer none", config)
        self.assertIn("--uefi-secure-boot auto", config)
        self.assertIn("console=ttyS0,115200n8", config)

    def test_image_installs_exact_white_package_artifacts(self) -> None:
        build = self.read("build.sh")
        install = self.read(
            "config/hooks/live/0200-install-white-runtime.hook.chroot"
        )
        readiness = self.read(
            "config/includes.chroot/usr/local/sbin/white-night-live-readiness"
        )
        expected_wheels = (
            "nightrecon_shared_core-0.43.0-*.whl",
            "nightrecon_white_engine-0.1.0a6-*.whl",
            "nightrecon_white_night-0.1.0a6-*.whl",
        )
        for expected in expected_wheels:
            self.assertIn(expected, install)
            self.assertIn(expected, readiness)
        self.assertIn("SHARED_CORE_VERSION=0.43.0", build)
        self.assertIn("WHITE_VERSION=0.1.0a6", build)
        self.assertIn("venv_dir=/opt/nightrecon/venv", install)
        self.assertIn("--no-index", install)
        self.assertIn("--no-deps", install)
        self.assertNotIn("packages/white-engine/nightrecon_white_engine", build)
        self.assertNotIn("packages/white-night/white_night_app", build)

    def test_installed_runtime_has_no_peer_night_dependency(self) -> None:
        install = self.read(
            "config/hooks/live/0200-install-white-runtime.hook.chroot"
        ).lower()
        self.assertIn('find_spec("nightrecon_red_engine") is none', install)
        for peer in (
            "nightrecon_blue",
            "nightrecon_purple",
            "nightrecon_black",
        ):
            self.assertNotIn(peer, install)

    def test_batch_three_still_does_not_create_persistence_or_touch_host_disks(self) -> None:
        paths = (
            "auto/config",
            "build.sh",
            "config/hooks/live/0200-install-white-runtime.hook.chroot",
            "config/includes.chroot/usr/local/sbin/white-night-live-mode-select",
            "config/includes.chroot/usr/local/sbin/white-night-live-app-start",
            "config/includes.chroot/usr/local/sbin/white-night-live-readiness",
        )
        combined = "\n".join(self.read(path).lower() for path in paths)
        for forbidden in (
            "cryptsetup",
            "luksformat",
            "mkfs.",
            "/dev/sda",
            "/dev/nvme",
            "mount /dev/",
        ):
            self.assertNotIn(forbidden, combined)

    def test_runtime_dependencies_remain_minimal(self) -> None:
        packages = {
            line.strip()
            for line in self.read(
                "config/package-lists/white-night.list.chroot"
            ).splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        }
        self.assertEqual(
            packages,
            {
                "ca-certificates",
                "python3",
                "python3-venv",
            },
        )

    def test_boot_mode_service_precedes_application_start(self) -> None:
        service = self.read(
            "config/includes.chroot/etc/systemd/system/white-night-live-app.service"
        )
        mode_service = self.read(
            "config/includes.chroot/etc/systemd/system/white-night-live-mode.service"
        )
        self.assertIn("Requires=white-night-live-mode.service", service)
        self.assertIn(
            "After=local-fs.target white-night-live-mode.service",
            service,
        )
        self.assertIn(
            "ExecStart=/opt/nightrecon/venv/bin/python "
            "/usr/local/sbin/white-night-live-mode-select",
            mode_service,
        )

    def test_application_start_is_mode_aware(self) -> None:
        start = self.read(
            "config/includes.chroot/usr/local/sbin/white-night-live-app-start"
        )
        self.assertIn('case "$mode" in', start)
        self.assertIn("ephemeral)", start)
        self.assertIn("recovery)", start)
        self.assertIn("secure-workspace)", start)
        self.assertIn('"$white_app" > "$output"', start)
        self.assertIn("WHITE_NIGHT_LIVE_AUTO_START_OK", start)
        self.assertIn("WHITE_NIGHT_LIVE_RECOVERY_READY", start)
        self.assertIn("WHITE_NIGHT_LIVE_SECURE_WORKSPACE_BLOCKED", start)
        self.assertIn("exit 78", start)

    def test_readiness_is_mode_aware(self) -> None:
        readiness = self.read(
            "config/includes.chroot/usr/local/sbin/white-night-live-readiness"
        )
        self.assertIn('case "$mode" in', readiness)
        self.assertIn("WHITE_NIGHT_LIVE_MODE_OK=ephemeral", readiness)
        self.assertIn("WHITE_NIGHT_LIVE_APP_OK", readiness)
        self.assertIn("WHITE_NIGHT_LIVE_MODE_OK=recovery", readiness)
        self.assertIn("WHITE_NIGHT_LIVE_RECOVERY_OK", readiness)
        self.assertIn(
            "Secure Workspace is blocked until encrypted persistence is configured",
            readiness,
        )


    def test_grub_menu_exposes_all_three_white_modes(self) -> None:
        config = self.read("config/bootloaders/grub-pc/config.cfg")
        grub = self.read("config/bootloaders/grub-pc/grub.cfg")
        self.assertIn("set default=0", config)
        self.assertIn("set timeout_style=menu", config)
        self.assertIn("White Night — Ephemeral Session", grub)
        self.assertIn(
            "nightrecon.live_mode=ephemeral",
            grub,
        )
        self.assertIn("White Night — Recovery & Integrity Check", grub)
        self.assertIn(
            "nightrecon.live_mode=recovery",
            grub,
        )
        self.assertIn("White Night — Secure Workspace", grub)
        self.assertIn(
            "nightrecon.live_mode=secure-workspace",
            grub,
        )
        self.assertIn("KERNEL_LIVE", grub)
        self.assertIn("APPEND_LIVE", grub)
        self.assertIn("INITRD_LIVE", grub)

    def test_vm_smoke_supports_explicit_menu_selection(self) -> None:
        smoke = (ROOT / "tests" / "white_live_vm_smoke.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("ephemeral)", smoke)
        self.assertIn("recovery)", smoke)
        self.assertIn("secure-workspace)", smoke)
        self.assertIn("sendkey down", smoke)
        self.assertIn("WHITE_NIGHT_LIVE_SECURE_WORKSPACE_BLOCKED", smoke)
        self.assertIn("White Night GRUB menu did not become visible", smoke)

    def test_vm_smoke_keeps_offline_default_ephemeral_gate(self) -> None:
        smoke = (ROOT / "tests" / "white_live_vm_smoke.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("OVMF_CODE", smoke)
        self.assertIn("-nic none", smoke)
        self.assertIn("sendkey down", smoke)
        self.assertIn("sendkey ret", smoke)
        self.assertIn("server=on,wait=off", smoke)
        self.assertIn("WHITE_NIGHT_LIVE_MODE_OK=ephemeral", smoke)
        self.assertIn("WHITE_NIGHT_LIVE_AUTO_START_OK", smoke)
        self.assertIn("WHITE_NIGHT_LIVE_APP_OK", smoke)
        self.assertNotIn("-net user", smoke)
        self.assertNotIn("-nic user", smoke)

    def test_profile_declares_three_modes_without_claiming_secure_workspace(self) -> None:
        profile = self.read(
            "config/includes.chroot/etc/nightrecon-live-profile.json"
        )
        self.assertIn('"live_batch": 3', profile)
        self.assertIn('"authorization_effect": "none"', profile)
        self.assertIn('"host_disk_policy": "no-automatic-mount"', profile)
        self.assertIn('"persistence": false', profile)
        self.assertIn('"encrypted_persistence_configured": false', profile)
        self.assertIn('"default_boot_mode": "ephemeral"', profile)
        self.assertIn('"secure-workspace"', profile)
        self.assertIn('"ephemeral"', profile)
        self.assertIn('"recovery"', profile)
        self.assertIn('"secure_workspace_ready": false', profile)


if __name__ == "__main__":
    unittest.main()
