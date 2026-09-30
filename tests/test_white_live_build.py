"""Static safety and deployment-contract tests for White Night Live Batch 2."""

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
            LIVE
            / "config"
            / "hooks"
            / "live"
            / "0100-enable-white-readiness.hook.chroot",
            LIVE
            / "config"
            / "hooks"
            / "live"
            / "0200-install-white-runtime.hook.chroot",
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
            / "etc"
            / "systemd"
            / "system"
            / "white-night-live-app.service",
            LIVE
            / "config"
            / "includes.chroot"
            / "usr"
            / "local"
            / "sbin"
            / "white-night-live-app-start",
            LIVE
            / "config"
            / "hooks"
            / "live"
            / "0300-enable-white-app.hook.chroot",
            LIVE
            / "config"
            / "includes.chroot"
            / "usr"
            / "local"
            / "sbin"
            / "white-night-live-readiness",
            ROOT / "tests" / "white_live_vm_smoke.sh",
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

    def test_image_stages_and_installs_exact_white_package_artifacts(self) -> None:
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
        self.assertIn('venv_dir=/opt/nightrecon/venv', install)
        self.assertIn("--no-index", install)
        self.assertIn("--no-deps", install)
        self.assertIn(
            'ln -sf "$venv_dir/bin/white-night-app" /usr/local/bin/white-night-app',
            install,
        )
        self.assertNotIn("packages/white-engine/nightrecon_white_engine", build)
        self.assertNotIn("packages/white-night/white_night_app", build)

    def test_installed_runtime_has_no_peer_night_dependency(self) -> None:
        install = self.read(
            "config/hooks/live/0200-install-white-runtime.hook.chroot"
        ).lower()
        self.assertIn('find_spec("nightrecon_red_engine") is none', install)
        for peer in ("nightrecon_blue", "nightrecon_purple", "nightrecon_black"):
            self.assertNotIn(peer, install)

    def test_batch_two_remains_nonpersistent_and_does_not_touch_host_disks(self) -> None:
        paths = (
            "auto/config",
            "build.sh",
            "config/hooks/live/0200-install-white-runtime.hook.chroot",
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

    def test_batch_two_runtime_dependencies_are_minimal(self) -> None:
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

    def test_readiness_executes_packaged_white_application(self) -> None:
        readiness = self.read(
            "config/includes.chroot/usr/local/sbin/white-night-live-readiness"
        )
        self.assertIn(
            '"$white_app" editions --json',
            readiness,
        )
        self.assertIn(
            'metadata.version("nightrecon-white-night") == "0.1.0a6"',
            readiness,
        )
        self.assertIn("WHITE_NIGHT_LIVE_APP_OK", readiness)

    def test_vm_smoke_is_uefi_offline_and_requires_app_marker(self) -> None:
        smoke = (ROOT / "tests" / "white_live_vm_smoke.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("OVMF_CODE", smoke)
        self.assertIn("-nic none", smoke)
        self.assertIn("sendkey ret", smoke)
        self.assertIn("server=on,wait=off", smoke)
        self.assertIn("WHITE_NIGHT_LIVE_AUTO_START_OK", smoke)
        self.assertIn("WHITE_NIGHT_LIVE_APP_OK", smoke)
        self.assertNotIn("-net user", smoke)
        self.assertNotIn("-nic user", smoke)


    def test_auto_start_uses_packaged_white_application(self) -> None:
        start = self.read(
            "config/includes.chroot/usr/local/sbin/white-night-live-app-start"
        )
        service = self.read(
            "config/includes.chroot/etc/systemd/system/white-night-live-app.service"
        )
        readiness_service = self.read(
            "config/includes.chroot/etc/systemd/system/white-night-live-readiness.service"
        )
        self.assertIn("white_app=/usr/local/bin/white-night-app", start)
        self.assertIn('"$white_app" > "$output"', start)
        self.assertIn("WHITE_NIGHT_LIVE_AUTO_START_OK", start)
        self.assertIn("ExecStart=/bin/sh /usr/local/sbin/white-night-live-app-start", service)
        self.assertIn("Requires=white-night-live-app.service", readiness_service)
        self.assertIn("After=local-fs.target white-night-live-app.service", readiness_service)

    def test_profile_declares_installed_app_with_auto_launch(self) -> None:
        profile = self.read(
            "config/includes.chroot/etc/nightrecon-live-profile.json"
        )
        self.assertIn('"live_batch": 2', profile)
        self.assertIn('"authorization_effect": "none"', profile)
        self.assertIn('"host_disk_policy": "no-automatic-mount"', profile)
        self.assertIn('"persistence": false', profile)
        self.assertIn('"runtime": "isolated-venv"', profile)
        self.assertIn('"application_installed": true', profile)
        self.assertIn('"application_auto_launch": true', profile)


if __name__ == "__main__":
    unittest.main()
