"""Safety tests for the bounded White Night LUKS2 provisioning helper."""

from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "live" / "white-night" / "tools" / "provision-white-workspace.sh"


class WhiteLiveProvisioningHelperTests(unittest.TestCase):
    def setUp(self) -> None:
        self.text = HELPER.read_text(encoding="utf-8")
        self.lower = self.text.lower()

    def test_requires_explicit_target_key_and_confirmation(self) -> None:
        self.assertIn("--target", self.text)
        self.assertIn("--key-file", self.text)
        self.assertIn("--confirm", self.text)
        self.assertIn('CONFIRMATION="PROVISION-WHITE-NIGHT-LUKS2"', self.text)
        self.assertIn("destructive confirmation token mismatch", self.text)

    def test_rejects_device_paths_and_symlinks(self) -> None:
        self.assertIn('/dev/*)', self.text)
        self.assertIn("block-device paths are not accepted", self.text)
        self.assertIn("symlink targets are not accepted", self.text)
        self.assertIn("resolved block-device paths are not accepted", self.text)

    def test_accepts_only_existing_regular_file_with_minimum_size(self) -> None:
        self.assertIn("target must be an existing regular file", self.text)
        self.assertIn("67108864", self.text)
        self.assertIn("minimum is 64 MiB", self.text)

    def test_requires_mode_0600_key_file(self) -> None:
        self.assertIn("key file permissions must be exactly 0600", self.text)
        self.assertIn('key_mode=$(stat -c %a -- "$key_file")', self.text)

    def test_refuses_existing_luks_and_formats_only_luks2(self) -> None:
        self.assertIn("target is already a LUKS container", self.text)
        self.assertIn("cryptsetup luksFormat", self.text)
        self.assertIn("--type luks2", self.text)
        self.assertIn("cryptsetup isLuks --type luks2", self.text)

    def test_contains_no_discovery_or_partitioning_surface(self) -> None:
        for forbidden in (
            "lsblk",
            "blkid",
            "parted",
            "fdisk",
            "sfdisk",
            "losetup",
            "wipefs",
            "mkfs.vfat",
        ):
            self.assertNotIn(forbidden, self.lower)


if __name__ == "__main__":
    unittest.main()
