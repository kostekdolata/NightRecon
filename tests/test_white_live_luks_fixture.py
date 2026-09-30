"""Static safety tests for the disposable White Night LUKS2 fixture."""

from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "white_live_luks_fixture.sh"


class WhiteLiveLuksFixtureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.text = FIXTURE.read_text(encoding="utf-8")
        self.lower = self.text.lower()

    def test_fixture_uses_disposable_regular_file_storage(self) -> None:
        self.assertIn("mktemp -d", self.text)
        self.assertIn('image="$tmp/workspace.img"', self.text)
        self.assertIn('truncate -s 96M "$image"', self.text)
        self.assertNotIn("/dev/sda", self.lower)
        self.assertNotIn("/dev/nvme", self.lower)
        self.assertNotIn("losetup", self.lower)
        self.assertNotIn("parted", self.lower)
        self.assertNotIn("fdisk", self.lower)

    def test_fixture_requires_luks2_and_fixed_ci_mapper_prefix(self) -> None:
        self.assertIn("--type luks2", self.text)
        self.assertIn('mapper="nightrecon-white-ci-$$"', self.text)
        self.assertIn("cryptsetup luksFormat", self.text)
        self.assertIn("cryptsetup isLuks --type luks2", self.text)

    def test_secret_is_file_backed_not_cli_literal_or_environment(self) -> None:
        self.assertIn('key_file="$tmp/workspace.key"', self.text)
        self.assertIn("path.chmod(0o600)", self.text)
        self.assertIn('--key-file "$key_file"', self.text)
        self.assertNotIn("PASSPHRASE=", self.text)
        self.assertNotIn("PASSWORD=", self.text)
        self.assertNotIn("echo $", self.text)

    def test_fixture_verifies_reopen_ephemeral_and_failure_paths(self) -> None:
        self.assertIn("Second phase: reopen", self.text)
        self.assertIn("image_hash_before_ephemeral", self.text)
        self.assertIn("wrong-key unlock unexpectedly succeeded", self.text)
        self.assertIn("malformed target unexpectedly identified as LUKS2", self.text)
        self.assertIn('cmp -s "$before_mounts" "$after_mounts"', self.text)
        self.assertIn("WHITE_NIGHT_LUKS2_FIXTURE_OK", self.text)

    def test_workspace_metadata_is_non_authoritative(self) -> None:
        self.assertIn('"authorization_effect":"none"', self.text)


if __name__ == "__main__":
    unittest.main()
