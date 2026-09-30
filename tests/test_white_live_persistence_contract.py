"""Acceptance-contract tests for White Night Live encrypted persistence."""

from __future__ import annotations

import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
LIVE = ROOT / "live" / "white-night"
CONTRACT = ROOT / "WHITE_LIVE_PERSISTENCE.md"


class WhiteLivePersistenceContractTests(unittest.TestCase):
    def test_contract_exists_and_locks_luks2(self) -> None:
        text = CONTRACT.read_text(encoding="utf-8")
        self.assertIn("LUKS2", text)
        self.assertIn("/var/lib/nightrecon-workspace", text)
        self.assertIn("nightrecon-white-workspace", text)
        self.assertIn("Runtime boot must never create or format a LUKS container", text)

    def test_contract_forbids_plaintext_fallback_and_host_disk_scan(self) -> None:
        text = CONTRACT.read_text(encoding="utf-8")
        self.assertIn("no fallback to unencrypted persistence occurs", text)
        self.assertIn("must not scan and mount general host filesystems", text)
        self.assertIn("no automatic formatting of `/dev/sd*` or `/dev/nvme*`", text)

    def test_current_profile_does_not_claim_secure_workspace_readiness(self) -> None:
        profile = json.loads(
            (
                LIVE
                / "config"
                / "includes.chroot"
                / "etc"
                / "nightrecon-live-profile.json"
            ).read_text(encoding="utf-8")
        )
        self.assertFalse(profile["persistence"])
        self.assertFalse(profile["encrypted_persistence_configured"])
        self.assertFalse(profile["secure_workspace_ready"])
        self.assertEqual(profile["authorization_effect"], "none")

    def test_current_runtime_contains_no_luks_formatting_logic(self) -> None:
        relevant = (
            LIVE / "build.sh",
            LIVE / "config" / "includes.chroot" / "usr" / "local" / "sbin" / "white-night-live-mode-select",
            LIVE / "config" / "includes.chroot" / "usr" / "local" / "sbin" / "white-night-live-app-start",
            LIVE / "config" / "includes.chroot" / "usr" / "local" / "sbin" / "white-night-live-readiness",
        )
        combined = "\n".join(
            path.read_text(encoding="utf-8").lower()
            for path in relevant
        )
        self.assertNotIn("luksformat", combined)
        self.assertNotIn("cryptsetup luksformat", combined)
        self.assertNotIn("mount /dev/", combined)

    def test_ephemeral_and_recovery_remain_nonpersistent_before_luks_batch(self) -> None:
        selector = (
            LIVE
            / "config"
            / "includes.chroot"
            / "usr"
            / "local"
            / "sbin"
            / "white-night-live-mode-select"
        ).read_text(encoding="utf-8")
        self.assertIn('"persistence_required": False', selector)
        self.assertIn('"maintenance_only": True', selector)
        self.assertIn('"blocked_reason": "encrypted-persistence-not-configured"', selector)


if __name__ == "__main__":
    unittest.main()
