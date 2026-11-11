"""Network-free trusted executable prerequisite checks."""
import hashlib
import os
from pathlib import Path
import tempfile
import unittest

from nightrecon_red_engine.tier1_prerequisite_attestation import (
    TrustedPrerequisiteError, attest_tier1_executables,
)
from nightrecon_red_engine.tier1_capability_plan import TIER1, plan_tier1_tools


class TrustedPrerequisiteTests(unittest.TestCase):
    def test_pinned_file_integrates_with_inert_planner(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "mock-tool"
            path.write_bytes(b"synthetic-not-an-executable")
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            result = attest_tier1_executables(
                platform="linux", registrations={"nmap": (str(path), digest)})
            self.assertEqual(set(result["tools"]), set(TIER1))
            self.assertTrue(result["available_tools"]["nmap"])
            self.assertFalse(result["available_tools"]["zap"])
            self.assertFalse(result["execution_allowed"])
            self.assertFalse(result["integration_verified"])
            plan = plan_tier1_tools(
                engagement_id="lab", authorized_targets=("127.0.0.1",),
                selected_tools=("nmap", "zap"),
                available_tools=result["available_tools"], platform="linux",
                intrusive_approval=True)
            self.assertFalse(plan["execution_allowed"])
            self.assertEqual(plan["decisions"][1]["selection_reason"],
                             "trusted_prerequisite_not_attested")
            path.write_bytes(b"tampered")
            changed = attest_tier1_executables(
                platform="linux", registrations={"nmap": (str(path), digest)})
            self.assertEqual(changed["tools"]["nmap"]["reason"], "digest_mismatch")

    def test_symlink_missing_and_budget_fail_closed(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "tool"
            path.write_bytes(b"data")
            digest = hashlib.sha256(b"data").hexdigest()
            link = Path(folder) / "link"
            try:
                link.symlink_to(path)
            except (OSError, NotImplementedError):
                link = None
            registrations = {"nmap": (str(link or Path(folder) / "missing"), digest),
                             "zap": (str(path), digest)}
            result = attest_tier1_executables(
                platform="linux", registrations=registrations, max_file_bytes=1)
            self.assertFalse(result["available_tools"]["nmap"])
            self.assertFalse(result["available_tools"]["zap"])
            self.assertEqual(result["tools"]["zap"]["reason"], "unavailable_or_unsafe_file")

    def test_invalid_registration_is_rejected(self):
        for registrations in (
            {"nmap": ("relative", "0" * 64)},
            {"nmap": ("/tmp/tool", "bad")},
            {"unknown": ("/tmp/tool", "0" * 64)},
            {"nmap": ("/tmp/tool\n", "0" * 64)},
        ):
            with self.subTest(registrations=registrations):
                with self.assertRaises(TrustedPrerequisiteError):
                    attest_tier1_executables(platform="linux", registrations=registrations)
        with self.assertRaises(TrustedPrerequisiteError):
            attest_tier1_executables(platform="other", registrations={})


if __name__ == "__main__":
    unittest.main()
