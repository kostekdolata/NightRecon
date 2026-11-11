"""Offline Tier 1 synthetic replay safety and provenance regression."""
import hashlib
import json
import unittest

from nightrecon_red_engine.tier1_capability_plan import TIER1
from nightrecon_red_engine.tier1_synthetic_executor_contract import (
    SyntheticExecutionError, replay_tier1_fixture,
)


class SyntheticReplayTests(unittest.TestCase):
    def replay(self, tool="nmap", **overrides):
        fixture = json.dumps({"tool": tool, "target": "127.0.0.1",
                              "synthetic": True,
                              "observations": [{"code": 200}]}).encode()
        params = dict(engagement_id="lab", tool=tool, target="127.0.0.1",
                      authorized_targets=("127.0.0.1",), fixture=fixture,
                      platform="linux", prerequisite_attested=True,
                      authorization_record="auth-1", approval_record="approval-1")
        params.update(overrides)
        return replay_tier1_fixture(**params)

    def test_all_seven_slots_are_synthetic_only(self):
        for tool in TIER1:
            with self.subTest(tool=tool):
                result = self.replay(tool)
                self.assertTrue(result["synthetic"])
                self.assertFalse(result["external_execution"])
                self.assertFalse(result["integration_verified"])
                self.assertEqual(result["observations"][0]["classification"],
                                 "synthetic_unverified")
                self.assertEqual(len(result["fixture_sha256"]), 64)

    def test_missing_approval_scope_prerequisite_or_cancellation_blocks(self):
        for changes in (
            {"approval_record": None},
            {"authorized_targets": ("localhost",)},
            {"prerequisite_attested": False},
            {"cancelled": True},
            {"authorization_record": ""},
            {"max_bytes": 1},
        ):
            with self.subTest(changes=changes), self.assertRaises(SyntheticExecutionError):
                self.replay(**changes)

    def test_malformed_and_tool_mismatch_fail_closed(self):
        for fixture in (b"{", b"[]", b"{}",
                        b'{"tool":"nmap","target":"127.0.0.1","synthetic":false,"observations":[]}',
                        b'{"tool":"nmap","target":"127.0.0.1","synthetic":true,"observations":[{"code":true}]}'):
            with self.subTest(fixture=fixture), self.assertRaises(SyntheticExecutionError):
                self.replay(fixture=fixture)

    def test_non_intrusive_capture_replay_does_not_require_intrusive_approval(self):
        result = self.replay("tshark", approval_record=None)
        self.assertFalse(result["external_execution"])


if __name__ == "__main__":
    unittest.main()
