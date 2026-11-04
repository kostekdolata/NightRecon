"""Nmap coordinator operator feedback and cancellation forwarding tests."""

import hashlib
import json
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from nightrecon_red_engine.governed_command_runner import CommandOutcome
from nightrecon_red_engine.governed_nmap_coordinator import (
    execute_governed_nmap_discovery,
    execute_managed_nmap_discovery,
)


XML = (
    '<nmaprun><host><status state="up"/>'
    '<address addr="192.0.2.1" addrtype="ipv4"/>'
    '<ports><port protocol="tcp" portid="443">'
    '<state state="open"/><service name="https"/></port></ports>'
    '</host></nmaprun>'
)


class NmapOperatorFeedbackTests(unittest.TestCase):
    def test_real_outcome_metadata_and_cancellation_propagation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            program = root / "nmap"
            program.write_bytes(b"test fixture - never executed")
            digest = hashlib.sha256(program.read_bytes()).hexdigest()
            stop = threading.Event()
            with patch(
                "nightrecon_red_engine.governed_nmap_coordinator.execute_atomically_governed",
                return_value=CommandOutcome("nmap-bounded-connect", 0, XML, ""),
            ) as runner:
                outcome = execute_governed_nmap_discovery(
                    authority=None, engagement_id="lab", action_id="job-12",
                    target="192.0.2.1", executable=program,
                    trusted_sha256=digest, audit_path=root / "auth.jsonl",
                    result_audit_path=root / "execution.jsonl",
                    enabled=True, cancel_event=stop,
                )
                self.assertIs(runner.call_args.kwargs["cancel_event"], stop)
                report = outcome.operator_report()
                self.assertEqual(report["action_id"], "job-12")
                self.assertEqual(report["target"], "192.0.2.1")
                self.assertEqual(report["tool"], "nmap")
                self.assertEqual(report["execution_status"], "succeeded")
                self.assertEqual(report["command_exit_code"], 0)
                self.assertEqual(report["evidence_status"], "unverified-observation")
                self.assertEqual(report["services"][0]["port"], 443)
                self.assertEqual(report["services"][0]["state"], "open")
                self.assertTrue(report["limitations"])
                self.assertNotIn("confirmed", json.dumps(report))

    def test_managed_scan_forwards_cancellation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            program = root / "nmap"
            program.write_bytes(b"fixture")
            digest = hashlib.sha256(program.read_bytes()).hexdigest()
            (root / "components.json").write_text(json.dumps({
                "schema": 1,
                "components": {"nmap": {"path": "nmap", "sha256": digest}},
            }), encoding="utf-8")
            stop = threading.Event()
            with patch(
                "nightrecon_red_engine.governed_nmap_coordinator.execute_atomically_governed",
                return_value=CommandOutcome("nmap-bounded-connect", 0, XML, ""),
            ) as runner:
                result = execute_managed_nmap_discovery(
                    authority=None, engagement_id="lab", action_id="managed",
                    target="192.0.2.1", components_root=root,
                    manifest_path=root / "components.json",
                    audit_path=root / "auth.jsonl",
                    result_audit_path=root / "execution.jsonl",
                    enabled=True, cancel_event=stop,
                )
                self.assertIs(runner.call_args.kwargs["cancel_event"], stop)
                self.assertEqual(result.operator_report()["action_id"], "managed")

    def test_untrusted_binary_rejected_without_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            program = root / "nmap"
            program.write_bytes(b"untrusted")
            with patch("nightrecon_red_engine.governed_nmap_coordinator.execute_atomically_governed") as runner:
                with self.assertRaises(PermissionError):
                    execute_governed_nmap_discovery(
                        authority=None, engagement_id="lab", action_id="blocked",
                        target="192.0.2.1", executable=program,
                        trusted_sha256="0" * 64, audit_path=root / "auth.jsonl",
                        result_audit_path=root / "execution.jsonl",
                        enabled=True, cancel_event=threading.Event(),
                    )
                runner.assert_not_called()


if __name__ == "__main__":
    unittest.main()
