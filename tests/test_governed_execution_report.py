"""Concurrent/interleaved Red Night tool audit report tests."""
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from nightrecon_red_engine.governed_execution_report import summarize_governed_execution_ledger
from nightrecon_red_engine.red_cli import main as public_red_main
from nightrecon_shared_core.editions import available_commands


class GovernedExecutionReportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "audit.jsonl"

    def write(self, events):
        self.path.write_text("\n".join(json.dumps(x) for x in events) + "\n", encoding="utf-8")

    def event(self, action, command, status, returncode=None, engagement="lab"):
        return {
            "action_id": action, "engagement_id": engagement,
            "command": command, "status": status,
            "returncode": returncode, "recorded_at": "2026-11-04T03:00:00+00:00",
            "stdout": "DO-NOT-LEAK", "password": "SECRET-DO-NOT-LEAK",
        }

    def test_interleaved_success_failure_and_missing_terminal(self):
        self.write([
            self.event("nmap", "nmap-bounded-connect", "started"),
            self.event("tshark", "tshark-bounded-offline", "started"),
            self.event("unknown", "untrusted-command", "started"),
            self.event("nmap", "nmap-bounded-connect", "completed", 0),
            self.event("tshark", "tshark-bounded-offline", "completed", 7),
        ])
        report = summarize_governed_execution_ledger(self.path)
        self.assertEqual(report["action_count"], 3)
        self.assertEqual(report["successful_actions"], 1)
        self.assertEqual(report["failed_or_incomplete_actions"], 2)
        actions = {a["action_id"]: a for a in report["actions"]}
        self.assertEqual(actions["nmap"]["tool"], "nmap")
        self.assertEqual(actions["nmap"]["execution_status"], "succeeded")
        self.assertEqual(actions["tshark"]["tool"], "tshark")
        self.assertEqual(actions["tshark"]["execution_status"], "failed-or-interrupted")
        self.assertEqual(actions["unknown"]["execution_status"], "incomplete-or-inconsistent")
        self.assertNotIn("SECRET-DO-NOT-LEAK", json.dumps(report))
        self.assertNotIn("DO-NOT-LEAK", json.dumps(report))

    def test_real_nuclei_executor_is_identified_in_unified_report(self):
        self.write([
            self.event("fingerprint", "nuclei-bounded-http-fingerprint", "started"),
            self.event("fingerprint", "nuclei-bounded-http-fingerprint", "completed", 0),
        ])
        report = summarize_governed_execution_ledger(self.path)
        self.assertEqual(report["actions"][0]["tool"], "nuclei")
        self.assertEqual(report["successful_actions"], 1)

    def test_repeated_action_or_inconsistent_command_never_success(self):
        self.write([
            self.event("same", "nmap-bounded-connect", "started"),
            self.event("same", "tshark-bounded-offline", "completed", 0),
        ])
        report = summarize_governed_execution_ledger(self.path)
        self.assertEqual(report["successful_actions"], 0)
        self.assertEqual(report["actions"][0]["execution_status"], "incomplete-or-inconsistent")

    def test_engagement_filter_and_public_cli(self):
        self.assertIn("tool-report", available_commands("red"))
        self.write([
            self.event("a", "nmap-bounded-connect", "started"),
            self.event("a", "nmap-bounded-connect", "completed", 0),
            self.event("b", "tshark-bounded-offline", "started", engagement="other"),
        ])
        with contextlib.redirect_stdout(io.StringIO()) as output:
            public_red_main(("tool-report", "--result-audit-path", str(self.path), "--engagement-id", "lab"))
        report = json.loads(output.getvalue())
        self.assertEqual(report["action_count"], 1)
        self.assertEqual(report["successful_actions"], 1)

    def test_malformed_events_fail_closed(self):
        self.path.write_text('{"action_id": "x"}\n', encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "metadata"):
            summarize_governed_execution_ledger(self.path)

    def test_oversize_ledger_fails_closed(self):
        self.path.write_bytes(b"X" * (8 * 1024 * 1024 + 1))
        with self.assertRaisesRegex(ValueError, "limit"):
            summarize_governed_execution_ledger(self.path)


if __name__ == "__main__":
    unittest.main()
