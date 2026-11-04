"""Public bounded concurrent assessment CLI with synthetic governed outcomes."""
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from nightrecon_red_engine.red_cli import main as public_red_main
from nightrecon_shared_core.editions import available_commands


class FakeOutcome:
    def __init__(self, tool):
        self.tool = tool
    def operator_report(self):
        return {"tool": self.tool, "command_exit_code": 0,
                "execution_status": "succeeded", "evidence_status": "unverified"}


class GovernedBatchCliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.plan = self.root / "plan.json"
        self.plan.write_text(json.dumps({
            "schema": 1,
            "tasks": [
                {"kind": "nmap", "engagement_id": "lab", "action_id": "nmap-one",
                 "target": "192.0.2.1", "executable": "/nmap",
                 "trusted_sha256": "a" * 64},
                {"kind": "tshark", "engagement_id": "lab", "action_id": "tshark-two",
                 "target": "192.0.2.2", "executable": "/tshark",
                 "trusted_sha256": "b" * 64,
                 "capture_root": str(self.root),
                 "capture_path": str(self.root / "sample.pcap")},
            ],
        }), encoding="utf-8")
        self.args = (
            "governed-batch", "--plan", str(self.plan),
            "--authority-db", str(self.root / "authority.db"),
            "--audit-dir", str(self.root), "--max-workers", "2",
        )

    def test_public_operator_batch_emits_live_events_and_final_report(self):
        self.assertIn("governed-batch", available_commands("red"))
        (self.root / "authority.db").touch()
        with patch(
            "nightrecon_red_engine.governed_assessment_batch.execute_governed_nmap_discovery",
            return_value=FakeOutcome("nmap"),
        ), patch(
            "nightrecon_red_engine.governed_assessment_batch.execute_governed_tshark_inspection",
            return_value=FakeOutcome("tshark"),
        ), contextlib.redirect_stdout(io.StringIO()) as out:
            public_red_main((*self.args, "--execute"))
        records = [json.loads(line) for line in out.getvalue().splitlines()]
        self.assertEqual(records[-1]["type"], "batch-report")
        self.assertEqual(records[-1]["summary"]["succeeded"], 2)
        self.assertEqual(len(records[-1]["tasks"]), 2)
        self.assertEqual(
            {r["status"] for r in records if r["type"] == "task-event"},
            {"queued", "running", "succeeded"},
        )

    def test_operator_opt_in_and_registered_database_required(self):
        with self.assertRaisesRegex(PermissionError, "--execute"):
            public_red_main(self.args)
        with self.assertRaisesRegex(FileNotFoundError, "authority database"):
            public_red_main((*self.args, "--execute"))

    def test_unknown_action_kind_fails_without_launch(self):
        (self.root / "authority.db").touch()
        payload = json.loads(self.plan.read_text(encoding="utf-8"))
        payload["tasks"][0]["kind"] = "shell"
        self.plan.write_text(json.dumps(payload), encoding="utf-8")
        with patch(
            "nightrecon_red_engine.governed_assessment_batch.execute_governed_nmap_discovery",
        ) as run:
            with self.assertRaisesRegex(ValueError, "Unapproved batch task"):
                public_red_main((*self.args, "--execute"))
            run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
