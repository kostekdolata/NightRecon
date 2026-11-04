"""Governed TShark offline integration; never launches real processes in unit tests."""
import contextlib
import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from nightrecon_red_engine.governed_command_runner import CommandOutcome
from nightrecon_red_engine.governed_tshark_coordinator import execute_governed_tshark_inspection
from nightrecon_red_engine.red_cli import main as public_red_main
from nightrecon_shared_core.editions import available_commands

OUTPUT = json.dumps([
    {"_source": {"layers": {"tcp": {}, "http": {"http.response.code": "200"}}}},
    {"_source": {"layers": {"tcp": {}, "tls": {}}}},
])


class GovernedTsharkTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.executable = self.root / "tshark"
        self.executable.write_bytes(b"fixture not executed")
        self.digest = hashlib.sha256(self.executable.read_bytes()).hexdigest()
        self.capture = self.root / "sample.pcap"
        self.capture.write_bytes(b"sample offline fixture")
        self.kwargs = dict(
            authority=None, engagement_id="lab", action_id="capture-1",
            target="192.0.2.1", executable=self.executable,
            trusted_sha256=self.digest, capture_path=self.capture,
            capture_root=self.root, audit_path=self.root / "auth.jsonl",
            result_audit_path=self.root / "execution.jsonl", enabled=True,
        )

    def test_real_executor_delegation_and_evidence_limits(self):
        with patch(
            "nightrecon_red_engine.governed_tshark_coordinator.execute_atomically_governed",
            return_value=CommandOutcome("tshark-bounded-offline", 0, OUTPUT, ""),
        ) as runner:
            result = execute_governed_tshark_inspection(**self.kwargs)
            command = runner.call_args.kwargs["command"]
            self.assertEqual(command.arguments, (
                "-r", str(self.capture), "-n", "-c", "5", "-T", "json",
            ))
            self.assertEqual(command.capability, "external.tshark.inspect")
            self.assertEqual(command.executable_sha256, self.digest)
            self.assertEqual(runner.call_args.kwargs["action_id"], "capture-1")
            report = result.operator_report()
            self.assertEqual(report["packets_observed"], 2)
            self.assertEqual(report["protocol_counts"]["tcp"], 2)
            self.assertEqual(report["execution_status"], "succeeded")
            self.assertEqual(report["evidence_status"], "unverified-observation")
            self.assertNotIn(str(self.capture), json.dumps(report))
            self.assertTrue(report["limitations"])

    def test_no_opt_in_no_execution(self):
        with patch("nightrecon_red_engine.governed_tshark_coordinator.execute_atomically_governed") as run:
            with self.assertRaisesRegex(PermissionError, "opt-in"):
                execute_governed_tshark_inspection(**{**self.kwargs, "enabled": False})
            run.assert_not_called()

    def test_untrusted_executable_blocked_before_execution(self):
        with patch("nightrecon_red_engine.governed_tshark_coordinator.execute_atomically_governed") as run:
            with self.assertRaisesRegex(PermissionError, "digest mismatch"):
                execute_governed_tshark_inspection(**{**self.kwargs, "trusted_sha256": "0" * 64})
            run.assert_not_called()

    def test_outside_capture_directory_blocked(self):
        with tempfile.TemporaryDirectory() as other:
            outside = Path(other) / "outside.pcap"
            outside.write_bytes(b"private")
            with patch("nightrecon_red_engine.governed_tshark_coordinator.execute_atomically_governed") as run:
                with self.assertRaisesRegex(PermissionError, "approved capture"):
                    execute_governed_tshark_inspection(**{**self.kwargs, "capture_path": outside})
                run.assert_not_called()

    def test_nonzero_exit_does_not_generate_success_evidence(self):
        with patch(
            "nightrecon_red_engine.governed_tshark_coordinator.execute_atomically_governed",
            return_value=CommandOutcome("tshark-bounded-offline", 7, "[]", "failed"),
        ):
            with self.assertRaisesRegex(RuntimeError, "exit code 7"):
                execute_governed_tshark_inspection(**self.kwargs)

    def test_public_cli_checks_authority_and_execute_opt_in(self):
        self.assertIn("tshark-inspect", available_commands("red"))
        argv = (
            "tshark-inspect", "192.0.2.1",
            "--authority-db", str(self.root / "nonexistent.db"),
            "--engagement-id", "lab", "--action-id", "capture-1",
            "--audit-path", str(self.root / "auth.jsonl"),
            "--result-audit-path", str(self.root / "execution.jsonl"),
            "--tshark-executable", str(self.executable),
            "--trusted-sha256", self.digest,
            "--capture-root", str(self.root), "--capture", str(self.capture),
        )
        with self.assertRaisesRegex(PermissionError, "opt-in"):
            public_red_main(argv)
        with self.assertRaisesRegex(FileNotFoundError, "authority database"):
            public_red_main((*argv, "--execute"))

    def test_public_cli_prints_structured_report(self):
        (self.root / "authority.db").touch()
        argv = (
            "tshark-inspect", "192.0.2.1",
            "--authority-db", str(self.root / "authority.db"),
            "--engagement-id", "lab", "--action-id", "capture-1",
            "--audit-path", str(self.root / "auth.jsonl"),
            "--result-audit-path", str(self.root / "execution.jsonl"),
            "--tshark-executable", str(self.executable),
            "--trusted-sha256", self.digest,
            "--capture-root", str(self.root), "--capture", str(self.capture),
            "--execute",
        )
        with patch(
            "nightrecon_red_engine.governed_tshark_coordinator.execute_atomically_governed",
            return_value=CommandOutcome("tshark-bounded-offline", 0, OUTPUT, ""),
        ), contextlib.redirect_stdout(io.StringIO()) as stream:
            public_red_main(argv)
            report = json.loads(stream.getvalue())
            self.assertEqual(report["tool"], "tshark")
            self.assertEqual(report["packets_observed"], 2)


if __name__ == "__main__":
    unittest.main()
