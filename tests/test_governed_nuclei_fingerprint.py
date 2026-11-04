"""Nuclei fixed-template governed operator path tests; no live network."""
import contextlib
import hashlib
import io
import json
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from nightrecon_red_engine.governed_command_runner import CommandOutcome
from nightrecon_red_engine.governed_nuclei_fingerprint import execute_governed_nuclei_fingerprint
from nightrecon_red_engine.red_cli import main as public_red_main
from nightrecon_shared_core.editions import available_commands

MATCH = json.dumps({
    "template-id": "rednight-safe-http-fingerprint",
    "matched-at": "http://192.0.2.4:8080/",
    "info": {"severity": "info"},
}) + "\n"


class GovernedNucleiTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.executable = self.root / "nuclei"
        self.executable.write_bytes(b"trusted test stub - not executed")
        self.digest = hashlib.sha256(self.executable.read_bytes()).hexdigest()
        self.params = {
            "authority": None,
            "engagement_id": "lab",
            "action_id": "scan1",
            "target_url": "http://192.0.2.4:8080",
            "executable": self.executable,
            "trusted_sha256": self.digest,
            "audit_path": self.root / "audit.jsonl",
            "result_audit_path": self.root / "results.jsonl",
            "enabled": True,
        }

    def test_fixed_low_impact_template_and_audit_delegate(self):
        cancel = threading.Event()
        with patch(
            "nightrecon_red_engine.governed_nuclei_fingerprint.execute_atomically_governed",
            return_value=CommandOutcome("nuclei-bounded-http-fingerprint", 0, MATCH, ""),
        ) as execute:
            result = execute_governed_nuclei_fingerprint(
                **self.params, cancel_event=cancel,
            )
            command = execute.call_args.kwargs["command"]
            args = command.arguments
            self.assertEqual(command.capability, "external.nuclei.http-fingerprint")
            self.assertEqual(command.executable_sha256, self.digest)
            self.assertEqual(command.timeout_seconds, 30)
            self.assertIn("-ni", args)
            self.assertIn("-duc", args)
            self.assertIn("-no-stdin", args)
            self.assertIn("-or", args)
            self.assertEqual(args[args.index("-rl") + 1], "1")
            self.assertEqual(args[args.index("-u") + 1], "http://192.0.2.4:8080")
            self.assertIs(execute.call_args.kwargs["cancel_event"], cancel)
        report = result.operator_report()
        self.assertEqual(report["execution_status"], "succeeded")
        self.assertEqual(report["templates_executed"], 1)
        self.assertEqual(report["observations"][0]["matched_origin"], "http://192.0.2.4:8080")
        self.assertEqual(report["evidence_status"], "unverified-http-observation")

    def test_out_of_scope_result_denied(self):
        foreign = MATCH.replace("192.0.2.4", "198.51.100.8")
        with patch(
            "nightrecon_red_engine.governed_nuclei_fingerprint.execute_atomically_governed",
            return_value=CommandOutcome("nuclei-bounded-http-fingerprint", 0, foreign, ""),
        ):
            with self.assertRaisesRegex(PermissionError, "outside"):
                execute_governed_nuclei_fingerprint(**self.params)

    def test_unapproved_template_result_denied(self):
        unexpected = MATCH.replace("rednight-safe-http-fingerprint", "foreign-template")
        with patch(
            "nightrecon_red_engine.governed_nuclei_fingerprint.execute_atomically_governed",
            return_value=CommandOutcome("nuclei-bounded-http-fingerprint", 0, unexpected, ""),
        ):
            with self.assertRaisesRegex(PermissionError, "unexpected template"):
                execute_governed_nuclei_fingerprint(**self.params)

    def test_nonzero_exit_never_claims_success(self):
        with patch(
            "nightrecon_red_engine.governed_nuclei_fingerprint.execute_atomically_governed",
            return_value=CommandOutcome("nuclei-bounded-http-fingerprint", 1, "", "failure"),
        ):
            with self.assertRaisesRegex(RuntimeError, "exit code 1"):
                execute_governed_nuclei_fingerprint(**self.params)

    def test_explicit_opt_in_scope_and_binary_integrity(self):
        with patch("nightrecon_red_engine.governed_nuclei_fingerprint.execute_atomically_governed") as execute:
            with self.assertRaises(PermissionError):
                execute_governed_nuclei_fingerprint(**{**self.params, "enabled": False})
            with self.assertRaises(ValueError):
                execute_governed_nuclei_fingerprint(**{**self.params, "target_url": "http://evil.example/"})
            with self.assertRaises(ValueError):
                execute_governed_nuclei_fingerprint(**{**self.params, "target_url": "http://192.0.2.4/private"})
            with self.assertRaises(PermissionError):
                execute_governed_nuclei_fingerprint(**{**self.params, "trusted_sha256": "0" * 64})
            execute.assert_not_called()

    def test_no_findings_is_valid_unverified_observation(self):
        with patch(
            "nightrecon_red_engine.governed_nuclei_fingerprint.execute_atomically_governed",
            return_value=CommandOutcome("nuclei-bounded-http-fingerprint", 0, "", ""),
        ):
            result = execute_governed_nuclei_fingerprint(**self.params)
            self.assertEqual(result.operator_report()["observations"], [])

    def test_public_cli_requires_approval_database_and_returns_result(self):
        self.assertIn("nuclei-fingerprint", available_commands("red"))
        args = (
            "nuclei-fingerprint", "http://192.0.2.4:8080",
            "--authority-db", str(self.root / "authority.db"),
            "--engagement-id", "lab", "--action-id", "scan1",
            "--audit-path", str(self.root / "audit.jsonl"),
            "--result-audit-path", str(self.root / "results.jsonl"),
            "--nuclei-executable", str(self.executable),
            "--trusted-sha256", self.digest,
        )
        with self.assertRaisesRegex(PermissionError, "--execute"):
            public_red_main(args)
        with self.assertRaisesRegex(FileNotFoundError, "authority database"):
            public_red_main((*args, "--execute"))
        (self.root / "authority.db").touch()
        with patch(
            "nightrecon_red_engine.governed_nuclei_fingerprint.execute_atomically_governed",
            return_value=CommandOutcome("nuclei-bounded-http-fingerprint", 0, MATCH, ""),
        ), contextlib.redirect_stdout(io.StringIO()) as output:
            public_red_main((*args, "--execute"))
        report = json.loads(output.getvalue())
        self.assertEqual(report["tool"], "nuclei")
        self.assertEqual(report["execution_status"], "succeeded")


if __name__ == "__main__":
    unittest.main()
