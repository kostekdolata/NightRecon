"""Operator CLI integration tests for the existing governed Nmap coordinator.

No network calls or binaries are executed in these tests.
"""

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from nightrecon_red_engine.advanced_cli import main
from nightrecon_red_engine.red_cli import main as public_red_main
from nightrecon_shared_core.editions import available_commands


class NmapGovernedCliTests(unittest.TestCase):
    def _arguments(self, folder):
        return (
            "nmap-governed", "192.0.2.1",
            "--authority-db", str(folder / "authority.db"),
            "--engagement-id", "lab", "--action-id", "scan-one",
            "--audit-path", str(folder / "auth.jsonl"),
            "--result-audit-path", str(folder / "execution.jsonl"),
            "--nmap-executable", str(folder / "nmap"),
            "--trusted-sha256", "a" * 64,
        )

    def test_public_red_night_entrypoint_routes_and_blocks_without_authority(self):
        self.assertIn("nmap-governed", available_commands("red"))
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with patch(
                "nightrecon_red_engine.governed_nmap_coordinator.execute_governed_nmap_discovery",
            ) as run:
                with self.assertRaisesRegex(FileNotFoundError, "authority database"):
                    public_red_main((*self._arguments(root), "--execute"))
                self.assertFalse((root / "authority.db").exists())
                run.assert_not_called()

    def test_opt_in_required_before_database_access_or_scan(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with patch(
                "nightrecon_red_engine.governed_nmap_coordinator.execute_governed_nmap_discovery",
            ) as run:
                with self.assertRaisesRegex(PermissionError, "explicitly supply"):
                    main(self._arguments(root))
                self.assertFalse((root / "authority.db").exists())
                run.assert_not_called()

    def test_missing_registered_authority_blocks_execution(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with patch(
                "nightrecon_red_engine.governed_nmap_coordinator.execute_governed_nmap_discovery",
            ) as run:
                with self.assertRaisesRegex(FileNotFoundError, "authority database"):
                    main((*self._arguments(root), "--execute"))
                self.assertFalse((root / "authority.db").exists())
                run.assert_not_called()

    def test_explicit_execution_reports_real_coordinator_result(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "authority.db").touch()
            expected = {
                "action_id": "scan-one", "target": "192.0.2.1",
                "tool": "nmap", "command_exit_code": 0,
                "execution_status": "succeeded",
                "evidence_status": "unverified-observation",
                "services": [{"port": 443, "state": "open"}],
            }
            class Result:
                def operator_report(self):
                    return expected

            with patch(
                "nightrecon_red_engine.governed_nmap_coordinator.execute_governed_nmap_discovery",
                return_value=Result(),
            ) as run, contextlib.redirect_stdout(io.StringIO()) as output:
                returned = main((*self._arguments(root), "--execute"))
                self.assertIsInstance(returned, Result)
                self.assertEqual(json.loads(output.getvalue()), expected)
                call = run.call_args.kwargs
                self.assertEqual(call["action_id"], "scan-one")
                self.assertEqual(call["target"], "192.0.2.1")
                self.assertTrue(call["enabled"])
                self.assertEqual(call["trusted_sha256"], "a" * 64)
                self.assertIsNotNone(call["authority"])

    def test_untrusted_request_has_no_silent_fallback(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "authority.db").touch()
            with patch(
                "nightrecon_red_engine.governed_nmap_coordinator.execute_governed_nmap_discovery",
                side_effect=PermissionError("scope_denied"),
            ):
                with self.assertRaisesRegex(PermissionError, "scope_denied"):
                    main((*self._arguments(root), "--execute"))


if __name__ == "__main__":
    unittest.main()
