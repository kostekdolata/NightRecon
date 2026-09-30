"""Red Night v0.44 Batch 3 appliance-session tests."""

from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
RED_APP_ROOT = ROOT / "packages" / "red-night"
if str(RED_APP_ROOT) not in sys.path:
    sys.path.insert(0, str(RED_APP_ROOT))

from red_night_app.appliance import (  # noqa: E402
    AUTHORIZATION_EFFECT,
    RedLiveSessionMode,
    main,
    prompt_for_mode,
    run_ephemeral_operator_session,
    session_decision,
)


class RedLiveApplianceTests(unittest.TestCase):
    def test_modes_are_explicit_and_non_authoritative(self):
        self.assertEqual(
            tuple(RedLiveSessionMode),
            (
                RedLiveSessionMode.SECURE_WORKSPACE,
                RedLiveSessionMode.EPHEMERAL_SESSION,
                RedLiveSessionMode.RECOVERY_INTEGRITY,
            ),
        )
        self.assertEqual(AUTHORIZATION_EFFECT, "none")
        for mode in RedLiveSessionMode:
            self.assertEqual(session_decision(mode).authorization_effect, "none")

    def test_secure_workspace_fails_closed_until_encrypted_persistence_exists(self):
        decision = session_decision(RedLiveSessionMode.SECURE_WORKSPACE)
        self.assertFalse(decision.available)
        self.assertFalse(decision.launch_red_application)
        self.assertFalse(decision.persistent_workspace)
        self.assertIn("batch-4", decision.reason)

    def test_ephemeral_session_launches_only_after_explicit_selection(self):
        outputs = []
        selections = iter(["wrong", "2"])
        selected = prompt_for_mode(
            input_fn=lambda _prompt: next(selections),
            output_fn=outputs.append,
        )
        self.assertIs(selected, RedLiveSessionMode.EPHEMERAL_SESSION)
        self.assertTrue(any("Invalid selection" in item for item in outputs))

    def test_ephemeral_operator_loop_routes_only_red_command_arguments(self):
        calls = []
        states = iter(["--version", "help", "exit"])

        def runner(args, cwd):
            calls.append((tuple(args), cwd, cwd.exists()))
            return 0

        with tempfile.TemporaryDirectory() as root:
            runtime_root = Path(root)
            code = run_ephemeral_operator_session(
                runtime_root=runtime_root,
                input_fn=lambda _prompt: next(states),
                output_fn=lambda _message: None,
                command_runner=runner,
            )

        self.assertEqual(code, 0)
        self.assertEqual(calls[0][0], ("--version",))
        self.assertEqual(calls[1][0], ("--help",))
        self.assertTrue(all(existed for _, _, existed in calls))
        self.assertTrue(all(not path.exists() for _, path, _ in calls))

    def test_recovery_mode_does_not_launch_red_commands(self):
        decision = session_decision(RedLiveSessionMode.RECOVERY_INTEGRITY)
        self.assertTrue(decision.available)
        self.assertFalse(decision.launch_red_application)
        self.assertFalse(decision.persistent_workspace)

    def test_dry_run_is_machine_readable_and_has_no_authorization_effect(self):
        with patch("builtins.print") as output:
            code = main(["--mode", "ephemeral-session", "--dry-run"])
        self.assertEqual(code, 0)
        payload = json.loads(output.call_args.args[0])
        self.assertEqual(payload["mode"], "ephemeral-session")
        self.assertTrue(payload["launch_red_application"])
        self.assertFalse(payload["persistent_workspace"])
        self.assertEqual(payload["authorization_effect"], "none")

    def test_secure_mode_cli_refuses_to_start_before_batch_four(self):
        with patch("builtins.print"):
            code = main(["--mode", "secure-workspace"])
        self.assertEqual(code, 3)


if __name__ == "__main__":
    unittest.main()
