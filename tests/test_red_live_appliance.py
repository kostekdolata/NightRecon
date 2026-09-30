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

from red_night_app.persistence import RedPersistenceState  # noqa: E402

from red_night_app.appliance import (  # noqa: E402
    REQUIRED_OS_PRIVILEGE,
    require_privileged_runtime,
    AUTHORIZATION_EFFECT,
    RedLiveSessionMode,
    main,
    prompt_for_mode,
    run_ephemeral_operator_session,
    run_secure_workspace_session,
    session_decision,
)


class RedLivePrivilegeTests(unittest.TestCase):
    def test_required_os_privilege_is_root(self):
        self.assertEqual(REQUIRED_OS_PRIVILEGE, "root")

    def test_privileged_runtime_accepts_root(self):
        with patch("red_night_app.appliance.require_platform_privilege") as guard:
            require_privileged_runtime()
        guard.assert_called_once_with()

    def test_privileged_runtime_rejects_non_root(self):
        with patch(
            "red_night_app.appliance.require_platform_privilege",
            side_effect=PermissionError("privilege required"),
        ):
            with self.assertRaises(PermissionError):
                require_privileged_runtime()


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
        self.assertEqual(decision.reason, "encrypted-persistence-not-mounted")

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

    def test_secure_workspace_locked_flow_unlocks_mounts_runs_and_closes(self):
        events = []
        states = iter(
            (
                RedPersistenceState.LUKS2_LOCKED,
                RedPersistenceState.LUKS2_OPEN,
                RedPersistenceState.MOUNTED,
            )
        )
        commands = iter(["--help", "exit"])

        def inspect(_config):
            state = next(states)
            events.append(("inspect", state.value))
            return state

        def unlock(_config, *, passphrase):
            events.append(("unlock", passphrase))

        def mount(_config):
            events.append(("mount",))

        def close(_config, *, mounted):
            events.append(("close", mounted))

        def runner(args, cwd):
            events.append(("run", tuple(args), str(cwd)))
            return 0

        outputs = []
        code = run_secure_workspace_session(
            device="/dev/disk/by-partuuid/1111-2222",
            input_fn=lambda _prompt: next(commands),
            output_fn=outputs.append,
            passphrase_fn=lambda _prompt: "secret",
            command_runner=runner,
            state_inspector=inspect,
            unlock_fn=unlock,
            mount_fn=mount,
            safe_close_fn=close,
        )

        self.assertEqual(code, 0)
        self.assertEqual(
            events,
            [
                ("inspect", "luks2-locked"),
                ("unlock", b"secret"),
                ("inspect", "luks2-open"),
                ("mount",),
                ("inspect", "mounted"),
                ("run", ("--help",), "/run/red-night-secure"),
                ("close", True),
            ],
        )
        self.assertTrue(any("Secure Workspace active" in item for item in outputs))

    def test_secure_workspace_preopened_mapping_is_unmounted_not_closed(self):
        events = []
        states = iter(
            (
                RedPersistenceState.LUKS2_OPEN,
                RedPersistenceState.MOUNTED,
            )
        )

        def inspect(_config):
            return next(states)

        def mount(_config):
            events.append("mount")

        def unmount(_config):
            events.append("unmount")

        def close(_config, *, mounted):
            events.append(("close", mounted))

        code = run_secure_workspace_session(
            device="/dev/disk/by-partuuid/1111-2222",
            input_fn=lambda _prompt: "exit",
            output_fn=lambda _message: None,
            command_runner=lambda _args, _cwd: 0,
            state_inspector=inspect,
            mount_fn=mount,
            unmount_fn=unmount,
            safe_close_fn=close,
        )

        self.assertEqual(code, 0)
        self.assertEqual(events, ["mount", "unmount"])

    def test_secure_workspace_premounted_workspace_is_left_mounted(self):
        events = []
        code = run_secure_workspace_session(
            device="/dev/disk/by-partuuid/1111-2222",
            input_fn=lambda _prompt: "exit",
            output_fn=lambda _message: None,
            command_runner=lambda _args, _cwd: 0,
            state_inspector=lambda _config: RedPersistenceState.MOUNTED,
            unmount_fn=lambda _config: events.append("unmount"),
            safe_close_fn=lambda _config, *, mounted: events.append(("close", mounted)),
        )
        self.assertEqual(code, 0)
        self.assertEqual(events, [])

    def test_secure_workspace_missing_or_uninitialized_fails_without_actions(self):
        for state in (
            RedPersistenceState.MISSING,
            RedPersistenceState.UNINITIALIZED,
        ):
            actions = []
            with self.subTest(state=state):
                code = run_secure_workspace_session(
                    device="/dev/disk/by-partuuid/1111-2222",
                    input_fn=lambda _prompt: "exit",
                    output_fn=lambda _message: None,
                    passphrase_fn=lambda _prompt: actions.append("secret") or "secret",
                    command_runner=lambda _args, _cwd: actions.append("run") or 0,
                    state_inspector=lambda _config, value=state: value,
                    unlock_fn=lambda _config, *, passphrase: actions.append("unlock"),
                    mount_fn=lambda _config: actions.append("mount"),
                    unmount_fn=lambda _config: actions.append("unmount"),
                    safe_close_fn=lambda _config, *, mounted: actions.append("close"),
                )
                self.assertEqual(code, 4)
                self.assertEqual(actions, [])

    def test_secure_workspace_mount_failure_after_unlock_closes_mapping(self):
        states = iter(
            (
                RedPersistenceState.LUKS2_LOCKED,
                RedPersistenceState.LUKS2_OPEN,
            )
        )
        closes = []

        with self.assertRaises(RuntimeError):
            run_secure_workspace_session(
                device="/dev/disk/by-partuuid/1111-2222",
                input_fn=lambda _prompt: "exit",
                output_fn=lambda _message: None,
                passphrase_fn=lambda _prompt: "secret",
                command_runner=lambda _args, _cwd: 0,
                state_inspector=lambda _config: next(states),
                unlock_fn=lambda _config, *, passphrase: None,
                mount_fn=lambda _config: (_ for _ in ()).throw(RuntimeError("mount failed")),
                safe_close_fn=lambda _config, *, mounted: closes.append(mounted),
            )
        self.assertEqual(closes, [False])

    def test_secure_workspace_requires_explicit_device_at_cli(self):
        with (
            patch("builtins.print") as output,
            patch("red_night_app.appliance.require_platform_privilege"),
        ):
            code = main(["--mode", "secure-workspace"])
        self.assertEqual(code, 4)
        self.assertTrue(
            any(
                "explicit persistence device" in str(call.args[0])
                for call in output.call_args_list
            )
        )

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



if __name__ == "__main__":
    unittest.main()
