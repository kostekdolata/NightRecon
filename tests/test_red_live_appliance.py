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
from red_night_app.persistence import RedPersistenceConfig, RedPersistenceState  # noqa: E402


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


class RedSecureWorkspaceIntegrationTests(unittest.TestCase):
    def config(self):
        return RedPersistenceConfig(
            device="/dev/disk/by-partuuid/1111-2222"
        )

    def test_locked_workspace_unlocks_mounts_runs_and_closes(self):
        calls = []
        commands = []
        states = iter(["--version", "exit"])

        def unlocker(config, *, passphrase):
            calls.append(("unlock", config.device, passphrase))

        def mounter(config):
            calls.append(("mount", config.mount_point))

        def closer(config, *, mounted):
            calls.append(("close", config.mount_point, mounted))

        def runner(args, cwd):
            commands.append((tuple(args), cwd))
            return 0

        code = run_secure_workspace_session(
            self.config(),
            input_fn=lambda _prompt: next(states),
            output_fn=lambda _message: None,
            passphrase_fn=lambda _prompt: b"secret",
            command_runner=runner,
            state_probe=lambda _config: RedPersistenceState.LUKS2_LOCKED,
            unlocker=unlocker,
            mounter=mounter,
            closer=closer,
        )

        self.assertEqual(code, 0)
        self.assertEqual(calls[0][0], "unlock")
        self.assertEqual(calls[0][2], b"secret")
        self.assertEqual(calls[1][0], "mount")
        self.assertEqual(calls[2], ("close", "/run/red-night-secure", True))
        self.assertEqual(commands[0][0], ("--version",))
        self.assertEqual(commands[0][1].as_posix(), "/run/red-night-secure")

    def test_already_mounted_workspace_is_reused_without_close(self):
        calls = []
        code = run_secure_workspace_session(
            self.config(),
            input_fn=lambda _prompt: "exit",
            output_fn=lambda _message: None,
            state_probe=lambda _config: RedPersistenceState.MOUNTED,
            unlocker=lambda *_args, **_kwargs: calls.append("unlock"),
            mounter=lambda *_args, **_kwargs: calls.append("mount"),
            closer=lambda *_args, **_kwargs: calls.append("close"),
        )
        self.assertEqual(code, 0)
        self.assertEqual(calls, [])

    def test_missing_uninitialized_and_open_unmounted_fail_closed(self):
        for state in (
            RedPersistenceState.MISSING,
            RedPersistenceState.UNINITIALIZED,
            RedPersistenceState.LUKS2_OPEN,
        ):
            with self.subTest(state=state):
                calls = []
                code = run_secure_workspace_session(
                    self.config(),
                    input_fn=lambda _prompt: "exit",
                    output_fn=lambda _message: None,
                    state_probe=lambda _config, value=state: value,
                    unlocker=lambda *_args, **_kwargs: calls.append("unlock"),
                    mounter=lambda *_args, **_kwargs: calls.append("mount"),
                    closer=lambda *_args, **_kwargs: calls.append("close"),
                )
                self.assertEqual(code, 3)
                self.assertEqual(calls, [])


    def test_uninitialized_workspace_requires_exact_device_confirmation(self):
        calls = []
        outputs = []
        code = run_secure_workspace_session(
            self.config(),
            input_fn=lambda _prompt: "no",
            output_fn=outputs.append,
            new_passphrase_fn=lambda _prompt: b"secret",
            state_probe=lambda _config: RedPersistenceState.UNINITIALIZED,
            provisioner=lambda *_args, **_kwargs: calls.append("provision"),
            closer=lambda *_args, **_kwargs: calls.append("close"),
        )
        self.assertEqual(code, 3)
        self.assertEqual(calls, [])
        self.assertTrue(any("cancelled" in item.lower() for item in outputs))

    def test_uninitialized_workspace_provisions_after_exact_confirmation(self):
        calls = []
        commands = []
        states = iter([
            "PROVISION /dev/disk/by-partuuid/1111-2222",
            "--version",
            "exit",
        ])

        def provisioner(config, *, passphrase, destructive_confirmation):
            calls.append((
                "provision",
                config.device,
                passphrase,
                destructive_confirmation,
            ))

        def closer(config, *, mounted):
            calls.append(("close", config.mount_point, mounted))

        def runner(args, cwd):
            commands.append((tuple(args), cwd))
            return 0

        code = run_secure_workspace_session(
            self.config(),
            input_fn=lambda _prompt: next(states),
            output_fn=lambda _message: None,
            new_passphrase_fn=lambda _prompt: b"new-secret",
            command_runner=runner,
            state_probe=lambda _config: RedPersistenceState.UNINITIALIZED,
            provisioner=provisioner,
            closer=closer,
        )

        self.assertEqual(code, 0)
        self.assertEqual(
            calls[0],
            (
                "provision",
                "/dev/disk/by-partuuid/1111-2222",
                b"new-secret",
                True,
            ),
        )
        self.assertEqual(calls[1], ("close", "/run/red-night-secure", True))
        self.assertEqual(commands[0][0], ("--version",))
        self.assertEqual(commands[0][1].as_posix(), "/run/red-night-secure")

    def test_new_passphrase_confirmation_mismatch_fails_before_provisioning(self):
        with (
            patch("red_night_app.appliance.getpass.getpass", side_effect=["one", "two"]),
        ):
            with self.assertRaises(ValueError):
                from red_night_app.appliance import _read_new_passphrase
                _read_new_passphrase("ignored")

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

    def test_secure_mode_cli_uses_explicit_persistence_device(self):
        with (
            patch("red_night_app.appliance.require_platform_privilege"),
            patch(
                "red_night_app.appliance.run_secure_workspace_session",
                return_value=3,
            ) as secure,
        ):
            code = main([
                "--mode",
                "secure-workspace",
                "--persistence-device",
                "/dev/disk/by-partuuid/1111-2222",
            ])
        self.assertEqual(code, 3)
        config = secure.call_args.args[0]
        self.assertEqual(config.device, "/dev/disk/by-partuuid/1111-2222")


if __name__ == "__main__":
    unittest.main()
