"""Red Night v0.44 Batch 4 privileged persistence executor tests."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
RED_APP_ROOT = ROOT / "packages" / "red-night"
if str(RED_APP_ROOT) not in sys.path:
    sys.path.insert(0, str(RED_APP_ROOT))

from red_night_app.persistence import (  # noqa: E402
    RedPersistenceAction,
    RedPersistenceConfig,
    RedPersistenceState,
    plan_persistence_action,
)
from red_night_app.persistence_executor import (  # noqa: E402
    CRYPTSETUP,
    E2FSCK,
    INSTALL,
    MKFS_EXT4,
    MOUNT,
    UMOUNT,
    PersistenceExecutionError,
    PrivilegedCommandResult,
    execute_persistence_plan,
    inspect_locked_workspace_integrity,
    mount_workspace,
    provision_workspace,
    safe_close_and_verify_workspace,
    safe_close_workspace,
    unlock_workspace,
)


class FakeRunner:
    def __init__(self, *, fail_at: int | None = None):
        self.calls: list[tuple[tuple[str, ...], bytes | None]] = []
        self.fail_at = fail_at

    def __call__(self, argv, stdin_bytes):
        self.calls.append((tuple(argv), stdin_bytes))
        if self.fail_at is not None and len(self.calls) == self.fail_at:
            return PrivilegedCommandResult(returncode=9)
        return PrivilegedCommandResult(returncode=0)


class RedLivePersistenceExecutorTests(unittest.TestCase):
    def make_config(self):
        return RedPersistenceConfig(
            device="/dev/disk/by-partuuid/1111-2222"
        )

    def test_provision_uses_fixed_order_and_secret_only_on_stdin(self):
        config = self.make_config()
        runner = FakeRunner()
        secret = b"correct horse battery staple"

        provision_workspace(
            config,
            passphrase=secret,
            destructive_confirmation=True,
            runner=runner,
            target_probe=lambda _device: True,
        )

        argv = [call[0] for call in runner.calls]
        stdin_values = [call[1] for call in runner.calls]

        self.assertEqual(
            argv,
            [
                (
                    CRYPTSETUP,
                    "luksFormat",
                    "--type",
                    "luks2",
                    "--batch-mode",
                    "--key-file",
                    "-",
                    config.device,
                ),
                (
                    CRYPTSETUP,
                    "open",
                    "--type",
                    "luks2",
                    "--key-file",
                    "-",
                    config.device,
                    config.mapper_name,
                ),
                (
                    MKFS_EXT4,
                    "-F",
                    "-L",
                    "RED_NIGHT_WORKSPACE",
                    f"/dev/mapper/{config.mapper_name}",
                ),
                (
                    INSTALL,
                    "-d",
                    "-m",
                    "0700",
                    config.mount_point,
                ),
                (
                    MOUNT,
                    "-t",
                    "ext4",
                    "-o",
                    "nosuid,nodev",
                    f"/dev/mapper/{config.mapper_name}",
                    config.mount_point,
                ),
            ],
        )
        self.assertEqual(stdin_values[:2], [secret, secret])
        self.assertEqual(stdin_values[2:], [None, None, None])

        for command, _stdin in runner.calls:
            joined = " ".join(command).encode()
            self.assertNotIn(secret, joined)

    def test_provision_refuses_without_explicit_destructive_confirmation(self):
        runner = FakeRunner()
        with self.assertRaises(ValueError):
            provision_workspace(
                self.make_config(),
                passphrase=b"secret",
                destructive_confirmation=False,
                runner=runner,
                target_probe=lambda _device: True,
            )
        self.assertEqual(runner.calls, [])

    def test_provision_refuses_target_with_existing_signature(self):
        runner = FakeRunner()
        with self.assertRaises(ValueError):
            provision_workspace(
                self.make_config(),
                passphrase=b"secret",
                destructive_confirmation=True,
                runner=runner,
                target_probe=lambda _device: False,
            )
        self.assertEqual(runner.calls, [])

    def test_unlock_and_mount_are_separate_operations(self):
        config = self.make_config()
        unlock_runner = FakeRunner()
        mount_runner = FakeRunner()

        unlock_workspace(
            config,
            passphrase=b"secret",
            runner=unlock_runner,
        )
        mount_workspace(config, runner=mount_runner)

        self.assertEqual(len(unlock_runner.calls), 1)
        self.assertEqual(
            unlock_runner.calls[0][0],
            (
                CRYPTSETUP,
                "open",
                "--type",
                "luks2",
                "--key-file",
                "-",
                config.device,
                config.mapper_name,
            ),
        )
        self.assertEqual(unlock_runner.calls[0][1], b"secret")

        self.assertEqual(
            [call[0][0] for call in mount_runner.calls],
            [INSTALL, MOUNT],
        )
        self.assertTrue(all(call[1] is None for call in mount_runner.calls))

    def test_safe_close_unmounts_before_cryptsetup_close(self):
        config = self.make_config()
        runner = FakeRunner()

        safe_close_workspace(config, mounted=True, runner=runner)

        self.assertEqual(
            [call[0] for call in runner.calls],
            [
                (UMOUNT, config.mount_point),
                (CRYPTSETUP, "close", config.mapper_name),
            ],
        )

    def test_open_but_unmounted_workspace_closes_without_umount(self):
        config = self.make_config()
        runner = FakeRunner()

        safe_close_workspace(config, mounted=False, runner=runner)

        self.assertEqual(
            [call[0] for call in runner.calls],
            [(CRYPTSETUP, "close", config.mapper_name)],
        )

    def test_safe_close_and_verify_requires_locked_final_state(self):
        config = self.make_config()
        runner = FakeRunner()

        observed = safe_close_and_verify_workspace(
            config,
            mounted=True,
            runner=runner,
            state_probe=lambda _config: RedPersistenceState.LUKS2_LOCKED,
        )

        self.assertIs(observed, RedPersistenceState.LUKS2_LOCKED)
        self.assertEqual(
            [call[0] for call in runner.calls],
            [
                (UMOUNT, config.mount_point),
                (CRYPTSETUP, "close", config.mapper_name),
            ],
        )

        with self.assertRaises(PersistenceExecutionError):
            safe_close_and_verify_workspace(
                config,
                mounted=False,
                runner=FakeRunner(),
                state_probe=lambda _config: RedPersistenceState.LUKS2_OPEN,
            )

    def test_integrity_inspection_is_read_only_and_restores_locked_state(self):
        config = self.make_config()
        runner = FakeRunner()

        result = inspect_locked_workspace_integrity(
            config,
            passphrase=b"secret",
            runner=runner,
            state_probe=lambda _config: RedPersistenceState.LUKS2_LOCKED,
        )

        self.assertTrue(result.clean)
        self.assertFalse(result.issues_detected)
        self.assertEqual(result.reason, "filesystem-clean")
        self.assertEqual(
            [call[0] for call in runner.calls],
            [
                (
                    CRYPTSETUP,
                    "open",
                    "--type",
                    "luks2",
                    "--key-file",
                    "-",
                    config.device,
                    config.mapper_name,
                ),
                (
                    E2FSCK,
                    "-f",
                    "-n",
                    f"/dev/mapper/{config.mapper_name}",
                ),
                (CRYPTSETUP, "close", config.mapper_name),
            ],
        )
        self.assertEqual(runner.calls[0][1], b"secret")
        self.assertTrue(all(call[1] is None for call in runner.calls[1:]))

    def test_integrity_inspection_reports_issues_without_repair(self):
        config = self.make_config()
        calls = []

        def runner(argv, stdin_bytes):
            calls.append((tuple(argv), stdin_bytes))
            if argv[0] == E2FSCK:
                return PrivilegedCommandResult(returncode=4)
            return PrivilegedCommandResult(returncode=0)

        result = inspect_locked_workspace_integrity(
            config,
            passphrase=b"secret",
            runner=runner,
            state_probe=lambda _config: RedPersistenceState.LUKS2_LOCKED,
        )

        self.assertFalse(result.clean)
        self.assertTrue(result.issues_detected)
        self.assertEqual(result.returncode, 4)
        self.assertIn("no-repair-performed", result.reason)
        self.assertEqual(calls[-1][0], (CRYPTSETUP, "close", config.mapper_name))

    def test_integrity_inspection_operational_failure_still_closes_mapper(self):
        config = self.make_config()
        calls = []

        def runner(argv, stdin_bytes):
            calls.append((tuple(argv), stdin_bytes))
            if argv[0] == E2FSCK:
                return PrivilegedCommandResult(returncode=8)
            return PrivilegedCommandResult(returncode=0)

        with self.assertRaises(PersistenceExecutionError):
            inspect_locked_workspace_integrity(
                config,
                passphrase=b"secret",
                runner=runner,
                state_probe=lambda _config: RedPersistenceState.LUKS2_LOCKED,
            )

        self.assertEqual(calls[-1][0], (CRYPTSETUP, "close", config.mapper_name))

    def test_executor_rejects_tampered_plan(self):
        config = self.make_config()
        canonical = plan_persistence_action(
            config,
            state=RedPersistenceState.LUKS2_LOCKED,
            action=RedPersistenceAction.UNLOCK,
        )
        tampered = replace(canonical, reason="tampered")
        runner = FakeRunner()

        with self.assertRaises(ValueError):
            execute_persistence_plan(
                config,
                tampered,
                passphrase=b"secret",
                runner=runner,
            )
        self.assertEqual(runner.calls, [])

    def test_executor_refuses_secret_when_not_required(self):
        config = self.make_config()
        plan = plan_persistence_action(
            config,
            state=RedPersistenceState.LUKS2_OPEN,
            action=RedPersistenceAction.MOUNT,
        )
        runner = FakeRunner()

        with self.assertRaises(ValueError):
            execute_persistence_plan(
                config,
                plan,
                passphrase=b"should-not-be-used",
                runner=runner,
            )
        self.assertEqual(runner.calls, [])

    def test_executor_refuses_missing_empty_or_nul_passphrase(self):
        config = self.make_config()
        plan = plan_persistence_action(
            config,
            state=RedPersistenceState.LUKS2_LOCKED,
            action=RedPersistenceAction.UNLOCK,
        )

        for secret in (None, b"", b"bad\x00secret"):
            runner = FakeRunner()
            with self.subTest(secret=secret):
                with self.assertRaises(ValueError):
                    execute_persistence_plan(
                        config,
                        plan,
                        passphrase=secret,
                        runner=runner,
                    )
                self.assertEqual(runner.calls, [])

    def test_failed_privileged_command_stops_sequence_and_redacts_secret(self):
        config = self.make_config()
        runner = FakeRunner(fail_at=2)
        secret = b"top-secret-passphrase"

        with self.assertRaises(PersistenceExecutionError) as caught:
            provision_workspace(
                config,
                passphrase=secret,
                destructive_confirmation=True,
                runner=runner,
                target_probe=lambda _device: True,
            )

        self.assertEqual(len(runner.calls), 2)
        self.assertNotIn(secret.decode(), str(caught.exception))
        self.assertNotIn(config.device, str(caught.exception))

    def test_executor_contains_no_shell_execution(self):
        source = (
            RED_APP_ROOT / "red_night_app" / "persistence_executor.py"
        ).read_text(encoding="utf-8")
        self.assertNotIn("shell=True", source)
        self.assertNotIn("os.system", source)
        self.assertNotIn("shlex", source)

    def test_disposable_fixture_proves_reboot_and_ephemeral_boundaries(self):
        source = (
            ROOT / "tests" / "red_live_luks_executor_runtime.py"
        ).read_text(encoding="utf-8")
        self.assertIn("--verify-reboot", source)
        self.assertIn("RED_NIGHT_REBOOT_PERSISTENCE_OK", source)
        self.assertIn("run_ephemeral_operator_session", source)
        self.assertIn("RED_NIGHT_EPHEMERAL_ISOLATION_OK", source)
        self.assertIn("sha256(image)", source)
        self.assertIn("input=secret + b", source)
        self.assertNotIn("secret.decode()", source)


if __name__ == "__main__":
    unittest.main()
