"""Red Night v0.44 Batch 4 encrypted-persistence contract tests."""

from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
RED_APP_ROOT = ROOT / "packages" / "red-night"
if str(RED_APP_ROOT) not in sys.path:
    sys.path.insert(0, str(RED_APP_ROOT))

from red_night_app.appliance import (  # noqa: E402
    RedLiveSessionMode,
    session_decision,
)
from red_night_app.persistence import (  # noqa: E402
    LUKS_TYPE,
    WORKSPACE_FILESYSTEM,
    WORKSPACE_MAPPER_NAME,
    WORKSPACE_MOUNT_POINT,
    RedPersistenceAction,
    RedPersistenceConfig,
    RedPersistenceState,
    RedPersistenceStep,
    plan_persistence_action,
    secure_workspace_ready,
)


class RedLivePersistenceContractTests(unittest.TestCase):
    def make_config(self, device="/dev/disk/by-partuuid/1111-2222"):
        return RedPersistenceConfig(device=device)

    def test_defaults_are_fixed_luks2_and_never_automatic(self):
        config = self.make_config()
        self.assertEqual(config.luks_type, LUKS_TYPE)
        self.assertEqual(config.filesystem, WORKSPACE_FILESYSTEM)
        self.assertEqual(config.mapper_name, WORKSPACE_MAPPER_NAME)
        self.assertEqual(config.mount_point, WORKSPACE_MOUNT_POINT)
        self.assertFalse(config.auto_discover)
        self.assertFalse(config.auto_format)
        self.assertFalse(config.auto_mount)

    def test_device_selection_must_be_explicit_and_stable(self):
        for device in (
            "",
            "/dev/sda1",
            "/dev/nvme0n1p3",
            "/dev/disk/by-id/",
            "/dev/disk/by-id/example-disk",
        ):
            with self.subTest(device=device):
                with self.assertRaises(ValueError):
                    RedPersistenceConfig(device=device)

        RedPersistenceConfig(device="/dev/disk/by-partuuid/1111-2222")
        RedPersistenceConfig(
            device="/dev/disk/by-id/usb-example_SERIAL-0:0-part3"
        )

    def test_contract_refuses_automatic_discovery_format_and_mount(self):
        for field in ("auto_discover", "auto_format", "auto_mount"):
            with self.subTest(field=field):
                kwargs = {"device": "/dev/disk/by-partuuid/1111-2222", field: True}
                with self.assertRaises(ValueError):
                    RedPersistenceConfig(**kwargs)

    def test_provisioning_requires_uninitialized_partition_and_confirmation(self):
        config = self.make_config()

        denied = plan_persistence_action(
            config,
            state=RedPersistenceState.UNINITIALIZED,
            action=RedPersistenceAction.PROVISION,
        )
        self.assertFalse(denied.allowed)
        self.assertTrue(denied.destructive)
        self.assertEqual(
            denied.reason,
            "explicit-destructive-confirmation-required",
        )
        self.assertEqual(denied.steps, ())

        allowed = plan_persistence_action(
            config,
            state=RedPersistenceState.UNINITIALIZED,
            action=RedPersistenceAction.PROVISION,
            destructive_confirmation=True,
        )
        self.assertTrue(allowed.allowed)
        self.assertTrue(allowed.destructive)
        self.assertTrue(allowed.requires_passphrase)
        self.assertEqual(
            allowed.steps,
            (
                RedPersistenceStep.LUKS2_FORMAT,
                RedPersistenceStep.LUKS2_OPEN,
                RedPersistenceStep.FILESYSTEM_CREATE,
                RedPersistenceStep.FILESYSTEM_MOUNT,
            ),
        )

    def test_existing_luks2_workspace_unlock_and_mount_are_separate(self):
        config = self.make_config()

        unlock = plan_persistence_action(
            config,
            state=RedPersistenceState.LUKS2_LOCKED,
            action=RedPersistenceAction.UNLOCK,
        )
        self.assertTrue(unlock.allowed)
        self.assertEqual(unlock.steps, (RedPersistenceStep.LUKS2_OPEN,))
        self.assertTrue(unlock.requires_passphrase)

        mount = plan_persistence_action(
            config,
            state=RedPersistenceState.LUKS2_OPEN,
            action=RedPersistenceAction.MOUNT,
        )
        self.assertTrue(mount.allowed)
        self.assertEqual(
            mount.steps,
            (RedPersistenceStep.FILESYSTEM_MOUNT,),
        )
        self.assertFalse(mount.requires_passphrase)

    def test_explicit_unmount_does_not_close_existing_mapping(self):
        config = self.make_config()
        plan = plan_persistence_action(
            config,
            state=RedPersistenceState.MOUNTED,
            action=RedPersistenceAction.UNMOUNT,
        )
        self.assertTrue(plan.allowed)
        self.assertFalse(plan.destructive)
        self.assertEqual(
            plan.steps,
            (RedPersistenceStep.FILESYSTEM_UNMOUNT,),
        )

    def test_safe_close_unmounts_before_closing_luks_mapping(self):
        config = self.make_config()
        plan = plan_persistence_action(
            config,
            state=RedPersistenceState.MOUNTED,
            action=RedPersistenceAction.SAFE_CLOSE,
        )
        self.assertTrue(plan.allowed)
        self.assertFalse(plan.destructive)
        self.assertEqual(
            plan.steps,
            (
                RedPersistenceStep.FILESYSTEM_UNMOUNT,
                RedPersistenceStep.LUKS2_CLOSE,
            ),
        )

    def test_missing_device_fails_closed_for_every_action(self):
        config = self.make_config()
        for action in RedPersistenceAction:
            with self.subTest(action=action):
                plan = plan_persistence_action(
                    config,
                    state=RedPersistenceState.MISSING,
                    action=action,
                    destructive_confirmation=True,
                )
                self.assertFalse(plan.allowed)
                self.assertEqual(
                    plan.reason,
                    "explicit-persistence-device-not-present",
                )

    def test_secure_workspace_requires_mounted_encrypted_workspace(self):
        for state in (
            RedPersistenceState.MISSING,
            RedPersistenceState.UNINITIALIZED,
            RedPersistenceState.LUKS2_LOCKED,
            RedPersistenceState.LUKS2_OPEN,
        ):
            with self.subTest(state=state):
                self.assertFalse(secure_workspace_ready(state))
                decision = session_decision(
                    RedLiveSessionMode.SECURE_WORKSPACE,
                    persistence_state=state,
                )
                self.assertFalse(decision.available)
                self.assertFalse(decision.launch_red_application)
                self.assertFalse(decision.persistent_workspace)
                self.assertEqual(
                    decision.reason,
                    "encrypted-persistence-not-mounted",
                )

        self.assertTrue(secure_workspace_ready(RedPersistenceState.MOUNTED))
        decision = session_decision(
            RedLiveSessionMode.SECURE_WORKSPACE,
            persistence_state=RedPersistenceState.MOUNTED,
        )
        self.assertTrue(decision.available)
        self.assertTrue(decision.launch_red_application)
        self.assertTrue(decision.persistent_workspace)
        self.assertEqual(decision.authorization_effect, "none")
        self.assertEqual(decision.reason, "encrypted-persistence-mounted")

    def test_batch_four_contract_contains_no_execution_adapter(self):
        source = (
            RED_APP_ROOT / "red_night_app" / "persistence.py"
        ).read_text(encoding="utf-8")
        forbidden = (
            "import subprocess",
            "from subprocess",
            "subprocess.run",
            "os.system",
            "/sbin/cryptsetup",
            "/usr/sbin/cryptsetup",
            "mkfs.ext4",
        )
        for token in forbidden:
            self.assertNotIn(token, source)


if __name__ == "__main__":
    unittest.main()
