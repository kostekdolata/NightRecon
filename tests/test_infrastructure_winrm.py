"""Tests for NightRecon read-only WinRM evidence contract."""

import unittest

from nightrecon.infrastructure_winrm import (
    WinRmConnectionProfile,
    WinRmPatchObservation,
    WinRmSystemObservation,
    build_winrm_patch_inventory_facts,
    build_winrm_system_identity_facts,
    supported_winrm_actions,
    validate_winrm_action,
)


class InfrastructureWinRmTests(unittest.TestCase):
    def test_profile_requires_tls_and_certificate_validation(self):
        profile = WinRmConnectionProfile(
            username="audit-user",
        )

        self.assertEqual(
            profile.port,
            5986,
        )
        self.assertTrue(
            profile.use_tls
        )
        self.assertTrue(
            profile.validate_server_certificate
        )

        with self.assertRaisesRegex(
            ValueError,
            "requires TLS",
        ):
            WinRmConnectionProfile(
                username="audit-user",
                use_tls=False,
            )

        with self.assertRaisesRegex(
            ValueError,
            "certificate validation",
        ):
            WinRmConnectionProfile(
                username="audit-user",
                validate_server_certificate=False,
            )

    def test_profile_bounds_are_enforced(self):
        with self.assertRaises(
            ValueError
        ):
            WinRmConnectionProfile(
                username="bad\nuser",
            )

        with self.assertRaises(
            ValueError
        ):
            WinRmConnectionProfile(
                username="audit-user",
                port=0,
            )

        with self.assertRaises(
            ValueError
        ):
            WinRmConnectionProfile(
                username="audit-user",
                connect_timeout=0,
            )

        with self.assertRaises(
            ValueError
        ):
            WinRmConnectionProfile(
                username="audit-user",
                operation_timeout=0,
            )

        with self.assertRaises(
            ValueError
        ):
            WinRmConnectionProfile(
                username="audit-user",
                max_patches=0,
            )

    def test_only_fixed_read_only_actions_are_supported(self):
        self.assertEqual(
            supported_winrm_actions(),
            (
                "winrm.system_identity",
                "winrm.patch_inventory",
            ),
        )

        self.assertEqual(
            validate_winrm_action(
                "winrm.system_identity"
            ),
            "winrm.system_identity",
        )

        with self.assertRaises(
            ValueError
        ):
            validate_winrm_action(
                "winrm.run_powershell"
            )

    def test_system_identity_normalizes_typed_facts(self):
        facts = build_winrm_system_identity_facts(
            WinRmSystemObservation(
                hostname="WIN-FILE01",
                os_name="Microsoft Windows Server 2025",
                os_version="10.0.26100",
                architecture="AMD64",
            )
        )

        self.assertEqual(
            tuple(
                (
                    fact.key,
                    fact.value,
                )
                for fact in facts
            ),
            (
                (
                    "windows.hostname",
                    "WIN-FILE01",
                ),
                (
                    "windows.os_name",
                    "Microsoft Windows Server 2025",
                ),
                (
                    "windows.os_version",
                    "10.0.26100",
                ),
                (
                    "windows.architecture",
                    "AMD64",
                ),
            ),
        )

    def test_system_identity_rejects_control_characters(self):
        with self.assertRaises(
            ValueError
        ):
            build_winrm_system_identity_facts(
                WinRmSystemObservation(
                    hostname="WIN\nBAD",
                    os_name="Windows",
                    os_version="1",
                    architecture="AMD64",
                )
            )

    def test_patch_inventory_is_bounded_normalized_and_deterministic(self):
        facts = build_winrm_patch_inventory_facts(
            (
                WinRmPatchObservation(
                    hotfix_id="kb5030219",
                ),
                WinRmPatchObservation(
                    hotfix_id="5012170",
                ),
            ),
            max_patches=10,
        )

        self.assertEqual(
            tuple(
                (
                    fact.key,
                    fact.value,
                )
                for fact in facts
            ),
            (
                (
                    "windows.patch_count",
                    "2",
                ),
                (
                    "windows.patch_0001.hotfix_id",
                    "KB5012170",
                ),
                (
                    "windows.patch_0002.hotfix_id",
                    "KB5030219",
                ),
            ),
        )

    def test_patch_inventory_rejects_duplicates_invalid_ids_and_overflow(self):
        with self.assertRaisesRegex(
            ValueError,
            "Duplicate",
        ):
            build_winrm_patch_inventory_facts(
                (
                    WinRmPatchObservation(
                        hotfix_id="KB5030219",
                    ),
                    WinRmPatchObservation(
                        hotfix_id="kb5030219",
                    ),
                ),
                max_patches=10,
            )

        with self.assertRaisesRegex(
            ValueError,
            "hotfix ID",
        ):
            build_winrm_patch_inventory_facts(
                (
                    WinRmPatchObservation(
                        hotfix_id="not-a-hotfix",
                    ),
                ),
                max_patches=10,
            )

        with self.assertRaisesRegex(
            ValueError,
            "exceed max_patches",
        ):
            build_winrm_patch_inventory_facts(
                (
                    WinRmPatchObservation(
                        hotfix_id="KB5000001",
                    ),
                    WinRmPatchObservation(
                        hotfix_id="KB5000002",
                    ),
                ),
                max_patches=1,
            )

        with self.assertRaises(
            ValueError
        ):
            build_winrm_patch_inventory_facts(
                (),
                max_patches=0,
            )


if __name__ == "__main__":
    unittest.main()
