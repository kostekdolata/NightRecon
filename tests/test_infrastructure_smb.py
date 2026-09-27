"""Tests for NightRecon bounded read-only SMB evidence contract."""

import unittest
from dataclasses import fields
from pathlib import Path

import nightrecon.infrastructure_smb as infrastructure_smb

from nightrecon.infrastructure_smb import (
    SmbConnectionProfile,
    SmbShareObservation,
    build_smb_server_identity_facts,
    build_smb_share_inventory_facts,
    supported_smb_actions,
    validate_smb_action,
)


class SmbEvidenceContractTests(unittest.TestCase):
    def test_module_source_contains_no_embedded_control_bytes(self):
        source = Path(
            infrastructure_smb.__file__
        ).read_bytes()

        for value in (
            0,
            31,
            127,
        ):
            with self.subTest(
                value=value
            ):
                self.assertNotIn(
                    bytes(
                        [
                            value,
                        ]
                    ),
                    source,
                )

    def test_profile_contains_non_secret_metadata_only(self):
        profile = SmbConnectionProfile(
            username="audit-user",
            port=445,
            connect_timeout=3.0,
            operation_timeout=4.0,
            max_shares=64,
        )

        names = {
            item.name
            for item in fields(
                profile
            )
        }

        self.assertEqual(
            names,
            {
                "username",
                "port",
                "connect_timeout",
                "operation_timeout",
                "max_shares",
            },
        )
        self.assertNotIn(
            "password",
            names,
        )
        self.assertNotIn(
            "credential",
            names,
        )
        self.assertNotIn(
            "command",
            names,
        )

    def test_profile_validation_fails_closed(self):
        invalid = (
            {
                "username": "",
            },
            {
                "username": "audit\nuser",
            },
            {
                "username": "audit-user",
                "port": 0,
            },
            {
                "username": "audit-user",
                "connect_timeout": 0,
            },
            {
                "username": "audit-user",
                "operation_timeout": 0,
            },
            {
                "username": "audit-user",
                "max_shares": 0,
            },
            {
                "username": "audit-user",
                "max_shares": 1025,
            },
        )

        for kwargs in invalid:
            with self.subTest(
                kwargs=kwargs
            ):
                with self.assertRaises(
                    ValueError
                ):
                    SmbConnectionProfile(
                        **kwargs
                    )

    def test_supported_actions_are_exact_and_read_only_symbolic_ids(self):
        self.assertEqual(
            supported_smb_actions(),
            (
                "smb.server_identity",
                "smb.share_inventory",
            ),
        )

        for action_id in supported_smb_actions():
            self.assertEqual(
                validate_smb_action(
                    action_id
                ),
                action_id,
            )

        for unsafe in (
            "smb.server_identity; whoami",
            "smb.write_file",
            "smb.delete_share",
            "",
        ):
            with self.subTest(
                unsafe=unsafe
            ):
                with self.assertRaises(
                    ValueError
                ):
                    validate_smb_action(
                        unsafe
                    )

    def test_server_identity_facts_are_bounded_and_deterministic(self):
        facts = build_smb_server_identity_facts(
            server_name="FILE01",
            domain_name="EXAMPLE",
            dialect="3.1.1",
            signing_required=True,
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
                    "smb.server_name",
                    "FILE01",
                ),
                (
                    "smb.domain_name",
                    "EXAMPLE",
                ),
                (
                    "smb.dialect",
                    "3.1.1",
                ),
                (
                    "smb.signing_required",
                    "true",
                ),
            ),
        )

    def test_server_identity_rejects_invalid_text(self):
        for field, value in (
            (
                "server_name",
                "",
            ),
            (
                "server_name",
                "FILE\n01",
            ),
            (
                "domain_name",
                "",
            ),
            (
                "dialect",
                "3.1.1\x00bad",
            ),
        ):
            kwargs = {
                "server_name": "FILE01",
                "domain_name": "EXAMPLE",
                "dialect": "3.1.1",
                "signing_required": False,
            }
            kwargs[
                field
            ] = value

            with self.subTest(
                field=field,
                value=value,
            ):
                with self.assertRaises(
                    ValueError
                ):
                    build_smb_server_identity_facts(
                        **kwargs
                    )

    def test_share_inventory_is_sorted_bounded_and_typed(self):
        facts = build_smb_share_inventory_facts(
            (
                SmbShareObservation(
                    name="Public",
                    share_type="disk",
                ),
                SmbShareObservation(
                    name="IPC$",
                    share_type="ipc",
                ),
                SmbShareObservation(
                    name="Print$",
                    share_type="print",
                ),
            ),
            max_shares=8,
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
                    "smb.share_count",
                    "3",
                ),
                (
                    "smb.share_001.name",
                    "IPC$",
                ),
                (
                    "smb.share_001.type",
                    "ipc",
                ),
                (
                    "smb.share_002.name",
                    "Print$",
                ),
                (
                    "smb.share_002.type",
                    "print",
                ),
                (
                    "smb.share_003.name",
                    "Public",
                ),
                (
                    "smb.share_003.type",
                    "disk",
                ),
            ),
        )

    def test_share_inventory_rejects_duplicates_and_limit_overflow(self):
        duplicate = (
            SmbShareObservation(
                name="Public",
                share_type="disk",
            ),
            SmbShareObservation(
                name="public",
                share_type="disk",
            ),
        )

        with self.assertRaisesRegex(
            ValueError,
            "Duplicate",
        ):
            build_smb_share_inventory_facts(
                duplicate,
                max_shares=8,
            )

        with self.assertRaisesRegex(
            ValueError,
            "exceed",
        ):
            build_smb_share_inventory_facts(
                (
                    SmbShareObservation(
                        name="A",
                        share_type="disk",
                    ),
                    SmbShareObservation(
                        name="B",
                        share_type="disk",
                    ),
                ),
                max_shares=1,
            )

    def test_share_observation_rejects_invalid_names_and_types(self):
        for kwargs in (
            {
                "name": "",
                "share_type": "disk",
            },
            {
                "name": "Bad\nShare",
                "share_type": "disk",
            },
            {
                "name": "Public",
                "share_type": "arbitrary",
            },
        ):
            with self.subTest(
                kwargs=kwargs
            ):
                with self.assertRaises(
                    ValueError
                ):
                    SmbShareObservation(
                        **kwargs
                    )

    def test_share_inventory_limit_validation_fails_closed(self):
        for limit in (
            0,
            1025,
        ):
            with self.subTest(
                limit=limit
            ):
                with self.assertRaises(
                    ValueError
                ):
                    build_smb_share_inventory_facts(
                        (),
                        max_shares=limit,
                    )


if __name__ == "__main__":
    unittest.main()
