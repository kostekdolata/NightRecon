"""Tests for NightRecon credentialed infrastructure models and registry."""

import unittest
from dataclasses import fields

from nightrecon.infrastructure_models import (
    CredentialKind,
    CredentialReference,
    CredentialSourceKind,
    InfrastructureAction,
    InfrastructureActionCategory,
    InfrastructureTransport,
)
from nightrecon.infrastructure_registry import (
    built_in_infrastructure_actions,
    get_infrastructure_action_definition,
)


class InfrastructureModelTests(unittest.TestCase):
    def test_credential_reference_contains_metadata_only(self):
        reference = CredentialReference(
            credential_id="corp-readonly",
            kind=CredentialKind.PASSWORD,
            source_kind=CredentialSourceKind.EXTERNAL_SECRET,
        )

        names = {
            item.name
            for item in fields(reference)
        }

        self.assertEqual(
            names,
            {
                "credential_id",
                "kind",
                "source_kind",
            },
        )
        self.assertNotIn(
            "password_value",
            names,
        )
        self.assertNotIn(
            "secret",
            names,
        )
        self.assertNotIn(
            "secret_value",
            names,
        )

    def test_infrastructure_action_has_no_command_field(self):
        action = InfrastructureAction(
            target="server.example.test",
            transport=InfrastructureTransport.SSH,
            action_id="ssh.system_identity",
            credential_id="corp-readonly",
        )

        names = {
            item.name
            for item in fields(action)
        }

        self.assertEqual(
            names,
            {
                "target",
                "transport",
                "action_id",
                "credential_id",
            },
        )
        self.assertNotIn(
            "command",
            names,
        )

    def test_builtin_registry_contains_only_non_mutating_symbolic_actions(self):
        actions = built_in_infrastructure_actions()

        self.assertGreater(
            len(actions),
            0,
        )
        self.assertEqual(
            len(
                {
                    item.action_id
                    for item in actions
                }
            ),
            len(actions),
        )

        for action in actions:
            with self.subTest(
                action_id=action.action_id
            ):
                self.assertFalse(
                    action.mutating
                )
                self.assertIn(
                    action.category,
                    {
                        InfrastructureActionCategory.IDENTITY,
                        InfrastructureActionCategory.INVENTORY,
                        InfrastructureActionCategory.PATCH,
                    },
                )
                self.assertNotIn(
                    " ",
                    action.action_id,
                )

    def test_registry_resolves_exact_symbolic_action(self):
        definition = get_infrastructure_action_definition(
            "ssh.system_identity"
        )

        self.assertEqual(
            definition.transport,
            InfrastructureTransport.SSH,
        )
        self.assertFalse(
            definition.mutating
        )

        with self.assertRaises(
            ValueError
        ):
            get_infrastructure_action_definition(
                "ssh.system_identity; whoami"
            )


if __name__ == "__main__":
    unittest.main()
