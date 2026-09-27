"""Tests for fail-closed credentialed infrastructure policy."""

import unittest

from nightrecon.infrastructure_models import (
    CredentialKind,
    CredentialReference,
    CredentialSourceKind,
    InfrastructureAction,
    InfrastructureActionCategory,
    InfrastructureActionDefinition,
    InfrastructureActionState,
    InfrastructureTransport,
)
from nightrecon.infrastructure_policy import (
    InfrastructureAssessmentPolicy,
    authorize_infrastructure_action,
    reserve_infrastructure_action,
)
from nightrecon.infrastructure_registry import (
    get_infrastructure_action_definition,
)
from nightrecon.scope import Scope


def _credential():
    return CredentialReference(
        credential_id="corp-readonly",
        kind=CredentialKind.PASSWORD,
        source_kind=CredentialSourceKind.EXTERNAL_SECRET,
    )


def _policy(
    *,
    allowed_transports=(
        InfrastructureTransport.SSH,
    ),
    max_actions=3,
):
    return InfrastructureAssessmentPolicy(
        scope=Scope.from_values(
            [
                "server.example.test",
            ]
        ),
        allowed_transports=allowed_transports,
        max_actions=max_actions,
    )


def _action(
    *,
    target="server.example.test",
    transport=InfrastructureTransport.SSH,
    action_id="ssh.system_identity",
    credential_id="corp-readonly",
):
    return InfrastructureAction(
        target=target,
        transport=transport,
        action_id=action_id,
        credential_id=credential_id,
    )


class InfrastructurePolicyTests(unittest.TestCase):
    def test_authorized_read_only_action_passes(self):
        policy = _policy()
        state = InfrastructureActionState(
            actions_used=0,
            max_actions=3,
        )
        action = _action()
        definition = get_infrastructure_action_definition(
            action.action_id
        )

        decision = authorize_infrastructure_action(
            action=action,
            definition=definition,
            credential=_credential(),
            policy=policy,
            state=state,
        )

        self.assertTrue(
            decision.allowed
        )
        self.assertEqual(
            decision.reason,
            "authorized",
        )
        self.assertEqual(
            decision.target,
            "server.example.test",
        )
        self.assertNotIn(
            "password",
            repr(decision).lower(),
        )

    def test_out_of_scope_target_is_denied(self):
        action = _action(
            target="outside.example.test"
        )
        decision = authorize_infrastructure_action(
            action=action,
            definition=get_infrastructure_action_definition(
                action.action_id
            ),
            credential=_credential(),
            policy=_policy(),
            state=InfrastructureActionState(
                actions_used=0,
                max_actions=3,
            ),
        )

        self.assertFalse(
            decision.allowed
        )
        self.assertEqual(
            decision.reason,
            "outside_authorized_scope",
        )

    def test_transport_must_be_allowlisted_and_match_definition(self):
        action = _action(
            transport=InfrastructureTransport.SMB,
            action_id="ssh.system_identity",
        )

        decision = authorize_infrastructure_action(
            action=action,
            definition=get_infrastructure_action_definition(
                "ssh.system_identity"
            ),
            credential=_credential(),
            policy=_policy(
                allowed_transports=(
                    InfrastructureTransport.SSH,
                    InfrastructureTransport.SMB,
                )
            ),
            state=InfrastructureActionState(
                actions_used=0,
                max_actions=3,
            ),
        )

        self.assertFalse(
            decision.allowed
        )
        self.assertEqual(
            decision.reason,
            "action_transport_mismatch",
        )

        smb_action = _action(
            transport=InfrastructureTransport.SMB,
            action_id="smb.server_identity",
        )
        smb_decision = authorize_infrastructure_action(
            action=smb_action,
            definition=get_infrastructure_action_definition(
                "smb.server_identity"
            ),
            credential=_credential(),
            policy=_policy(),
            state=InfrastructureActionState(
                actions_used=0,
                max_actions=3,
            ),
        )

        self.assertFalse(
            smb_decision.allowed
        )
        self.assertEqual(
            smb_decision.reason,
            "transport_not_allowed",
        )

    def test_credential_reference_must_match_exactly(self):
        action = _action(
            credential_id="other-reference"
        )

        decision = authorize_infrastructure_action(
            action=action,
            definition=get_infrastructure_action_definition(
                action.action_id
            ),
            credential=_credential(),
            policy=_policy(),
            state=InfrastructureActionState(
                actions_used=0,
                max_actions=3,
            ),
        )

        self.assertFalse(
            decision.allowed
        )
        self.assertEqual(
            decision.reason,
            "credential_reference_mismatch",
        )

    def test_mutating_action_is_blocked_by_default(self):
        definition = InfrastructureActionDefinition(
            action_id="ssh.mutating-test",
            transport=InfrastructureTransport.SSH,
            category=InfrastructureActionCategory.CONFIGURATION,
            description="Test-only mutating action.",
            mutating=True,
        )
        action = _action(
            action_id="ssh.mutating-test"
        )

        decision = authorize_infrastructure_action(
            action=action,
            definition=definition,
            credential=_credential(),
            policy=_policy(),
            state=InfrastructureActionState(
                actions_used=0,
                max_actions=3,
            ),
        )

        self.assertFalse(
            decision.allowed
        )
        self.assertEqual(
            decision.reason,
            "mutating_action_not_allowed",
        )

    def test_budget_is_enforced_and_reserved_immutably(self):
        policy = _policy(
            max_actions=1
        )
        state = InfrastructureActionState(
            actions_used=0,
            max_actions=1,
        )
        action = _action()
        decision = authorize_infrastructure_action(
            action=action,
            definition=get_infrastructure_action_definition(
                action.action_id
            ),
            credential=_credential(),
            policy=policy,
            state=state,
        )

        reserved = reserve_infrastructure_action(
            state=state,
            decision=decision,
        )

        self.assertEqual(
            state.actions_used,
            0,
        )
        self.assertEqual(
            reserved.actions_used,
            1,
        )
        self.assertEqual(
            reserved.actions_remaining,
            0,
        )

        exhausted = authorize_infrastructure_action(
            action=action,
            definition=get_infrastructure_action_definition(
                action.action_id
            ),
            credential=_credential(),
            policy=policy,
            state=reserved,
        )

        self.assertFalse(
            exhausted.allowed
        )
        self.assertEqual(
            exhausted.reason,
            "action_budget_exhausted",
        )

    def test_invalid_policy_and_mismatched_state_fail_closed(self):
        with self.assertRaises(
            ValueError
        ):
            InfrastructureAssessmentPolicy(
                scope=Scope.from_values(
                    [
                        "server.example.test",
                    ]
                ),
                allowed_transports=(),
            )

        with self.assertRaises(
            ValueError
        ):
            authorize_infrastructure_action(
                action=_action(),
                definition=get_infrastructure_action_definition(
                    "ssh.system_identity"
                ),
                credential=_credential(),
                policy=_policy(
                    max_actions=3
                ),
                state=InfrastructureActionState(
                    actions_used=0,
                    max_actions=2,
                ),
            )


if __name__ == "__main__":
    unittest.main()
