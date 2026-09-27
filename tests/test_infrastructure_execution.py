"""Tests for NightRecon one-shot infrastructure execution contract."""

import unittest
from unittest.mock import patch

from nightrecon.credential_resolution import (
    CredentialBinding,
    resolve_credential,
)
from nightrecon.infrastructure_execution import (
    InfrastructureAdapterOutcome,
    InfrastructureFact,
    execute_infrastructure_action,
)
from nightrecon.infrastructure_models import (
    CredentialKind,
    CredentialReference,
    CredentialSourceKind,
    InfrastructureAction,
    InfrastructureActionState,
    InfrastructureTransport,
)
from nightrecon.infrastructure_policy import (
    InfrastructureAssessmentPolicy,
    authorize_infrastructure_action,
)
from nightrecon.infrastructure_registry import (
    get_infrastructure_action_definition,
)
from nightrecon.scope import Scope


_SECRET = "transport-contract-secret"


class _FakeSshAdapter:
    transport = InfrastructureTransport.SSH

    def __init__(
        self,
        *,
        success=True,
        fail=False,
    ):
        self.success = success
        self.fail = fail
        self.calls = []
        self.observed_secret = None

    def execute(
        self,
        *,
        target,
        action_id,
        credential,
    ):
        with credential.material.reveal_text() as value:
            self.observed_secret = value
            self.calls.append(
                (
                    target,
                    action_id,
                    credential.reference.credential_id,
                )
            )

            if self.fail:
                raise RuntimeError(
                    f"adapter failure with {_SECRET}"
                )

            return InfrastructureAdapterOutcome(
                success=self.success,
                reason=(
                    "completed"
                    if self.success
                    else "adapter_reported_failure"
                ),
                facts=(
                    InfrastructureFact(
                        key="test.identity",
                        value="example",
                    ),
                ),
            )


class _FakeSmbAdapter(
    _FakeSshAdapter
):
    transport = (
        InfrastructureTransport.SMB
    )


def _credential():
    reference = CredentialReference(
        credential_id="corp-readonly",
        kind=CredentialKind.PASSWORD,
        source_kind=CredentialSourceKind.ENVIRONMENT,
    )
    return resolve_credential(
        CredentialBinding(
            reference=reference,
            source_name="NIGHTRECON_TRANSPORT_SECRET",
        ),
        environment={
            "NIGHTRECON_TRANSPORT_SECRET": _SECRET,
        },
    )


def _action():
    return InfrastructureAction(
        target="server.example.test",
        transport=InfrastructureTransport.SSH,
        action_id="ssh.system_identity",
        credential_id="corp-readonly",
    )


def _policy():
    return InfrastructureAssessmentPolicy(
        scope=Scope.from_values(
            [
                "server.example.test",
            ]
        ),
        allowed_transports=(
            InfrastructureTransport.SSH,
        ),
        max_actions=2,
    )


def _decision(
    action,
    state,
):
    definition = get_infrastructure_action_definition(
        action.action_id
    )
    return (
        definition,
        authorize_infrastructure_action(
            action=action,
            definition=definition,
            credential=CredentialReference(
                credential_id="corp-readonly",
                kind=CredentialKind.PASSWORD,
                source_kind=CredentialSourceKind.ENVIRONMENT,
            ),
            policy=_policy(),
            state=state,
        ),
    )


class InfrastructureExecutionTests(unittest.TestCase):
    def test_authorized_action_consumes_one_shot_credential_and_budget(self):
        action = _action()
        state = InfrastructureActionState(
            actions_used=0,
            max_actions=2,
        )
        definition, decision = _decision(
            action,
            state,
        )
        credential = _credential()
        adapter = _FakeSshAdapter()

        result = execute_infrastructure_action(
            action=action,
            definition=definition,
            decision=decision,
            state=state,
            credential=credential,
            adapter=adapter,
        )

        self.assertTrue(
            result.success
        )
        self.assertEqual(
            result.reason,
            "completed",
        )
        self.assertEqual(
            result.state.actions_used,
            1,
        )
        self.assertEqual(
            result.facts,
            (
                InfrastructureFact(
                    key="test.identity",
                    value="example",
                ),
            ),
        )
        self.assertEqual(
            adapter.calls,
            [
                (
                    "server.example.test",
                    "ssh.system_identity",
                    "corp-readonly",
                )
            ],
        )
        self.assertEqual(
            adapter.observed_secret,
            _SECRET,
        )
        self.assertTrue(
            credential.material.cleared
        )
        self.assertNotIn(
            _SECRET,
            repr(
                result
            ),
        )

    def test_denied_action_never_reaches_adapter_and_credential_is_cleared(self):
        action = _action()
        state = InfrastructureActionState(
            actions_used=0,
            max_actions=2,
        )
        definition, decision = _decision(
            action,
            state,
        )
        denied = type(
            decision
        )(
            allowed=False,
            reason="outside_authorized_scope",
            target=decision.target,
            transport=decision.transport,
            action_id=decision.action_id,
            credential_id=decision.credential_id,
        )
        credential = _credential()
        adapter = _FakeSshAdapter()

        with self.assertRaises(
            PermissionError
        ):
            execute_infrastructure_action(
                action=action,
                definition=definition,
                decision=denied,
                state=state,
                credential=credential,
                adapter=adapter,
            )

        self.assertEqual(
            adapter.calls,
            [],
        )
        self.assertTrue(
            credential.material.cleared
        )
        self.assertEqual(
            state.actions_used,
            0,
        )

    def test_transport_mismatch_fails_before_adapter_and_clears_credential(self):
        action = _action()
        state = InfrastructureActionState(
            actions_used=0,
            max_actions=2,
        )
        definition, decision = _decision(
            action,
            state,
        )
        credential = _credential()
        adapter = _FakeSmbAdapter()

        with self.assertRaisesRegex(
            ValueError,
            "adapter does not match",
        ):
            execute_infrastructure_action(
                action=action,
                definition=definition,
                decision=decision,
                state=state,
                credential=credential,
                adapter=adapter,
            )

        self.assertEqual(
            adapter.calls,
            [],
        )
        self.assertTrue(
            credential.material.cleared
        )

    def test_adapter_failure_is_sanitized_and_consumes_attempt_budget(self):
        action = _action()
        state = InfrastructureActionState(
            actions_used=0,
            max_actions=2,
        )
        definition, decision = _decision(
            action,
            state,
        )
        credential = _credential()
        adapter = _FakeSshAdapter(
            fail=True
        )

        result = execute_infrastructure_action(
            action=action,
            definition=definition,
            decision=decision,
            state=state,
            credential=credential,
            adapter=adapter,
        )

        self.assertFalse(
            result.success
        )
        self.assertEqual(
            result.reason,
            "transport_failed",
        )
        self.assertEqual(
            result.state.actions_used,
            1,
        )
        self.assertNotIn(
            _SECRET,
            repr(
                result
            ),
        )
        self.assertTrue(
            credential.material.cleared
        )

    def test_adapter_reported_failure_is_secret_free(self):
        action = _action()
        state = InfrastructureActionState(
            actions_used=0,
            max_actions=2,
        )
        definition, decision = _decision(
            action,
            state,
        )
        credential = _credential()
        adapter = _FakeSshAdapter(
            success=False
        )

        result = execute_infrastructure_action(
            action=action,
            definition=definition,
            decision=decision,
            state=state,
            credential=credential,
            adapter=adapter,
        )

        self.assertFalse(
            result.success
        )
        self.assertEqual(
            result.reason,
            "adapter_reported_failure",
        )
        self.assertEqual(
            result.state.actions_used,
            1,
        )
        self.assertNotIn(
            _SECRET,
            repr(
                result
            ),
        )

    def test_expired_credential_never_reaches_adapter_or_consumes_budget(self):
        action = _action()
        state = InfrastructureActionState(
            actions_used=0,
            max_actions=2,
        )
        definition, decision = _decision(
            action,
            state,
        )

        with patch(
            "nightrecon.credential_resolution.time.monotonic",
            side_effect=[
                100.0,
                102.0,
            ],
        ):
            reference = CredentialReference(
                credential_id="corp-readonly",
                kind=CredentialKind.PASSWORD,
                source_kind=CredentialSourceKind.ENVIRONMENT,
            )
            credential = resolve_credential(
                CredentialBinding(
                    reference=reference,
                    source_name="NIGHTRECON_TRANSPORT_SECRET",
                ),
                environment={
                    "NIGHTRECON_TRANSPORT_SECRET": _SECRET,
                },
                ttl_seconds=1.0,
            )
            adapter = _FakeSshAdapter()
            result = execute_infrastructure_action(
                action=action,
                definition=definition,
                decision=decision,
                state=state,
                credential=credential,
                adapter=adapter,
            )

        self.assertFalse(
            result.success
        )
        self.assertEqual(
            result.reason,
            "credential_unavailable",
        )
        self.assertEqual(
            result.state.actions_used,
            0,
        )
        self.assertEqual(
            adapter.calls,
            [],
        )
        self.assertTrue(
            credential.material.cleared
        )


    def test_typed_fact_validation_rejects_unbounded_or_duplicate_data(self):
        with self.assertRaises(
            ValueError
        ):
            InfrastructureFact(
                key="Bad Key",
                value="value",
            )

        with self.assertRaises(
            ValueError
        ):
            InfrastructureFact(
                key="identity.value",
                value="X" * 513,
            )

        fact = InfrastructureFact(
            key="identity.value",
            value="example",
        )

        with self.assertRaises(
            ValueError
        ):
            InfrastructureAdapterOutcome(
                success=True,
                reason="completed",
                facts=(
                    fact,
                    fact,
                ),
            )

        with self.assertRaises(
            ValueError
        ):
            InfrastructureAdapterOutcome(
                success=False,
                reason="contains spaces",
            )

if __name__ == "__main__":
    unittest.main()
