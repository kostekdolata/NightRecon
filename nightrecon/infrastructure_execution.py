"""One-shot credentialed infrastructure execution contract.

This module orchestrates already-authorized symbolic infrastructure actions.
It does not implement SSH, SMB, WinRM, database, shell, or arbitrary-command
transport logic.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from nightrecon.credential_resolution import (
    ResolvedCredential,
)
from nightrecon.infrastructure_models import (
    InfrastructureAction,
    InfrastructureActionDecision,
    InfrastructureActionDefinition,
    InfrastructureActionState,
    InfrastructureTransport,
)
from nightrecon.infrastructure_policy import (
    reserve_infrastructure_action,
)


class InfrastructureTransportAdapter(
    Protocol
):
    """Protocol-neutral adapter contract for one symbolic action."""

    @property
    def transport(
        self,
    ) -> InfrastructureTransport:
        ...

    def execute(
        self,
        *,
        target: str,
        action_id: str,
        credential: ResolvedCredential,
    ) -> bool:
        """Execute one allowlisted symbolic action and return success."""
        ...


@dataclass(frozen=True)
class InfrastructureExecutionResult:
    """Secret-free outcome of one attempted infrastructure action."""

    success: bool
    reason: str
    target: str
    transport: InfrastructureTransport
    action_id: str
    credential_id: str
    state: InfrastructureActionState


def _decision_matches_action(
    *,
    action: InfrastructureAction,
    decision: InfrastructureActionDecision,
) -> bool:
    return (
        decision.target
        == action.target
        and decision.transport
        == action.transport
        and decision.action_id
        == action.action_id
        and decision.credential_id
        == action.credential_id
    )


def execute_infrastructure_action(
    *,
    action: InfrastructureAction,
    definition: InfrastructureActionDefinition,
    decision: InfrastructureActionDecision,
    state: InfrastructureActionState,
    credential: ResolvedCredential,
    adapter: InfrastructureTransportAdapter,
) -> InfrastructureExecutionResult:
    """Execute one pre-authorized symbolic action through a one-shot lease."""

    try:
        if not decision.allowed:
            raise PermissionError(
                "Infrastructure action decision is not authorized."
            )

        if not _decision_matches_action(
            action=action,
            decision=decision,
        ):
            raise ValueError(
                "Infrastructure action decision does not match action."
            )

        if (
            definition.action_id
            != action.action_id
            or definition.transport
            != action.transport
        ):
            raise ValueError(
                "Infrastructure action definition does not match action."
            )

        if (
            credential.reference.credential_id
            != action.credential_id
        ):
            raise ValueError(
                "Resolved credential does not match action credential reference."
            )

        if adapter.transport != action.transport:
            raise ValueError(
                "Infrastructure transport adapter does not match action."
            )

        if not credential.material.active:
            credential.clear()
            return InfrastructureExecutionResult(
                success=False,
                reason="credential_unavailable",
                target=action.target,
                transport=action.transport,
                action_id=action.action_id,
                credential_id=action.credential_id,
                state=state,
            )

        reserved_state = reserve_infrastructure_action(
            state=state,
            decision=decision,
        )

        try:
            success = bool(
                adapter.execute(
                    target=action.target,
                    action_id=action.action_id,
                    credential=credential,
                )
            )
        except Exception:
            return InfrastructureExecutionResult(
                success=False,
                reason="transport_failed",
                target=action.target,
                transport=action.transport,
                action_id=action.action_id,
                credential_id=action.credential_id,
                state=reserved_state,
            )

        return InfrastructureExecutionResult(
            success=success,
            reason=(
                "completed"
                if success
                else "adapter_reported_failure"
            ),
            target=action.target,
            transport=action.transport,
            action_id=action.action_id,
            credential_id=action.credential_id,
            state=reserved_state,
        )
    finally:
        credential.clear()
