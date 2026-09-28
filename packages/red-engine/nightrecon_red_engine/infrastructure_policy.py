"""Fail-closed policy for credentialed infrastructure assessment."""

from __future__ import annotations

from dataclasses import dataclass

from nightrecon_red_engine.infrastructure_models import (
    CredentialReference,
    InfrastructureAction,
    InfrastructureActionDecision,
    InfrastructureActionDefinition,
    InfrastructureActionState,
    InfrastructureTransport,
)
from nightrecon_shared_core.authorization import Scope
from nightrecon_red_engine.targets import parse_target


@dataclass(frozen=True)
class InfrastructureAssessmentPolicy:
    """Authorization and budget policy for credentialed assessment."""

    scope: Scope
    allowed_transports: tuple[InfrastructureTransport, ...]
    max_actions: int = 20
    allow_mutating_actions: bool = False

    def __post_init__(self) -> None:
        if self.max_actions < 1:
            raise ValueError(
                "max_actions must be at least 1."
            )

        transports = tuple(
            dict.fromkeys(
                self.allowed_transports
            )
        )

        if not transports:
            raise ValueError(
                "allowed_transports must not be empty."
            )

        object.__setattr__(
            self,
            "allowed_transports",
            transports,
        )


def authorize_infrastructure_action(
    *,
    action: InfrastructureAction,
    definition: InfrastructureActionDefinition,
    credential: CredentialReference,
    policy: InfrastructureAssessmentPolicy,
    state: InfrastructureActionState,
) -> InfrastructureActionDecision:
    """Authorize one symbolic credentialed action before any execution."""

    if state.actions_used < 0:
        raise ValueError(
            "actions_used cannot be negative."
        )

    if state.max_actions != policy.max_actions:
        raise ValueError(
            "Action-state budget does not match policy."
        )

    target = parse_target(
        action.target
    )

    def deny(
        reason: str,
    ) -> InfrastructureActionDecision:
        return InfrastructureActionDecision(
            allowed=False,
            reason=reason,
            target=target.value,
            transport=action.transport,
            action_id=action.action_id,
            credential_id=action.credential_id,
        )

    if state.actions_used >= policy.max_actions:
        return deny(
            "action_budget_exhausted"
        )

    if not policy.scope.is_authorized(
        target
    ):
        return deny(
            "outside_authorized_scope"
        )

    if (
        action.transport
        not in policy.allowed_transports
    ):
        return deny(
            "transport_not_allowed"
        )

    if (
        definition.transport
        != action.transport
    ):
        return deny(
            "action_transport_mismatch"
        )

    if (
        definition.action_id
        != action.action_id
    ):
        return deny(
            "action_definition_mismatch"
        )

    if (
        credential.credential_id
        != action.credential_id
    ):
        return deny(
            "credential_reference_mismatch"
        )

    if (
        definition.mutating
        and not policy.allow_mutating_actions
    ):
        return deny(
            "mutating_action_not_allowed"
        )

    return InfrastructureActionDecision(
        allowed=True,
        reason="authorized",
        target=target.value,
        transport=action.transport,
        action_id=action.action_id,
        credential_id=action.credential_id,
    )


def reserve_infrastructure_action(
    *,
    state: InfrastructureActionState,
    decision: InfrastructureActionDecision,
) -> InfrastructureActionState:
    """Reserve one action slot after an allowed decision."""

    if not decision.allowed:
        raise PermissionError(
            "Infrastructure action is not authorized."
        )

    if state.actions_used >= state.max_actions:
        raise PermissionError(
            "Infrastructure action budget is exhausted."
        )

    return InfrastructureActionState(
        actions_used=(
            state.actions_used + 1
        ),
        max_actions=state.max_actions,
    )
