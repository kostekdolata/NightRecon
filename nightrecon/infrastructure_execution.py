"""One-shot credentialed infrastructure execution contract.

This module orchestrates already-authorized symbolic infrastructure actions.
It does not implement SSH, SMB, WinRM, database, shell, or arbitrary-command
transport logic.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
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


_FACT_KEY_PATTERN = re.compile(
    r"^[a-z][a-z0-9_.-]{0,63}$"
)
_REASON_PATTERN = re.compile(
    r"^[a-z][a-z0-9_-]{0,63}$"
)


@dataclass(frozen=True)
class InfrastructureFact:
    """Bounded typed observation emitted by a transport adapter."""

    key: str
    value: str

    def __post_init__(self) -> None:
        if not _FACT_KEY_PATTERN.fullmatch(
            self.key
        ):
            raise ValueError(
                "Infrastructure fact key is invalid."
            )

        normalized = self.value.strip()

        if not normalized:
            raise ValueError(
                "Infrastructure fact value must be non-empty."
            )

        if len(normalized) > 512:
            raise ValueError(
                "Infrastructure fact value exceeds 512 characters."
            )

        if any(
            ord(character) < 32
            and character not in {
                "\t",
            }
            for character in normalized
        ):
            raise ValueError(
                "Infrastructure fact value contains control characters."
            )

        object.__setattr__(
            self,
            "value",
            normalized,
        )


@dataclass(frozen=True)
class InfrastructureAdapterOutcome:
    """Secret-free typed adapter outcome."""

    success: bool
    reason: str
    facts: tuple[InfrastructureFact, ...] = ()

    def __post_init__(self) -> None:
        if not _REASON_PATTERN.fullmatch(
            self.reason
        ):
            raise ValueError(
                "Infrastructure adapter reason is invalid."
            )

        keys = [
            fact.key
            for fact in self.facts
        ]

        if len(keys) != len(
            set(keys)
        ):
            raise ValueError(
                "Infrastructure adapter facts contain duplicate keys."
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
    ) -> InfrastructureAdapterOutcome:
        """Execute one allowlisted symbolic action and return typed facts."""
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
    facts: tuple[InfrastructureFact, ...] = ()


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
            outcome = adapter.execute(
                target=action.target,
                action_id=action.action_id,
                credential=credential,
            )

            if not isinstance(
                outcome,
                InfrastructureAdapterOutcome,
            ):
                raise TypeError(
                    "Transport adapter returned an invalid outcome."
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
            success=outcome.success,
            reason=outcome.reason,
            target=action.target,
            transport=action.transport,
            action_id=action.action_id,
            credential_id=action.credential_id,
            state=reserved_state,
            facts=outcome.facts,
        )
    finally:
        credential.clear()
