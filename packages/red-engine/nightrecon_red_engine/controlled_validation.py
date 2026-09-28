"""Authorization-first controlled validation runtime.

Validation adapters are deterministic proof mechanisms, not exploit payloads.
The runtime owns approval, target scope, action budget, result state, and
secret-free evidence validation. Adapters are never called when authorization
is denied.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Mapping, Protocol, Any

from nightrecon_shared_core.workspace import LocalWorkspace


_VALID_IMPACTS = frozenset({"low", "standard", "high"})
_FORBIDDEN_EVIDENCE_KEYS = (
    "password", "passwd", "secret", "token", "credential", "cookie",
    "authorization", "api_key", "apikey", "private_key", "session",
)


def _required(value: str, field: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(f"{field} must be a nonblank, trimmed string")
    return value


def _validate_evidence(value: Any, path: str = "$") -> None:
    if isinstance(value, Mapping):
        for key, nested in value.items():
            if not isinstance(key, str):
                raise ValueError("validation evidence keys must be strings")
            lowered = key.lower()
            if any(fragment in lowered for fragment in _FORBIDDEN_EVIDENCE_KEYS):
                raise ValueError(f"secret-like validation evidence is not allowed: {path}.{key}")
            _validate_evidence(nested, f"{path}.{key}")
    elif isinstance(value, (list, tuple)):
        for index, nested in enumerate(value):
            _validate_evidence(nested, f"{path}[{index}]")


class ValidationState(str, Enum):
    DENIED = "denied"
    CONFIRMED = "confirmed"
    NOT_CONFIRMED = "not-confirmed"
    ERROR = "error"


@dataclass(frozen=True)
class ValidationDefinition:
    validation_id: str
    target: str
    title: str
    impact: str = "standard"
    requires_approval: bool = False

    def __post_init__(self) -> None:
        _required(self.validation_id, "validation_id")
        _required(self.target, "target")
        _required(self.title, "title")
        if self.impact not in _VALID_IMPACTS:
            raise ValueError("impact must be low, standard, or high")


@dataclass(frozen=True)
class ValidationObservation:
    confirmed: bool
    summary: str
    evidence: Mapping[str, Any]
    limitations: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _required(self.summary, "summary")
        if not isinstance(self.evidence, Mapping):
            raise ValueError("validation evidence must be an object")
        _validate_evidence(self.evidence)
        for limitation in self.limitations:
            _required(limitation, "limitation")


class ValidationAdapter(Protocol):
    def execute(self, definition: ValidationDefinition) -> ValidationObservation: ...


@dataclass(frozen=True)
class ControlledValidationResult:
    engagement_id: str
    validation_id: str
    target: str
    state: ValidationState
    reason_code: str
    summary: str
    evidence: Mapping[str, Any]
    limitations: tuple[str, ...]
    actions_used: int
    remaining_actions: int


def run_controlled_validation(
    workspace: LocalWorkspace,
    adapter: ValidationAdapter,
    definition: ValidationDefinition,
    *,
    engagement_id: str,
    approval_present: bool = False,
    now: datetime | None = None,
) -> ControlledValidationResult:
    _required(engagement_id, "engagement_id")
    effective_impact = "high" if definition.requires_approval else definition.impact
    decision = workspace.authorize_action(
        engagement_id,
        capability="validation.run",
        target=definition.target,
        impact=effective_impact,
        approval_present=approval_present,
        consume=True,
        now=now,
    )
    if not decision.allowed:
        return ControlledValidationResult(
            engagement_id=engagement_id,
            validation_id=definition.validation_id,
            target=definition.target,
            state=ValidationState.DENIED,
            reason_code=decision.reason_code,
            summary=decision.reason,
            evidence={},
            limitations=(),
            actions_used=decision.actions_used,
            remaining_actions=decision.remaining_actions,
        )

    try:
        observation = adapter.execute(definition)
    except Exception as exc:
        return ControlledValidationResult(
            engagement_id=engagement_id,
            validation_id=definition.validation_id,
            target=definition.target,
            state=ValidationState.ERROR,
            reason_code="adapter_error",
            summary=f"validation adapter failed: {type(exc).__name__}",
            evidence={},
            limitations=("Adapter raised an exception; no exploitability verdict.",),
            actions_used=decision.actions_used,
            remaining_actions=decision.remaining_actions,
        )

    return ControlledValidationResult(
        engagement_id=engagement_id,
        validation_id=definition.validation_id,
        target=definition.target,
        state=(
            ValidationState.CONFIRMED
            if observation.confirmed
            else ValidationState.NOT_CONFIRMED
        ),
        reason_code="validated" if observation.confirmed else "not_confirmed",
        summary=observation.summary,
        evidence=dict(observation.evidence),
        limitations=observation.limitations,
        actions_used=decision.actions_used,
        remaining_actions=decision.remaining_actions,
    )
