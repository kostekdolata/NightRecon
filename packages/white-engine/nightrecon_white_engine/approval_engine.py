"""Immutable, network-free White Night approval workflow engine.

Approvals are bound to one engagement, one compiled policy bundle, and one exact
action context. Workflow updates return a new value with an append-only,
hash-linked event history. Nothing in this module executes an action.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from hashlib import sha256
import json
import re
from typing import Any, Mapping

from nightrecon_shared_core.authorization import parse_target


APPROVAL_SCHEMA_VERSION = 1
APPROVAL_EVENT_SCHEMA_VERSION = 1
APPROVAL_GRANT_SCHEMA_VERSION = 1

_VALID_MODES = frozenset({"single", "dual", "quorum"})
_VALID_DECISIONS = frozenset({"approve", "reject"})
_VALID_EVENT_TYPES = frozenset({
    "requested",
    "approved",
    "rejected",
    "delegated",
    "escalated",
    "revoked",
})
_VALID_IMPACTS = frozenset({"low", "standard", "high"})
_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_ROLE_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_CAPABILITY_PATTERN = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")


class ApprovalWorkflowError(ValueError):
    """Approval workflow state or evidence is invalid."""


def _required_text(value: str, field: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ApprovalWorkflowError(f"{field} must be a nonblank, trimmed string")
    return value


def _identifier(value: str, field: str) -> str:
    _required_text(value, field)
    if _ID_PATTERN.fullmatch(value) is None:
        raise ApprovalWorkflowError(f"{field} contains unsupported characters")
    return value


def _role(value: str, field: str = "role") -> str:
    _required_text(value, field)
    if _ROLE_PATTERN.fullmatch(value) is None:
        raise ApprovalWorkflowError(f"{field} contains unsupported characters")
    return value


def _sha256(value: str, field: str) -> str:
    _required_text(value, field)
    if (
        len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ApprovalWorkflowError(f"{field} must be a lowercase SHA-256")
    return value


def _iso8601(value: str, field: str) -> str:
    _required_text(value, field)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise ApprovalWorkflowError(f"{field} must be ISO-8601") from exc
    if parsed.tzinfo is None:
        raise ApprovalWorkflowError(f"{field} must include a timezone")
    return value


def _parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _canonical_json(payload: Mapping[str, Any]) -> str:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def _fingerprint(payload: Mapping[str, Any]) -> str:
    return sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


def _sorted_unique(
    values: tuple[str, ...],
    *,
    field: str,
    minimum: int = 0,
    role_values: bool = False,
) -> tuple[str, ...]:
    if not isinstance(values, tuple):
        raise ApprovalWorkflowError(f"{field} must be a tuple")
    if len(values) < minimum:
        raise ApprovalWorkflowError(
            f"{field} must contain at least {minimum} item(s)"
        )
    if len(values) != len(set(values)):
        raise ApprovalWorkflowError(f"{field} must not contain duplicates")
    for value in values:
        (_role if role_values else _required_text)(value, field)
    return tuple(sorted(values))


@dataclass(frozen=True)
class ApprovalPrincipal:
    principal_id: str
    roles: tuple[str, ...]

    def __post_init__(self) -> None:
        _identifier(self.principal_id, "principal_id")
        roles = _sorted_unique(
            self.roles,
            field="roles",
            minimum=1,
            role_values=True,
        )
        object.__setattr__(self, "roles", roles)

    def to_dict(self) -> dict[str, Any]:
        return {
            "principal_id": self.principal_id,
            "roles": list(self.roles),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "ApprovalPrincipal":
        if not isinstance(payload, Mapping) or set(payload) != {
            "principal_id", "roles"
        }:
            raise ApprovalWorkflowError("approval principal schema is not supported")
        if not isinstance(payload["roles"], list):
            raise ApprovalWorkflowError("principal roles must be a list")
        return cls(
            principal_id=payload["principal_id"],
            roles=tuple(payload["roles"]),
        )


@dataclass(frozen=True)
class ApprovalPolicy:
    mode: str
    required_approvals: int
    eligible_roles: tuple[str, ...]
    requester_may_approve: bool = False
    allow_delegation: bool = True
    escalation_after_seconds: int | None = None
    escalation_roles: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.mode not in _VALID_MODES:
            raise ApprovalWorkflowError("approval mode must be single, dual, or quorum")
        if (
            not isinstance(self.required_approvals, int)
            or isinstance(self.required_approvals, bool)
            or self.required_approvals < 1
        ):
            raise ApprovalWorkflowError("required_approvals must be positive")
        if self.mode == "single" and self.required_approvals != 1:
            raise ApprovalWorkflowError("single approval requires exactly one approval")
        if self.mode == "dual" and self.required_approvals != 2:
            raise ApprovalWorkflowError("dual approval requires exactly two approvals")
        if self.mode == "quorum" and self.required_approvals < 2:
            raise ApprovalWorkflowError("quorum approval requires at least two approvals")

        eligible = _sorted_unique(
            self.eligible_roles,
            field="eligible_roles",
            minimum=1,
            role_values=True,
        )
        escalations = _sorted_unique(
            self.escalation_roles,
            field="escalation_roles",
            role_values=True,
        )
        if not isinstance(self.requester_may_approve, bool):
            raise ApprovalWorkflowError("requester_may_approve must be boolean")
        if not isinstance(self.allow_delegation, bool):
            raise ApprovalWorkflowError("allow_delegation must be boolean")
        if self.escalation_after_seconds is not None and (
            not isinstance(self.escalation_after_seconds, int)
            or isinstance(self.escalation_after_seconds, bool)
            or self.escalation_after_seconds < 1
        ):
            raise ApprovalWorkflowError(
                "escalation_after_seconds must be a positive integer"
            )
        object.__setattr__(self, "eligible_roles", eligible)
        object.__setattr__(self, "escalation_roles", escalations)

    def to_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "required_approvals": self.required_approvals,
            "eligible_roles": list(self.eligible_roles),
            "requester_may_approve": self.requester_may_approve,
            "allow_delegation": self.allow_delegation,
            "escalation_after_seconds": self.escalation_after_seconds,
            "escalation_roles": list(self.escalation_roles),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "ApprovalPolicy":
        required = {
            "mode",
            "required_approvals",
            "eligible_roles",
            "requester_may_approve",
            "allow_delegation",
            "escalation_after_seconds",
            "escalation_roles",
        }
        if not isinstance(payload, Mapping) or set(payload) != required:
            raise ApprovalWorkflowError("approval policy schema is not supported")
        if not isinstance(payload["eligible_roles"], list):
            raise ApprovalWorkflowError("eligible_roles must be a list")
        if not isinstance(payload["escalation_roles"], list):
            raise ApprovalWorkflowError("escalation_roles must be a list")
        return cls(
            mode=payload["mode"],
            required_approvals=payload["required_approvals"],
            eligible_roles=tuple(payload["eligible_roles"]),
            requester_may_approve=payload["requester_may_approve"],
            allow_delegation=payload["allow_delegation"],
            escalation_after_seconds=payload["escalation_after_seconds"],
            escalation_roles=tuple(payload["escalation_roles"]),
        )


@dataclass(frozen=True)
class ApprovalRequest:
    request_id: str
    engagement_id: str
    policy_bundle_fingerprint: str
    requested_at: str
    expires_at: str
    requested_by: str
    principals: tuple[ApprovalPrincipal, ...]
    capability: str
    target: str
    impact: str
    reason: str
    policy: ApprovalPolicy
    operation_id: str | None = None
    schema_version: int = APPROVAL_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != APPROVAL_SCHEMA_VERSION:
            raise ApprovalWorkflowError("unsupported approval request schema")
        _identifier(self.request_id, "request_id")
        _identifier(self.engagement_id, "engagement_id")
        _sha256(self.policy_bundle_fingerprint, "policy_bundle_fingerprint")
        _iso8601(self.requested_at, "requested_at")
        _iso8601(self.expires_at, "expires_at")
        if _parse_time(self.expires_at) <= _parse_time(self.requested_at):
            raise ApprovalWorkflowError("expires_at must be later than requested_at")
        _identifier(self.requested_by, "requested_by")
        if self.operation_id is not None:
            _identifier(self.operation_id, "operation_id")
        if not isinstance(self.principals, tuple) or not self.principals:
            raise ApprovalWorkflowError("principals must be a nonempty tuple")
        principals = tuple(sorted(self.principals, key=lambda item: item.principal_id))
        if any(not isinstance(item, ApprovalPrincipal) for item in principals):
            raise ApprovalWorkflowError(
                "principals must contain ApprovalPrincipal values"
            )
        ids = [item.principal_id for item in principals]
        if len(ids) != len(set(ids)):
            raise ApprovalWorkflowError("principal_id values must be unique")
        if self.requested_by not in ids:
            raise ApprovalWorkflowError("requested_by must identify a principal")

        if (
            not isinstance(self.capability, str)
            or _CAPABILITY_PATTERN.fullmatch(self.capability) is None
        ):
            raise ApprovalWorkflowError("capability is invalid")
        target = parse_target(self.target).value
        if self.impact not in _VALID_IMPACTS:
            raise ApprovalWorkflowError("impact must be low, standard, or high")
        _required_text(self.reason, "reason")
        if not isinstance(self.policy, ApprovalPolicy):
            raise ApprovalWorkflowError("policy must be ApprovalPolicy")

        eligible_principals = {
            principal.principal_id
            for principal in principals
            if set(principal.roles).intersection(self.policy.eligible_roles)
            and (
                self.policy.requester_may_approve
                or principal.principal_id != self.requested_by
            )
        }
        if len(eligible_principals) < self.policy.required_approvals:
            raise ApprovalWorkflowError(
                "not enough eligible principals for required approvals"
            )

        object.__setattr__(self, "principals", principals)
        object.__setattr__(self, "target", target)

    def principal(self, principal_id: str) -> ApprovalPrincipal:
        for principal in self.principals:
            if principal.principal_id == principal_id:
                return principal
        raise ApprovalWorkflowError(f"unknown approval principal: {principal_id}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "request_id": self.request_id,
            "engagement_id": self.engagement_id,
            "policy_bundle_fingerprint": self.policy_bundle_fingerprint,
            "requested_at": self.requested_at,
            "expires_at": self.expires_at,
            "requested_by": self.requested_by,
            "principals": [item.to_dict() for item in self.principals],
            "capability": self.capability,
            "target": self.target,
            "impact": self.impact,
            "reason": self.reason,
            "policy": self.policy.to_dict(),
            "operation_id": self.operation_id,
        }

    @property
    def fingerprint(self) -> str:
        return _fingerprint(self.to_dict())

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "ApprovalRequest":
        required = {
            "schema_version",
            "request_id",
            "engagement_id",
            "policy_bundle_fingerprint",
            "requested_at",
            "expires_at",
            "requested_by",
            "principals",
            "capability",
            "target",
            "impact",
            "reason",
            "policy",
            "operation_id",
        }
        if not isinstance(payload, Mapping) or set(payload) != required:
            raise ApprovalWorkflowError("approval request schema is not supported")
        if not isinstance(payload["principals"], list):
            raise ApprovalWorkflowError("principals must be a list")
        return cls(
            schema_version=payload["schema_version"],
            request_id=payload["request_id"],
            engagement_id=payload["engagement_id"],
            policy_bundle_fingerprint=payload["policy_bundle_fingerprint"],
            requested_at=payload["requested_at"],
            expires_at=payload["expires_at"],
            requested_by=payload["requested_by"],
            principals=tuple(
                ApprovalPrincipal.from_dict(item)
                for item in payload["principals"]
            ),
            capability=payload["capability"],
            target=payload["target"],
            impact=payload["impact"],
            reason=payload["reason"],
            policy=ApprovalPolicy.from_dict(payload["policy"]),
            operation_id=payload["operation_id"],
        )


@dataclass(frozen=True)
class ApprovalEvent:
    event_id: str
    request_id: str
    sequence: int
    event_type: str
    occurred_at: str
    actor_id: str
    actor_role: str | None
    reason: str
    details: tuple[tuple[str, str], ...] = ()
    previous_event_fingerprint: str | None = None
    schema_version: int = APPROVAL_EVENT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != APPROVAL_EVENT_SCHEMA_VERSION:
            raise ApprovalWorkflowError("unsupported approval event schema")
        _identifier(self.event_id, "event_id")
        _identifier(self.request_id, "request_id")
        if (
            not isinstance(self.sequence, int)
            or isinstance(self.sequence, bool)
            or self.sequence < 0
        ):
            raise ApprovalWorkflowError("event sequence must be nonnegative")
        if self.event_type not in _VALID_EVENT_TYPES:
            raise ApprovalWorkflowError("unsupported approval event type")
        _iso8601(self.occurred_at, "occurred_at")
        _identifier(self.actor_id, "actor_id")
        if self.actor_role is not None:
            _role(self.actor_role, "actor_role")
        _required_text(self.reason, "reason")
        if self.previous_event_fingerprint is not None:
            _sha256(
                self.previous_event_fingerprint,
                "previous_event_fingerprint",
            )
        if not isinstance(self.details, tuple):
            raise ApprovalWorkflowError("event details must be a tuple")
        normalized = tuple(sorted(self.details))
        if len(normalized) != len(set(normalized)):
            raise ApprovalWorkflowError("event details must not contain duplicates")
        for key, value in normalized:
            _required_text(key, "event detail key")
            _required_text(value, "event detail value")
        object.__setattr__(self, "details", normalized)

    def _payload(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "event_id": self.event_id,
            "request_id": self.request_id,
            "sequence": self.sequence,
            "event_type": self.event_type,
            "occurred_at": self.occurred_at,
            "actor_id": self.actor_id,
            "actor_role": self.actor_role,
            "reason": self.reason,
            "details": [[key, value] for key, value in self.details],
            "previous_event_fingerprint": self.previous_event_fingerprint,
        }

    @property
    def fingerprint(self) -> str:
        return _fingerprint(self._payload())

    def to_dict(self) -> dict[str, Any]:
        payload = self._payload()
        payload["fingerprint"] = self.fingerprint
        return payload

    def detail(self, key: str) -> str | None:
        for item_key, value in self.details:
            if item_key == key:
                return value
        return None

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "ApprovalEvent":
        required = {
            "schema_version",
            "event_id",
            "request_id",
            "sequence",
            "event_type",
            "occurred_at",
            "actor_id",
            "actor_role",
            "reason",
            "details",
            "previous_event_fingerprint",
            "fingerprint",
        }
        if not isinstance(payload, Mapping) or set(payload) != required:
            raise ApprovalWorkflowError("approval event schema is not supported")
        if not isinstance(payload["details"], list):
            raise ApprovalWorkflowError("approval event details must be a list")
        details: list[tuple[str, str]] = []
        for item in payload["details"]:
            if not isinstance(item, list) or len(item) != 2:
                raise ApprovalWorkflowError("approval event detail is invalid")
            details.append((item[0], item[1]))
        event = cls(
            schema_version=payload["schema_version"],
            event_id=payload["event_id"],
            request_id=payload["request_id"],
            sequence=payload["sequence"],
            event_type=payload["event_type"],
            occurred_at=payload["occurred_at"],
            actor_id=payload["actor_id"],
            actor_role=payload["actor_role"],
            reason=payload["reason"],
            details=tuple(details),
            previous_event_fingerprint=payload["previous_event_fingerprint"],
        )
        if payload["fingerprint"] != event.fingerprint:
            raise ApprovalWorkflowError(
                "approval event fingerprint verification failed"
            )
        return event


@dataclass(frozen=True)
class ApprovalGrant:
    request_id: str
    engagement_id: str
    policy_bundle_fingerprint: str
    capability: str
    target: str
    impact: str
    approved_at: str
    expires_at: str
    approver_ids: tuple[str, ...]
    workflow_fingerprint: str
    schema_version: int = APPROVAL_GRANT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != APPROVAL_GRANT_SCHEMA_VERSION:
            raise ApprovalWorkflowError("unsupported approval grant schema")
        _identifier(self.request_id, "request_id")
        _identifier(self.engagement_id, "engagement_id")
        _sha256(self.policy_bundle_fingerprint, "policy_bundle_fingerprint")
        if (
            not isinstance(self.capability, str)
            or _CAPABILITY_PATTERN.fullmatch(self.capability) is None
        ):
            raise ApprovalWorkflowError("capability is invalid")
        object.__setattr__(self, "target", parse_target(self.target).value)
        if self.impact not in _VALID_IMPACTS:
            raise ApprovalWorkflowError("impact must be low, standard, or high")
        _iso8601(self.approved_at, "approved_at")
        _iso8601(self.expires_at, "expires_at")
        approvers = _sorted_unique(
            self.approver_ids,
            field="approver_ids",
            minimum=1,
        )
        _sha256(self.workflow_fingerprint, "workflow_fingerprint")
        object.__setattr__(self, "approver_ids", approvers)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "request_id": self.request_id,
            "engagement_id": self.engagement_id,
            "policy_bundle_fingerprint": self.policy_bundle_fingerprint,
            "capability": self.capability,
            "target": self.target,
            "impact": self.impact,
            "approved_at": self.approved_at,
            "expires_at": self.expires_at,
            "approver_ids": list(self.approver_ids),
            "workflow_fingerprint": self.workflow_fingerprint,
        }


@dataclass(frozen=True)
class ApprovalWorkflow:
    request: ApprovalRequest
    events: tuple[ApprovalEvent, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.request, ApprovalRequest):
            raise ApprovalWorkflowError("request must be ApprovalRequest")
        if not isinstance(self.events, tuple) or not self.events:
            raise ApprovalWorkflowError("approval workflow requires events")

        seen_ids: set[str] = set()
        previous: ApprovalEvent | None = None
        for index, event in enumerate(self.events):
            if not isinstance(event, ApprovalEvent):
                raise ApprovalWorkflowError(
                    "events must contain ApprovalEvent values"
                )
            if event.event_id in seen_ids:
                raise ApprovalWorkflowError("approval event IDs must be unique")
            seen_ids.add(event.event_id)
            if event.request_id != self.request.request_id:
                raise ApprovalWorkflowError(
                    "approval event belongs to another request"
                )
            if event.sequence != index:
                raise ApprovalWorkflowError(
                    "approval event sequence is not contiguous"
                )
            expected_previous = None if previous is None else previous.fingerprint
            if event.previous_event_fingerprint != expected_previous:
                raise ApprovalWorkflowError(
                    "approval event chain verification failed"
                )
            if _parse_time(event.occurred_at) < _parse_time(self.request.requested_at):
                raise ApprovalWorkflowError(
                    "approval event predates the request"
                )
            if previous is not None and (
                _parse_time(event.occurred_at) < _parse_time(previous.occurred_at)
            ):
                raise ApprovalWorkflowError(
                    "approval events are not chronologically ordered"
                )
            previous = event

        first = self.events[0]
        if first.event_type != "requested":
            raise ApprovalWorkflowError(
                "approval workflow must begin with requested event"
            )
        if first.detail("request_fingerprint") != self.request.fingerprint:
            raise ApprovalWorkflowError(
                "requested event is not bound to request fingerprint"
            )
        self._validate_history()

    @classmethod
    def create(
        cls,
        request: ApprovalRequest,
        *,
        event_id: str,
        actor_id: str | None = None,
        reason: str = "approval requested",
    ) -> "ApprovalWorkflow":
        actor = request.requested_by if actor_id is None else actor_id
        request.principal(actor)
        event = ApprovalEvent(
            event_id=event_id,
            request_id=request.request_id,
            sequence=0,
            event_type="requested",
            occurred_at=request.requested_at,
            actor_id=actor,
            actor_role=None,
            reason=reason,
            details=(("request_fingerprint", request.fingerprint),),
        )
        return cls(request=request, events=(event,))

    def _validate_history(self) -> None:
        state = "pending"
        approving_actors: set[str] = set()
        authority_sources: set[str] = set()
        escalated = False

        for event in self.events[1:]:
            if (
                state == "pending"
                and _parse_time(event.occurred_at)
                >= _parse_time(self.request.expires_at)
            ):
                raise ApprovalWorkflowError(
                    "approval workflow contains a decision after request expiry"
                )

            if state in {"rejected", "revoked"}:
                raise ApprovalWorkflowError(
                    "approval workflow contains events after terminal state"
                )
            if state == "approved" and event.event_type != "revoked":
                raise ApprovalWorkflowError(
                    "approved workflow may only be revoked"
                )

            if event.event_type == "approved":
                if state != "pending":
                    raise ApprovalWorkflowError(
                        "approval decision is not valid in current state"
                    )
                if event.actor_id in approving_actors:
                    raise ApprovalWorkflowError(
                        "principal approved the request more than once"
                    )
                authority_source = event.detail("authority_source")
                if authority_source is None:
                    raise ApprovalWorkflowError(
                        "approval event is missing authority source"
                    )
                if authority_source in authority_sources:
                    raise ApprovalWorkflowError(
                        "approval authority source was counted more than once"
                    )
                approving_actors.add(event.actor_id)
                authority_sources.add(authority_source)
                if (
                    len(authority_sources)
                    >= self.request.policy.required_approvals
                ):
                    state = "approved"
            elif event.event_type == "rejected":
                if state != "pending":
                    raise ApprovalWorkflowError(
                        "rejection is not valid in current state"
                    )
                state = "rejected"
            elif event.event_type == "revoked":
                if state != "approved":
                    raise ApprovalWorkflowError(
                        "revocation requires an approved workflow"
                    )
                state = "revoked"
            elif event.event_type == "delegated":
                if state != "pending":
                    raise ApprovalWorkflowError(
                        "delegation is not valid in current state"
                    )
            elif event.event_type == "escalated":
                if state != "pending":
                    raise ApprovalWorkflowError(
                        "escalation is not valid in current state"
                    )
                if escalated:
                    raise ApprovalWorkflowError(
                        "approval workflow was escalated more than once"
                    )
                escalated = True

    @property
    def fingerprint(self) -> str:
        payload = {
            "request_fingerprint": self.request.fingerprint,
            "event_fingerprints": [event.fingerprint for event in self.events],
        }
        return _fingerprint(payload)

    def to_dict(self) -> dict[str, Any]:
        return {
            "request": self.request.to_dict(),
            "events": [event.to_dict() for event in self.events],
            "workflow_fingerprint": self.fingerprint,
        }

    def to_json(self) -> str:
        return _canonical_json(self.to_dict())

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "ApprovalWorkflow":
        if not isinstance(payload, Mapping) or set(payload) != {
            "request", "events", "workflow_fingerprint"
        }:
            raise ApprovalWorkflowError("approval workflow schema is not supported")
        if not isinstance(payload["request"], Mapping):
            raise ApprovalWorkflowError("approval request must be an object")
        if not isinstance(payload["events"], list):
            raise ApprovalWorkflowError("approval events must be a list")
        workflow = cls(
            request=ApprovalRequest.from_dict(payload["request"]),
            events=tuple(
                ApprovalEvent.from_dict(item) for item in payload["events"]
            ),
        )
        if payload["workflow_fingerprint"] != workflow.fingerprint:
            raise ApprovalWorkflowError(
                "approval workflow fingerprint verification failed"
            )
        return workflow

    @classmethod
    def from_json(cls, payload: str) -> "ApprovalWorkflow":
        try:
            decoded = json.loads(payload)
        except (TypeError, json.JSONDecodeError) as exc:
            raise ApprovalWorkflowError(
                "approval workflow is not valid JSON"
            ) from exc
        return cls.from_dict(decoded)

    def _append(
        self,
        *,
        event_id: str,
        event_type: str,
        occurred_at: str,
        actor_id: str,
        actor_role: str | None,
        reason: str,
        details: tuple[tuple[str, str], ...] = (),
    ) -> "ApprovalWorkflow":
        event = ApprovalEvent(
            event_id=event_id,
            request_id=self.request.request_id,
            sequence=len(self.events),
            event_type=event_type,
            occurred_at=occurred_at,
            actor_id=actor_id,
            actor_role=actor_role,
            reason=reason,
            details=details,
            previous_event_fingerprint=self.events[-1].fingerprint,
        )
        return ApprovalWorkflow(
            request=self.request,
            events=self.events + (event,),
        )

    def approval_events(self, at: str | None = None) -> tuple[ApprovalEvent, ...]:
        cutoff = None if at is None else _parse_time(_iso8601(at, "at"))
        return tuple(
            event
            for event in self.events
            if event.event_type == "approved"
            and (cutoff is None or _parse_time(event.occurred_at) <= cutoff)
        )

    def rejection_event(self, at: str | None = None) -> ApprovalEvent | None:
        cutoff = None if at is None else _parse_time(_iso8601(at, "at"))
        return next(
            (
                event
                for event in self.events
                if event.event_type == "rejected"
                and (cutoff is None or _parse_time(event.occurred_at) <= cutoff)
            ),
            None,
        )

    def revocation_event(self, at: str | None = None) -> ApprovalEvent | None:
        cutoff = None if at is None else _parse_time(_iso8601(at, "at"))
        return next(
            (
                event
                for event in self.events
                if event.event_type == "revoked"
                and (cutoff is None or _parse_time(event.occurred_at) <= cutoff)
            ),
            None,
        )

    def escalated(self, at: str | None = None) -> bool:
        cutoff = None if at is None else _parse_time(_iso8601(at, "at"))
        return any(
            event.event_type == "escalated"
            and (cutoff is None or _parse_time(event.occurred_at) <= cutoff)
            for event in self.events
        )

    def status(self, at: str) -> str:
        _iso8601(at, "at")
        if self.revocation_event(at) is not None:
            return "revoked"
        if self.rejection_event(at) is not None:
            return "rejected"
        if _parse_time(at) >= _parse_time(self.request.expires_at):
            return "expired"
        if len(self.approval_events(at)) >= self.request.policy.required_approvals:
            return "approved"
        return "pending"

    def _ensure_pending(self, at: str) -> None:
        status = self.status(at)
        if status != "pending":
            raise ApprovalWorkflowError(
                f"approval request is not pending: {status}"
            )

    def _eligible_authority(
        self,
        actor_id: str,
        *,
        at: str,
    ) -> tuple[str, str]:
        principal = self.request.principal(actor_id)
        direct = sorted(
            set(principal.roles).intersection(self.request.policy.eligible_roles)
        )
        if direct:
            return direct[0], actor_id

        for event in reversed(self.events):
            if (
                event.event_type == "delegated"
                and event.detail("delegate_id") == actor_id
                and event.detail("delegated_role") in self.request.policy.eligible_roles
            ):
                valid_until = event.detail("valid_until")
                if (
                    _parse_time(event.occurred_at) <= _parse_time(at)
                    and valid_until is not None
                    and _parse_time(at) < _parse_time(valid_until)
                ):
                    return event.detail("delegated_role") or "", event.actor_id
        raise ApprovalWorkflowError(
            "principal does not hold eligible approval authority"
        )

    def approve(
        self,
        *,
        event_id: str,
        actor_id: str,
        occurred_at: str,
        reason: str,
    ) -> "ApprovalWorkflow":
        _iso8601(occurred_at, "occurred_at")
        self._ensure_pending(occurred_at)
        if (
            not self.request.policy.requester_may_approve
            and actor_id == self.request.requested_by
        ):
            raise ApprovalWorkflowError(
                "requester cannot approve this request"
            )
        if any(event.actor_id == actor_id for event in self.approval_events()):
            raise ApprovalWorkflowError(
                "principal already approved this request"
            )
        role, authority_source = self._eligible_authority(
            actor_id,
            at=occurred_at,
        )
        used_sources = {
            event.detail("authority_source")
            for event in self.approval_events(occurred_at)
        }
        if authority_source in used_sources:
            raise ApprovalWorkflowError(
                "approval authority source already counted for this request"
            )
        return self._append(
            event_id=event_id,
            event_type="approved",
            occurred_at=occurred_at,
            actor_id=actor_id,
            actor_role=role,
            reason=reason,
            details=(("authority_source", authority_source),),
        )

    def reject(
        self,
        *,
        event_id: str,
        actor_id: str,
        occurred_at: str,
        reason: str,
    ) -> "ApprovalWorkflow":
        _iso8601(occurred_at, "occurred_at")
        self._ensure_pending(occurred_at)
        if (
            not self.request.policy.requester_may_approve
            and actor_id == self.request.requested_by
        ):
            raise ApprovalWorkflowError(
                "requester cannot reject their own request"
            )
        role, authority_source = self._eligible_authority(
            actor_id,
            at=occurred_at,
        )
        return self._append(
            event_id=event_id,
            event_type="rejected",
            occurred_at=occurred_at,
            actor_id=actor_id,
            actor_role=role,
            reason=reason,
            details=(("authority_source", authority_source),),
        )

    def delegate(
        self,
        *,
        event_id: str,
        delegator_id: str,
        delegate_id: str,
        delegated_role: str,
        occurred_at: str,
        valid_until: str,
        reason: str,
    ) -> "ApprovalWorkflow":
        _iso8601(occurred_at, "occurred_at")
        _iso8601(valid_until, "valid_until")
        self._ensure_pending(occurred_at)
        if not self.request.policy.allow_delegation:
            raise ApprovalWorkflowError("approval delegation is disabled")
        if delegator_id == delegate_id:
            raise ApprovalWorkflowError("delegator and delegate must differ")
        if (
            not self.request.policy.requester_may_approve
            and (
                delegator_id == self.request.requested_by
                or delegate_id == self.request.requested_by
            )
        ):
            raise ApprovalWorkflowError(
                "separation of duties forbids requester delegation"
            )
        delegator = self.request.principal(delegator_id)
        self.request.principal(delegate_id)
        _role(delegated_role, "delegated_role")
        if delegated_role not in self.request.policy.eligible_roles:
            raise ApprovalWorkflowError("delegated role is not approval-eligible")
        if delegated_role not in delegator.roles:
            raise ApprovalWorkflowError(
                "delegator does not directly hold delegated role"
            )
        if _parse_time(valid_until) <= _parse_time(occurred_at):
            raise ApprovalWorkflowError(
                "delegation valid_until must be later than occurred_at"
            )
        if _parse_time(valid_until) > _parse_time(self.request.expires_at):
            raise ApprovalWorkflowError(
                "delegation cannot outlive the approval request"
            )
        return self._append(
            event_id=event_id,
            event_type="delegated",
            occurred_at=occurred_at,
            actor_id=delegator_id,
            actor_role=delegated_role,
            reason=reason,
            details=(
                ("delegate_id", delegate_id),
                ("delegated_role", delegated_role),
                ("valid_until", valid_until),
            ),
        )

    def escalation_due(self, at: str) -> bool:
        _iso8601(at, "at")
        seconds = self.request.policy.escalation_after_seconds
        if seconds is None or self.status(at) != "pending" or self.escalated(at):
            return False
        due = _parse_time(self.request.requested_at) + timedelta(seconds=seconds)
        return _parse_time(at) >= due

    def escalate(
        self,
        *,
        event_id: str,
        actor_id: str,
        occurred_at: str,
        reason: str,
    ) -> "ApprovalWorkflow":
        _iso8601(occurred_at, "occurred_at")
        self.request.principal(actor_id)
        if not self.escalation_due(occurred_at):
            raise ApprovalWorkflowError("approval escalation is not due")
        return self._append(
            event_id=event_id,
            event_type="escalated",
            occurred_at=occurred_at,
            actor_id=actor_id,
            actor_role=None,
            reason=reason,
            details=tuple(
                ("escalation_role", role)
                for role in self.request.policy.escalation_roles
            ),
        )

    def revoke(
        self,
        *,
        event_id: str,
        actor_id: str,
        occurred_at: str,
        reason: str,
    ) -> "ApprovalWorkflow":
        _iso8601(occurred_at, "occurred_at")
        if self.status(occurred_at) != "approved":
            raise ApprovalWorkflowError(
                "only a currently approved request can be revoked"
            )
        principal = self.request.principal(actor_id)
        eligible = sorted(
            set(principal.roles).intersection(self.request.policy.eligible_roles)
        )
        if not eligible:
            raise ApprovalWorkflowError(
                "revocation requires direct eligible authority"
            )
        return self._append(
            event_id=event_id,
            event_type="revoked",
            occurred_at=occurred_at,
            actor_id=actor_id,
            actor_role=eligible[0],
            reason=reason,
        )

    def grant(self, at: str) -> ApprovalGrant:
        _iso8601(at, "at")
        if self.status(at) != "approved":
            raise ApprovalWorkflowError(
                "approval grant is unavailable unless request is approved"
            )
        approvals = self.approval_events(at)
        approved_at = approvals[
            self.request.policy.required_approvals - 1
        ].occurred_at
        approvers = tuple(
            event.actor_id
            for event in approvals[:self.request.policy.required_approvals]
        )
        return ApprovalGrant(
            request_id=self.request.request_id,
            engagement_id=self.request.engagement_id,
            policy_bundle_fingerprint=self.request.policy_bundle_fingerprint,
            capability=self.request.capability,
            target=self.request.target,
            impact=self.request.impact,
            approved_at=approved_at,
            expires_at=self.request.expires_at,
            approver_ids=approvers,
            workflow_fingerprint=self.fingerprint,
        )

    def grant_matches(
        self,
        grant: ApprovalGrant,
        *,
        engagement_id: str,
        policy_bundle_fingerprint: str,
        capability: str,
        target: str,
        impact: str,
        at: str,
    ) -> bool:
        _iso8601(at, "at")
        try:
            target_value = parse_target(target).value
        except ValueError:
            return False
        if self.status(at) != "approved":
            return False
        if grant.workflow_fingerprint != self.fingerprint:
            return False
        return (
            grant.request_id == self.request.request_id
            and grant.engagement_id == engagement_id == self.request.engagement_id
            and grant.policy_bundle_fingerprint
            == policy_bundle_fingerprint
            == self.request.policy_bundle_fingerprint
            and grant.capability == capability == self.request.capability
            and grant.target == target_value == self.request.target
            and grant.impact == impact == self.request.impact
            and _parse_time(at) < _parse_time(grant.expires_at)
        )
