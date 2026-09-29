"""Persistent, network-free engagement execution authorization policy."""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping
import json
import os
import re
import tempfile

from nightrecon_shared_core.authorization import Scope, parse_target


_POLICY_SCHEMA_VERSION = 1
_AUDIT_SCHEMA_VERSION = 1
_VALID_IMPACTS = frozenset({"low", "standard", "high"})
_IMPACT_RANK = {"low": 0, "standard": 1, "high": 2}
_CAPABILITY_PATTERN = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")


def _required_text(value: str, field: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(f"{field} must be a nonblank, trimmed string")
    return value


def _iso8601(value: str, field: str) -> str:
    _required_text(value, field)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field} must be ISO-8601") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{field} must include a timezone")
    return value


def _parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _capabilities(values: tuple[str, ...], field: str) -> tuple[str, ...]:
    if not values:
        raise ValueError(f"{field} must contain at least one capability")
    if len(values) != len(set(values)):
        raise ValueError(f"{field} must not contain duplicates")
    for value in values:
        if not isinstance(value, str) or _CAPABILITY_PATTERN.fullmatch(value) is None:
            raise ValueError(f"{field} contains an invalid capability")
    return tuple(sorted(values))


@dataclass(frozen=True)
class EngagementExecutionPolicy:
    engagement_id: str
    scope: tuple[str, ...]
    valid_from: str
    valid_until: str
    max_actions: int
    permitted_capabilities: tuple[str, ...]
    max_impact: str = "high"
    approval_required_capabilities: tuple[str, ...] = ()
    revoked: bool = False
    actions_used: int = 0
    schema_version: int = _POLICY_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != _POLICY_SCHEMA_VERSION:
            raise ValueError("unsupported engagement execution policy schema version")
        _required_text(self.engagement_id, "engagement_id")
        if not self.scope:
            raise ValueError("scope must contain at least one target rule")
        Scope.from_values(list(self.scope))
        _iso8601(self.valid_from, "valid_from")
        _iso8601(self.valid_until, "valid_until")
        if _parse_time(self.valid_until) <= _parse_time(self.valid_from):
            raise ValueError("valid_until must be later than valid_from")
        if not isinstance(self.max_actions, int) or isinstance(self.max_actions, bool) or self.max_actions < 1:
            raise ValueError("max_actions must be a positive integer")
        if not isinstance(self.actions_used, int) or isinstance(self.actions_used, bool):
            raise ValueError("actions_used must be an integer")
        if self.actions_used < 0 or self.actions_used > self.max_actions:
            raise ValueError("actions_used must be between zero and max_actions")
        permitted = _capabilities(self.permitted_capabilities, "permitted_capabilities")
        if self.max_impact not in _VALID_IMPACTS:
            raise ValueError("max_impact must be low, standard, or high")
        required = tuple(sorted(self.approval_required_capabilities))
        if len(required) != len(set(required)):
            raise ValueError("approval_required_capabilities must not contain duplicates")
        if any(item not in permitted for item in required):
            raise ValueError("approval-required capabilities must also be permitted")

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["scope"] = list(self.scope)
        payload["permitted_capabilities"] = list(self.permitted_capabilities)
        payload["approval_required_capabilities"] = list(self.approval_required_capabilities)
        return payload

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "EngagementExecutionPolicy":
        if not isinstance(payload, Mapping):
            raise ValueError("engagement execution policy must be an object")
        legacy_required = {
            "schema_version", "engagement_id", "scope", "valid_from", "valid_until",
            "max_actions", "permitted_capabilities", "approval_required_capabilities",
            "revoked", "actions_used",
        }
        current_required = legacy_required | {"max_impact"}
        if set(payload) not in (legacy_required, current_required):
            raise ValueError("engagement execution policy schema is not supported")
        return cls(
            schema_version=payload["schema_version"],
            engagement_id=payload["engagement_id"],
            scope=tuple(payload["scope"]),
            valid_from=payload["valid_from"],
            valid_until=payload["valid_until"],
            max_actions=payload["max_actions"],
            permitted_capabilities=tuple(payload["permitted_capabilities"]),
            max_impact=payload.get("max_impact", "high"),
            approval_required_capabilities=tuple(payload["approval_required_capabilities"]),
            revoked=payload["revoked"],
            actions_used=payload["actions_used"],
        )


@dataclass(frozen=True)
class AuthorizationDecision:
    engagement_id: str
    allowed: bool
    reason_code: str
    reason: str
    capability: str
    target: str
    impact: str
    approval_present: bool
    actions_used: int
    max_actions: int
    remaining_actions: int


def evaluate_action(
    policy: EngagementExecutionPolicy,
    *,
    engagement_status: str | None,
    capability: str,
    target: str,
    impact: str = "standard",
    approval_present: bool = False,
    now: datetime | None = None,
) -> AuthorizationDecision:
    _required_text(capability, "capability")
    if _CAPABILITY_PATTERN.fullmatch(capability) is None:
        raise ValueError("capability is invalid")
    target_obj = parse_target(target)
    if impact not in _VALID_IMPACTS:
        raise ValueError("impact must be low, standard, or high")
    current = datetime.now(timezone.utc) if now is None else now
    if current.tzinfo is None:
        raise ValueError("now must include a timezone")

    reason_code = "authorized"
    reason = "action is authorized by the active engagement policy"
    allowed = True

    if engagement_status != "active":
        allowed, reason_code, reason = False, "engagement_not_active", "engagement status is not active"
    elif policy.revoked:
        allowed, reason_code, reason = False, "authorization_revoked", "engagement authorization has been revoked"
    elif current < _parse_time(policy.valid_from):
        allowed, reason_code, reason = False, "authorization_not_started", "authorization validity window has not started"
    elif current > _parse_time(policy.valid_until):
        allowed, reason_code, reason = False, "authorization_expired", "authorization validity window has expired"
    elif capability not in policy.permitted_capabilities:
        allowed, reason_code, reason = False, "capability_not_permitted", "capability is not permitted by the engagement policy"
    elif _IMPACT_RANK[impact] > _IMPACT_RANK[policy.max_impact]:
        allowed, reason_code, reason = False, "impact_exceeds_policy", "action impact exceeds the engagement policy ceiling"
    elif not Scope.from_values(list(policy.scope)).is_authorized(target_obj):
        allowed, reason_code, reason = False, "target_out_of_scope", "target is outside the engagement scope"
    elif policy.actions_used >= policy.max_actions:
        allowed, reason_code, reason = False, "action_budget_exhausted", "engagement action budget is exhausted"
    elif (
        (impact == "high" or capability in policy.approval_required_capabilities)
        and not approval_present
    ):
        allowed, reason_code, reason = False, "approval_required", "action requires explicit operator approval"

    used = policy.actions_used
    remaining = max(0, policy.max_actions - used)
    return AuthorizationDecision(
        engagement_id=policy.engagement_id,
        allowed=allowed,
        reason_code=reason_code,
        reason=reason,
        capability=capability,
        target=target_obj.value,
        impact=impact,
        approval_present=approval_present,
        actions_used=used,
        max_actions=policy.max_actions,
        remaining_actions=remaining,
    )


@dataclass(frozen=True)
class AuthorizationAuditRecord:
    occurred_at: str
    engagement_id: str
    allowed: bool
    reason_code: str
    capability: str
    target: str
    impact: str
    approval_present: bool
    actions_used: int
    max_actions: int
    schema_version: int = _AUDIT_SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class FileEngagementPolicyStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._policies: dict[str, EngagementExecutionPolicy] = {}
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("engagement authorization store is not valid UTF-8 JSON") from exc
        if not isinstance(payload, dict) or set(payload) != {"schema_version", "policies"}:
            raise ValueError("engagement authorization store schema is not supported")
        if payload["schema_version"] != _POLICY_SCHEMA_VERSION:
            raise ValueError("engagement authorization store schema version is not supported")
        if not isinstance(payload["policies"], list):
            raise ValueError("policies must be a list")
        for item in payload["policies"]:
            policy = EngagementExecutionPolicy.from_dict(item)
            if policy.engagement_id in self._policies:
                raise ValueError("engagement authorization store contains a duplicate policy")
            self._policies[policy.engagement_id] = policy

    def _persist(self) -> None:
        payload = {
            "schema_version": _POLICY_SCHEMA_VERSION,
            "policies": [
                self._policies[key].to_dict()
                for key in sorted(self._policies)
            ],
        }
        serialized = json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(
            prefix=self.path.name + ".", suffix=".tmp", dir=str(self.path.parent), text=True
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(serialized)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_name, self.path)
        except BaseException:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
            raise

    def policy(self, engagement_id: str) -> EngagementExecutionPolicy | None:
        _required_text(engagement_id, "engagement_id")
        return self._policies.get(engagement_id)

    def set_policy(self, policy: EngagementExecutionPolicy) -> None:
        existing = self._policies.get(policy.engagement_id)
        if existing is not None and existing != policy:
            raise ValueError(f"engagement authorization policy already exists: {policy.engagement_id}")
        if existing is None:
            self._policies[policy.engagement_id] = policy
            self._persist()

    def replace_policy(self, policy: EngagementExecutionPolicy) -> None:
        if policy.engagement_id not in self._policies:
            raise ValueError(f"engagement authorization policy not found: {policy.engagement_id}")
        self._policies[policy.engagement_id] = policy
        self._persist()

    def revoke(self, engagement_id: str) -> EngagementExecutionPolicy:
        policy = self.policy(engagement_id)
        if policy is None:
            raise ValueError(f"engagement authorization policy not found: {engagement_id}")
        if policy.revoked:
            return policy
        revoked = replace(policy, revoked=True)
        self.replace_policy(revoked)
        return revoked

    def consume_action(self, engagement_id: str) -> EngagementExecutionPolicy:
        policy = self.policy(engagement_id)
        if policy is None:
            raise ValueError(f"engagement authorization policy not found: {engagement_id}")
        if policy.actions_used >= policy.max_actions:
            raise ValueError("engagement action budget is exhausted")
        updated = replace(policy, actions_used=policy.actions_used + 1)
        self.replace_policy(updated)
        return updated


def append_authorization_audit(
    path: str | Path,
    decision: AuthorizationDecision,
    *,
    occurred_at: datetime | None = None,
) -> AuthorizationAuditRecord:
    when = datetime.now(timezone.utc) if occurred_at is None else occurred_at
    if when.tzinfo is None:
        raise ValueError("occurred_at must include a timezone")
    record = AuthorizationAuditRecord(
        occurred_at=when.isoformat(),
        engagement_id=decision.engagement_id,
        allowed=decision.allowed,
        reason_code=decision.reason_code,
        capability=decision.capability,
        target=decision.target,
        impact=decision.impact,
        approval_present=decision.approval_present,
        actions_used=decision.actions_used,
        max_actions=decision.max_actions,
    )
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(record.to_dict(), sort_keys=True, separators=(",", ":")) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    return record


def read_authorization_audit(path: str | Path) -> tuple[AuthorizationAuditRecord, ...]:
    source = Path(path)
    if not source.exists():
        return ()
    records: list[AuthorizationAuditRecord] = []
    for line in source.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        payload = json.loads(line)
        records.append(AuthorizationAuditRecord(**payload))
    return tuple(records)
