"""Tamper-evident, secret-safe White Night logical audit trail.

The audit is append-only at the domain level: existing events cannot be altered
or removed when persisted through the provided stores. Physical files are
atomically replaced so the same semantics work on standalone installs and Live
USB persistence without requiring a database.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import tempfile
from typing import Any, Mapping, Protocol


AUDIT_SCHEMA_VERSION = 1
AUDIT_EVENT_SCHEMA_VERSION = 1

_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_EVENT_TYPE_PATTERN = re.compile(r"^[a-z][a-z0-9_.-]{0,127}$")
_REASON_CODE_PATTERN = re.compile(r"^[a-z][a-z0-9_.-]{0,127}$")
_VALID_OUTCOMES = frozenset({"info", "success", "denied", "error"})
_FORBIDDEN_FIELD_FRAGMENTS = (
    "password",
    "passwd",
    "secret",
    "token",
    "credential",
    "cookie",
    "authorization",
    "api_key",
    "apikey",
    "private_key",
    "session",
)


class AuditTrailError(ValueError):
    """Audit state, history, or secret-safety validation failed."""


def _required_text(value: str, field: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise AuditTrailError(
            f"{field} must be a nonblank, trimmed string"
        )
    return value


def _identifier(value: str, field: str) -> str:
    _required_text(value, field)
    if _ID_PATTERN.fullmatch(value) is None:
        raise AuditTrailError(
            f"{field} contains unsupported characters"
        )
    return value


def _iso8601(value: str, field: str) -> str:
    _required_text(value, field)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise AuditTrailError(f"{field} must be ISO-8601") from exc
    if parsed.tzinfo is None:
        raise AuditTrailError(f"{field} must include a timezone")
    return value


def _parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _sha256(value: str, field: str) -> str:
    _required_text(value, field)
    if (
        len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise AuditTrailError(f"{field} must be a lowercase SHA-256")
    return value


def _canonical_json(payload: Mapping[str, Any]) -> str:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def _fingerprint(payload: Mapping[str, Any]) -> str:
    return sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


def _reject_secret_keys(value: Any, path: str = "$") -> None:
    if isinstance(value, Mapping):
        for key, nested in value.items():
            if not isinstance(key, str):
                raise AuditTrailError(
                    "audit detail object keys must be strings"
                )
            lowered = key.lower()
            if any(fragment in lowered for fragment in _FORBIDDEN_FIELD_FRAGMENTS):
                raise AuditTrailError(
                    f"secret-like audit field is not allowed: {path}.{key}"
                )
            _reject_secret_keys(nested, f"{path}.{key}")
    elif isinstance(value, (list, tuple)):
        for index, nested in enumerate(value):
            _reject_secret_keys(nested, f"{path}[{index}]")


@dataclass(frozen=True)
class AuditEvent:
    event_id: str
    trail_id: str
    engagement_id: str
    sequence: int
    event_type: str
    occurred_at: str
    actor_id: str
    subject_type: str
    subject_id: str
    outcome: str
    reason_code: str
    summary: str
    details: tuple[tuple[str, str], ...] = ()
    previous_event_fingerprint: str | None = None
    schema_version: int = AUDIT_EVENT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != AUDIT_EVENT_SCHEMA_VERSION:
            raise AuditTrailError("unsupported audit event schema")
        _identifier(self.event_id, "event_id")
        _identifier(self.trail_id, "trail_id")
        _identifier(self.engagement_id, "engagement_id")
        if (
            not isinstance(self.sequence, int)
            or isinstance(self.sequence, bool)
            or self.sequence < 0
        ):
            raise AuditTrailError(
                "audit event sequence must be nonnegative"
            )
        _required_text(self.event_type, "event_type")
        if _EVENT_TYPE_PATTERN.fullmatch(self.event_type) is None:
            raise AuditTrailError("event_type is invalid")
        _iso8601(self.occurred_at, "occurred_at")
        _identifier(self.actor_id, "actor_id")
        _required_text(self.subject_type, "subject_type")
        if _EVENT_TYPE_PATTERN.fullmatch(self.subject_type) is None:
            raise AuditTrailError("subject_type is invalid")
        _identifier(self.subject_id, "subject_id")
        if self.outcome not in _VALID_OUTCOMES:
            raise AuditTrailError("unsupported audit outcome")
        _required_text(self.reason_code, "reason_code")
        if _REASON_CODE_PATTERN.fullmatch(self.reason_code) is None:
            raise AuditTrailError("reason_code is invalid")
        _required_text(self.summary, "summary")
        if self.previous_event_fingerprint is not None:
            _sha256(
                self.previous_event_fingerprint,
                "previous_event_fingerprint",
            )
        if not isinstance(self.details, tuple):
            raise AuditTrailError("audit details must be a tuple")
        normalized = tuple(sorted(self.details))
        keys = [key for key, _ in normalized]
        if len(keys) != len(set(keys)):
            raise AuditTrailError(
                "audit detail keys must be unique"
            )
        for key, value in normalized:
            _required_text(key, "audit detail key")
            _required_text(value, "audit detail value")
            _reject_secret_keys({key: value})
        object.__setattr__(self, "details", normalized)

    def _payload(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "event_id": self.event_id,
            "trail_id": self.trail_id,
            "engagement_id": self.engagement_id,
            "sequence": self.sequence,
            "event_type": self.event_type,
            "occurred_at": self.occurred_at,
            "actor_id": self.actor_id,
            "subject_type": self.subject_type,
            "subject_id": self.subject_id,
            "outcome": self.outcome,
            "reason_code": self.reason_code,
            "summary": self.summary,
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

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "AuditEvent":
        required = {
            "schema_version",
            "event_id",
            "trail_id",
            "engagement_id",
            "sequence",
            "event_type",
            "occurred_at",
            "actor_id",
            "subject_type",
            "subject_id",
            "outcome",
            "reason_code",
            "summary",
            "details",
            "previous_event_fingerprint",
            "fingerprint",
        }
        if not isinstance(payload, Mapping) or set(payload) != required:
            raise AuditTrailError("audit event schema is not supported")
        details = payload["details"]
        if not isinstance(details, list):
            raise AuditTrailError("audit details must be a list")
        pairs: list[tuple[str, str]] = []
        for item in details:
            if (
                not isinstance(item, list)
                or len(item) != 2
                or not all(isinstance(value, str) for value in item)
            ):
                raise AuditTrailError("audit detail is invalid")
            pairs.append((item[0], item[1]))
        event = cls(
            schema_version=payload["schema_version"],
            event_id=payload["event_id"],
            trail_id=payload["trail_id"],
            engagement_id=payload["engagement_id"],
            sequence=payload["sequence"],
            event_type=payload["event_type"],
            occurred_at=payload["occurred_at"],
            actor_id=payload["actor_id"],
            subject_type=payload["subject_type"],
            subject_id=payload["subject_id"],
            outcome=payload["outcome"],
            reason_code=payload["reason_code"],
            summary=payload["summary"],
            details=tuple(pairs),
            previous_event_fingerprint=payload[
                "previous_event_fingerprint"
            ],
        )
        if payload["fingerprint"] != event.fingerprint:
            raise AuditTrailError(
                "audit event fingerprint verification failed"
            )
        return event


@dataclass(frozen=True)
class AuditTrail:
    trail_id: str
    engagement_id: str
    events: tuple[AuditEvent, ...]
    schema_version: int = AUDIT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != AUDIT_SCHEMA_VERSION:
            raise AuditTrailError("unsupported audit trail schema")
        _identifier(self.trail_id, "trail_id")
        _identifier(self.engagement_id, "engagement_id")
        if not isinstance(self.events, tuple) or not self.events:
            raise AuditTrailError(
                "audit trail requires at least one event"
            )
        seen: set[str] = set()
        previous: AuditEvent | None = None
        previous_time: datetime | None = None
        for index, event in enumerate(self.events):
            if not isinstance(event, AuditEvent):
                raise AuditTrailError(
                    "events must contain AuditEvent values"
                )
            if event.event_id in seen:
                raise AuditTrailError(
                    "audit event IDs must be unique"
                )
            seen.add(event.event_id)
            if event.trail_id != self.trail_id:
                raise AuditTrailError(
                    "audit event belongs to another trail"
                )
            if event.engagement_id != self.engagement_id:
                raise AuditTrailError(
                    "audit event belongs to another engagement"
                )
            if event.sequence != index:
                raise AuditTrailError(
                    "audit event sequence is not contiguous"
                )
            expected_previous = (
                None if previous is None else previous.fingerprint
            )
            if event.previous_event_fingerprint != expected_previous:
                raise AuditTrailError(
                    "audit event chain verification failed"
                )
            occurred = _parse_time(event.occurred_at)
            if previous_time is not None and occurred < previous_time:
                raise AuditTrailError(
                    "audit events are not chronologically ordered"
                )
            previous = event
            previous_time = occurred

    @classmethod
    def create(
        cls,
        *,
        trail_id: str,
        engagement_id: str,
        event_id: str,
        event_type: str,
        occurred_at: str,
        actor_id: str,
        subject_type: str,
        subject_id: str,
        outcome: str,
        reason_code: str,
        summary: str,
        details: tuple[tuple[str, str], ...] = (),
    ) -> "AuditTrail":
        event = AuditEvent(
            event_id=event_id,
            trail_id=trail_id,
            engagement_id=engagement_id,
            sequence=0,
            event_type=event_type,
            occurred_at=occurred_at,
            actor_id=actor_id,
            subject_type=subject_type,
            subject_id=subject_id,
            outcome=outcome,
            reason_code=reason_code,
            summary=summary,
            details=details,
        )
        return cls(
            trail_id=trail_id,
            engagement_id=engagement_id,
            events=(event,),
        )

    def append(
        self,
        *,
        event_id: str,
        event_type: str,
        occurred_at: str,
        actor_id: str,
        subject_type: str,
        subject_id: str,
        outcome: str,
        reason_code: str,
        summary: str,
        details: tuple[tuple[str, str], ...] = (),
    ) -> "AuditTrail":
        event = AuditEvent(
            event_id=event_id,
            trail_id=self.trail_id,
            engagement_id=self.engagement_id,
            sequence=len(self.events),
            event_type=event_type,
            occurred_at=occurred_at,
            actor_id=actor_id,
            subject_type=subject_type,
            subject_id=subject_id,
            outcome=outcome,
            reason_code=reason_code,
            summary=summary,
            details=details,
            previous_event_fingerprint=self.events[-1].fingerprint,
        )
        return AuditTrail(
            trail_id=self.trail_id,
            engagement_id=self.engagement_id,
            events=self.events + (event,),
        )

    @property
    def fingerprint(self) -> str:
        return _fingerprint({
            "schema_version": self.schema_version,
            "trail_id": self.trail_id,
            "engagement_id": self.engagement_id,
            "event_fingerprints": [
                event.fingerprint for event in self.events
            ],
        })

    def verify_integrity(self) -> bool:
        return bool(self.fingerprint)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "trail_id": self.trail_id,
            "engagement_id": self.engagement_id,
            "events": [event.to_dict() for event in self.events],
            "trail_fingerprint": self.fingerprint,
        }

    def to_json(self) -> str:
        return _canonical_json(self.to_dict())

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "AuditTrail":
        required = {
            "schema_version",
            "trail_id",
            "engagement_id",
            "events",
            "trail_fingerprint",
        }
        if not isinstance(payload, Mapping) or set(payload) != required:
            raise AuditTrailError(
                "audit trail schema is not supported"
            )
        if not isinstance(payload["events"], list):
            raise AuditTrailError("audit events must be a list")
        trail = cls(
            schema_version=payload["schema_version"],
            trail_id=payload["trail_id"],
            engagement_id=payload["engagement_id"],
            events=tuple(
                AuditEvent.from_dict(item) for item in payload["events"]
            ),
        )
        if payload["trail_fingerprint"] != trail.fingerprint:
            raise AuditTrailError(
                "audit trail fingerprint verification failed"
            )
        return trail

    @classmethod
    def from_json(cls, payload: str) -> "AuditTrail":
        try:
            decoded = json.loads(payload)
        except (TypeError, json.JSONDecodeError) as exc:
            raise AuditTrailError(
                "audit trail is not valid JSON"
            ) from exc
        return cls.from_dict(decoded)


class AuditStore(Protocol):
    def create(self, trail: AuditTrail) -> None: ...
    def advance(self, trail: AuditTrail) -> None: ...
    def trail(self, trail_id: str) -> AuditTrail | None: ...
    def trails(self) -> tuple[str, ...]: ...


class InMemoryAuditStore:
    def __init__(self) -> None:
        self._trails: dict[str, AuditTrail] = {}

    def create(self, trail: AuditTrail) -> None:
        existing = self._trails.get(trail.trail_id)
        if existing is None:
            self._trails[trail.trail_id] = trail
            return
        if existing != trail:
            raise AuditTrailError(
                f"conflicting audit trail already exists: {trail.trail_id}"
            )

    def advance(self, trail: AuditTrail) -> None:
        previous = self._trails.get(trail.trail_id)
        if previous is None:
            raise AuditTrailError(
                f"audit trail not found: {trail.trail_id}"
            )
        if previous.engagement_id != trail.engagement_id:
            raise AuditTrailError(
                "audit engagement cannot change"
            )
        old_events = tuple(
            event.fingerprint for event in previous.events
        )
        new_events = tuple(
            event.fingerprint for event in trail.events
        )
        if new_events[:len(old_events)] != old_events:
            raise AuditTrailError(
                "audit history is not an append-only extension"
            )
        self._trails[trail.trail_id] = trail

    def trail(self, trail_id: str) -> AuditTrail | None:
        _identifier(trail_id, "trail_id")
        return self._trails.get(trail_id)

    def trails(self) -> tuple[str, ...]:
        return tuple(sorted(self._trails))


class FileAuditStore:
    """Atomic local persistence for append-only logical audit trails."""

    SCHEMA_VERSION = 1

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._memory = InMemoryAuditStore()
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            payload = json.loads(
                self.path.read_text(encoding="utf-8")
            )
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AuditTrailError(
                "audit store is not valid UTF-8 JSON"
            ) from exc
        if (
            not isinstance(payload, Mapping)
            or set(payload) != {"schema_version", "trails"}
            or payload["schema_version"] != self.SCHEMA_VERSION
            or not isinstance(payload["trails"], list)
        ):
            raise AuditTrailError(
                "audit store schema is not supported"
            )
        seen: set[str] = set()
        for item in payload["trails"]:
            trail = AuditTrail.from_dict(item)
            if trail.trail_id in seen:
                raise AuditTrailError(
                    "audit store contains duplicate trail"
                )
            seen.add(trail.trail_id)
            self._memory.create(trail)

    def _persist(self) -> None:
        payload = {
            "schema_version": self.SCHEMA_VERSION,
            "trails": [
                self._memory.trail(trail_id).to_dict()
                for trail_id in self._memory.trails()
                if self._memory.trail(trail_id) is not None
            ],
        }
        serialized = _canonical_json(payload) + "\n"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(
            prefix=self.path.name + ".",
            suffix=".tmp",
            dir=str(self.path.parent),
            text=True,
        )
        try:
            with os.fdopen(
                fd,
                "w",
                encoding="utf-8",
                newline="\n",
            ) as handle:
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

    def create(self, trail: AuditTrail) -> None:
        before = self._memory.trail(trail.trail_id)
        self._memory.create(trail)
        if before != trail:
            self._persist()

    def advance(self, trail: AuditTrail) -> None:
        previous = self._memory.trail(trail.trail_id)
        self._memory.advance(trail)
        if previous != trail:
            self._persist()

    def trail(self, trail_id: str) -> AuditTrail | None:
        return self._memory.trail(trail_id)

    def trails(self) -> tuple[str, ...]:
        return self._memory.trails()


def render_audit_summary(trail: AuditTrail) -> str:
    """Secret-safe audit summary; event details are intentionally omitted."""

    lines = [
        f"Audit trail: {trail.trail_id}",
        f"Engagement: {trail.engagement_id}",
        f"Events: {len(trail.events)}",
        f"Trail fingerprint: {trail.fingerprint}",
    ]
    for event in trail.events:
        lines.append(
            " | ".join((
                str(event.sequence),
                event.event_type,
                event.occurred_at,
                event.actor_id,
                event.subject_type,
                event.subject_id,
                event.outcome,
                event.reason_code,
                event.fingerprint,
            ))
        )
    return "\n".join(lines)
