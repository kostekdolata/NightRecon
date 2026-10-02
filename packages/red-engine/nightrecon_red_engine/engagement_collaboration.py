"""Red Night engagement collaboration metadata with no authorization effect."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import Enum
import json
import os
from pathlib import Path
import tempfile


MAX_TEXT_LENGTH = 4000
MAX_EVENTS = 10000


class CollaborationEventKind(str, Enum):
    ANNOTATION = "annotation"
    REVIEW_STATE = "review-state"
    ASSIGNMENT = "assignment"
    HANDOFF = "handoff"


class ReviewState(str, Enum):
    PENDING = "pending"
    IN_REVIEW = "in-review"
    APPROVED = "approved"
    CHANGES_REQUESTED = "changes-requested"
    CLOSED = "closed"


_ALLOWED_SUBJECT_KINDS = frozenset({
    "engagement", "evidence", "finding", "validation", "report",
})


def _required(value: str, field: str, *, max_length: int = 512) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(f"{field} must be a nonblank, trimmed string")
    if len(value) > max_length:
        raise ValueError(f"{field} exceeds maximum length {max_length}")
    return value


@dataclass(frozen=True)
class CollaborationEvent:
    event_id: str
    engagement_id: str
    occurred_at: str
    actor_id: str
    kind: CollaborationEventKind
    subject_kind: str
    subject_id: str
    note: str | None = None
    review_state: ReviewState | None = None
    assignee_id: str | None = None
    authorization_effect: str = "none"

    def __post_init__(self) -> None:
        _required(self.event_id, "event_id")
        _required(self.engagement_id, "engagement_id")
        _required(self.actor_id, "actor_id")
        _required(self.subject_id, "subject_id")
        if self.subject_kind not in _ALLOWED_SUBJECT_KINDS:
            raise ValueError("subject_kind is not supported")
        try:
            parsed = datetime.fromisoformat(self.occurred_at)
        except ValueError as exc:
            raise ValueError("occurred_at must be ISO-8601") from exc
        if parsed.tzinfo is None:
            raise ValueError("occurred_at must include a timezone")
        if self.authorization_effect != "none":
            raise ValueError("collaboration events cannot grant authorization")
        if self.note is not None:
            _required(self.note, "note", max_length=MAX_TEXT_LENGTH)
        if self.assignee_id is not None:
            _required(self.assignee_id, "assignee_id")
        if self.kind is CollaborationEventKind.ANNOTATION:
            if self.note is None or self.review_state is not None or self.assignee_id is not None:
                raise ValueError("annotation requires note only")
        elif self.kind is CollaborationEventKind.REVIEW_STATE:
            if self.review_state is None or self.note is not None or self.assignee_id is not None:
                raise ValueError("review-state requires review_state only")
        elif self.kind is CollaborationEventKind.ASSIGNMENT:
            if self.assignee_id is None or self.note is not None or self.review_state is not None:
                raise ValueError("assignment requires assignee_id only")
        elif self.kind is CollaborationEventKind.HANDOFF:
            if self.assignee_id is None or self.note is None or self.review_state is not None:
                raise ValueError("handoff requires assignee_id and note")

    def to_dict(self) -> dict[str, object]:
        payload = asdict(self)
        payload["kind"] = self.kind.value
        payload["review_state"] = (
            None if self.review_state is None else self.review_state.value
        )
        return payload


@dataclass(frozen=True)
class CollaborationSummary:
    engagement_id: str
    total_events: int
    annotations: int
    review_state_changes: int
    assignments: int
    handoffs: int
    current_assignments: tuple[tuple[str, str, str], ...]
    current_review_states: tuple[tuple[str, str, str], ...]
    participating_operators: tuple[str, ...]
    authorization_effect: str = "none"

    def to_dict(self) -> dict[str, object]:
        return {
            "engagement_id": self.engagement_id,
            "total_events": self.total_events,
            "annotations": self.annotations,
            "review_state_changes": self.review_state_changes,
            "assignments": self.assignments,
            "handoffs": self.handoffs,
            "current_assignments": [
                {
                    "subject_kind": kind,
                    "subject_id": subject_id,
                    "assignee_id": assignee,
                }
                for kind, subject_id, assignee in self.current_assignments
            ],
            "current_review_states": [
                {
                    "subject_kind": kind,
                    "subject_id": subject_id,
                    "review_state": state,
                }
                for kind, subject_id, state in self.current_review_states
            ],
            "participating_operators": list(self.participating_operators),
            "authorization_effect": self.authorization_effect,
        }


class CollaborationStore:
    """Append-only collaboration event store.

    The local store is designed for deterministic offline use. Event IDs are
    immutable and duplicate/conflicting IDs fail closed. It does not claim
    multi-process locking; service/database deployments must provide serialized
    writers around this contract.
    """

    SCHEMA_VERSION = 1

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._events: dict[str, CollaborationEvent] = {}
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("collaboration store is not valid UTF-8 JSON") from exc
        if not isinstance(payload, dict) or set(payload) != {"schema_version", "events"}:
            raise ValueError("collaboration store schema is not supported")
        if payload["schema_version"] != self.SCHEMA_VERSION:
            raise ValueError("collaboration store schema version is not supported")
        if not isinstance(payload["events"], list) or len(payload["events"]) > MAX_EVENTS:
            raise ValueError("collaboration store event collection is invalid")
        for item in payload["events"]:
            decoded = dict(item)
            decoded["kind"] = CollaborationEventKind(decoded["kind"])
            if decoded.get("review_state") is not None:
                decoded["review_state"] = ReviewState(decoded["review_state"])
            event = CollaborationEvent(**decoded)
            previous = self._events.get(event.event_id)
            if previous is not None and previous != event:
                raise ValueError("collaboration store contains conflicting event IDs")
            if previous is not None:
                raise ValueError("collaboration store contains duplicate event IDs")
            self._events[event.event_id] = event

    def _persist(self) -> None:
        payload = {
            "schema_version": self.SCHEMA_VERSION,
            "events": [
                self._events[key].to_dict()
                for key in sorted(self._events)
            ],
        }
        serialized = json.dumps(
            payload, sort_keys=True, separators=(",", ":")
        ) + "\n"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(
            prefix=self.path.name + ".",
            suffix=".tmp",
            dir=str(self.path.parent),
            text=True,
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

    def append(self, event: CollaborationEvent) -> CollaborationEvent:
        if len(self._events) >= MAX_EVENTS:
            raise ValueError("collaboration store event limit reached")
        previous = self._events.get(event.event_id)
        if previous is not None:
            if previous == event:
                return previous
            raise ValueError("collaboration event ID already exists with different content")
        self._events[event.event_id] = event
        self._persist()
        return event

    def record(
        self,
        *,
        event_id: str,
        engagement_id: str,
        actor_id: str,
        kind: CollaborationEventKind,
        subject_kind: str,
        subject_id: str,
        note: str | None = None,
        review_state: ReviewState | None = None,
        assignee_id: str | None = None,
        now: datetime | None = None,
    ) -> CollaborationEvent:
        timestamp = datetime.now(timezone.utc) if now is None else now
        if timestamp.tzinfo is None:
            raise ValueError("now must include a timezone")
        return self.append(CollaborationEvent(
            event_id=event_id,
            engagement_id=engagement_id,
            occurred_at=timestamp.isoformat(),
            actor_id=actor_id,
            kind=kind,
            subject_kind=subject_kind,
            subject_id=subject_id,
            note=note,
            review_state=review_state,
            assignee_id=assignee_id,
        ))

    def events(self, engagement_id: str | None = None) -> tuple[CollaborationEvent, ...]:
        values = self._events.values()
        if engagement_id is not None:
            values = (
                event for event in values
                if event.engagement_id == engagement_id
            )
        return tuple(sorted(
            values,
            key=lambda item: (item.occurred_at, item.event_id),
        ))

    def summary(self, engagement_id: str) -> CollaborationSummary:
        events = self.events(engagement_id)
        assignments: dict[tuple[str, str], str] = {}
        reviews: dict[tuple[str, str], str] = {}
        operators: set[str] = set()
        counts = {kind: 0 for kind in CollaborationEventKind}

        for event in events:
            operators.add(event.actor_id)
            counts[event.kind] += 1
            key = (event.subject_kind, event.subject_id)
            if event.kind in {
                CollaborationEventKind.ASSIGNMENT,
                CollaborationEventKind.HANDOFF,
            }:
                assert event.assignee_id is not None
                assignments[key] = event.assignee_id
                operators.add(event.assignee_id)
            if event.kind is CollaborationEventKind.REVIEW_STATE:
                assert event.review_state is not None
                reviews[key] = event.review_state.value

        return CollaborationSummary(
            engagement_id=engagement_id,
            total_events=len(events),
            annotations=counts[CollaborationEventKind.ANNOTATION],
            review_state_changes=counts[CollaborationEventKind.REVIEW_STATE],
            assignments=counts[CollaborationEventKind.ASSIGNMENT],
            handoffs=counts[CollaborationEventKind.HANDOFF],
            current_assignments=tuple(
                (kind, subject_id, assignee)
                for (kind, subject_id), assignee in sorted(assignments.items())
            ),
            current_review_states=tuple(
                (kind, subject_id, state)
                for (kind, subject_id), state in sorted(reviews.items())
            ),
            participating_operators=tuple(sorted(operators)),
        )
