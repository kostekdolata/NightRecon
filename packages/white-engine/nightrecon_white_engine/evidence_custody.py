"""White Night evidence custody and integrity manifests.

This layer governs the existing shared-core EvidenceRecord contract. It never
turns evidence into authorization, never stores secret-bearing payload fields,
and performs no network or target activity.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import tempfile
from typing import Any, Mapping, Protocol

from nightrecon_shared_core.contracts import EvidenceRecord

from nightrecon_white_engine.engagement_domain import DataHandlingPolicy


CUSTODY_SCHEMA_VERSION = 1
CUSTODY_EVENT_SCHEMA_VERSION = 1
MANIFEST_SCHEMA_VERSION = 1
EXPORT_BUNDLE_SCHEMA_VERSION = 1

_VALID_CLASSIFICATIONS = ("public", "internal", "confidential", "restricted")
_CLASSIFICATION_RANK = {
    value: index for index, value in enumerate(_VALID_CLASSIFICATIONS)
}
_VALID_CUSTODY_EVENTS = frozenset({
    "ingested",
    "derived",
    "transferred",
    "exported",
})
_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
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


class EvidenceCustodyError(ValueError):
    """Evidence custody state, integrity, or governance is invalid."""


def _required_text(value: str, field: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise EvidenceCustodyError(
            f"{field} must be a nonblank, trimmed string"
        )
    return value


def _identifier(value: str, field: str) -> str:
    _required_text(value, field)
    if _ID_PATTERN.fullmatch(value) is None:
        raise EvidenceCustodyError(
            f"{field} contains unsupported characters"
        )
    return value


def _iso8601(value: str, field: str) -> str:
    _required_text(value, field)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise EvidenceCustodyError(f"{field} must be ISO-8601") from exc
    if parsed.tzinfo is None:
        raise EvidenceCustodyError(f"{field} must include a timezone")
    return value


def _parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _sha256(value: str, field: str) -> str:
    _required_text(value, field)
    if (
        len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise EvidenceCustodyError(f"{field} must be a lowercase SHA-256")
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
                raise EvidenceCustodyError(
                    "custody metadata object keys must be strings"
                )
            lowered = key.lower()
            if any(fragment in lowered for fragment in _FORBIDDEN_FIELD_FRAGMENTS):
                raise EvidenceCustodyError(
                    f"secret-like custody field is not allowed: {path}.{key}"
                )
            _reject_secret_keys(nested, f"{path}.{key}")
    elif isinstance(value, (list, tuple)):
        for index, nested in enumerate(value):
            _reject_secret_keys(nested, f"{path}[{index}]")


def _sorted_unique_ids(
    values: tuple[str, ...],
    *,
    field: str,
) -> tuple[str, ...]:
    if not isinstance(values, tuple):
        raise EvidenceCustodyError(f"{field} must be a tuple")
    if len(values) != len(set(values)):
        raise EvidenceCustodyError(f"{field} must not contain duplicates")
    for value in values:
        _identifier(value, field)
    return tuple(sorted(values))


def _policy_fingerprint(policy: DataHandlingPolicy) -> str:
    return _fingerprint(policy.to_dict())


def _record_fingerprint(record: EvidenceRecord) -> str:
    return sha256(record.to_json().encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class CustodiedEvidence:
    """One shared-core evidence record under White custody governance."""

    record: EvidenceRecord
    classification: str
    retained_from: str
    retain_until: str
    export_allowed: bool
    parent_evidence_ids: tuple[str, ...] = ()
    record_fingerprint: str = ""
    schema_version: int = CUSTODY_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != CUSTODY_SCHEMA_VERSION:
            raise EvidenceCustodyError(
                "unsupported custodied evidence schema"
            )
        if not isinstance(self.record, EvidenceRecord):
            raise EvidenceCustodyError("record must be EvidenceRecord")
        if self.classification not in _CLASSIFICATION_RANK:
            raise EvidenceCustodyError("unsupported evidence classification")
        _iso8601(self.retained_from, "retained_from")
        _iso8601(self.retain_until, "retain_until")
        if _parse_time(self.retain_until) <= _parse_time(self.retained_from):
            raise EvidenceCustodyError(
                "retain_until must be later than retained_from"
            )
        if not isinstance(self.export_allowed, bool):
            raise EvidenceCustodyError("export_allowed must be boolean")
        parents = _sorted_unique_ids(
            self.parent_evidence_ids,
            field="parent_evidence_ids",
        )
        if self.record.evidence_id in parents:
            raise EvidenceCustodyError(
                "evidence cannot derive from itself"
            )
        expected = _record_fingerprint(self.record)
        if self.record_fingerprint:
            _sha256(self.record_fingerprint, "record_fingerprint")
            if self.record_fingerprint != expected:
                raise EvidenceCustodyError(
                    "evidence record fingerprint verification failed"
                )
        else:
            object.__setattr__(self, "record_fingerprint", expected)
        object.__setattr__(self, "parent_evidence_ids", parents)

    @property
    def evidence_id(self) -> str:
        return self.record.evidence_id

    @property
    def fingerprint(self) -> str:
        return _fingerprint({
            "schema_version": self.schema_version,
            "record": self.record.to_dict(),
            "classification": self.classification,
            "retained_from": self.retained_from,
            "retain_until": self.retain_until,
            "export_allowed": self.export_allowed,
            "parent_evidence_ids": list(self.parent_evidence_ids),
            "record_fingerprint": self.record_fingerprint,
        })

    def retention_status(self, at: str) -> str:
        _iso8601(at, "at")
        return (
            "expired"
            if _parse_time(at) >= _parse_time(self.retain_until)
            else "retained"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "record": self.record.to_dict(),
            "classification": self.classification,
            "retained_from": self.retained_from,
            "retain_until": self.retain_until,
            "export_allowed": self.export_allowed,
            "parent_evidence_ids": list(self.parent_evidence_ids),
            "record_fingerprint": self.record_fingerprint,
            "custodied_evidence_fingerprint": self.fingerprint,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "CustodiedEvidence":
        required = {
            "schema_version",
            "record",
            "classification",
            "retained_from",
            "retain_until",
            "export_allowed",
            "parent_evidence_ids",
            "record_fingerprint",
            "custodied_evidence_fingerprint",
        }
        if not isinstance(payload, Mapping) or set(payload) != required:
            raise EvidenceCustodyError(
                "custodied evidence schema is not supported"
            )
        if not isinstance(payload["record"], Mapping):
            raise EvidenceCustodyError("record must be an object")
        parents = payload["parent_evidence_ids"]
        if not isinstance(parents, list):
            raise EvidenceCustodyError(
                "parent_evidence_ids must be a list"
            )
        try:
            record = EvidenceRecord.from_dict(payload["record"])
        except ValueError as exc:
            raise EvidenceCustodyError(str(exc)) from exc
        item = cls(
            schema_version=payload["schema_version"],
            record=record,
            classification=payload["classification"],
            retained_from=payload["retained_from"],
            retain_until=payload["retain_until"],
            export_allowed=payload["export_allowed"],
            parent_evidence_ids=tuple(parents),
            record_fingerprint=payload["record_fingerprint"],
        )
        if payload["custodied_evidence_fingerprint"] != item.fingerprint:
            raise EvidenceCustodyError(
                "custodied evidence fingerprint verification failed"
            )
        return item


@dataclass(frozen=True)
class CustodyEvent:
    event_id: str
    case_id: str
    engagement_id: str
    sequence: int
    event_type: str
    occurred_at: str
    actor_id: str
    reason: str
    evidence_id: str | None = None
    details: tuple[tuple[str, str], ...] = ()
    previous_event_fingerprint: str | None = None
    schema_version: int = CUSTODY_EVENT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != CUSTODY_EVENT_SCHEMA_VERSION:
            raise EvidenceCustodyError("unsupported custody event schema")
        _identifier(self.event_id, "event_id")
        _identifier(self.case_id, "case_id")
        _identifier(self.engagement_id, "engagement_id")
        if (
            not isinstance(self.sequence, int)
            or isinstance(self.sequence, bool)
            or self.sequence < 0
        ):
            raise EvidenceCustodyError(
                "custody event sequence must be nonnegative"
            )
        if self.event_type not in _VALID_CUSTODY_EVENTS:
            raise EvidenceCustodyError("unsupported custody event type")
        _iso8601(self.occurred_at, "occurred_at")
        _identifier(self.actor_id, "actor_id")
        _required_text(self.reason, "reason")
        if self.evidence_id is not None:
            _identifier(self.evidence_id, "evidence_id")
        if self.previous_event_fingerprint is not None:
            _sha256(
                self.previous_event_fingerprint,
                "previous_event_fingerprint",
            )
        if not isinstance(self.details, tuple):
            raise EvidenceCustodyError("custody details must be a tuple")
        normalized = tuple(sorted(self.details))
        keys = [key for key, _ in normalized]
        if len(keys) != len(set(keys)):
            raise EvidenceCustodyError(
                "custody detail keys must be unique"
            )
        for key, value in normalized:
            _required_text(key, "custody detail key")
            _required_text(value, "custody detail value")
            _reject_secret_keys({key: value})
        object.__setattr__(self, "details", normalized)

    def detail(self, key: str) -> str | None:
        for item_key, value in self.details:
            if item_key == key:
                return value
        return None

    def _payload(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "event_id": self.event_id,
            "case_id": self.case_id,
            "engagement_id": self.engagement_id,
            "sequence": self.sequence,
            "event_type": self.event_type,
            "occurred_at": self.occurred_at,
            "actor_id": self.actor_id,
            "reason": self.reason,
            "evidence_id": self.evidence_id,
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
    def from_dict(cls, payload: Mapping[str, Any]) -> "CustodyEvent":
        required = {
            "schema_version",
            "event_id",
            "case_id",
            "engagement_id",
            "sequence",
            "event_type",
            "occurred_at",
            "actor_id",
            "reason",
            "evidence_id",
            "details",
            "previous_event_fingerprint",
            "fingerprint",
        }
        if not isinstance(payload, Mapping) or set(payload) != required:
            raise EvidenceCustodyError(
                "custody event schema is not supported"
            )
        details = payload["details"]
        if not isinstance(details, list):
            raise EvidenceCustodyError("custody details must be a list")
        pairs: list[tuple[str, str]] = []
        for item in details:
            if (
                not isinstance(item, list)
                or len(item) != 2
                or not all(isinstance(value, str) for value in item)
            ):
                raise EvidenceCustodyError(
                    "custody detail is invalid"
                )
            pairs.append((item[0], item[1]))
        event = cls(
            schema_version=payload["schema_version"],
            event_id=payload["event_id"],
            case_id=payload["case_id"],
            engagement_id=payload["engagement_id"],
            sequence=payload["sequence"],
            event_type=payload["event_type"],
            occurred_at=payload["occurred_at"],
            actor_id=payload["actor_id"],
            reason=payload["reason"],
            evidence_id=payload["evidence_id"],
            details=tuple(pairs),
            previous_event_fingerprint=payload[
                "previous_event_fingerprint"
            ],
        )
        if payload["fingerprint"] != event.fingerprint:
            raise EvidenceCustodyError(
                "custody event fingerprint verification failed"
            )
        return event


@dataclass(frozen=True)
class ManifestEntry:
    evidence_id: str
    source_night: str
    evidence_type: str
    observed_at: str
    classification: str
    retain_until: str
    record_fingerprint: str
    custodied_evidence_fingerprint: str
    parent_evidence_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        _identifier(self.evidence_id, "evidence_id")
        _required_text(self.source_night, "source_night")
        _required_text(self.evidence_type, "evidence_type")
        _iso8601(self.observed_at, "observed_at")
        if self.classification not in _CLASSIFICATION_RANK:
            raise EvidenceCustodyError(
                "unsupported manifest classification"
            )
        _iso8601(self.retain_until, "retain_until")
        _sha256(self.record_fingerprint, "record_fingerprint")
        _sha256(
            self.custodied_evidence_fingerprint,
            "custodied_evidence_fingerprint",
        )
        parents = _sorted_unique_ids(
            self.parent_evidence_ids,
            field="parent_evidence_ids",
        )
        object.__setattr__(self, "parent_evidence_ids", parents)

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "source_night": self.source_night,
            "evidence_type": self.evidence_type,
            "observed_at": self.observed_at,
            "classification": self.classification,
            "retain_until": self.retain_until,
            "record_fingerprint": self.record_fingerprint,
            "custodied_evidence_fingerprint": (
                self.custodied_evidence_fingerprint
            ),
            "parent_evidence_ids": list(self.parent_evidence_ids),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "ManifestEntry":
        required = {
            "evidence_id",
            "source_night",
            "evidence_type",
            "observed_at",
            "classification",
            "retain_until",
            "record_fingerprint",
            "custodied_evidence_fingerprint",
            "parent_evidence_ids",
        }
        if not isinstance(payload, Mapping) or set(payload) != required:
            raise EvidenceCustodyError(
                "manifest entry schema is not supported"
            )
        parents = payload["parent_evidence_ids"]
        if not isinstance(parents, list):
            raise EvidenceCustodyError(
                "manifest parent_evidence_ids must be a list"
            )
        return cls(
            evidence_id=payload["evidence_id"],
            source_night=payload["source_night"],
            evidence_type=payload["evidence_type"],
            observed_at=payload["observed_at"],
            classification=payload["classification"],
            retain_until=payload["retain_until"],
            record_fingerprint=payload["record_fingerprint"],
            custodied_evidence_fingerprint=payload[
                "custodied_evidence_fingerprint"
            ],
            parent_evidence_ids=tuple(parents),
        )


@dataclass(frozen=True)
class EvidenceManifest:
    case_id: str
    engagement_id: str
    generated_at: str
    case_fingerprint: str
    entries: tuple[ManifestEntry, ...]
    authorization_effect: str = "none"
    schema_version: int = MANIFEST_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != MANIFEST_SCHEMA_VERSION:
            raise EvidenceCustodyError(
                "unsupported evidence manifest schema"
            )
        _identifier(self.case_id, "case_id")
        _identifier(self.engagement_id, "engagement_id")
        _iso8601(self.generated_at, "generated_at")
        _sha256(self.case_fingerprint, "case_fingerprint")
        if self.authorization_effect != "none":
            raise EvidenceCustodyError(
                "evidence manifests must never grant authorization"
            )
        if not isinstance(self.entries, tuple):
            raise EvidenceCustodyError(
                "manifest entries must be a tuple"
            )
        entries = tuple(
            sorted(self.entries, key=lambda item: item.evidence_id)
        )
        if any(not isinstance(item, ManifestEntry) for item in entries):
            raise EvidenceCustodyError(
                "manifest entries must contain ManifestEntry values"
            )
        ids = [item.evidence_id for item in entries]
        if len(ids) != len(set(ids)):
            raise EvidenceCustodyError(
                "manifest evidence IDs must be unique"
            )
        object.__setattr__(self, "entries", entries)

    def _payload(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "case_id": self.case_id,
            "engagement_id": self.engagement_id,
            "generated_at": self.generated_at,
            "case_fingerprint": self.case_fingerprint,
            "entries": [item.to_dict() for item in self.entries],
            "authorization_effect": self.authorization_effect,
        }

    @property
    def fingerprint(self) -> str:
        return _fingerprint(self._payload())

    def to_dict(self) -> dict[str, Any]:
        payload = self._payload()
        payload["manifest_fingerprint"] = self.fingerprint
        return payload

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "EvidenceManifest":
        required = {
            "schema_version",
            "case_id",
            "engagement_id",
            "generated_at",
            "case_fingerprint",
            "entries",
            "authorization_effect",
            "manifest_fingerprint",
        }
        if not isinstance(payload, Mapping) or set(payload) != required:
            raise EvidenceCustodyError(
                "evidence manifest schema is not supported"
            )
        entries = payload["entries"]
        if not isinstance(entries, list):
            raise EvidenceCustodyError(
                "manifest entries must be a list"
            )
        manifest = cls(
            schema_version=payload["schema_version"],
            case_id=payload["case_id"],
            engagement_id=payload["engagement_id"],
            generated_at=payload["generated_at"],
            case_fingerprint=payload["case_fingerprint"],
            entries=tuple(
                ManifestEntry.from_dict(item) for item in entries
            ),
            authorization_effect=payload["authorization_effect"],
        )
        if payload["manifest_fingerprint"] != manifest.fingerprint:
            raise EvidenceCustodyError(
                "evidence manifest fingerprint verification failed"
            )
        return manifest


@dataclass(frozen=True)
class EvidenceCustodyCase:
    case_id: str
    engagement_id: str
    data_handling: DataHandlingPolicy
    items: tuple[CustodiedEvidence, ...]
    events: tuple[CustodyEvent, ...]
    schema_version: int = CUSTODY_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != CUSTODY_SCHEMA_VERSION:
            raise EvidenceCustodyError(
                "unsupported evidence custody case schema"
            )
        _identifier(self.case_id, "case_id")
        _identifier(self.engagement_id, "engagement_id")
        if not isinstance(self.data_handling, DataHandlingPolicy):
            raise EvidenceCustodyError(
                "data_handling must be DataHandlingPolicy"
            )
        if not isinstance(self.items, tuple) or not self.items:
            raise EvidenceCustodyError(
                "custody case requires at least one evidence item"
            )
        items = tuple(sorted(self.items, key=lambda item: item.evidence_id))
        if any(not isinstance(item, CustodiedEvidence) for item in items):
            raise EvidenceCustodyError(
                "items must contain CustodiedEvidence values"
            )
        ids = [item.evidence_id for item in items]
        if len(ids) != len(set(ids)):
            raise EvidenceCustodyError(
                "custody evidence IDs must be unique"
            )
        if any(
            item.record.engagement_id != self.engagement_id
            for item in items
        ):
            raise EvidenceCustodyError(
                "all custody evidence must belong to the case engagement"
            )
        if any(
            _CLASSIFICATION_RANK[item.classification]
            < _CLASSIFICATION_RANK[self.data_handling.classification]
            for item in items
        ):
            raise EvidenceCustodyError(
                "evidence classification cannot be below engagement policy"
            )
        known = set(ids)
        for item in items:
            missing = set(item.parent_evidence_ids) - known
            if missing:
                raise EvidenceCustodyError(
                    "derived evidence references unknown parents"
                )

        if not isinstance(self.events, tuple) or not self.events:
            raise EvidenceCustodyError(
                "custody case requires at least one event"
            )
        object.__setattr__(self, "items", items)
        self._validate_events()

    @property
    def data_handling_fingerprint(self) -> str:
        return _policy_fingerprint(self.data_handling)

    def item(self, evidence_id: str) -> CustodiedEvidence:
        for item in self.items:
            if item.evidence_id == evidence_id:
                return item
        raise EvidenceCustodyError(
            f"evidence not found in custody case: {evidence_id}"
        )

    def _validate_events(self) -> None:
        item_by_id = {item.evidence_id: item for item in self.items}
        origins: set[str] = set()
        custodians: dict[str, str] = {}
        previous: CustodyEvent | None = None
        last_time: datetime | None = None

        for index, event in enumerate(self.events):
            if not isinstance(event, CustodyEvent):
                raise EvidenceCustodyError(
                    "events must contain CustodyEvent values"
                )
            if event.case_id != self.case_id:
                raise EvidenceCustodyError(
                    "custody event belongs to another case"
                )
            if event.engagement_id != self.engagement_id:
                raise EvidenceCustodyError(
                    "custody event belongs to another engagement"
                )
            if event.sequence != index:
                raise EvidenceCustodyError(
                    "custody event sequence is not contiguous"
                )
            expected_previous = (
                None if previous is None else previous.fingerprint
            )
            if event.previous_event_fingerprint != expected_previous:
                raise EvidenceCustodyError(
                    "custody event chain verification failed"
                )
            occurred = _parse_time(event.occurred_at)
            if last_time is not None and occurred < last_time:
                raise EvidenceCustodyError(
                    "custody events are not chronologically ordered"
                )

            if event.event_type in {"ingested", "derived"}:
                if event.evidence_id is None:
                    raise EvidenceCustodyError(
                        "evidence origin event requires evidence_id"
                    )
                if event.evidence_id in origins:
                    raise EvidenceCustodyError(
                        "evidence has more than one origin event"
                    )
                item = item_by_id.get(event.evidence_id)
                if item is None:
                    raise EvidenceCustodyError(
                        "custody event references unknown evidence"
                    )
                if item.retained_from != event.occurred_at:
                    raise EvidenceCustodyError(
                        "evidence retention start must match origin event"
                    )
                custodian = event.detail("custodian_id")
                if custodian is None:
                    raise EvidenceCustodyError(
                        "evidence origin event requires custodian_id"
                    )
                _identifier(custodian, "custodian_id")
                encoded_parents = event.detail("parent_evidence_ids")
                expected_parents = item.parent_evidence_ids
                if event.event_type == "derived":
                    if not expected_parents or encoded_parents is None:
                        raise EvidenceCustodyError(
                            "derived evidence requires parent evidence"
                        )
                    try:
                        decoded = json.loads(encoded_parents)
                    except json.JSONDecodeError as exc:
                        raise EvidenceCustodyError(
                            "derived parent evidence is invalid"
                        ) from exc
                    if (
                        not isinstance(decoded, list)
                        or tuple(sorted(decoded)) != expected_parents
                    ):
                        raise EvidenceCustodyError(
                            "derived parent evidence does not match item"
                        )
                elif expected_parents or encoded_parents is not None:
                    raise EvidenceCustodyError(
                        "ingested evidence cannot claim derivation parents"
                    )
                origins.add(event.evidence_id)
                custodians[event.evidence_id] = custodian

            elif event.event_type == "transferred":
                if event.evidence_id is None:
                    raise EvidenceCustodyError(
                        "transfer event requires evidence_id"
                    )
                if event.evidence_id not in custodians:
                    raise EvidenceCustodyError(
                        "cannot transfer evidence before origin custody"
                    )
                from_id = event.detail("from_custodian")
                to_id = event.detail("to_custodian")
                if from_id is None or to_id is None:
                    raise EvidenceCustodyError(
                        "transfer event requires from/to custodians"
                    )
                _identifier(from_id, "from_custodian")
                _identifier(to_id, "to_custodian")
                if from_id == to_id:
                    raise EvidenceCustodyError(
                        "custody transfer requires different custodians"
                    )
                if custodians[event.evidence_id] != from_id:
                    raise EvidenceCustodyError(
                        "custody transfer source does not hold evidence"
                    )
                if event.actor_id != from_id:
                    raise EvidenceCustodyError(
                        "custody transfer actor must be current custodian"
                    )
                custodians[event.evidence_id] = to_id

            elif event.event_type == "exported":
                if event.evidence_id is not None:
                    raise EvidenceCustodyError(
                        "case export event must not target one evidence item"
                    )
                destination = event.detail("destination")
                if destination is None:
                    raise EvidenceCustodyError(
                        "export event requires destination label"
                    )
                _required_text(destination, "destination")

            previous = event
            last_time = occurred

        if origins != set(item_by_id):
            raise EvidenceCustodyError(
                "every custody item requires exactly one origin event"
            )

    @property
    def fingerprint(self) -> str:
        return _fingerprint({
            "schema_version": self.schema_version,
            "case_id": self.case_id,
            "engagement_id": self.engagement_id,
            "data_handling": self.data_handling.to_dict(),
            "data_handling_fingerprint": self.data_handling_fingerprint,
            "item_fingerprints": [
                item.fingerprint for item in self.items
            ],
            "event_fingerprints": [
                event.fingerprint for event in self.events
            ],
            "authorization_effect": "none",
        })

    def verify_integrity(self) -> bool:
        return bool(self.fingerprint)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "case_id": self.case_id,
            "engagement_id": self.engagement_id,
            "data_handling": self.data_handling.to_dict(),
            "data_handling_fingerprint": self.data_handling_fingerprint,
            "items": [item.to_dict() for item in self.items],
            "events": [event.to_dict() for event in self.events],
            "authorization_effect": "none",
            "case_fingerprint": self.fingerprint,
        }

    def to_json(self) -> str:
        return _canonical_json(self.to_dict())

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "EvidenceCustodyCase":
        required = {
            "schema_version",
            "case_id",
            "engagement_id",
            "data_handling",
            "data_handling_fingerprint",
            "items",
            "events",
            "authorization_effect",
            "case_fingerprint",
        }
        if not isinstance(payload, Mapping) or set(payload) != required:
            raise EvidenceCustodyError(
                "evidence custody case schema is not supported"
            )
        if payload["authorization_effect"] != "none":
            raise EvidenceCustodyError(
                "evidence custody state must not grant authorization"
            )
        if not isinstance(payload["data_handling"], Mapping):
            raise EvidenceCustodyError(
                "data_handling must be an object"
            )
        if not isinstance(payload["items"], list):
            raise EvidenceCustodyError("items must be a list")
        if not isinstance(payload["events"], list):
            raise EvidenceCustodyError("events must be a list")
        try:
            policy = DataHandlingPolicy.from_dict(
                payload["data_handling"]
            )
        except ValueError as exc:
            raise EvidenceCustodyError(str(exc)) from exc
        if (
            payload["data_handling_fingerprint"]
            != _policy_fingerprint(policy)
        ):
            raise EvidenceCustodyError(
                "data handling fingerprint verification failed"
            )
        case = cls(
            schema_version=payload["schema_version"],
            case_id=payload["case_id"],
            engagement_id=payload["engagement_id"],
            data_handling=policy,
            items=tuple(
                CustodiedEvidence.from_dict(item)
                for item in payload["items"]
            ),
            events=tuple(
                CustodyEvent.from_dict(event)
                for event in payload["events"]
            ),
        )
        if payload["case_fingerprint"] != case.fingerprint:
            raise EvidenceCustodyError(
                "evidence custody case fingerprint verification failed"
            )
        return case

    @classmethod
    def from_json(cls, payload: str) -> "EvidenceCustodyCase":
        try:
            decoded = json.loads(payload)
        except (TypeError, json.JSONDecodeError) as exc:
            raise EvidenceCustodyError(
                "evidence custody case is not valid JSON"
            ) from exc
        return cls.from_dict(decoded)

    @staticmethod
    def _custodied_item(
        record: EvidenceRecord,
        policy: DataHandlingPolicy,
        *,
        retained_from: str,
        parent_evidence_ids: tuple[str, ...] = (),
        classification: str | None = None,
    ) -> CustodiedEvidence:
        _iso8601(retained_from, "retained_from")
        chosen_classification = (
            policy.classification
            if classification is None
            else classification
        )
        if chosen_classification not in _CLASSIFICATION_RANK:
            raise EvidenceCustodyError(
                "unsupported evidence classification"
            )
        if (
            _CLASSIFICATION_RANK[chosen_classification]
            < _CLASSIFICATION_RANK[policy.classification]
        ):
            raise EvidenceCustodyError(
                "evidence classification cannot be below engagement policy"
            )
        retain_until = (
            _parse_time(retained_from)
            + timedelta(days=policy.retention_days)
        ).isoformat()
        return CustodiedEvidence(
            record=record,
            classification=chosen_classification,
            retained_from=retained_from,
            retain_until=retain_until,
            export_allowed=policy.export_allowed,
            parent_evidence_ids=parent_evidence_ids,
        )

    @classmethod
    def create(
        cls,
        *,
        case_id: str,
        engagement_id: str,
        data_handling: DataHandlingPolicy,
        record: EvidenceRecord,
        actor_id: str,
        custodian_id: str,
        occurred_at: str,
        event_id: str,
        reason: str,
        classification: str | None = None,
    ) -> "EvidenceCustodyCase":
        if record.engagement_id != engagement_id:
            raise EvidenceCustodyError(
                "evidence engagement does not match custody case"
            )
        item = cls._custodied_item(
            record,
            data_handling,
            retained_from=occurred_at,
            classification=classification,
        )
        event = CustodyEvent(
            event_id=event_id,
            case_id=case_id,
            engagement_id=engagement_id,
            sequence=0,
            event_type="ingested",
            occurred_at=occurred_at,
            actor_id=actor_id,
            reason=reason,
            evidence_id=record.evidence_id,
            details=(("custodian_id", custodian_id),),
        )
        return cls(
            case_id=case_id,
            engagement_id=engagement_id,
            data_handling=data_handling,
            items=(item,),
            events=(event,),
        )

    def _append_event(
        self,
        *,
        event_id: str,
        event_type: str,
        occurred_at: str,
        actor_id: str,
        reason: str,
        evidence_id: str | None = None,
        details: tuple[tuple[str, str], ...] = (),
        items: tuple[CustodiedEvidence, ...] | None = None,
    ) -> "EvidenceCustodyCase":
        event = CustodyEvent(
            event_id=event_id,
            case_id=self.case_id,
            engagement_id=self.engagement_id,
            sequence=len(self.events),
            event_type=event_type,
            occurred_at=occurred_at,
            actor_id=actor_id,
            reason=reason,
            evidence_id=evidence_id,
            details=details,
            previous_event_fingerprint=self.events[-1].fingerprint,
        )
        return EvidenceCustodyCase(
            case_id=self.case_id,
            engagement_id=self.engagement_id,
            data_handling=self.data_handling,
            items=self.items if items is None else items,
            events=self.events + (event,),
        )

    def add_record(
        self,
        record: EvidenceRecord,
        *,
        actor_id: str,
        custodian_id: str,
        occurred_at: str,
        event_id: str,
        reason: str,
        parent_evidence_ids: tuple[str, ...] = (),
        classification: str | None = None,
    ) -> "EvidenceCustodyCase":
        if record.engagement_id != self.engagement_id:
            raise EvidenceCustodyError(
                "evidence engagement does not match custody case"
            )
        if any(item.evidence_id == record.evidence_id for item in self.items):
            raise EvidenceCustodyError(
                "evidence_id already exists in custody case"
            )
        parents = _sorted_unique_ids(
            parent_evidence_ids,
            field="parent_evidence_ids",
        )
        known = {item.evidence_id for item in self.items}
        if set(parents) - known:
            raise EvidenceCustodyError(
                "derived evidence references unknown parents"
            )
        item = self._custodied_item(
            record,
            self.data_handling,
            retained_from=occurred_at,
            parent_evidence_ids=parents,
            classification=classification,
        )
        event_type = "derived" if parents else "ingested"
        details: tuple[tuple[str, str], ...]
        if parents:
            details = (
                ("custodian_id", custodian_id),
                (
                    "parent_evidence_ids",
                    json.dumps(list(parents), separators=(",", ":")),
                ),
            )
        else:
            details = (("custodian_id", custodian_id),)
        return self._append_event(
            event_id=event_id,
            event_type=event_type,
            occurred_at=occurred_at,
            actor_id=actor_id,
            reason=reason,
            evidence_id=record.evidence_id,
            details=details,
            items=self.items + (item,),
        )

    def current_custodian(
        self,
        evidence_id: str,
        *,
        at: str | None = None,
    ) -> str:
        self.item(evidence_id)
        cutoff = (
            None
            if at is None
            else _parse_time(_iso8601(at, "at"))
        )
        custodian: str | None = None
        for event in self.events:
            if (
                cutoff is not None
                and _parse_time(event.occurred_at) > cutoff
            ):
                continue
            if event.evidence_id != evidence_id:
                continue
            if event.event_type in {"ingested", "derived"}:
                custodian = event.detail("custodian_id")
            elif event.event_type == "transferred":
                custodian = event.detail("to_custodian")
        if custodian is None:
            raise EvidenceCustodyError(
                "custodian state is unavailable"
            )
        return custodian

    def transfer(
        self,
        evidence_id: str,
        *,
        actor_id: str,
        to_custodian: str,
        occurred_at: str,
        event_id: str,
        reason: str,
    ) -> "EvidenceCustodyCase":
        current = self.current_custodian(
            evidence_id,
            at=occurred_at,
        )
        if actor_id != current:
            raise EvidenceCustodyError(
                "custody transfer actor must be current custodian"
            )
        _identifier(to_custodian, "to_custodian")
        if to_custodian == current:
            raise EvidenceCustodyError(
                "custody transfer requires different custodians"
            )
        return self._append_event(
            event_id=event_id,
            event_type="transferred",
            occurred_at=occurred_at,
            actor_id=actor_id,
            reason=reason,
            evidence_id=evidence_id,
            details=(
                ("from_custodian", current),
                ("to_custodian", to_custodian),
            ),
        )

    def manifest(self, *, generated_at: str) -> EvidenceManifest:
        _iso8601(generated_at, "generated_at")
        return EvidenceManifest(
            case_id=self.case_id,
            engagement_id=self.engagement_id,
            generated_at=generated_at,
            case_fingerprint=self.fingerprint,
            entries=tuple(
                ManifestEntry(
                    evidence_id=item.evidence_id,
                    source_night=item.record.source_night,
                    evidence_type=item.record.evidence_type,
                    observed_at=item.record.observed_at,
                    classification=item.classification,
                    retain_until=item.retain_until,
                    record_fingerprint=item.record_fingerprint,
                    custodied_evidence_fingerprint=item.fingerprint,
                    parent_evidence_ids=item.parent_evidence_ids,
                )
                for item in self.items
            ),
        )

    def _assert_exportable(self, at: str) -> None:
        _iso8601(at, "at")
        if not self.data_handling.export_allowed:
            raise EvidenceCustodyError(
                "engagement data-handling policy forbids export"
            )
        expired = tuple(
            item.evidence_id
            for item in self.items
            if item.retention_status(at) == "expired"
        )
        if expired:
            raise EvidenceCustodyError(
                "expired evidence cannot be exported: "
                + ",".join(expired)
            )
        if any(not item.export_allowed for item in self.items):
            raise EvidenceCustodyError(
                "custody item policy forbids export"
            )

    def export(
        self,
        *,
        actor_id: str,
        destination: str,
        occurred_at: str,
        event_id: str,
        reason: str,
    ) -> tuple["EvidenceCustodyCase", "EvidenceExportBundle"]:
        self._assert_exportable(occurred_at)
        _required_text(destination, "destination")
        _reject_secret_keys({"destination": destination})
        updated = self._append_event(
            event_id=event_id,
            event_type="exported",
            occurred_at=occurred_at,
            actor_id=actor_id,
            reason=reason,
            details=(("destination", destination),),
        )
        manifest = updated.manifest(generated_at=occurred_at)
        bundle = EvidenceExportBundle(
            case=updated,
            manifest=manifest,
            records=tuple(item.record for item in updated.items),
        )
        return updated, bundle


@dataclass(frozen=True)
class EvidenceExportBundle:
    case: EvidenceCustodyCase
    manifest: EvidenceManifest
    records: tuple[EvidenceRecord, ...]
    authorization_effect: str = "none"
    schema_version: int = EXPORT_BUNDLE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != EXPORT_BUNDLE_SCHEMA_VERSION:
            raise EvidenceCustodyError(
                "unsupported evidence export schema"
            )
        if self.authorization_effect != "none":
            raise EvidenceCustodyError(
                "exported evidence must never grant authorization"
            )
        if not isinstance(self.case, EvidenceCustodyCase):
            raise EvidenceCustodyError(
                "case must be EvidenceCustodyCase"
            )
        if not isinstance(self.manifest, EvidenceManifest):
            raise EvidenceCustodyError(
                "manifest must be EvidenceManifest"
            )
        if (
            self.manifest.case_id != self.case.case_id
            or self.manifest.engagement_id != self.case.engagement_id
            or self.manifest.case_fingerprint != self.case.fingerprint
        ):
            raise EvidenceCustodyError(
                "manifest is not bound to custody case"
            )
        if not isinstance(self.records, tuple):
            raise EvidenceCustodyError(
                "export records must be a tuple"
            )
        records = tuple(
            sorted(self.records, key=lambda item: item.evidence_id)
        )
        if any(not isinstance(item, EvidenceRecord) for item in records):
            raise EvidenceCustodyError(
                "export records must contain EvidenceRecord values"
            )
        ids = [item.evidence_id for item in records]
        if len(ids) != len(set(ids)):
            raise EvidenceCustodyError(
                "export record IDs must be unique"
            )
        expected = {
            item.evidence_id: item.record_fingerprint
            for item in self.case.items
        }
        actual = {
            record.evidence_id: _record_fingerprint(record)
            for record in records
        }
        if actual != expected:
            raise EvidenceCustodyError(
                "export records do not match custody fingerprints"
            )
        manifest_ids = {
            item.evidence_id for item in self.manifest.entries
        }
        if manifest_ids != set(expected):
            raise EvidenceCustodyError(
                "manifest records do not match custody case"
            )
        object.__setattr__(self, "records", records)

    def _payload(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "authorization_effect": self.authorization_effect,
            "case": self.case.to_dict(),
            "manifest": self.manifest.to_dict(),
            "records": [record.to_dict() for record in self.records],
        }

    @property
    def fingerprint(self) -> str:
        return _fingerprint(self._payload())

    def to_dict(self) -> dict[str, Any]:
        payload = self._payload()
        payload["bundle_fingerprint"] = self.fingerprint
        return payload

    def to_json(self) -> str:
        return _canonical_json(self.to_dict())

    def verify_integrity(self) -> bool:
        return bool(self.fingerprint)

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "EvidenceExportBundle":
        required = {
            "schema_version",
            "authorization_effect",
            "case",
            "manifest",
            "records",
            "bundle_fingerprint",
        }
        if not isinstance(payload, Mapping) or set(payload) != required:
            raise EvidenceCustodyError(
                "evidence export bundle schema is not supported"
            )
        if not isinstance(payload["case"], Mapping):
            raise EvidenceCustodyError(
                "export case must be an object"
            )
        if not isinstance(payload["manifest"], Mapping):
            raise EvidenceCustodyError(
                "export manifest must be an object"
            )
        if not isinstance(payload["records"], list):
            raise EvidenceCustodyError(
                "export records must be a list"
            )
        try:
            records = tuple(
                EvidenceRecord.from_dict(item)
                for item in payload["records"]
            )
        except ValueError as exc:
            raise EvidenceCustodyError(str(exc)) from exc
        bundle = cls(
            schema_version=payload["schema_version"],
            authorization_effect=payload["authorization_effect"],
            case=EvidenceCustodyCase.from_dict(payload["case"]),
            manifest=EvidenceManifest.from_dict(payload["manifest"]),
            records=records,
        )
        if payload["bundle_fingerprint"] != bundle.fingerprint:
            raise EvidenceCustodyError(
                "evidence export bundle fingerprint verification failed"
            )
        return bundle

    @classmethod
    def from_json(cls, payload: str) -> "EvidenceExportBundle":
        try:
            decoded = json.loads(payload)
        except (TypeError, json.JSONDecodeError) as exc:
            raise EvidenceCustodyError(
                "evidence export bundle is not valid JSON"
            ) from exc
        return cls.from_dict(decoded)


class CustodyStore(Protocol):
    def create(self, case: EvidenceCustodyCase) -> None: ...
    def advance(self, case: EvidenceCustodyCase) -> None: ...
    def case(self, case_id: str) -> EvidenceCustodyCase | None: ...
    def cases(self) -> tuple[str, ...]: ...


class InMemoryCustodyStore:
    def __init__(self) -> None:
        self._cases: dict[str, EvidenceCustodyCase] = {}

    def create(self, case: EvidenceCustodyCase) -> None:
        existing = self._cases.get(case.case_id)
        if existing is None:
            self._cases[case.case_id] = case
            return
        if existing != case:
            raise EvidenceCustodyError(
                f"conflicting custody case already exists: {case.case_id}"
            )

    def advance(self, case: EvidenceCustodyCase) -> None:
        previous = self._cases.get(case.case_id)
        if previous is None:
            raise EvidenceCustodyError(
                f"custody case not found: {case.case_id}"
            )
        if previous.engagement_id != case.engagement_id:
            raise EvidenceCustodyError(
                "custody case engagement cannot change"
            )
        if previous.data_handling != case.data_handling:
            raise EvidenceCustodyError(
                "custody data-handling policy cannot change in place"
            )
        previous_items = {
            item.evidence_id: item for item in previous.items
        }
        current_items = {
            item.evidence_id: item for item in case.items
        }
        if any(
            current_items.get(evidence_id) != item
            for evidence_id, item in previous_items.items()
        ):
            raise EvidenceCustodyError(
                "existing custody evidence cannot be modified or removed"
            )
        old_events = tuple(
            event.fingerprint for event in previous.events
        )
        new_events = tuple(event.fingerprint for event in case.events)
        if new_events[:len(old_events)] != old_events:
            raise EvidenceCustodyError(
                "custody history is not an append-only extension"
            )
        self._cases[case.case_id] = case

    def case(self, case_id: str) -> EvidenceCustodyCase | None:
        _identifier(case_id, "case_id")
        return self._cases.get(case_id)

    def cases(self) -> tuple[str, ...]:
        return tuple(sorted(self._cases))


class FileCustodyStore:
    """Atomic local custody store; logical history remains append-only."""

    SCHEMA_VERSION = 1

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._memory = InMemoryCustodyStore()
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            payload = json.loads(
                self.path.read_text(encoding="utf-8")
            )
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise EvidenceCustodyError(
                "custody store is not valid UTF-8 JSON"
            ) from exc
        if (
            not isinstance(payload, Mapping)
            or set(payload) != {"schema_version", "cases"}
            or payload["schema_version"] != self.SCHEMA_VERSION
            or not isinstance(payload["cases"], list)
        ):
            raise EvidenceCustodyError(
                "custody store schema is not supported"
            )
        seen: set[str] = set()
        for item in payload["cases"]:
            case = EvidenceCustodyCase.from_dict(item)
            if case.case_id in seen:
                raise EvidenceCustodyError(
                    "custody store contains duplicate case"
                )
            seen.add(case.case_id)
            self._memory.create(case)

    def _persist(self) -> None:
        payload = {
            "schema_version": self.SCHEMA_VERSION,
            "cases": [
                self._memory.case(case_id).to_dict()
                for case_id in self._memory.cases()
                if self._memory.case(case_id) is not None
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

    def create(self, case: EvidenceCustodyCase) -> None:
        before = self._memory.case(case.case_id)
        self._memory.create(case)
        if before != case:
            self._persist()

    def advance(self, case: EvidenceCustodyCase) -> None:
        previous = self._memory.case(case.case_id)
        self._memory.advance(case)
        if previous != case:
            self._persist()

    def case(self, case_id: str) -> EvidenceCustodyCase | None:
        return self._memory.case(case_id)

    def cases(self) -> tuple[str, ...]:
        return self._memory.cases()


def render_custody_summary(
    case: EvidenceCustodyCase,
    *,
    at: str,
) -> str:
    """Human-readable secret-safe custody summary without evidence data."""

    _iso8601(at, "at")
    lines = [
        f"Custody case: {case.case_id}",
        f"Engagement: {case.engagement_id}",
        f"Classification floor: {case.data_handling.classification}",
        f"Retention days: {case.data_handling.retention_days}",
        f"Export allowed: {'yes' if case.data_handling.export_allowed else 'no'}",
        f"Evidence items: {len(case.items)}",
        f"Custody events: {len(case.events)}",
        f"Case fingerprint: {case.fingerprint}",
        "Authorization effect: none",
    ]
    for item in case.items:
        lines.append(
            " | ".join((
                item.evidence_id,
                item.record.source_night,
                item.record.evidence_type,
                item.classification,
                item.retention_status(at),
                item.record_fingerprint,
            ))
        )
    return "\n".join(lines)
