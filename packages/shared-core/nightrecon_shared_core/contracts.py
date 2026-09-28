"""Versioned, secret-free contracts for cross-Night engagement evidence."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any, Mapping
import json


SCHEMA_VERSION = 1
_VALID_NIGHTS = frozenset({"white", "blue", "red", "purple", "black"})
_VALID_ENGAGEMENT_STATUS = frozenset({"planned", "active", "paused", "completed", "archived"})
_FORBIDDEN_FIELD_FRAGMENTS = (
    "password", "passwd", "secret", "token", "credential", "cookie",
    "authorization", "api_key", "apikey", "private_key", "session",
)


def _required_text(value: str, field: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(f"{field} must be a nonblank, trimmed string")
    return value


def _optional_text(value: str | None, field: str) -> str | None:
    if value is None:
        return None
    return _required_text(value, field)


def _iso8601(value: str, field: str) -> str:
    _required_text(value, field)
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field} must be ISO-8601") from exc
    return value


def _reject_secret_keys(value: Any, path: str = "$") -> None:
    if isinstance(value, Mapping):
        for key, nested in value.items():
            if not isinstance(key, str):
                raise ValueError("evidence data object keys must be strings")
            lowered = key.lower()
            if any(fragment in lowered for fragment in _FORBIDDEN_FIELD_FRAGMENTS):
                raise ValueError(f"secret-like evidence field is not allowed: {path}.{key}")
            _reject_secret_keys(nested, f"{path}.{key}")
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            _reject_secret_keys(nested, f"{path}[{index}]")


@dataclass(frozen=True)
class EngagementMetadata:
    """Portable non-authoritative engagement coordination metadata."""

    engagement_id: str
    name: str
    created_at: str
    authorization_reference: str
    status: str = "planned"
    description: str | None = None
    schema_version: int = SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError("unsupported engagement metadata schema version")
        _required_text(self.engagement_id, "engagement_id")
        _required_text(self.name, "name")
        _iso8601(self.created_at, "created_at")
        _required_text(self.authorization_reference, "authorization_reference")
        if self.status not in _VALID_ENGAGEMENT_STATUS:
            raise ValueError("unsupported engagement status")
        _optional_text(self.description, "description")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "EngagementMetadata":
        if not isinstance(payload, Mapping):
            raise ValueError("engagement metadata must be an object")
        required = {
            "schema_version", "engagement_id", "name", "created_at",
            "authorization_reference", "status", "description",
        }
        if set(payload) != required:
            raise ValueError("engagement metadata schema is not supported")
        return cls(**dict(payload))


@dataclass(frozen=True)
class EvidenceRecord:
    """Portable evidence record shared across independently installable Nights."""

    engagement_id: str
    evidence_id: str
    source_night: str
    evidence_type: str
    observed_at: str
    provenance: str
    data: Mapping[str, Any]
    limitations: tuple[str, ...] = ()
    schema_version: int = SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError("unsupported evidence schema version")
        _required_text(self.engagement_id, "engagement_id")
        _required_text(self.evidence_id, "evidence_id")
        _required_text(self.evidence_type, "evidence_type")
        _required_text(self.provenance, "provenance")
        if self.source_night not in _VALID_NIGHTS:
            raise ValueError("source_night must identify a known Night")
        _iso8601(self.observed_at, "observed_at")
        if not isinstance(self.data, Mapping):
            raise ValueError("data must be an object")
        _reject_secret_keys(self.data)
        for limitation in self.limitations:
            _required_text(limitation, "limitation")

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["data"] = dict(self.data)
        return payload

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "EvidenceRecord":
        if not isinstance(payload, Mapping):
            raise ValueError("evidence record must be an object")
        required = {
            "schema_version", "engagement_id", "evidence_id", "source_night",
            "evidence_type", "observed_at", "provenance", "data", "limitations",
        }
        if set(payload) != required:
            raise ValueError("evidence record schema is not supported")
        limitations = payload["limitations"]
        if not isinstance(limitations, (list, tuple)) or any(
            not isinstance(item, str) for item in limitations
        ):
            raise ValueError("limitations must be a list or tuple of strings")
        return cls(
            schema_version=payload["schema_version"],
            engagement_id=payload["engagement_id"],
            evidence_id=payload["evidence_id"],
            source_night=payload["source_night"],
            evidence_type=payload["evidence_type"],
            observed_at=payload["observed_at"],
            provenance=payload["provenance"],
            data=payload["data"],
            limitations=tuple(limitations),
        )


@dataclass(frozen=True)
class EngagementEnvelope:
    """Portable bundle for standalone export/import or shared-stack exchange."""

    engagement_id: str
    records: tuple[EvidenceRecord, ...]
    metadata: EngagementMetadata | None = None
    schema_version: int = SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError("unsupported engagement schema version")
        _required_text(self.engagement_id, "engagement_id")
        if any(record.engagement_id != self.engagement_id for record in self.records):
            raise ValueError("all evidence records must belong to the envelope engagement")
        if self.metadata is not None and self.metadata.engagement_id != self.engagement_id:
            raise ValueError("engagement metadata must belong to the envelope engagement")
        ids = [record.evidence_id for record in self.records]
        if len(ids) != len(set(ids)):
            raise ValueError("evidence_id values must be unique within an engagement envelope")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "engagement_id": self.engagement_id,
            "metadata": None if self.metadata is None else self.metadata.to_dict(),
            "records": [record.to_dict() for record in self.records],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "EngagementEnvelope":
        if not isinstance(payload, Mapping):
            raise ValueError("engagement envelope must be an object")
        fields = set(payload)
        if fields not in (
            {"schema_version", "engagement_id", "records"},
            {"schema_version", "engagement_id", "metadata", "records"},
        ):
            raise ValueError("engagement envelope schema is not supported")
        records = payload["records"]
        if not isinstance(records, list):
            raise ValueError("records must be a list")
        metadata_payload = payload.get("metadata")
        if metadata_payload is not None and not isinstance(metadata_payload, Mapping):
            raise ValueError("metadata must be an object or null")
        return cls(
            schema_version=payload["schema_version"],
            engagement_id=payload["engagement_id"],
            metadata=(
                None if metadata_payload is None
                else EngagementMetadata.from_dict(metadata_payload)
            ),
            records=tuple(EvidenceRecord.from_dict(item) for item in records),
        )

    @classmethod
    def from_json(cls, payload: str) -> "EngagementEnvelope":
        try:
            decoded = json.loads(payload)
        except (TypeError, json.JSONDecodeError) as exc:
            raise ValueError("engagement envelope is not valid JSON") from exc
        return cls.from_dict(decoded)
