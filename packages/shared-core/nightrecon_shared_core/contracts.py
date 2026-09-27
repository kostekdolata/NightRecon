"""Versioned, secret-free contracts for cross-Night engagement evidence."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Mapping
import json


SCHEMA_VERSION = 1
_VALID_NIGHTS = frozenset({"white", "blue", "red", "purple", "black"})
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


def _required_text(value: str, field: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(f"{field} must be a nonblank, trimmed string")
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
        try:
            datetime.fromisoformat(self.observed_at.replace("Z", "+00:00"))
        except (TypeError, ValueError) as exc:
            raise ValueError("observed_at must be ISO-8601") from exc
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


@dataclass(frozen=True)
class EngagementEnvelope:
    """Portable bundle for standalone export/import or shared-stack exchange."""

    engagement_id: str
    records: tuple[EvidenceRecord, ...]
    schema_version: int = SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError("unsupported engagement schema version")
        _required_text(self.engagement_id, "engagement_id")
        if any(record.engagement_id != self.engagement_id for record in self.records):
            raise ValueError("all evidence records must belong to the envelope engagement")
        ids = [record.evidence_id for record in self.records]
        if len(ids) != len(set(ids)):
            raise ValueError("evidence_id values must be unique within an engagement envelope")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "engagement_id": self.engagement_id,
            "records": [record.to_dict() for record in self.records],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))
