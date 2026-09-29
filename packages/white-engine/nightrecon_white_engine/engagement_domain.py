"""Immutable White Night engagement, scope, and ROE authoring domain.

These models describe operator-approved intent. They do not themselves authorize
or execute any active operation. Batch 4 will compile an approved ROE into the
shared-core execution-policy contract.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
from hashlib import sha256
import json
import re
from typing import Any, Mapping

from nightrecon_shared_core.authorization import Scope


ENGAGEMENT_SCHEMA_VERSION = 1
ROE_SCHEMA_VERSION = 1

_VALID_STATUSES = frozenset({"planned", "active", "paused", "completed", "archived"})
_VALID_INTRUSIVENESS = (
    "passive",
    "safe-active",
    "intrusive",
    "destructive",
)
_VALID_CLASSIFICATIONS = frozenset({
    "public",
    "internal",
    "confidential",
    "restricted",
})
_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_TECHNIQUE_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/ -]{0,127}$")


def _required_text(value: str, field: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(f"{field} must be a nonblank, trimmed string")
    return value


def _optional_text(value: str | None, field: str) -> str | None:
    if value is None:
        return None
    return _required_text(value, field)


def _identifier(value: str, field: str) -> str:
    _required_text(value, field)
    if _ID_PATTERN.fullmatch(value) is None:
        raise ValueError(f"{field} contains unsupported characters")
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


def _unique_sorted_text(
    values: tuple[str, ...],
    *,
    field: str,
    minimum: int = 0,
    pattern: re.Pattern[str] | None = None,
) -> tuple[str, ...]:
    if not isinstance(values, tuple):
        raise ValueError(f"{field} must be a tuple")
    if len(values) < minimum:
        raise ValueError(f"{field} must contain at least {minimum} item(s)")
    if len(values) != len(set(values)):
        raise ValueError(f"{field} must not contain duplicates")
    for value in values:
        _required_text(value, field)
        if pattern is not None and pattern.fullmatch(value) is None:
            raise ValueError(f"{field} contains an invalid value")
    return tuple(sorted(values))


@dataclass(frozen=True)
class EngagementContact:
    """A named engagement participant/contact without authentication secrets."""

    contact_id: str
    display_name: str
    role: str
    email: str | None = None
    phone: str | None = None

    def __post_init__(self) -> None:
        _identifier(self.contact_id, "contact_id")
        _required_text(self.display_name, "display_name")
        _required_text(self.role, "role")
        _optional_text(self.email, "email")
        _optional_text(self.phone, "phone")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "EngagementContact":
        required = {"contact_id", "display_name", "role", "email", "phone"}
        if not isinstance(payload, Mapping) or set(payload) != required:
            raise ValueError("engagement contact schema is not supported")
        return cls(**dict(payload))


@dataclass(frozen=True)
class ScopeDefinition:
    """Declared allowed/excluded targets for ROE authoring.

    This is descriptive input for future policy compilation. Active operations
    continue to rely on shared-core authorization enforcement.
    """

    allowed: tuple[str, ...]
    excluded: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        allowed = _unique_sorted_text(
            self.allowed, field="allowed", minimum=1
        )
        excluded = _unique_sorted_text(
            self.excluded, field="excluded"
        )
        # Reuse the canonical shared-core target-rule parser for syntax
        # validation without treating this authoring model as authorization.
        Scope.from_values(list(allowed))
        if excluded:
            Scope.from_values(list(excluded))
        object.__setattr__(self, "allowed", allowed)
        object.__setattr__(self, "excluded", excluded)

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": list(self.allowed),
            "excluded": list(self.excluded),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "ScopeDefinition":
        if not isinstance(payload, Mapping) or set(payload) != {"allowed", "excluded"}:
            raise ValueError("scope definition schema is not supported")
        if not isinstance(payload["allowed"], list) or not isinstance(payload["excluded"], list):
            raise ValueError("scope targets must be lists")
        return cls(
            allowed=tuple(payload["allowed"]),
            excluded=tuple(payload["excluded"]),
        )


@dataclass(frozen=True)
class DataHandlingPolicy:
    classification: str = "confidential"
    retention_days: int = 90
    export_allowed: bool = True
    notes: str | None = None

    def __post_init__(self) -> None:
        if self.classification not in _VALID_CLASSIFICATIONS:
            raise ValueError("unsupported data classification")
        if (
            not isinstance(self.retention_days, int)
            or isinstance(self.retention_days, bool)
            or self.retention_days < 1
            or self.retention_days > 3650
        ):
            raise ValueError("retention_days must be between 1 and 3650")
        if not isinstance(self.export_allowed, bool):
            raise ValueError("export_allowed must be boolean")
        _optional_text(self.notes, "notes")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "DataHandlingPolicy":
        required = {"classification", "retention_days", "export_allowed", "notes"}
        if not isinstance(payload, Mapping) or set(payload) != required:
            raise ValueError("data handling policy schema is not supported")
        return cls(**dict(payload))


@dataclass(frozen=True)
class RulesOfEngagement:
    engagement_id: str
    version: int
    title: str
    created_at: str
    valid_from: str
    valid_until: str
    scope: ScopeDefinition
    allowed_techniques: tuple[str, ...]
    prohibited_techniques: tuple[str, ...] = ()
    max_intrusiveness: str = "safe-active"
    max_actions: int = 100
    data_handling: DataHandlingPolicy = DataHandlingPolicy()
    deviation_requires_approval: bool = True
    notes: str | None = None
    schema_version: int = ROE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != ROE_SCHEMA_VERSION:
            raise ValueError("unsupported ROE schema version")
        _identifier(self.engagement_id, "engagement_id")
        if not isinstance(self.version, int) or isinstance(self.version, bool) or self.version < 1:
            raise ValueError("version must be a positive integer")
        _required_text(self.title, "title")
        _iso8601(self.created_at, "created_at")
        _iso8601(self.valid_from, "valid_from")
        _iso8601(self.valid_until, "valid_until")
        if _parse_time(self.valid_until) <= _parse_time(self.valid_from):
            raise ValueError("valid_until must be later than valid_from")
        if not isinstance(self.scope, ScopeDefinition):
            raise ValueError("scope must be a ScopeDefinition")

        allowed = _unique_sorted_text(
            self.allowed_techniques,
            field="allowed_techniques",
            minimum=1,
            pattern=_TECHNIQUE_PATTERN,
        )
        prohibited = _unique_sorted_text(
            self.prohibited_techniques,
            field="prohibited_techniques",
            pattern=_TECHNIQUE_PATTERN,
        )
        overlap = set(allowed).intersection(prohibited)
        if overlap:
            raise ValueError("a technique cannot be both allowed and prohibited")
        object.__setattr__(self, "allowed_techniques", allowed)
        object.__setattr__(self, "prohibited_techniques", prohibited)

        if self.max_intrusiveness not in _VALID_INTRUSIVENESS:
            raise ValueError("unsupported max_intrusiveness")
        if (
            not isinstance(self.max_actions, int)
            or isinstance(self.max_actions, bool)
            or self.max_actions < 1
        ):
            raise ValueError("max_actions must be a positive integer")
        if not isinstance(self.data_handling, DataHandlingPolicy):
            raise ValueError("data_handling must be a DataHandlingPolicy")
        if not isinstance(self.deviation_requires_approval, bool):
            raise ValueError("deviation_requires_approval must be boolean")
        _optional_text(self.notes, "notes")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "engagement_id": self.engagement_id,
            "version": self.version,
            "title": self.title,
            "created_at": self.created_at,
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
            "scope": self.scope.to_dict(),
            "allowed_techniques": list(self.allowed_techniques),
            "prohibited_techniques": list(self.prohibited_techniques),
            "max_intrusiveness": self.max_intrusiveness,
            "max_actions": self.max_actions,
            "data_handling": self.data_handling.to_dict(),
            "deviation_requires_approval": self.deviation_requires_approval,
            "notes": self.notes,
        }

    def canonical_json(self) -> str:
        return json.dumps(
            self.to_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )

    @property
    def fingerprint(self) -> str:
        return sha256(self.canonical_json().encode("utf-8")).hexdigest()

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "RulesOfEngagement":
        required = {
            "schema_version",
            "engagement_id",
            "version",
            "title",
            "created_at",
            "valid_from",
            "valid_until",
            "scope",
            "allowed_techniques",
            "prohibited_techniques",
            "max_intrusiveness",
            "max_actions",
            "data_handling",
            "deviation_requires_approval",
            "notes",
        }
        if not isinstance(payload, Mapping) or set(payload) != required:
            raise ValueError("ROE schema is not supported")
        if not isinstance(payload["allowed_techniques"], list):
            raise ValueError("allowed_techniques must be a list")
        if not isinstance(payload["prohibited_techniques"], list):
            raise ValueError("prohibited_techniques must be a list")
        return cls(
            schema_version=payload["schema_version"],
            engagement_id=payload["engagement_id"],
            version=payload["version"],
            title=payload["title"],
            created_at=payload["created_at"],
            valid_from=payload["valid_from"],
            valid_until=payload["valid_until"],
            scope=ScopeDefinition.from_dict(payload["scope"]),
            allowed_techniques=tuple(payload["allowed_techniques"]),
            prohibited_techniques=tuple(payload["prohibited_techniques"]),
            max_intrusiveness=payload["max_intrusiveness"],
            max_actions=payload["max_actions"],
            data_handling=DataHandlingPolicy.from_dict(payload["data_handling"]),
            deviation_requires_approval=payload["deviation_requires_approval"],
            notes=payload["notes"],
        )


@dataclass(frozen=True)
class EngagementDefinition:
    engagement_id: str
    version: int
    name: str
    created_at: str
    status: str
    owner_contact_id: str
    contacts: tuple[EngagementContact, ...]
    roe: RulesOfEngagement
    description: str | None = None
    schema_version: int = ENGAGEMENT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != ENGAGEMENT_SCHEMA_VERSION:
            raise ValueError("unsupported engagement definition schema version")
        _identifier(self.engagement_id, "engagement_id")
        if not isinstance(self.version, int) or isinstance(self.version, bool) or self.version < 1:
            raise ValueError("version must be a positive integer")
        _required_text(self.name, "name")
        _iso8601(self.created_at, "created_at")
        if self.status not in _VALID_STATUSES:
            raise ValueError("unsupported engagement status")
        _identifier(self.owner_contact_id, "owner_contact_id")
        if not isinstance(self.contacts, tuple) or not self.contacts:
            raise ValueError("contacts must be a nonempty tuple")
        for contact in self.contacts:
            if not isinstance(contact, EngagementContact):
                raise ValueError("contacts must contain EngagementContact values")
        contacts = tuple(sorted(self.contacts, key=lambda item: item.contact_id))
        ids = [contact.contact_id for contact in contacts]
        if len(ids) != len(set(ids)):
            raise ValueError("contact_id values must be unique")
        if self.owner_contact_id not in ids:
            raise ValueError("owner_contact_id must identify an engagement contact")
        if not isinstance(self.roe, RulesOfEngagement):
            raise ValueError("roe must be RulesOfEngagement")
        if self.roe.engagement_id != self.engagement_id:
            raise ValueError("ROE must belong to the engagement")
        object.__setattr__(self, "contacts", contacts)
        _optional_text(self.description, "description")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "engagement_id": self.engagement_id,
            "version": self.version,
            "name": self.name,
            "created_at": self.created_at,
            "status": self.status,
            "owner_contact_id": self.owner_contact_id,
            "contacts": [item.to_dict() for item in self.contacts],
            "roe": self.roe.to_dict(),
            "description": self.description,
        }

    def canonical_json(self) -> str:
        return json.dumps(
            self.to_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )

    @property
    def fingerprint(self) -> str:
        return sha256(self.canonical_json().encode("utf-8")).hexdigest()

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "EngagementDefinition":
        required = {
            "schema_version",
            "engagement_id",
            "version",
            "name",
            "created_at",
            "status",
            "owner_contact_id",
            "contacts",
            "roe",
            "description",
        }
        if not isinstance(payload, Mapping) or set(payload) != required:
            raise ValueError("engagement definition schema is not supported")
        if not isinstance(payload["contacts"], list):
            raise ValueError("contacts must be a list")
        return cls(
            schema_version=payload["schema_version"],
            engagement_id=payload["engagement_id"],
            version=payload["version"],
            name=payload["name"],
            created_at=payload["created_at"],
            status=payload["status"],
            owner_contact_id=payload["owner_contact_id"],
            contacts=tuple(
                EngagementContact.from_dict(item) for item in payload["contacts"]
            ),
            roe=RulesOfEngagement.from_dict(payload["roe"]),
            description=payload["description"],
        )
