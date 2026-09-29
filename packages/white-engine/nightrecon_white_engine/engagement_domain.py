"""Immutable White Night engagement, scope, and ROE authoring domain.

These models are network-free and non-authoritative for execution. They describe
what an engagement intends to permit. Batch 4 will compile an approved definition
into shared-core execution policy; constructing or loading these objects never
grants authorization by itself.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
import hashlib
import ipaddress
import json
import re
from typing import Any, Mapping

from nightrecon_shared_core.authorization import Scope, TargetType, parse_target


ENGAGEMENT_DEFINITION_SCHEMA_VERSION = 1

_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_ACTION_PATTERN = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")
_TECHNIQUE_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}$")


class EngagementEnvironment(str, Enum):
    PRODUCTION = "production"
    TEST = "test"
    CYBER_RANGE = "cyber-range"


class EngagementRole(str, Enum):
    ENGAGEMENT_LEAD = "engagement-lead"
    OPERATOR = "operator"
    APPROVER = "approver"
    CLIENT_CONTACT = "client-contact"
    EMERGENCY_CONTACT = "emergency-contact"
    FACILITATOR = "facilitator"
    OBSERVER = "observer"
    REVIEWER = "reviewer"


class WindowKind(str, Enum):
    TESTING = "testing"
    EXERCISE = "exercise"


class IntrusivenessLevel(str, Enum):
    PASSIVE = "passive"
    SAFE_ACTIVE = "safe-active"
    INTRUSIVE = "intrusive"
    DESTRUCTIVE = "destructive"


class DataClassification(str, Enum):
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


class ExportPolicy(str, Enum):
    PROHIBITED = "prohibited"
    APPROVED_ONLY = "approved-only"
    ALLOWED = "allowed"


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


def _utc_iso8601(value: str, field: str) -> str:
    _required_text(value, field)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field} must be ISO-8601") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{field} must include a timezone")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _enum(value: str | Enum, enum_type: type[Enum], field: str) -> Enum:
    try:
        return value if isinstance(value, enum_type) else enum_type(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field} is not supported") from exc


def _sorted_unique_text(
    values: tuple[str, ...],
    *,
    field: str,
    pattern: re.Pattern[str] | None = None,
) -> tuple[str, ...]:
    if not isinstance(values, tuple):
        raise ValueError(f"{field} must be a tuple")
    normalized: list[str] = []
    for value in values:
        _required_text(value, field)
        if pattern is not None and pattern.fullmatch(value) is None:
            raise ValueError(f"{field} contains an invalid value")
        normalized.append(value)
    if len(normalized) != len(set(normalized)):
        raise ValueError(f"{field} must not contain duplicates")
    return tuple(sorted(normalized))


def _normalize_target(value: str) -> str:
    target = parse_target(value)
    if target.target_type == TargetType.CIDR:
        return str(ipaddress.ip_network(target.value, strict=False))
    if target.target_type in (TargetType.IPV4, TargetType.IPV6):
        return str(ipaddress.ip_address(target.value))
    return target.value


def _canonical_targets(values: tuple[str, ...], field: str) -> tuple[str, ...]:
    if not isinstance(values, tuple):
        raise ValueError(f"{field} must be a tuple")
    normalized = tuple(_normalize_target(value) for value in values)
    if len(normalized) != len(set(normalized)):
        raise ValueError(f"{field} must not contain duplicate targets")
    return tuple(sorted(normalized))


def _exact_keys(payload: Mapping[str, Any], required: set[str], label: str) -> None:
    if not isinstance(payload, Mapping) or set(payload) != required:
        raise ValueError(f"{label} schema is not supported")


@dataclass(frozen=True)
class AuthorizedContact:
    contact_id: str
    display_name: str
    roles: tuple[EngagementRole, ...]
    organization: str | None = None
    email: str | None = None
    phone: str | None = None

    def __post_init__(self) -> None:
        _identifier(self.contact_id, "contact_id")
        _required_text(self.display_name, "display_name")
        if not isinstance(self.roles, tuple) or not self.roles:
            raise ValueError("roles must contain at least one role")
        roles = tuple(
            sorted(
                (
                    _enum(role, EngagementRole, "role")
                    for role in self.roles
                ),
                key=lambda role: role.value,
            )
        )
        if len(roles) != len(set(roles)):
            raise ValueError("roles must not contain duplicates")
        object.__setattr__(self, "roles", roles)
        _optional_text(self.organization, "organization")
        _optional_text(self.email, "email")
        _optional_text(self.phone, "phone")
        if self.email is not None and (
            "@" not in self.email or " " in self.email or self.email.startswith("@")
        ):
            raise ValueError("email is not valid")

    def to_dict(self) -> dict[str, Any]:
        return {
            "contact_id": self.contact_id,
            "display_name": self.display_name,
            "roles": [role.value for role in self.roles],
            "organization": self.organization,
            "email": self.email,
            "phone": self.phone,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "AuthorizedContact":
        _exact_keys(
            payload,
            {"contact_id", "display_name", "roles", "organization", "email", "phone"},
            "authorized contact",
        )
        if not isinstance(payload["roles"], list):
            raise ValueError("roles must be a list")
        return cls(
            contact_id=payload["contact_id"],
            display_name=payload["display_name"],
            roles=tuple(EngagementRole(item) for item in payload["roles"]),
            organization=payload["organization"],
            email=payload["email"],
            phone=payload["phone"],
        )


@dataclass(frozen=True)
class EngagementWindow:
    window_id: str
    kind: WindowKind
    starts_at: str
    ends_at: str
    description: str | None = None

    def __post_init__(self) -> None:
        _identifier(self.window_id, "window_id")
        object.__setattr__(self, "kind", _enum(self.kind, WindowKind, "kind"))
        starts = _utc_iso8601(self.starts_at, "starts_at")
        ends = _utc_iso8601(self.ends_at, "ends_at")
        if _parse_time(ends) <= _parse_time(starts):
            raise ValueError("ends_at must be later than starts_at")
        object.__setattr__(self, "starts_at", starts)
        object.__setattr__(self, "ends_at", ends)
        _optional_text(self.description, "description")

    def to_dict(self) -> dict[str, Any]:
        return {
            "window_id": self.window_id,
            "kind": self.kind.value,
            "starts_at": self.starts_at,
            "ends_at": self.ends_at,
            "description": self.description,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "EngagementWindow":
        _exact_keys(
            payload,
            {"window_id", "kind", "starts_at", "ends_at", "description"},
            "engagement window",
        )
        return cls(
            window_id=payload["window_id"],
            kind=WindowKind(payload["kind"]),
            starts_at=payload["starts_at"],
            ends_at=payload["ends_at"],
            description=payload["description"],
        )


@dataclass(frozen=True)
class ScopeDefinition:
    allowed_targets: tuple[str, ...]
    excluded_targets: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        allowed = _canonical_targets(self.allowed_targets, "allowed_targets")
        if not allowed:
            raise ValueError("allowed_targets must contain at least one target")
        excluded = _canonical_targets(self.excluded_targets, "excluded_targets")
        allowed_scope = Scope.from_values(list(allowed))
        for value in excluded:
            if not allowed_scope.is_authorized(parse_target(value)):
                raise ValueError("excluded target must be contained by allowed scope")
        object.__setattr__(self, "allowed_targets", allowed)
        object.__setattr__(self, "excluded_targets", excluded)

    def _overlaps_exclusion(self, value: str) -> bool:
        target = parse_target(_normalize_target(value))
        if target.target_type == TargetType.HOSTNAME:
            return target.value in self.excluded_targets

        if target.target_type in (TargetType.IPV4, TargetType.IPV6):
            if not self.excluded_targets:
                return False
            return Scope.from_values(list(self.excluded_targets)).is_authorized(target)

        target_network = ipaddress.ip_network(target.value, strict=False)
        for excluded in self.excluded_targets:
            excluded_target = parse_target(excluded)
            if excluded_target.target_type == TargetType.CIDR:
                excluded_network = ipaddress.ip_network(excluded_target.value, strict=False)
                if target_network.version == excluded_network.version and target_network.overlaps(
                    excluded_network
                ):
                    return True
            elif excluded_target.target_type in (TargetType.IPV4, TargetType.IPV6):
                address = ipaddress.ip_address(excluded_target.value)
                if address.version == target_network.version and address in target_network:
                    return True
        return False

    def allows(self, value: str) -> bool:
        normalized = _normalize_target(value)
        target = parse_target(normalized)
        allowed = Scope.from_values(list(self.allowed_targets)).is_authorized(target)
        return allowed and not self._overlaps_exclusion(normalized)

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed_targets": list(self.allowed_targets),
            "excluded_targets": list(self.excluded_targets),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "ScopeDefinition":
        _exact_keys(payload, {"allowed_targets", "excluded_targets"}, "scope definition")
        if not isinstance(payload["allowed_targets"], list) or not isinstance(
            payload["excluded_targets"], list
        ):
            raise ValueError("scope target collections must be lists")
        return cls(
            allowed_targets=tuple(payload["allowed_targets"]),
            excluded_targets=tuple(payload["excluded_targets"]),
        )


@dataclass(frozen=True)
class ActionConstraints:
    allowed_action_classes: tuple[str, ...] = ()
    allowed_techniques: tuple[str, ...] = ()
    max_intrusiveness: IntrusivenessLevel = IntrusivenessLevel.PASSIVE
    max_actions: int = 0
    max_concurrent_actions: int = 0

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "allowed_action_classes",
            _sorted_unique_text(
                self.allowed_action_classes,
                field="allowed_action_classes",
                pattern=_ACTION_PATTERN,
            ),
        )
        object.__setattr__(
            self,
            "allowed_techniques",
            _sorted_unique_text(
                self.allowed_techniques,
                field="allowed_techniques",
                pattern=_TECHNIQUE_PATTERN,
            ),
        )
        object.__setattr__(
            self,
            "max_intrusiveness",
            _enum(self.max_intrusiveness, IntrusivenessLevel, "max_intrusiveness"),
        )
        if (
            not isinstance(self.max_actions, int)
            or isinstance(self.max_actions, bool)
            or self.max_actions < 0
        ):
            raise ValueError("max_actions must be a non-negative integer")
        if (
            not isinstance(self.max_concurrent_actions, int)
            or isinstance(self.max_concurrent_actions, bool)
            or self.max_concurrent_actions < 0
        ):
            raise ValueError("max_concurrent_actions must be a non-negative integer")
        if self.max_actions == 0 and self.max_concurrent_actions != 0:
            raise ValueError("max_concurrent_actions must be zero when max_actions is zero")
        if self.max_actions > 0:
            if self.max_concurrent_actions < 1:
                raise ValueError(
                    "max_concurrent_actions must be positive when max_actions is positive"
                )
            if self.max_concurrent_actions > self.max_actions:
                raise ValueError("max_concurrent_actions cannot exceed max_actions")
            if not self.allowed_action_classes:
                raise ValueError(
                    "allowed_action_classes are required when active actions are budgeted"
                )

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed_action_classes": list(self.allowed_action_classes),
            "allowed_techniques": list(self.allowed_techniques),
            "max_intrusiveness": self.max_intrusiveness.value,
            "max_actions": self.max_actions,
            "max_concurrent_actions": self.max_concurrent_actions,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "ActionConstraints":
        _exact_keys(
            payload,
            {
                "allowed_action_classes",
                "allowed_techniques",
                "max_intrusiveness",
                "max_actions",
                "max_concurrent_actions",
            },
            "action constraints",
        )
        if not isinstance(payload["allowed_action_classes"], list) or not isinstance(
            payload["allowed_techniques"], list
        ):
            raise ValueError("action constraint collections must be lists")
        return cls(
            allowed_action_classes=tuple(payload["allowed_action_classes"]),
            allowed_techniques=tuple(payload["allowed_techniques"]),
            max_intrusiveness=IntrusivenessLevel(payload["max_intrusiveness"]),
            max_actions=payload["max_actions"],
            max_concurrent_actions=payload["max_concurrent_actions"],
        )


@dataclass(frozen=True)
class DataHandlingPolicy:
    classification: DataClassification = DataClassification.CONFIDENTIAL
    retention_days: int = 30
    export_policy: ExportPolicy = ExportPolicy.APPROVED_ONLY
    require_encryption_at_rest: bool = True
    require_encryption_in_transit: bool = True
    notes: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "classification",
            _enum(self.classification, DataClassification, "classification"),
        )
        object.__setattr__(
            self, "export_policy", _enum(self.export_policy, ExportPolicy, "export_policy")
        )
        if (
            not isinstance(self.retention_days, int)
            or isinstance(self.retention_days, bool)
            or self.retention_days < 0
            or self.retention_days > 3650
        ):
            raise ValueError("retention_days must be between 0 and 3650")
        if not isinstance(self.require_encryption_at_rest, bool):
            raise ValueError("require_encryption_at_rest must be a boolean")
        if not isinstance(self.require_encryption_in_transit, bool):
            raise ValueError("require_encryption_in_transit must be a boolean")
        _optional_text(self.notes, "notes")

    def to_dict(self) -> dict[str, Any]:
        return {
            "classification": self.classification.value,
            "retention_days": self.retention_days,
            "export_policy": self.export_policy.value,
            "require_encryption_at_rest": self.require_encryption_at_rest,
            "require_encryption_in_transit": self.require_encryption_in_transit,
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "DataHandlingPolicy":
        _exact_keys(
            payload,
            {
                "classification",
                "retention_days",
                "export_policy",
                "require_encryption_at_rest",
                "require_encryption_in_transit",
                "notes",
            },
            "data handling policy",
        )
        return cls(
            classification=DataClassification(payload["classification"]),
            retention_days=payload["retention_days"],
            export_policy=ExportPolicy(payload["export_policy"]),
            require_encryption_at_rest=payload["require_encryption_at_rest"],
            require_encryption_in_transit=payload["require_encryption_in_transit"],
            notes=payload["notes"],
        )


@dataclass(frozen=True)
class RulesOfEngagementTerms:
    objective: str
    communications_channel: str
    emergency_procedure: str
    prohibited_actions: tuple[str, ...] = ()
    additional_terms: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _required_text(self.objective, "objective")
        _required_text(self.communications_channel, "communications_channel")
        _required_text(self.emergency_procedure, "emergency_procedure")
        object.__setattr__(
            self,
            "prohibited_actions",
            _sorted_unique_text(self.prohibited_actions, field="prohibited_actions"),
        )
        if not isinstance(self.additional_terms, tuple):
            raise ValueError("additional_terms must be a tuple")
        for item in self.additional_terms:
            _required_text(item, "additional_terms")
        if len(self.additional_terms) != len(set(self.additional_terms)):
            raise ValueError("additional_terms must not contain duplicates")

    def to_dict(self) -> dict[str, Any]:
        return {
            "objective": self.objective,
            "communications_channel": self.communications_channel,
            "emergency_procedure": self.emergency_procedure,
            "prohibited_actions": list(self.prohibited_actions),
            "additional_terms": list(self.additional_terms),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "RulesOfEngagementTerms":
        _exact_keys(
            payload,
            {
                "objective",
                "communications_channel",
                "emergency_procedure",
                "prohibited_actions",
                "additional_terms",
            },
            "rules of engagement terms",
        )
        if not isinstance(payload["prohibited_actions"], list) or not isinstance(
            payload["additional_terms"], list
        ):
            raise ValueError("ROE term collections must be lists")
        return cls(
            objective=payload["objective"],
            communications_channel=payload["communications_channel"],
            emergency_procedure=payload["emergency_procedure"],
            prohibited_actions=tuple(payload["prohibited_actions"]),
            additional_terms=tuple(payload["additional_terms"]),
        )


@dataclass(frozen=True)
class EngagementDefinition:
    engagement_id: str
    revision: int
    name: str
    purpose: str
    created_at: str
    environment: EngagementEnvironment
    contacts: tuple[AuthorizedContact, ...]
    windows: tuple[EngagementWindow, ...]
    scope: ScopeDefinition
    constraints: ActionConstraints
    data_handling: DataHandlingPolicy
    roe: RulesOfEngagementTerms
    schema_version: int = ENGAGEMENT_DEFINITION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != ENGAGEMENT_DEFINITION_SCHEMA_VERSION:
            raise ValueError("unsupported engagement definition schema version")
        _identifier(self.engagement_id, "engagement_id")
        if (
            not isinstance(self.revision, int)
            or isinstance(self.revision, bool)
            or self.revision < 1
        ):
            raise ValueError("revision must be a positive integer")
        _required_text(self.name, "name")
        _required_text(self.purpose, "purpose")
        object.__setattr__(
            self, "created_at", _utc_iso8601(self.created_at, "created_at")
        )
        environment = _enum(self.environment, EngagementEnvironment, "environment")
        object.__setattr__(self, "environment", environment)

        if not isinstance(self.contacts, tuple) or not self.contacts:
            raise ValueError("contacts must contain at least one authorized contact")
        contacts = tuple(sorted(self.contacts, key=lambda item: item.contact_id))
        contact_ids = [item.contact_id for item in contacts]
        if len(contact_ids) != len(set(contact_ids)):
            raise ValueError("contact_id values must be unique")
        roles = {role for contact in contacts for role in contact.roles}
        if EngagementRole.ENGAGEMENT_LEAD not in roles:
            raise ValueError("at least one engagement lead is required")
        if EngagementRole.EMERGENCY_CONTACT not in roles:
            raise ValueError("at least one emergency contact is required")
        object.__setattr__(self, "contacts", contacts)

        if not isinstance(self.windows, tuple) or not self.windows:
            raise ValueError("windows must contain at least one engagement window")
        windows = tuple(
            sorted(
                self.windows,
                key=lambda item: (item.starts_at, item.ends_at, item.window_id),
            )
        )
        window_ids = [item.window_id for item in windows]
        if len(window_ids) != len(set(window_ids)):
            raise ValueError("window_id values must be unique")
        object.__setattr__(self, "windows", windows)

        if not isinstance(self.scope, ScopeDefinition):
            raise ValueError("scope must be a ScopeDefinition")
        if not isinstance(self.constraints, ActionConstraints):
            raise ValueError("constraints must be ActionConstraints")
        if not isinstance(self.data_handling, DataHandlingPolicy):
            raise ValueError("data_handling must be a DataHandlingPolicy")
        if not isinstance(self.roe, RulesOfEngagementTerms):
            raise ValueError("roe must be RulesOfEngagementTerms")

        if (
            self.constraints.max_intrusiveness == IntrusivenessLevel.DESTRUCTIVE
            and environment != EngagementEnvironment.CYBER_RANGE
        ):
            raise ValueError(
                "destructive intrusiveness is permitted only for cyber-range engagements"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "engagement_id": self.engagement_id,
            "revision": self.revision,
            "name": self.name,
            "purpose": self.purpose,
            "created_at": self.created_at,
            "environment": self.environment.value,
            "contacts": [item.to_dict() for item in self.contacts],
            "windows": [item.to_dict() for item in self.windows],
            "scope": self.scope.to_dict(),
            "constraints": self.constraints.to_dict(),
            "data_handling": self.data_handling.to_dict(),
            "roe": self.roe.to_dict(),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))

    def fingerprint(self) -> str:
        return hashlib.sha256(self.to_json().encode("utf-8")).hexdigest()

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "EngagementDefinition":
        _exact_keys(
            payload,
            {
                "schema_version",
                "engagement_id",
                "revision",
                "name",
                "purpose",
                "created_at",
                "environment",
                "contacts",
                "windows",
                "scope",
                "constraints",
                "data_handling",
                "roe",
            },
            "engagement definition",
        )
        if not isinstance(payload["contacts"], list) or not isinstance(
            payload["windows"], list
        ):
            raise ValueError("contacts and windows must be lists")
        return cls(
            schema_version=payload["schema_version"],
            engagement_id=payload["engagement_id"],
            revision=payload["revision"],
            name=payload["name"],
            purpose=payload["purpose"],
            created_at=payload["created_at"],
            environment=EngagementEnvironment(payload["environment"]),
            contacts=tuple(
                AuthorizedContact.from_dict(item) for item in payload["contacts"]
            ),
            windows=tuple(
                EngagementWindow.from_dict(item) for item in payload["windows"]
            ),
            scope=ScopeDefinition.from_dict(payload["scope"]),
            constraints=ActionConstraints.from_dict(payload["constraints"]),
            data_handling=DataHandlingPolicy.from_dict(payload["data_handling"]),
            roe=RulesOfEngagementTerms.from_dict(payload["roe"]),
        )

    @classmethod
    def from_json(cls, payload: str) -> "EngagementDefinition":
        try:
            decoded = json.loads(payload)
        except (TypeError, json.JSONDecodeError) as exc:
            raise ValueError("engagement definition is not valid JSON") from exc
        if not isinstance(decoded, Mapping):
            raise ValueError("engagement definition must be a JSON object")
        return cls.from_dict(decoded)


def render_rules_of_engagement(definition: EngagementDefinition) -> str:
    """Render a deterministic human-readable ROE from one source definition."""

    lines = [
        f"# Rules of Engagement — {definition.name}",
        "",
        f"- Engagement ID: `{definition.engagement_id}`",
        f"- Revision: {definition.revision}",
        f"- Definition fingerprint: `sha256:{definition.fingerprint()}`",
        f"- Environment: {definition.environment.value}",
        f"- Created: {definition.created_at}",
        "",
        "## Purpose and objective",
        "",
        definition.purpose,
        "",
        definition.roe.objective,
        "",
        "## Authorized contacts",
        "",
    ]
    for contact in definition.contacts:
        role_text = ", ".join(role.value for role in contact.roles)
        organization = f" — {contact.organization}" if contact.organization else ""
        lines.append(
            f"- {contact.display_name}{organization} "
            f"(`{contact.contact_id}`): {role_text}"
        )

    lines.extend(["", "## Authorized windows", ""])
    for window in definition.windows:
        description = f" — {window.description}" if window.description else ""
        lines.append(
            f"- {window.kind.value}: {window.starts_at} to {window.ends_at} "
            f"(`{window.window_id}`){description}"
        )

    lines.extend(["", "## Scope", "", "### Allowed targets", ""])
    lines.extend(f"- `{target}`" for target in definition.scope.allowed_targets)
    lines.extend(["", "### Explicit exclusions", ""])
    if definition.scope.excluded_targets:
        lines.extend(
            f"- `{target}`" for target in definition.scope.excluded_targets
        )
    else:
        lines.append("- None declared.")

    constraints = definition.constraints
    lines.extend(
        [
            "",
            "## Activity constraints",
            "",
            f"- Maximum intrusiveness: **{constraints.max_intrusiveness.value}**",
            f"- Total action budget: **{constraints.max_actions}**",
            f"- Maximum concurrent actions: **{constraints.max_concurrent_actions}**",
            "- Allowed action classes: "
            + (
                ", ".join(f"`{item}`" for item in constraints.allowed_action_classes)
                if constraints.allowed_action_classes
                else "none"
            ),
            "- Allowed techniques: "
            + (
                ", ".join(f"`{item}`" for item in constraints.allowed_techniques)
                if constraints.allowed_techniques
                else "none"
            ),
            "",
            "## Prohibited actions",
            "",
        ]
    )
    if definition.roe.prohibited_actions:
        lines.extend(f"- {item}" for item in definition.roe.prohibited_actions)
    else:
        lines.append("- No additional prohibited actions declared beyond policy limits.")

    handling = definition.data_handling
    lines.extend(
        [
            "",
            "## Data handling",
            "",
            f"- Classification: **{handling.classification.value}**",
            f"- Retention: **{handling.retention_days} days**",
            f"- Export policy: **{handling.export_policy.value}**",
            "- Encryption at rest required: "
            + ("yes" if handling.require_encryption_at_rest else "no"),
            "- Encryption in transit required: "
            + ("yes" if handling.require_encryption_in_transit else "no"),
        ]
    )
    if handling.notes:
        lines.append(f"- Notes: {handling.notes}")

    lines.extend(
        [
            "",
            "## Communications and emergency procedure",
            "",
            f"- Engagement communications: {definition.roe.communications_channel}",
            f"- Emergency procedure: {definition.roe.emergency_procedure}",
            "",
            "## Additional terms",
            "",
        ]
    )
    if definition.roe.additional_terms:
        lines.extend(f"- {item}" for item in definition.roe.additional_terms)
    else:
        lines.append("- None.")

    lines.extend(
        [
            "",
            "## Authorization boundary",
            "",
            "This ROE definition is descriptive engagement input. It does not by itself "
            "grant NightRecon execution authorization. Active operations remain subject "
            "to shared-core enforcement and, once implemented, an approved compiled "
            "policy and required approval state.",
            "",
        ]
    )
    return "\n".join(lines)
