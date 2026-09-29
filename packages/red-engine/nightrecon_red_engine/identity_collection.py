"""Authorization-first read-only identity collection runtime.

Provider adapters may query approved identity systems, but this module owns the
bounded request, preflight, normalization, and evidence conversion. Providers
return only secret-free directory entries and are never called when engagement
authorization is denied.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol
import json

from nightrecon_red_engine.graph_identity_evidence import IdentityEvidenceBundle
from nightrecon_red_engine.red_directory_import import (
    DirectoryImportLimits,
    import_directory_snapshot,
)
from nightrecon_shared_core.workspace import LocalWorkspace


_VALID_SOURCE_TYPES = frozenset({"active-directory", "entra-id"})
_VALID_ENTRY_KINDS = frozenset({"user", "computer", "service", "application", "group"})
_VALID_CORRELATION_PROPERTY_KEYS = frozenset({
    "dns_hostname",
    "spn_hosts",
    "entra_tenant_id",
    "entra_object_id",
    "entra_app_id",
})


def _required(value: str, field: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(f"{field} must be a nonblank, trimmed string")
    return value


@dataclass(frozen=True)
class DirectoryEntry:
    distinguished_name: str
    kind: str
    name: str
    members: tuple[str, ...] = ()
    properties: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        _required(self.distinguished_name, "distinguished_name")
        _required(self.name, "name")
        if self.kind not in _VALID_ENTRY_KINDS:
            raise ValueError(
                "kind must be user, computer, service, application, or group"
            )
        if self.kind != "group" and self.members:
            raise ValueError("only group entries can contain members")
        if len(self.members) != len(set(self.members)):
            raise ValueError("members must be unique")
        for member in self.members:
            _required(member, "member")
        keys: set[str] = set()
        for key, value in self.properties:
            normalized_key = _required(key, "property key")
            _required(value, "property value")
            if normalized_key not in _VALID_CORRELATION_PROPERTY_KEYS:
                raise ValueError("DirectoryEntry property key is not allowlisted")
            if normalized_key in keys:
                raise ValueError("DirectoryEntry properties must have unique keys")
            keys.add(normalized_key)


@dataclass(frozen=True)
class IdentityCollectionLimits:
    max_entries: int = 1_000
    max_memberships: int = 5_000
    max_serialized_bytes: int = 1_000_000

    def __post_init__(self) -> None:
        if min(self.max_entries, self.max_memberships, self.max_serialized_bytes) < 1:
            raise ValueError("identity collection limits must be positive")


@dataclass(frozen=True)
class IdentityCollectionRequest:
    engagement_id: str
    source_id: str
    source_type: str
    target: str
    limits: IdentityCollectionLimits = IdentityCollectionLimits()
    approval_present: bool = False

    def __post_init__(self) -> None:
        _required(self.engagement_id, "engagement_id")
        _required(self.source_id, "source_id")
        _required(self.target, "target")
        if self.source_type not in _VALID_SOURCE_TYPES:
            raise ValueError("source_type must be active-directory or entra-id")


@dataclass(frozen=True)
class IdentityProviderCollection:
    """Provider output plus bounded-completeness metadata."""

    entries: tuple[DirectoryEntry, ...]
    truncated: bool = False
    request_count: int = 0
    duration_ms: int = 0
    limitations: tuple[str, ...] = ()
    supplemental_evidence: IdentityEvidenceBundle = IdentityEvidenceBundle.empty()

    def __post_init__(self) -> None:
        if not isinstance(self.entries, tuple) or any(
            not isinstance(entry, DirectoryEntry) for entry in self.entries
        ):
            raise ValueError(
                "identity provider entries must be a tuple of DirectoryEntry records"
            )
        if type(self.truncated) is not bool:
            raise ValueError("identity provider truncated must be a boolean")
        if type(self.request_count) is not int or self.request_count < 0:
            raise ValueError("identity provider request_count must be a nonnegative integer")
        if type(self.duration_ms) is not int or self.duration_ms < 0:
            raise ValueError("identity provider duration_ms must be a nonnegative integer")
        if any(
            not isinstance(item, str) or not item or item != item.strip()
            for item in self.limitations
        ):
            raise ValueError("identity provider limitations must be nonblank strings")
        if not isinstance(self.supplemental_evidence, IdentityEvidenceBundle):
            raise ValueError(
                "identity provider supplemental_evidence must be IdentityEvidenceBundle"
            )


class ReadOnlyIdentityProvider(Protocol):
    def collect(
        self,
        request: IdentityCollectionRequest,
    ) -> IdentityProviderCollection | tuple[DirectoryEntry, ...]: ...


@dataclass(frozen=True)
class IdentityCollectionResult:
    source_type: str
    target: str
    entry_count: int
    unresolved_members: int
    evidence: IdentityEvidenceBundle
    truncated: bool = False
    provider_requests: int = 0
    provider_duration_ms: int = 0
    limitations: tuple[str, ...] = ()


@dataclass(frozen=True)
class IdentityCollectionDenied(ValueError):
    reason_code: str
    reason: str

    def __str__(self) -> str:
        return f"{self.reason_code}: {self.reason}"


def _snapshot(entries: tuple[DirectoryEntry, ...]) -> bytes:
    payload_entries: list[dict[str, object]] = []
    for entry in entries:
        record: dict[str, object] = {
            "dn": entry.distinguished_name,
            "kind": entry.kind,
            "name": entry.name,
        }
        if entry.kind == "group":
            record["members"] = list(entry.members)
        if entry.properties:
            record["properties"] = dict(entry.properties)
        payload_entries.append(record)
    return json.dumps(
        {"schema_version": 1, "entries": payload_entries},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _provider_collection(
    output: IdentityProviderCollection | tuple[DirectoryEntry, ...],
) -> IdentityProviderCollection:
    if isinstance(output, IdentityProviderCollection):
        return output
    if isinstance(output, tuple):
        return IdentityProviderCollection(entries=output)
    raise ValueError(
        "identity provider must return IdentityProviderCollection or "
        "a tuple of DirectoryEntry records"
    )


def _merge_identity_evidence(
    base: IdentityEvidenceBundle,
    supplemental: IdentityEvidenceBundle,
) -> IdentityEvidenceBundle:
    def unique(items, key, description):
        combined = tuple(items)
        seen: set[object] = set()
        for item in combined:
            natural = key(item)
            if natural in seen:
                raise ValueError(f"duplicate {description} in identity evidence")
            seen.add(natural)
        return combined

    identities = unique(
        base.identities + supplemental.identities,
        lambda item: item.natural_key,
        "identity",
    )
    groups = unique(
        base.groups + supplemental.groups,
        lambda item: item.natural_key,
        "group",
    )
    roles = unique(
        base.roles + supplemental.roles,
        lambda item: item.natural_key,
        "role",
    )
    memberships = unique(
        base.memberships + supplemental.memberships,
        lambda item: (item.member_kind, item.member_key, item.group_key),
        "membership relationship",
    )
    permissions = unique(
        base.permissions + supplemental.permissions,
        lambda item: item.natural_key,
        "permission",
    )
    relationships = unique(
        base.relationships + supplemental.relationships,
        lambda item: (
            item.source_kind,
            item.source_key,
            item.target_kind,
            item.target_key,
            item.relationship,
        ),
        "identity relationship",
    )

    identity_keys = {item.natural_key for item in identities}
    group_keys = {item.natural_key for item in groups}
    role_keys = {item.natural_key for item in roles}
    for item in memberships:
        member_keys = (
            identity_keys
            if item.member_kind.value == "identity"
            else group_keys
        )
        if item.member_key not in member_keys:
            raise ValueError("membership source is missing from identity evidence")
        if item.group_key not in group_keys:
            raise ValueError("membership group is missing from identity evidence")

    for item in relationships:
        source_keys = identity_keys if item.source_kind.value == "identity" else group_keys
        if item.source_key not in source_keys:
            raise ValueError("identity relationship source is missing from evidence")
        if item.target_kind.value == "identity":
            target_keys = identity_keys
        elif item.target_kind.value == "group":
            target_keys = group_keys
        elif item.target_kind.value == "permission":
            target_keys = role_keys
        else:
            raise ValueError("identity relationship target kind is unsupported")
        if item.target_key not in target_keys:
            raise ValueError("identity relationship target is missing from evidence")

    return IdentityEvidenceBundle(
        identities=tuple(sorted(identities, key=lambda item: item.natural_key)),
        groups=tuple(sorted(groups, key=lambda item: item.natural_key)),
        memberships=tuple(sorted(
            memberships,
            key=lambda item: (
                item.group_key,
                item.member_kind.value,
                item.member_key,
            ),
        )),
        permissions=tuple(sorted(
            permissions,
            key=lambda item: item.natural_key,
        )),
        roles=tuple(sorted(roles, key=lambda item: item.natural_key)),
        relationships=tuple(sorted(
            relationships,
            key=lambda item: (
                item.relationship,
                item.source_kind.value,
                item.source_key,
                item.target_kind.value,
                item.target_key,
            ),
        )),
    )


def collect_authorized_identity_intelligence(
    workspace: LocalWorkspace,
    provider: ReadOnlyIdentityProvider,
    request: IdentityCollectionRequest,
    *,
    now: datetime | None = None,
) -> IdentityCollectionResult:
    decision = workspace.authorize_action(
        request.engagement_id,
        capability="identity.collect",
        target=request.target,
        impact="standard",
        approval_present=request.approval_present,
        consume=True,
        now=now,
    )
    if not decision.allowed:
        raise IdentityCollectionDenied(decision.reason_code, decision.reason)

    provider_output = _provider_collection(provider.collect(request))
    entries = provider_output.entries

    if len(entries) > request.limits.max_entries:
        raise ValueError("identity collection exceeds max_entries")
    membership_count = sum(len(entry.members) for entry in entries)
    if membership_count > request.limits.max_memberships:
        raise ValueError("identity collection exceeds max_memberships")
    payload = _snapshot(entries)
    if len(payload) > request.limits.max_serialized_bytes:
        raise ValueError("identity collection exceeds max_serialized_bytes")

    namespace = "ad" if request.source_type == "active-directory" else "entra"
    imported = import_directory_snapshot(
        payload,
        source_id=request.source_id,
        namespace=namespace,
        limits=DirectoryImportLimits(
            max_bytes=request.limits.max_serialized_bytes,
            max_entries=request.limits.max_entries,
            max_memberships=request.limits.max_memberships,
        ),
    )
    evidence = _merge_identity_evidence(
        imported.evidence,
        provider_output.supplemental_evidence,
    )
    return IdentityCollectionResult(
        source_type=request.source_type,
        target=request.target,
        entry_count=len(entries),
        unresolved_members=imported.unresolved_members,
        evidence=evidence,
        truncated=provider_output.truncated,
        provider_requests=provider_output.request_count,
        provider_duration_ms=provider_output.duration_ms,
        limitations=provider_output.limitations,
    )
