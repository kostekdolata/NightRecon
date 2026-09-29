"""Offline, bounded directory-export bridge to the identity evidence contract.

The input is a deliberately narrow normalized snapshot, not a live LDAP query.
Never infer group membership from names or create a node for an absent member.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json

from nightrecon_red_engine.graph_identity_evidence import (
    GroupEvidence,
    GroupMembershipEvidence,
    IdentityEvidence,
    IdentityEvidenceBundle,
)
from nightrecon_red_engine.graph_models import GraphNodeKind


@dataclass(frozen=True)
class DirectoryImportLimits:
    max_bytes: int = 1_000_000
    max_entries: int = 1_000
    max_memberships: int = 5_000

    def __post_init__(self) -> None:
        if min(self.max_bytes, self.max_entries, self.max_memberships) < 1:
            raise ValueError("directory import limits must be positive")


@dataclass(frozen=True)
class DirectoryImportResult:
    evidence: IdentityEvidenceBundle
    unresolved_members: int


def _unique_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("directory export contains a duplicate JSON field")
        result[key] = value
    return result


def _required_text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(f"directory export requires a nonblank, trimmed {field}")
    return value


def directory_natural_key(
    kind: str,
    dn: str,
    *,
    namespace: str = "ad",
) -> str:
    """Return an opaque graph key for one exact provider-native identifier."""

    if kind not in (
        "user", "computer", "service", "application", "domain", "role", "group"
    ):
        raise ValueError(
            "directory node kind must be user, computer, service, application, domain, role, or group"
        )
    _required_text(dn, "dn")
    _required_text(namespace, "namespace")
    if namespace not in {"ad", "entra"}:
        raise ValueError("directory namespace must be ad or entra")
    return f"{namespace}:{kind}:{sha256(dn.encode('utf-8')).hexdigest()}"


def import_directory_snapshot(
    payload: bytes,
    *,
    source_id: str,
    limits: DirectoryImportLimits | None = None,
    namespace: str = "ad",
) -> DirectoryImportResult:
    """Import a secret-free JSON snapshot; reject extra fields and over-budget data.

    Schema: {"schema_version": 1, "entries": [{"dn": str, "kind": "user",
    "computer", "service", "application", or "group", "name": str,
    "members": [str, ...] (groups only)}]}.
    References must match a DN exactly in the same snapshot. Absent references
    are counted, never materialized as an observed membership.
    """

    active = limits or DirectoryImportLimits()
    _required_text(source_id, "source_id")
    _required_text(namespace, "namespace")
    if namespace not in {"ad", "entra"}:
        raise ValueError("directory namespace must be ad or entra")
    if not isinstance(payload, bytes) or len(payload) > active.max_bytes:
        raise ValueError("directory export must be bytes within max_bytes")
    try:
        data = json.loads(payload.decode("utf-8"), object_pairs_hook=_unique_keys)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("directory export is not valid UTF-8 JSON") from exc
    if (
        not isinstance(data, dict)
        or set(data) != {"schema_version", "entries"}
        or type(data["schema_version"]) is not int
        or data["schema_version"] != 1
        or not isinstance(data["entries"], list)
    ):
        raise ValueError("directory export schema is not supported")

    entries = data["entries"]
    if len(entries) > active.max_entries:
        raise ValueError("directory export exceeds max_entries")
    by_dn: dict[str, tuple[str, str]] = {}
    identities: list[IdentityEvidence] = []
    groups: list[GroupEvidence] = []
    total_members = 0

    for index, entry in enumerate(entries):
        if not isinstance(entry, dict) or set(entry) not in (
            {"dn", "kind", "name"}, {"dn", "kind", "name", "members"},
        ):
            raise ValueError("directory entry has unsupported fields")
        dn = _required_text(entry["dn"], "dn")
        name = _required_text(entry["name"], "name")
        kind = entry["kind"]
        if kind not in (
            "user", "computer", "service", "application", "domain", "group"
        ):
            raise ValueError(
                "directory entry kind must be user, computer, service, application, domain, or group"
            )
        if dn in by_dn:
            raise ValueError("directory export contains a duplicate DN")
        if kind != "group" and "members" in entry:
            raise ValueError("only group entries can declare group members")
        members = entry.get("members", [])
        if not isinstance(members, list):
            raise ValueError("group members must be a list")
        total_members += len(members)
        if total_members > active.max_memberships:
            raise ValueError("directory export exceeds max_memberships")
        if any(not isinstance(member, str) or not member or member != member.strip()
               for member in members) or len(set(members)) != len(members):
            raise ValueError("group members must be unique, trimmed DNs")
        key = directory_natural_key(kind, dn, namespace=namespace)
        by_dn[dn] = (kind, key)
        provenance = f"{source_id}#entry-{index}"
        identity_types = {
            "user": f"{namespace}-user",
            "computer": f"{namespace}-computer",
            "service": f"{namespace}-service",
            "application": f"{namespace}-application",
            "domain": f"{namespace}-domain",
        }
        if kind in identity_types:
            identities.append(
                IdentityEvidence(
                    key,
                    name,
                    provenance,
                    identity_types[kind],
                )
            )
        else:
            groups.append(GroupEvidence(key, name, provenance))

    memberships: list[GroupMembershipEvidence] = []
    unresolved = 0
    for index, entry in enumerate(entries):
        if entry["kind"] != "group":
            continue
        group_key = by_dn[entry["dn"]][1]
        for member in entry.get("members", []):
            found = by_dn.get(member)
            if found is None:
                unresolved += 1
                continue
            kind, member_key = found
            memberships.append(GroupMembershipEvidence(
                member_kind=(
                    GraphNodeKind.GROUP
                    if kind == "group"
                    else GraphNodeKind.IDENTITY
                ),
                member_key=member_key,
                group_key=group_key,
                source_id=f"{source_id}#entry-{index}",
            ))

    return DirectoryImportResult(
        evidence=IdentityEvidenceBundle(
            identities=tuple(sorted(identities, key=lambda item: item.natural_key)),
            groups=tuple(sorted(groups, key=lambda item: item.natural_key)),
            memberships=tuple(sorted(
                memberships,
                key=lambda item: (item.group_key, item.member_kind.value, item.member_key),
            )),
        ),
        unresolved_members=unresolved,
    )
