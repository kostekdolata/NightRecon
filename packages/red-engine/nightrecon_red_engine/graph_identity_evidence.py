"""Generic offline identity evidence contracts for NightRecon Generation 2."""

from __future__ import annotations

from dataclasses import dataclass

from nightrecon_red_engine.graph_models import GraphEvidenceState, GraphNodeKind


def _require(value: str, name: str) -> str:
    normalized = value.strip()
    if not normalized:
        raise ValueError(f"{name} must not be empty")
    return normalized


@dataclass(frozen=True)
class IdentityEvidence:
    natural_key: str
    label: str
    source_id: str
    identity_type: str = ""
    properties: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        _require(self.natural_key, "natural_key")
        _require(self.label, "label")
        _require(self.source_id, "source_id")


@dataclass(frozen=True)
class GroupEvidence:
    natural_key: str
    label: str
    source_id: str
    properties: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        _require(self.natural_key, "natural_key")
        _require(self.label, "label")
        _require(self.source_id, "source_id")


@dataclass(frozen=True)
class GroupMembershipEvidence:
    member_kind: GraphNodeKind
    member_key: str
    group_key: str
    source_id: str
    evidence_state: GraphEvidenceState = GraphEvidenceState.OBSERVED

    def __post_init__(self) -> None:
        if self.member_kind not in {
            GraphNodeKind.IDENTITY,
            GraphNodeKind.GROUP,
        }:
            raise ValueError("group membership members must be identity or group nodes")
        _require(self.member_key, "member_key")
        _require(self.group_key, "group_key")
        _require(self.source_id, "source_id")


@dataclass(frozen=True)
class PermissionEvidence:
    natural_key: str
    label: str
    subject_kind: GraphNodeKind
    subject_key: str
    target_kind: GraphNodeKind
    target_key: str
    source_id: str
    evidence_state: GraphEvidenceState = GraphEvidenceState.OBSERVED
    properties: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        _require(self.natural_key, "natural_key")
        _require(self.label, "label")
        _require(self.subject_key, "subject_key")
        _require(self.target_key, "target_key")
        _require(self.source_id, "source_id")
        if self.subject_kind not in {
            GraphNodeKind.IDENTITY,
            GraphNodeKind.GROUP,
        }:
            raise ValueError("permission subjects must be identity or group nodes")
        if self.target_kind not in {
            GraphNodeKind.ASSET,
            GraphNodeKind.SERVICE,
            GraphNodeKind.CRITICAL_ASSET,
        }:
            raise ValueError(
                "permission targets must be asset, service, or critical-asset nodes"
            )


@dataclass(frozen=True)
class RoleEvidence:
    natural_key: str
    label: str
    source_id: str
    properties: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        _require(self.natural_key, "natural_key")
        _require(self.label, "label")
        _require(self.source_id, "source_id")


@dataclass(frozen=True)
class IdentityRelationshipEvidence:
    source_kind: GraphNodeKind
    source_key: str
    target_kind: GraphNodeKind
    target_key: str
    relationship: str
    source_id: str
    evidence_state: GraphEvidenceState = GraphEvidenceState.OBSERVED
    properties: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        if self.source_kind not in {
            GraphNodeKind.IDENTITY,
            GraphNodeKind.GROUP,
        }:
            raise ValueError("identity relationship source must be identity or group")
        if self.target_kind not in {
            GraphNodeKind.IDENTITY,
            GraphNodeKind.GROUP,
            GraphNodeKind.PERMISSION,
        }:
            raise ValueError(
                "identity relationship target must be identity, group, or permission"
            )
        _require(self.source_key, "source_key")
        _require(self.target_key, "target_key")
        relationship = _require(self.relationship, "relationship").lower()
        if relationship not in {
            "owns",
            "assigned-role",
            "manages",
            "delegates-to",
            "domain-trust",
        }:
            raise ValueError("identity relationship type is unsupported")
        if self.source_kind == self.target_kind and self.source_key == self.target_key:
            raise ValueError("identity relationships cannot be self-referential")
        _require(self.source_id, "source_id")


@dataclass(frozen=True)
class IdentityEvidenceBundle:
    identities: tuple[IdentityEvidence, ...] = ()
    groups: tuple[GroupEvidence, ...] = ()
    memberships: tuple[GroupMembershipEvidence, ...] = ()
    permissions: tuple[PermissionEvidence, ...] = ()
    roles: tuple[RoleEvidence, ...] = ()
    relationships: tuple[IdentityRelationshipEvidence, ...] = ()

    @classmethod
    def empty(cls) -> "IdentityEvidenceBundle":
        return cls()
