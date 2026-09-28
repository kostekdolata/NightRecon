"""Immutable identity-graph models for NightRecon Generation 2."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from hashlib import sha256


class GraphNodeKind(str, Enum):
    """Supported node kinds in the initial identity graph."""

    ASSET = "asset"
    SERVICE = "service"
    IDENTITY = "identity"
    GROUP = "group"
    PERMISSION = "permission"
    VULNERABILITY = "vulnerability"
    CRITICAL_ASSET = "critical-asset"
    ASSESSMENT_FINDING = "assessment-finding"


class GraphEvidenceState(str, Enum):
    """Whether a graph fact is directly observed or inferred."""

    OBSERVED = "observed"
    INFERRED = "inferred"


@dataclass(frozen=True)
class GraphProvenance:
    """Non-secret provenance for one graph fact."""

    source_type: str
    source_id: str
    observed_at: str = ""

    def __post_init__(self) -> None:
        if not self.source_type.strip():
            raise ValueError("source_type must not be empty")
        if not self.source_id.strip():
            raise ValueError("source_id must not be empty")


def stable_graph_id(*parts: str) -> str:
    """Return a deterministic opaque identifier for normalized graph parts."""

    normalized = tuple(part.strip().lower() for part in parts)
    if not normalized or any(not part for part in normalized):
        raise ValueError("stable graph identifiers require non-empty parts")
    digest = sha256("\x1f".join(normalized).encode("utf-8")).hexdigest()
    return f"gr-{digest}"


@dataclass(frozen=True)
class GraphNode:
    """One immutable graph node."""

    node_id: str
    kind: GraphNodeKind
    natural_key: str
    label: str
    provenance: tuple[GraphProvenance, ...]
    properties: tuple[tuple[str, str], ...] = ()

    @classmethod
    def create(
        cls,
        *,
        kind: GraphNodeKind,
        natural_key: str,
        label: str,
        provenance: tuple[GraphProvenance, ...],
        properties: tuple[tuple[str, str], ...] = (),
    ) -> "GraphNode":
        normalized_key = natural_key.strip()
        normalized_label = label.strip()
        if not normalized_key:
            raise ValueError("natural_key must not be empty")
        if not normalized_label:
            raise ValueError("label must not be empty")
        if not provenance:
            raise ValueError("graph nodes require provenance")

        normalized_properties = _normalize_properties(properties)
        normalized_provenance = _normalize_provenance(provenance)
        return cls(
            node_id=stable_graph_id("node", kind.value, normalized_key),
            kind=kind,
            natural_key=normalized_key,
            label=normalized_label,
            provenance=normalized_provenance,
            properties=normalized_properties,
        )


@dataclass(frozen=True)
class GraphEdge:
    """One immutable relationship between two graph nodes."""

    edge_id: str
    source_node_id: str
    target_node_id: str
    relationship: str
    evidence_state: GraphEvidenceState
    provenance: tuple[GraphProvenance, ...]
    properties: tuple[tuple[str, str], ...] = ()

    @classmethod
    def create(
        cls,
        *,
        source_node_id: str,
        target_node_id: str,
        relationship: str,
        evidence_state: GraphEvidenceState,
        provenance: tuple[GraphProvenance, ...],
        properties: tuple[tuple[str, str], ...] = (),
    ) -> "GraphEdge":
        source = source_node_id.strip()
        target = target_node_id.strip()
        relation = relationship.strip().lower()
        if not source or not target:
            raise ValueError("graph edges require source and target node identifiers")
        if not relation:
            raise ValueError("relationship must not be empty")
        if source == target:
            raise ValueError("self-referential graph edges are not allowed")
        if not provenance:
            raise ValueError("graph edges require provenance")

        normalized_properties = _normalize_properties(properties)
        normalized_provenance = _normalize_provenance(provenance)
        return cls(
            edge_id=stable_graph_id(
                "edge",
                source,
                target,
                relation,
                evidence_state.value,
            ),
            source_node_id=source,
            target_node_id=target,
            relationship=relation,
            evidence_state=evidence_state,
            provenance=normalized_provenance,
            properties=normalized_properties,
        )


@dataclass(frozen=True)
class IdentityGraph:
    """Deterministic immutable graph snapshot."""

    nodes: tuple[GraphNode, ...]
    edges: tuple[GraphEdge, ...]

    @classmethod
    def empty(cls) -> "IdentityGraph":
        return cls(nodes=(), edges=())


def _normalize_properties(
    properties: tuple[tuple[str, str], ...],
) -> tuple[tuple[str, str], ...]:
    normalized: dict[str, str] = {}
    for key, value in properties:
        normalized_key = key.strip().lower()
        normalized_value = value.strip()
        if not normalized_key:
            raise ValueError("graph property keys must not be empty")
        if normalized_key in normalized:
            raise ValueError(f"duplicate graph property: {normalized_key}")
        normalized[normalized_key] = normalized_value
    return tuple(sorted(normalized.items()))


def _normalize_provenance(
    provenance: tuple[GraphProvenance, ...],
) -> tuple[GraphProvenance, ...]:
    unique = {
        (
            item.source_type.strip(),
            item.source_id.strip(),
            item.observed_at.strip(),
        ): item
        for item in provenance
    }
    return tuple(
        GraphProvenance(*key)
        for key in sorted(unique)
    )
