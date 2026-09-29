"""Deterministic bounded cross-domain attack-path atlas.

The atlas is a structural evidence-review surface. It does not rank risk,
predict exploitability, or execute validation. It enumerates directed
evidence-backed paths from selected start-node kinds to critical assets under
one global exploration budget.
"""

from __future__ import annotations

from collections import Counter, deque
from dataclasses import dataclass
from hashlib import sha256

from nightrecon_red_engine.graph_index import IdentityGraphIndex
from nightrecon_red_engine.graph_models import (
    GraphEdge,
    GraphEvidenceState,
    GraphNode,
    GraphNodeKind,
    IdentityGraph,
)
from nightrecon_red_engine.graph_validation import assert_valid_identity_graph


ATLAS_INTERPRETATION = (
    "Structural evidence review only; path presence and repeated participation "
    "do not establish exploitability, likelihood, impact, or risk."
)

_DEFAULT_START_KINDS = (
    GraphNodeKind.IDENTITY,
    GraphNodeKind.GROUP,
    GraphNodeKind.ASSET,
    GraphNodeKind.SERVICE,
)


@dataclass(frozen=True)
class AttackPathAtlasLimits:
    """Global hard ceilings for one atlas build."""

    max_starts: int = 128
    max_targets: int = 64
    max_depth: int = 6
    max_paths: int = 512
    max_expansions: int = 20_000

    def __post_init__(self) -> None:
        for field in (
            "max_starts",
            "max_targets",
            "max_depth",
            "max_paths",
            "max_expansions",
        ):
            value = getattr(self, field)
            if type(value) is not int or value < 1:
                raise ValueError(f"{field} must be a positive integer")


@dataclass(frozen=True)
class AttackPathProvenanceSource:
    """One non-secret provenance source supporting a returned path."""

    source_type: str
    source_id: str

    def to_dict(self) -> dict[str, str]:
        return {
            "source_type": self.source_type,
            "source_id": self.source_id,
        }


@dataclass(frozen=True)
class AttackPathAtlasPath:
    """One deterministic evidence-backed path to a critical asset."""

    path_id: str
    start_node_id: str
    target_node_id: str
    node_ids: tuple[str, ...]
    edge_ids: tuple[str, ...]
    relationships: tuple[str, ...]
    observed_hops: int
    inferred_hops: int
    evidence_ids: tuple[str, ...]
    provenance_sources: tuple[AttackPathProvenanceSource, ...]

    @property
    def hop_count(self) -> int:
        return len(self.edge_ids)

    def to_dict(self) -> dict[str, object]:
        return {
            "path_id": self.path_id,
            "start_node_id": self.start_node_id,
            "target_node_id": self.target_node_id,
            "node_ids": list(self.node_ids),
            "edge_ids": list(self.edge_ids),
            "relationships": list(self.relationships),
            "hop_count": self.hop_count,
            "observed_hops": self.observed_hops,
            "inferred_hops": self.inferred_hops,
            "evidence_ids": list(self.evidence_ids),
            "provenance_sources": [
                item.to_dict() for item in self.provenance_sources
            ],
        }


@dataclass(frozen=True)
class AttackPathParticipation:
    """Structural participation count across returned paths."""

    subject_id: str
    subject_type: str
    path_count: int
    path_ids: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "subject_id": self.subject_id,
            "subject_type": self.subject_type,
            "path_count": self.path_count,
            "path_ids": list(self.path_ids),
        }


@dataclass(frozen=True)
class AttackPathAtlas:
    """Bounded deterministic atlas over one immutable unified graph."""

    start_node_ids: tuple[str, ...]
    target_node_ids: tuple[str, ...]
    paths: tuple[AttackPathAtlasPath, ...]
    node_participation: tuple[AttackPathParticipation, ...]
    edge_participation: tuple[AttackPathParticipation, ...]
    expansions: int
    truncated: bool
    truncation_reasons: tuple[str, ...]
    interpretation: str = ATLAS_INTERPRETATION

    def to_dict(self) -> dict[str, object]:
        return {
            "start_node_ids": list(self.start_node_ids),
            "target_node_ids": list(self.target_node_ids),
            "paths": [item.to_dict() for item in self.paths],
            "node_participation": [
                item.to_dict() for item in self.node_participation
            ],
            "edge_participation": [
                item.to_dict() for item in self.edge_participation
            ],
            "expansions": self.expansions,
            "truncated": self.truncated,
            "truncation_reasons": list(self.truncation_reasons),
            "interpretation": self.interpretation,
        }


def _path_id(edge_ids: tuple[str, ...]) -> str:
    if not edge_ids:
        raise ValueError("atlas paths require at least one edge")
    digest = sha256("\x1f".join(edge_ids).encode("utf-8")).hexdigest()
    return f"atlas-{digest}"


def _evidence_ids(edges: tuple[GraphEdge, ...]) -> tuple[str, ...]:
    return tuple(sorted({
        item.source_id
        for edge in edges
        for item in edge.provenance
        if item.source_type == "engagement-evidence"
    }))


def _provenance_sources(
    edges: tuple[GraphEdge, ...],
) -> tuple[AttackPathProvenanceSource, ...]:
    return tuple(
        AttackPathProvenanceSource(source_type, source_id)
        for source_type, source_id in sorted({
            (item.source_type, item.source_id)
            for edge in edges
            for item in edge.provenance
        })
    )


def _ordered_nodes(
    nodes: tuple[GraphNode, ...],
) -> tuple[GraphNode, ...]:
    return tuple(sorted(
        nodes,
        key=lambda item: (
            item.kind.value,
            item.natural_key.casefold(),
            item.node_id,
        ),
    ))


def _participation(
    paths: tuple[AttackPathAtlasPath, ...],
    *,
    subject_type: str,
) -> tuple[AttackPathParticipation, ...]:
    members: dict[str, set[str]] = {}
    for path in paths:
        if subject_type == "node":
            # Endpoints are intentionally excluded: repeated participation is
            # meant to describe interior structural convergence.
            subjects = path.node_ids[1:-1]
        elif subject_type == "edge":
            subjects = path.edge_ids
        else:
            raise ValueError("subject_type must be node or edge")
        for subject_id in subjects:
            members.setdefault(subject_id, set()).add(path.path_id)

    return tuple(
        AttackPathParticipation(
            subject_id=subject_id,
            subject_type=subject_type,
            path_count=len(path_ids),
            path_ids=tuple(sorted(path_ids)),
        )
        for subject_id, path_ids in sorted(
            members.items(),
            key=lambda item: (-len(item[1]), item[0]),
        )
    )


def build_cross_domain_attack_path_atlas(
    graph: IdentityGraph,
    *,
    start_kinds: tuple[GraphNodeKind, ...] = _DEFAULT_START_KINDS,
    relationships: tuple[str, ...] = (),
    limits: AttackPathAtlasLimits | None = None,
) -> AttackPathAtlas:
    """Enumerate bounded directed paths to critical assets under one budget."""

    assert_valid_identity_graph(graph)
    active = limits or AttackPathAtlasLimits()

    if not start_kinds:
        raise ValueError("start_kinds must not be empty")
    if len(set(start_kinds)) != len(start_kinds):
        raise ValueError("start_kinds must not contain duplicates")
    if any(not isinstance(kind, GraphNodeKind) for kind in start_kinds):
        raise ValueError("start_kinds must contain GraphNodeKind values")
    if GraphNodeKind.CRITICAL_ASSET in start_kinds:
        raise ValueError("critical-asset cannot be a start kind")

    if any(
        not isinstance(item, str)
        or not item
        or item != item.strip()
        for item in relationships
    ):
        raise ValueError("relationships must contain unique nonblank strings")
    normalized_relationships = tuple(
        item.lower()
        for item in relationships
    )
    if len(normalized_relationships) != len(set(normalized_relationships)):
        raise ValueError("relationships must contain unique nonblank strings")
    allowed_relationships = tuple(sorted(normalized_relationships))
    allowed = set(allowed_relationships)

    index = IdentityGraphIndex(graph)
    selected_starts = _ordered_nodes(tuple(
        node for node in graph.nodes if node.kind in set(start_kinds)
    ))
    selected_targets = _ordered_nodes(
        index.nodes_by_kind(GraphNodeKind.CRITICAL_ASSET)
    )

    truncation_reasons: list[str] = []
    if len(selected_starts) > active.max_starts:
        selected_starts = selected_starts[:active.max_starts]
        truncation_reasons.append("start node ceiling reached")
    if len(selected_targets) > active.max_targets:
        selected_targets = selected_targets[:active.max_targets]
        truncation_reasons.append("critical target ceiling reached")

    target_ids = {node.node_id for node in selected_targets}
    paths: list[AttackPathAtlasPath] = []
    seen_paths: set[tuple[str, ...]] = set()
    expansions = 0
    hard_stop = False

    for start in selected_starts:
        if hard_stop or not target_ids:
            break
        queue: deque[
            tuple[tuple[GraphNode, ...], tuple[GraphEdge, ...]]
        ] = deque([((start,), ())])

        while queue:
            if expansions >= active.max_expansions:
                if "global expansion ceiling reached" not in truncation_reasons:
                    truncation_reasons.append("global expansion ceiling reached")
                hard_stop = True
                break

            nodes, edges = queue.popleft()
            expansions += 1
            current = nodes[-1]

            for edge in index.outgoing_edges(current.node_id):
                if allowed and edge.relationship not in allowed:
                    continue

                next_node = index.node(edge.target_node_id)
                if next_node is None:
                    continue
                if any(item.node_id == next_node.node_id for item in nodes):
                    continue

                if len(edges) >= active.max_depth:
                    if "path depth ceiling reached" not in truncation_reasons:
                        truncation_reasons.append("path depth ceiling reached")
                    continue

                next_nodes = nodes + (next_node,)
                next_edges = edges + (edge,)

                if next_node.node_id in target_ids:
                    edge_ids = tuple(item.edge_id for item in next_edges)
                    if edge_ids in seen_paths:
                        continue
                    seen_paths.add(edge_ids)

                    if len(paths) >= active.max_paths:
                        if "path count ceiling reached" not in truncation_reasons:
                            truncation_reasons.append("path count ceiling reached")
                        hard_stop = True
                        break

                    observed_hops = sum(
                        item.evidence_state is GraphEvidenceState.OBSERVED
                        for item in next_edges
                    )
                    inferred_hops = len(next_edges) - observed_hops
                    paths.append(AttackPathAtlasPath(
                        path_id=_path_id(edge_ids),
                        start_node_id=start.node_id,
                        target_node_id=next_node.node_id,
                        node_ids=tuple(item.node_id for item in next_nodes),
                        edge_ids=edge_ids,
                        relationships=tuple(
                            item.relationship for item in next_edges
                        ),
                        observed_hops=observed_hops,
                        inferred_hops=inferred_hops,
                        evidence_ids=_evidence_ids(next_edges),
                        provenance_sources=_provenance_sources(next_edges),
                    ))
                    # Critical assets terminate the review path.
                    continue

                if expansions + len(queue) >= active.max_expansions:
                    if "global expansion ceiling reached" not in truncation_reasons:
                        truncation_reasons.append("global expansion ceiling reached")
                    continue
                queue.append((next_nodes, next_edges))

            if hard_stop:
                break

    ordered_paths = tuple(sorted(
        paths,
        key=lambda item: (
            item.inferred_hops,
            item.hop_count,
            item.start_node_id,
            item.target_node_id,
            item.edge_ids,
        ),
    ))

    return AttackPathAtlas(
        start_node_ids=tuple(item.node_id for item in selected_starts),
        target_node_ids=tuple(item.node_id for item in selected_targets),
        paths=ordered_paths,
        node_participation=_participation(
            ordered_paths,
            subject_type="node",
        ),
        edge_participation=_participation(
            ordered_paths,
            subject_type="edge",
        ),
        expansions=expansions,
        truncated=bool(truncation_reasons),
        truncation_reasons=tuple(truncation_reasons),
    )
