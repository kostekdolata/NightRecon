"""Descriptive structural summaries for NightRecon identity graphs."""

from __future__ import annotations

from dataclasses import dataclass

from nightrecon.graph_models import GraphEvidenceState, GraphNodeKind, IdentityGraph


@dataclass(frozen=True)
class IdentityGraphSummary:
    """Descriptive counts for one immutable identity graph."""

    node_count: int
    edge_count: int
    asset_count: int
    service_count: int
    vulnerability_count: int
    assessment_finding_count: int
    identity_count: int
    group_count: int
    permission_count: int
    critical_asset_count: int
    observed_edge_count: int
    inferred_edge_count: int
    relationship_counts: tuple[tuple[str, int], ...]


def summarize_identity_graph(graph: IdentityGraph) -> IdentityGraphSummary:
    """Return deterministic descriptive graph metrics without ranking."""

    kind_counts = {
        kind: 0
        for kind in GraphNodeKind
    }
    for node in graph.nodes:
        kind_counts[node.kind] += 1

    relationship_counts: dict[str, int] = {}
    observed = 0
    inferred = 0

    for edge in graph.edges:
        relationship_counts[edge.relationship] = (
            relationship_counts.get(edge.relationship, 0) + 1
        )
        if edge.evidence_state is GraphEvidenceState.OBSERVED:
            observed += 1
        elif edge.evidence_state is GraphEvidenceState.INFERRED:
            inferred += 1

    return IdentityGraphSummary(
        node_count=len(graph.nodes),
        edge_count=len(graph.edges),
        asset_count=kind_counts[GraphNodeKind.ASSET],
        service_count=kind_counts[GraphNodeKind.SERVICE],
        vulnerability_count=kind_counts[GraphNodeKind.VULNERABILITY],
        assessment_finding_count=kind_counts[
            GraphNodeKind.ASSESSMENT_FINDING
        ],
        identity_count=kind_counts[GraphNodeKind.IDENTITY],
        group_count=kind_counts[GraphNodeKind.GROUP],
        permission_count=kind_counts[GraphNodeKind.PERMISSION],
        critical_asset_count=kind_counts[GraphNodeKind.CRITICAL_ASSET],
        observed_edge_count=observed,
        inferred_edge_count=inferred,
        relationship_counts=tuple(sorted(relationship_counts.items())),
    )
