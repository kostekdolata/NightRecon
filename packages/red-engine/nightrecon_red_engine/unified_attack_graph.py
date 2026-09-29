"""Evidence-backed unified attack-graph projection.

Only explicit engagement evidence creates graph facts. Missing endpoints remain
unresolved and no exploitability conclusion is inferred from graph reachability.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Any

from nightrecon_red_engine.graph_builder import GraphBuildLimits, IdentityGraphBuilder
from nightrecon_red_engine.graph_correlation import (
    CrossSurfaceCorrelationLimits,
    CrossSurfaceUnresolved,
    correlate_exact_cross_surface_evidence,
)
from nightrecon_red_engine.graph_models import (
    GraphEdge,
    GraphEvidenceState,
    GraphNode,
    GraphNodeKind,
    GraphProvenance,
    IdentityGraph,
)
from nightrecon_shared_core.contracts import EvidenceRecord


_NODE_TYPES = {
    "asset.observation": (GraphNodeKind.ASSET, "asset_key"),
    "identity.observation": (GraphNodeKind.IDENTITY, "identity_key"),
    "group.observation": (GraphNodeKind.GROUP, "group_key"),
    "permission.observation": (GraphNodeKind.PERMISSION, "permission_key"),
    "service.observation": (GraphNodeKind.SERVICE, "service_key"),
}
_KIND_BY_VALUE = {item.value: item for item in GraphNodeKind}


def _required_text(data: Mapping[str, Any], key: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(f"{key} must be a nonblank, trimmed string")
    return value


def _provenance(record: EvidenceRecord) -> tuple[GraphProvenance, ...]:
    return (
        GraphProvenance(
            source_type="engagement-evidence",
            source_id=record.evidence_id,
            observed_at=record.observed_at,
        ),
    )


@dataclass(frozen=True)
class UnifiedGraphBuildResult:
    graph: IdentityGraph
    projected_records: tuple[str, ...]
    unresolved_records: tuple[str, ...]
    ignored_records: tuple[str, ...]


def _node(
    record: EvidenceRecord,
    kind: GraphNodeKind,
    natural_key: str,
    label: str,
) -> GraphNode:
    properties_value = record.data.get("properties", {})
    if not isinstance(properties_value, Mapping):
        raise ValueError("graph node properties must be an object")
    properties: list[tuple[str, str]] = []
    for key, value in properties_value.items():
        if (
            not isinstance(key, str)
            or not key
            or key != key.strip()
            or not isinstance(value, str)
            or not value
            or value != value.strip()
        ):
            raise ValueError(
                "graph node properties must contain trimmed nonblank strings"
            )
        properties.append((key, value))
    return GraphNode.create(
        kind=kind,
        natural_key=natural_key,
        label=label,
        provenance=_provenance(record),
        properties=tuple(sorted(properties)),
    )


def build_unified_attack_graph(
    records: tuple[EvidenceRecord, ...],
    *,
    limits: GraphBuildLimits | None = None,
) -> UnifiedGraphBuildResult:
    builder = IdentityGraphBuilder(limits)
    nodes: dict[tuple[GraphNodeKind, str], GraphNode] = {}
    projected: set[str] = set()
    unresolved: set[str] = set()
    ignored: set[str] = set()

    # First pass: entities that can exist independently.
    for record in sorted(records, key=lambda item: item.evidence_id):
        spec = _NODE_TYPES.get(record.evidence_type)
        if spec is None:
            continue
        kind, key_field = spec
        natural_key = _required_text(record.data, key_field)
        label = _required_text(record.data, "label")
        node = _node(record, kind, natural_key, label)
        builder.add_node(node)
        nodes[(kind, natural_key)] = node
        projected.add(record.evidence_id)

    # Second pass: findings/critical markers/relationships depend on entities.
    for record in sorted(records, key=lambda item: item.evidence_id):
        data = record.data
        if record.evidence_type in _NODE_TYPES:
            continue

        if record.evidence_type == "vulnerability.observation":
            asset_key = _required_text(data, "asset_key")
            asset = nodes.get((GraphNodeKind.ASSET, asset_key))
            if asset is None:
                unresolved.add(record.evidence_id)
                continue
            vulnerability_id = _required_text(data, "vulnerability_id")
            label = _required_text(data, "label")
            vuln = _node(record, GraphNodeKind.VULNERABILITY, vulnerability_id, label)
            builder.add_node(vuln)
            nodes[(GraphNodeKind.VULNERABILITY, vulnerability_id)] = vuln
            builder.add_edge(GraphEdge.create(
                source_node_id=asset.node_id,
                target_node_id=vuln.node_id,
                relationship="has-vulnerability",
                evidence_state=GraphEvidenceState.OBSERVED,
                provenance=_provenance(record),
            ))
            projected.add(record.evidence_id)
            continue

        if record.evidence_type == "critical-asset.observation":
            asset_key = _required_text(data, "asset_key")
            asset = nodes.get((GraphNodeKind.ASSET, asset_key))
            if asset is None:
                unresolved.add(record.evidence_id)
                continue
            critical_key = _required_text(data, "critical_key")
            label = _required_text(data, "label")
            critical = _node(record, GraphNodeKind.CRITICAL_ASSET, critical_key, label)
            builder.add_node(critical)
            nodes[(GraphNodeKind.CRITICAL_ASSET, critical_key)] = critical
            builder.add_edge(GraphEdge.create(
                source_node_id=asset.node_id,
                target_node_id=critical.node_id,
                relationship="represents-critical-asset",
                evidence_state=GraphEvidenceState.OBSERVED,
                provenance=_provenance(record),
            ))
            projected.add(record.evidence_id)
            continue

        if record.evidence_type == "assessment.finding":
            kind_value = _required_text(data, "target_kind")
            target_kind = _KIND_BY_VALUE.get(kind_value)
            if target_kind is None:
                raise ValueError("assessment finding target_kind is unsupported")
            target_key = _required_text(data, "target_key")
            target = nodes.get((target_kind, target_key))
            if target is None:
                unresolved.add(record.evidence_id)
                continue
            finding_key = _required_text(data, "finding_key")
            label = _required_text(data, "label")
            finding = _node(
                record, GraphNodeKind.ASSESSMENT_FINDING, finding_key, label
            )
            builder.add_node(finding)
            nodes[(GraphNodeKind.ASSESSMENT_FINDING, finding_key)] = finding
            builder.add_edge(GraphEdge.create(
                source_node_id=target.node_id,
                target_node_id=finding.node_id,
                relationship="has-finding",
                evidence_state=GraphEvidenceState.OBSERVED,
                provenance=_provenance(record),
            ))
            projected.add(record.evidence_id)
            continue

        if record.evidence_type == "graph.relationship":
            source_kind = _KIND_BY_VALUE.get(_required_text(data, "source_kind"))
            target_kind = _KIND_BY_VALUE.get(_required_text(data, "target_kind"))
            if source_kind is None or target_kind is None:
                raise ValueError("graph relationship uses an unsupported node kind")
            source = nodes.get((source_kind, _required_text(data, "source_key")))
            target = nodes.get((target_kind, _required_text(data, "target_key")))
            if source is None or target is None:
                unresolved.add(record.evidence_id)
                continue
            state_text = data.get("evidence_state", "observed")
            try:
                state = GraphEvidenceState(state_text)
            except ValueError as exc:
                raise ValueError("graph relationship evidence_state is unsupported") from exc
            builder.add_edge(GraphEdge.create(
                source_node_id=source.node_id,
                target_node_id=target.node_id,
                relationship=_required_text(data, "relationship"),
                evidence_state=state,
                provenance=_provenance(record),
            ))
            projected.add(record.evidence_id)
            continue

        ignored.add(record.evidence_id)

    return UnifiedGraphBuildResult(
        graph=builder.build(),
        projected_records=tuple(sorted(projected)),
        unresolved_records=tuple(sorted(unresolved)),
        ignored_records=tuple(sorted(ignored)),
    )


@dataclass(frozen=True)
class GraphEdgeExplanation:
    edge_id: str
    source_label: str
    target_label: str
    relationship: str
    evidence_state: str
    evidence_ids: tuple[str, ...]
    interpretation: str


def explain_edge(graph: IdentityGraph, edge_id: str) -> GraphEdgeExplanation:
    edges = {edge.edge_id: edge for edge in graph.edges}
    nodes = {node.node_id: node for node in graph.nodes}
    edge = edges.get(edge_id)
    if edge is None:
        raise ValueError("graph edge not found")
    source = nodes[edge.source_node_id]
    target = nodes[edge.target_node_id]
    return GraphEdgeExplanation(
        edge_id=edge.edge_id,
        source_label=source.label,
        target_label=target.label,
        relationship=edge.relationship,
        evidence_state=edge.evidence_state.value,
        evidence_ids=tuple(sorted({
            item.source_id
            for item in edge.provenance
            if item.source_type == "engagement-evidence"
        })),
        interpretation=(
            "Graph relationship only; this edge is not an independent "
            "exploitability or compromise verdict."
        ),
    )


@dataclass(frozen=True)
class CorrelatedUnifiedGraphBuildResult:
    graph: IdentityGraph
    projected_records: tuple[str, ...]
    unresolved_records: tuple[str, ...]
    ignored_records: tuple[str, ...]
    correlated_edge_ids: tuple[str, ...]
    unresolved_correlations: tuple[CrossSurfaceUnresolved, ...]


def build_correlated_unified_attack_graph(
    records: tuple[EvidenceRecord, ...],
    *,
    limits: GraphBuildLimits | None = None,
    correlation_limits: CrossSurfaceCorrelationLimits | None = None,
) -> CorrelatedUnifiedGraphBuildResult:
    """Build the portable engagement graph and add exact cross-surface links."""

    base = build_unified_attack_graph(records, limits=limits)
    correlated = correlate_exact_cross_surface_evidence(
        base.graph,
        limits=correlation_limits,
    )
    return CorrelatedUnifiedGraphBuildResult(
        graph=correlated.graph,
        projected_records=base.projected_records,
        unresolved_records=base.unresolved_records,
        ignored_records=base.ignored_records,
        correlated_edge_ids=correlated.correlated_edge_ids,
        unresolved_correlations=correlated.unresolved,
    )
