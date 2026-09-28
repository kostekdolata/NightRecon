"""Project generic identity evidence into the NightRecon identity graph."""

from __future__ import annotations

from nightrecon_red_engine.graph_builder import GraphBuildLimits, IdentityGraphBuilder
from nightrecon_red_engine.graph_identity_evidence import IdentityEvidenceBundle
from nightrecon_red_engine.graph_models import (
    GraphEdge,
    GraphNode,
    GraphNodeKind,
    GraphProvenance,
    IdentityGraph,
)


def add_identity_evidence_to_identity_graph(
    graph: IdentityGraph,
    evidence: IdentityEvidenceBundle,
    *,
    observed_at: str = "",
    limits: GraphBuildLimits | None = None,
) -> IdentityGraph:
    """Add offline identity/group/permission evidence to an existing graph."""

    builder = IdentityGraphBuilder(limits)
    nodes_by_key: dict[tuple[GraphNodeKind, str], GraphNode] = {}

    for node in graph.nodes:
        builder.add_node(node)
        nodes_by_key[(node.kind, node.natural_key)] = node
    for edge in graph.edges:
        builder.add_edge(edge)

    for record in evidence.identities:
        properties = list(record.properties)
        if record.identity_type:
            properties.append(("identity_type", record.identity_type))
        node = GraphNode.create(
            kind=GraphNodeKind.IDENTITY,
            natural_key=record.natural_key,
            label=record.label,
            provenance=_provenance(record.source_id, observed_at),
            properties=tuple(properties),
        )
        builder.add_node(node)
        nodes_by_key[(node.kind, node.natural_key)] = node

    for record in evidence.groups:
        node = GraphNode.create(
            kind=GraphNodeKind.GROUP,
            natural_key=record.natural_key,
            label=record.label,
            provenance=_provenance(record.source_id, observed_at),
            properties=record.properties,
        )
        builder.add_node(node)
        nodes_by_key[(node.kind, node.natural_key)] = node

    for record in evidence.memberships:
        member = _require_node(
            nodes_by_key,
            record.member_kind,
            record.member_key,
            "group membership member",
        )
        group = _require_node(
            nodes_by_key,
            GraphNodeKind.GROUP,
            record.group_key,
            "group membership group",
        )
        provenance = _provenance(record.source_id, observed_at)
        builder.add_edge(
            GraphEdge.create(
                source_node_id=member.node_id,
                target_node_id=group.node_id,
                relationship="member-of",
                evidence_state=record.evidence_state,
                provenance=provenance,
            )
        )

    for record in evidence.permissions:
        subject = _require_node(
            nodes_by_key,
            record.subject_kind,
            record.subject_key,
            "permission subject",
        )
        target = _require_node(
            nodes_by_key,
            record.target_kind,
            record.target_key,
            "permission target",
        )
        provenance = _provenance(record.source_id, observed_at)
        permission = GraphNode.create(
            kind=GraphNodeKind.PERMISSION,
            natural_key=record.natural_key,
            label=record.label,
            provenance=provenance,
            properties=record.properties,
        )
        builder.add_node(permission)
        nodes_by_key[(permission.kind, permission.natural_key)] = permission
        builder.add_edge(
            GraphEdge.create(
                source_node_id=subject.node_id,
                target_node_id=permission.node_id,
                relationship="has-permission",
                evidence_state=record.evidence_state,
                provenance=provenance,
            )
        )
        builder.add_edge(
            GraphEdge.create(
                source_node_id=permission.node_id,
                target_node_id=target.node_id,
                relationship="applies-to",
                evidence_state=record.evidence_state,
                provenance=provenance,
            )
        )

    return builder.build()


def _require_node(
    nodes_by_key: dict[tuple[GraphNodeKind, str], GraphNode],
    kind: GraphNodeKind,
    natural_key: str,
    description: str,
) -> GraphNode:
    node = nodes_by_key.get((kind, natural_key.strip()))
    if node is None:
        raise ValueError(
            f"{description} is missing from graph: {kind.value}:{natural_key.strip()}"
        )
    return node


def _provenance(source_id: str, observed_at: str) -> tuple[GraphProvenance, ...]:
    return (
        GraphProvenance(
            source_type="identity-evidence",
            source_id=source_id.strip(),
            observed_at=observed_at.strip(),
        ),
    )
