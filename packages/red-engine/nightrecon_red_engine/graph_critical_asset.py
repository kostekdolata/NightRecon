"""Critical-asset evidence contracts and projection for NightRecon Generation 2."""

from __future__ import annotations

from dataclasses import dataclass

from nightrecon_red_engine.graph_builder import GraphBuildLimits, IdentityGraphBuilder
from nightrecon_red_engine.graph_models import (
    GraphEdge,
    GraphEvidenceState,
    GraphNode,
    GraphNodeKind,
    GraphProvenance,
    IdentityGraph,
)


@dataclass(frozen=True)
class CriticalAssetEvidence:
    """Mark an existing asset as operationally critical without duplicating it."""

    asset_key: str
    label: str
    source_id: str
    rationale: str = ""
    evidence_state: GraphEvidenceState = GraphEvidenceState.OBSERVED
    properties: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        if not self.asset_key.strip():
            raise ValueError("asset_key must not be empty")
        if not self.label.strip():
            raise ValueError("label must not be empty")
        if not self.source_id.strip():
            raise ValueError("source_id must not be empty")


def add_critical_asset_evidence_to_identity_graph(
    graph: IdentityGraph,
    evidence: tuple[CriticalAssetEvidence, ...],
    *,
    observed_at: str = "",
    limits: GraphBuildLimits | None = None,
) -> IdentityGraph:
    """Attach criticality evidence to existing asset nodes."""

    builder = IdentityGraphBuilder(limits)
    assets_by_key: dict[str, GraphNode] = {}

    for node in graph.nodes:
        builder.add_node(node)
        if node.kind is GraphNodeKind.ASSET:
            assets_by_key[node.natural_key] = node
    for edge in graph.edges:
        builder.add_edge(edge)

    for record in evidence:
        asset_key = record.asset_key.strip()
        asset = assets_by_key.get(asset_key)
        if asset is None:
            raise ValueError(
                f"critical asset reference is missing from graph: {asset_key}"
            )

        provenance = (
            GraphProvenance(
                source_type="critical-asset-evidence",
                source_id=record.source_id.strip(),
                observed_at=observed_at.strip(),
            ),
        )
        properties = list(record.properties)
        if record.rationale:
            properties.append(("rationale", record.rationale))

        critical = GraphNode.create(
            kind=GraphNodeKind.CRITICAL_ASSET,
            natural_key=asset_key,
            label=record.label,
            provenance=provenance,
            properties=tuple(properties),
        )
        builder.add_node(critical)
        builder.add_edge(
            GraphEdge.create(
                source_node_id=asset.node_id,
                target_node_id=critical.node_id,
                relationship="classified-as-critical",
                evidence_state=record.evidence_state,
                provenance=provenance,
            )
        )

    return builder.build()
