"""Deterministic v0.42 exposure-intelligence comparison/runtime gate."""

from __future__ import annotations

from nightrecon_red_engine.attack_path_atlas import (
    build_cross_domain_attack_path_atlas,
)
from nightrecon_red_engine.exposure_review import build_exposure_review
from nightrecon_red_engine.graph_builder import IdentityGraphBuilder
from nightrecon_red_engine.graph_models import (
    GraphEdge,
    GraphEvidenceState,
    GraphNode,
    GraphNodeKind,
    GraphProvenance,
)
from nightrecon_red_engine.specialist_comparison import (
    ExpectedEdgeSignature,
    ExpectedPathSignature,
    SpecialistComparisonExpectation,
    run_specialist_fixture_comparison,
)
from nightrecon_red_engine.validation_candidates import (
    compile_validation_candidates,
)


def prov(key):
    return (GraphProvenance("engagement-evidence", key),)


identity = GraphNode.create(
    kind=GraphNodeKind.IDENTITY,
    natural_key="identity:operator",
    label="Operator",
    provenance=prov("identity"),
)
asset = GraphNode.create(
    kind=GraphNodeKind.ASSET,
    natural_key="192.0.2.77",
    label="Application",
    provenance=prov("asset"),
)
critical = GraphNode.create(
    kind=GraphNodeKind.CRITICAL_ASSET,
    natural_key="critical:billing",
    label="Billing",
    provenance=prov("critical"),
)
edge_a = GraphEdge.create(
    source_node_id=identity.node_id,
    target_node_id=asset.node_id,
    relationship="correlates-to",
    evidence_state=GraphEvidenceState.INFERRED,
    provenance=prov("corr"),
)
edge_b = GraphEdge.create(
    source_node_id=asset.node_id,
    target_node_id=critical.node_id,
    relationship="classified-as-critical",
    evidence_state=GraphEvidenceState.OBSERVED,
    provenance=prov("critical-link"),
)
builder = IdentityGraphBuilder()
for item in (identity, asset, critical):
    builder.add_node(item)
for item in (edge_a, edge_b):
    builder.add_edge(item)
graph = builder.build()

atlas = build_cross_domain_attack_path_atlas(
    graph,
    start_kinds=(GraphNodeKind.IDENTITY,),
)
compilation = compile_validation_candidates(graph, atlas)
review = build_exposure_review(atlas, compilation)
assert len(compilation.candidates) == 1
assert compilation.candidates[0].execution_mode == "proposal-only"
assert compilation.candidates[0].approval_required is True
assert len(review.paths) == 1
assert any(
    item.gap_type == "inferred-path-evidence"
    for item in review.evidence_gaps
)

result = run_specialist_fixture_comparison(
    graph,
    SpecialistComparisonExpectation(
        paths=(
            ExpectedPathSignature(
                "identity:operator",
                "critical:billing",
                ("correlates-to", "classified-as-critical"),
            ),
        ),
        edges=(
            ExpectedEdgeSignature(
                "identity:operator",
                "192.0.2.77",
                "correlates-to",
                "inferred",
            ),
            ExpectedEdgeSignature(
                "192.0.2.77",
                "critical:billing",
                "classified-as-critical",
                "observed",
            ),
        ),
        operator_steps=4,
    ),
    start_kinds=(GraphNodeKind.IDENTITY,),
)
assert result.missed_paths == 0
assert result.invented_paths == 0
assert result.missed_edges == 0
assert result.invented_edges == 0
assert result.evidence_incomplete_paths == 0
assert result.atlas_truncated is False
assert result.duration_ms < 5000.0

print("v0.42 exposure intelligence comparison/runtime: passed")
