"""Deterministic v0.43 candidate-to-technique eligibility runtime gate."""

from __future__ import annotations

from nightrecon_red_engine.attack_path_atlas import (
    build_cross_domain_attack_path_atlas,
)
from nightrecon_red_engine.graph_builder import IdentityGraphBuilder
from nightrecon_red_engine.graph_models import (
    GraphEdge,
    GraphEvidenceState,
    GraphNode,
    GraphNodeKind,
    GraphProvenance,
)
from nightrecon_red_engine.validation_candidates import (
    compile_validation_candidates,
)
from nightrecon_red_engine.validation_eligibility import (
    plan_validation_eligibility,
)


def provenance(key):
    return (GraphProvenance("engagement-evidence", key),)


identity = GraphNode.create(
    kind=GraphNodeKind.IDENTITY,
    natural_key="identity:runtime",
    label="Runtime identity",
    provenance=provenance("identity"),
)
service = GraphNode.create(
    kind=GraphNodeKind.SERVICE,
    natural_key="192.0.2.43:443/tcp",
    label="https",
    provenance=provenance("service"),
    properties=(
        ("address", "192.0.2.43"),
        ("port", "443"),
        ("protocol", "tcp"),
        ("tls_certificate_sha256", "abc123"),
    ),
)
critical = GraphNode.create(
    kind=GraphNodeKind.CRITICAL_ASSET,
    natural_key="critical:runtime",
    label="Runtime critical asset",
    provenance=provenance("critical"),
)
edges = (
    GraphEdge.create(
        source_node_id=identity.node_id,
        target_node_id=service.node_id,
        relationship="correlates-to",
        evidence_state=GraphEvidenceState.INFERRED,
        provenance=provenance("edge-1"),
    ),
    GraphEdge.create(
        source_node_id=service.node_id,
        target_node_id=critical.node_id,
        relationship="evidence-path",
        evidence_state=GraphEvidenceState.OBSERVED,
        provenance=provenance("edge-2"),
    ),
)
builder = IdentityGraphBuilder()
for node in (identity, service, critical):
    builder.add_node(node)
for edge in edges:
    builder.add_edge(edge)
graph = builder.build()

atlas = build_cross_domain_attack_path_atlas(
    graph,
    start_kinds=(GraphNodeKind.IDENTITY,),
)
compilation = compile_validation_candidates(graph, atlas)
plan = plan_validation_eligibility(graph, compilation)

assert len(plan.options) == 2
assert {
    item.technique_id for item in plan.options
} == {
    "service.tcp-property-proof",
    "service.tls-property-proof",
}
assert all(item.execution_mode == "proposal-only" for item in plan.options)
assert all(
    item.target_node_id == service.node_id
    for item in plan.options
)
assert {
    item.technique_id for item in plan.rejections
} == {"web.http-policy-proof"}
assert "not automatic technique selection" in plan.interpretation

print("v0.43 validation eligibility runtime: passed")
