"""Deterministic v0.43 adapter-contract runtime gate."""

from __future__ import annotations

from nightrecon_red_engine.attack_path_atlas import (
    build_cross_domain_attack_path_atlas,
)
from nightrecon_red_engine.controlled_validation import ValidationObservation
from nightrecon_red_engine.graph_builder import IdentityGraphBuilder
from nightrecon_red_engine.graph_models import (
    GraphEdge,
    GraphEvidenceState,
    GraphNode,
    GraphNodeKind,
    GraphProvenance,
)
from nightrecon_red_engine.validation_adapter_contracts import (
    BUILTIN_VALIDATION_ADAPTER_CONTRACT_REGISTRY,
    bind_validation_eligibility_option,
    check_validation_observation_contract,
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
    natural_key="identity:adapter-runtime",
    label="Adapter runtime identity",
    provenance=provenance("identity"),
)
service = GraphNode.create(
    kind=GraphNodeKind.SERVICE,
    natural_key="192.0.2.45:443/tcp",
    label="https",
    provenance=provenance("service"),
    properties=(
        ("address", "192.0.2.45"),
        ("port", "443"),
        ("protocol", "tcp"),
        ("tls_certificate_sha256", "abc123"),
    ),
)
critical = GraphNode.create(
    kind=GraphNodeKind.CRITICAL_ASSET,
    natural_key="critical:adapter-runtime",
    label="Adapter runtime critical asset",
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
eligibility = plan_validation_eligibility(graph, compilation)
tls_option = next(
    item for item in eligibility.options
    if item.technique_id == "service.tls-property-proof"
)
binding = bind_validation_eligibility_option(graph, tls_option)

assert binding.execution_mode == "contract-only"
assert binding.side_effect_mode == "none"
assert binding.target_node_id == service.node_id

contract = BUILTIN_VALIDATION_ADAPTER_CONTRACT_REGISTRY.for_technique(
    binding.technique_id
)
postconditions = check_validation_observation_contract(
    contract,
    ValidationObservation(
        confirmed=True,
        summary="TLS metadata observed.",
        evidence={
            "tls_version": "TLSv1.3",
            "cipher": "TLS_AES_256_GCM_SHA384",
            "certificate_sha256": "abc123",
        },
    ),
)
assert postconditions.valid is True
assert postconditions.reason == "contract-satisfied"
assert "permission to validate" in binding.interpretation

print("v0.43 adapter/precondition/postcondition contract runtime: passed")
