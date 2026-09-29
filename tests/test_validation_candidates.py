"""Validation candidates remain deterministic proposals and never execute."""

from __future__ import annotations

import unittest

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
    ValidationCandidateLimits,
    compile_validation_candidates,
)


def prov(key):
    return (GraphProvenance("engagement-evidence", key),)


def fixture():
    identity = GraphNode.create(
        kind=GraphNodeKind.IDENTITY,
        natural_key="identity:alice",
        label="Alice",
        provenance=prov("identity"),
    )
    asset = GraphNode.create(
        kind=GraphNodeKind.ASSET,
        natural_key="192.0.2.10",
        label="App",
        provenance=prov("asset"),
    )
    critical = GraphNode.create(
        kind=GraphNodeKind.CRITICAL_ASSET,
        natural_key="critical:finance",
        label="Finance",
        provenance=prov("critical"),
    )
    edges = (
        GraphEdge.create(
            source_node_id=identity.node_id,
            target_node_id=asset.node_id,
            relationship="correlates-to",
            evidence_state=GraphEvidenceState.INFERRED,
            provenance=prov("correlation"),
        ),
        GraphEdge.create(
            source_node_id=asset.node_id,
            target_node_id=critical.node_id,
            relationship="classified-as-critical",
            evidence_state=GraphEvidenceState.OBSERVED,
            provenance=prov("critical-link"),
        ),
    )
    builder = IdentityGraphBuilder()
    for item in (identity, asset, critical):
        builder.add_node(item)
    for edge in edges:
        builder.add_edge(edge)
    graph = builder.build()
    atlas = build_cross_domain_attack_path_atlas(
        graph,
        start_kinds=(GraphNodeKind.IDENTITY,),
    )
    return graph, atlas


class ValidationCandidateTests(unittest.TestCase):
    def test_compilation_is_proposal_only_and_preserves_evidence(self):
        graph, atlas = fixture()
        result = compile_validation_candidates(graph, atlas)

        self.assertEqual(len(result.candidates), 1)
        candidate = result.candidates[0]
        self.assertEqual(candidate.execution_mode, "proposal-only")
        self.assertTrue(candidate.approval_required)
        self.assertTrue(candidate.scope_review_required)
        self.assertEqual(candidate.required_capability, "validation.run")
        self.assertEqual(candidate.path_id, atlas.paths[0].path_id)
        self.assertEqual(candidate.inferred_hops, 1)
        self.assertEqual(candidate.evidence_ids, atlas.paths[0].evidence_ids)
        self.assertIn(
            "does not establish exploitability",
            candidate.interpretation,
        )

    def test_identical_inputs_produce_identical_candidates(self):
        graph, atlas = fixture()
        self.assertEqual(
            compile_validation_candidates(graph, atlas),
            compile_validation_candidates(graph, atlas),
        )

    def test_limits_reject_nonpositive_values(self):
        with self.assertRaisesRegex(ValueError, "max_candidates"):
            ValidationCandidateLimits(max_candidates=0)

    def test_stale_path_edge_fails_closed(self):
        graph, atlas = fixture()
        empty = IdentityGraphBuilder().build()
        with self.assertRaises(ValueError):
            compile_validation_candidates(empty, atlas)


if __name__ == "__main__":
    unittest.main()
