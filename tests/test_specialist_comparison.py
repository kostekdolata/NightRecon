"""Fixture comparison metrics are explicit and make no parity claim."""

from __future__ import annotations

import unittest

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


def prov(key):
    return (GraphProvenance("engagement-evidence", key),)


def fixture():
    identity = GraphNode.create(
        kind=GraphNodeKind.IDENTITY,
        natural_key="identity:alice",
        label="Alice",
        provenance=prov("identity"),
    )
    critical = GraphNode.create(
        kind=GraphNodeKind.CRITICAL_ASSET,
        natural_key="critical:finance",
        label="Finance",
        provenance=prov("critical"),
    )
    edge = GraphEdge.create(
        source_node_id=identity.node_id,
        target_node_id=critical.node_id,
        relationship="observed-access",
        evidence_state=GraphEvidenceState.OBSERVED,
        provenance=prov("edge"),
    )
    builder = IdentityGraphBuilder()
    builder.add_node(identity)
    builder.add_node(critical)
    builder.add_edge(edge)
    return builder.build()


class SpecialistComparisonTests(unittest.TestCase):
    def test_exact_fixture_has_no_missed_or_invented_paths_or_edges(self):
        result = run_specialist_fixture_comparison(
            fixture(),
            SpecialistComparisonExpectation(
                paths=(
                    ExpectedPathSignature(
                        "identity:alice",
                        "critical:finance",
                        ("observed-access",),
                    ),
                ),
                edges=(
                    ExpectedEdgeSignature(
                        "identity:alice",
                        "critical:finance",
                        "observed-access",
                        "observed",
                    ),
                ),
                operator_steps=3,
            ),
            start_kinds=(GraphNodeKind.IDENTITY,),
        )

        self.assertEqual(result.matched_paths, 1)
        self.assertEqual(result.missed_paths, 0)
        self.assertEqual(result.invented_paths, 0)
        self.assertEqual(result.matched_edges, 1)
        self.assertEqual(result.missed_edges, 0)
        self.assertEqual(result.invented_edges, 0)
        self.assertEqual(result.evidence_incomplete_paths, 0)
        self.assertGreaterEqual(result.duration_ms, 0.0)
        self.assertIn("do not establish parity", result.interpretation)

    def test_invented_edge_is_measured_not_hidden(self):
        result = run_specialist_fixture_comparison(
            fixture(),
            SpecialistComparisonExpectation(
                paths=(),
                edges=(),
                operator_steps=1,
            ),
            start_kinds=(GraphNodeKind.IDENTITY,),
        )
        self.assertEqual(result.invented_paths, 1)
        self.assertEqual(result.invented_edges, 1)


if __name__ == "__main__":
    unittest.main()
