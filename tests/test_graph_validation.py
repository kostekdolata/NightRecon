"""Tests for NightRecon identity graph consistency validation."""

import unittest

from nightrecon.graph_builder import IdentityGraphBuilder
from nightrecon.graph_models import (
    GraphEdge,
    GraphEvidenceState,
    GraphNode,
    GraphNodeKind,
    GraphProvenance,
    IdentityGraph,
)
from nightrecon.graph_validation import (
    assert_valid_identity_graph,
    validate_identity_graph,
)


class GraphValidationTests(unittest.TestCase):
    def setUp(self):
        self.provenance = (
            GraphProvenance(source_type="test", source_id="evidence-1"),
        )

    def test_valid_graph_returns_no_issues(self):
        asset = GraphNode.create(
            kind=GraphNodeKind.ASSET,
            natural_key="192.0.2.1",
            label="asset",
            provenance=self.provenance,
        )
        service = GraphNode.create(
            kind=GraphNodeKind.SERVICE,
            natural_key="192.0.2.1:443/tcp",
            label="https",
            provenance=self.provenance,
        )
        edge = GraphEdge.create(
            source_node_id=asset.node_id,
            target_node_id=service.node_id,
            relationship="exposes",
            evidence_state=GraphEvidenceState.OBSERVED,
            provenance=self.provenance,
        )
        builder = IdentityGraphBuilder()
        builder.add_node(asset)
        builder.add_node(service)
        builder.add_edge(edge)
        graph = builder.build()

        self.assertEqual(validate_identity_graph(graph), ())
        assert_valid_identity_graph(graph)

    def test_missing_edge_target_is_reported(self):
        asset = GraphNode.create(
            kind=GraphNodeKind.ASSET,
            natural_key="192.0.2.2",
            label="asset",
            provenance=self.provenance,
        )
        missing = GraphNode.create(
            kind=GraphNodeKind.SERVICE,
            natural_key="192.0.2.2:22/tcp",
            label="ssh",
            provenance=self.provenance,
        )
        edge = GraphEdge.create(
            source_node_id=asset.node_id,
            target_node_id=missing.node_id,
            relationship="exposes",
            evidence_state=GraphEvidenceState.OBSERVED,
            provenance=self.provenance,
        )
        graph = IdentityGraph(nodes=(asset,), edges=(edge,))

        issues = validate_identity_graph(graph)

        self.assertEqual(
            tuple(issue.code for issue in issues),
            ("missing-edge-target",),
        )

    def test_wrong_relationship_node_kinds_are_reported(self):
        first = GraphNode.create(
            kind=GraphNodeKind.SERVICE,
            natural_key="a:1/tcp",
            label="one",
            provenance=self.provenance,
        )
        second = GraphNode.create(
            kind=GraphNodeKind.SERVICE,
            natural_key="b:2/tcp",
            label="two",
            provenance=self.provenance,
        )
        edge = GraphEdge.create(
            source_node_id=first.node_id,
            target_node_id=second.node_id,
            relationship="exposes",
            evidence_state=GraphEvidenceState.OBSERVED,
            provenance=self.provenance,
        )
        graph = IdentityGraph(nodes=(first, second), edges=(edge,))

        self.assertEqual(
            tuple(issue.code for issue in validate_identity_graph(graph)),
            ("invalid-relationship-kinds",),
        )

    def test_core_evidence_relationships_cannot_be_inferred(self):
        asset = GraphNode.create(
            kind=GraphNodeKind.ASSET,
            natural_key="192.0.2.3",
            label="asset",
            provenance=self.provenance,
        )
        service = GraphNode.create(
            kind=GraphNodeKind.SERVICE,
            natural_key="192.0.2.3:80/tcp",
            label="http",
            provenance=self.provenance,
        )
        edge = GraphEdge.create(
            source_node_id=asset.node_id,
            target_node_id=service.node_id,
            relationship="exposes",
            evidence_state=GraphEvidenceState.INFERRED,
            provenance=self.provenance,
        )
        graph = IdentityGraph(nodes=(asset, service), edges=(edge,))

        with self.assertRaisesRegex(
            ValueError,
            "invalid-evidence-state",
        ):
            assert_valid_identity_graph(graph)


if __name__ == "__main__":
    unittest.main()
