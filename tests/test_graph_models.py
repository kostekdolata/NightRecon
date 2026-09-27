"""Tests for the NightRecon Generation 2 identity graph foundation."""

import unittest

from nightrecon.graph_builder import GraphBuildLimits, IdentityGraphBuilder
from nightrecon.graph_models import (
    GraphEdge,
    GraphEvidenceState,
    GraphNode,
    GraphNodeKind,
    GraphProvenance,
    stable_graph_id,
)


class GraphModelTests(unittest.TestCase):
    def setUp(self):
        self.provenance = (
            GraphProvenance(
                source_type="asset-inventory",
                source_id="scan-123",
                observed_at="2026-09-27T16:00:00+00:00",
            ),
        )

    def test_stable_graph_id_is_normalized_and_deterministic(self):
        first = stable_graph_id("Node", "ASSET", "192.0.2.10")
        second = stable_graph_id(" node ", "asset", " 192.0.2.10 ")

        self.assertEqual(first, second)
        self.assertTrue(first.startswith("gr-"))

    def test_node_creation_normalizes_properties_and_provenance(self):
        node = GraphNode.create(
            kind=GraphNodeKind.ASSET,
            natural_key="192.0.2.10",
            label="Example host",
            provenance=self.provenance + self.provenance,
            properties=(("Hostname", "host.example"), ("Port", "443")),
        )

        self.assertEqual(node.kind, GraphNodeKind.ASSET)
        self.assertEqual(
            node.properties,
            (("hostname", "host.example"), ("port", "443")),
        )
        self.assertEqual(node.provenance, self.provenance)

    def test_duplicate_property_names_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "duplicate graph property"):
            GraphNode.create(
                kind=GraphNodeKind.IDENTITY,
                natural_key="user:alice",
                label="Alice",
                provenance=self.provenance,
                properties=(("Domain", "EXAMPLE"), ("domain", "OTHER")),
            )

    def test_edge_identity_separates_observed_from_inferred(self):
        source = GraphNode.create(
            kind=GraphNodeKind.IDENTITY,
            natural_key="user:alice",
            label="Alice",
            provenance=self.provenance,
        )
        target = GraphNode.create(
            kind=GraphNodeKind.GROUP,
            natural_key="group:admins",
            label="Admins",
            provenance=self.provenance,
        )

        observed = GraphEdge.create(
            source_node_id=source.node_id,
            target_node_id=target.node_id,
            relationship="member-of",
            evidence_state=GraphEvidenceState.OBSERVED,
            provenance=self.provenance,
        )
        inferred = GraphEdge.create(
            source_node_id=source.node_id,
            target_node_id=target.node_id,
            relationship="member-of",
            evidence_state=GraphEvidenceState.INFERRED,
            provenance=self.provenance,
        )

        self.assertNotEqual(observed.edge_id, inferred.edge_id)
        self.assertEqual(observed.relationship, "member-of")

    def test_builder_is_deterministic_and_deduplicates_exact_facts(self):
        asset = GraphNode.create(
            kind=GraphNodeKind.ASSET,
            natural_key="192.0.2.10",
            label="host",
            provenance=self.provenance,
        )
        service = GraphNode.create(
            kind=GraphNodeKind.SERVICE,
            natural_key="192.0.2.10:443/tcp",
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

        first = IdentityGraphBuilder()
        first.add_node(service)
        first.add_node(asset)
        first.add_node(asset)
        first.add_edge(edge)
        first.add_edge(edge)

        second = IdentityGraphBuilder()
        second.add_node(asset)
        second.add_node(service)
        second.add_edge(edge)

        self.assertEqual(first.build(), second.build())
        self.assertEqual(len(first.build().nodes), 2)
        self.assertEqual(len(first.build().edges), 1)

    def test_builder_rejects_edges_for_missing_nodes(self):
        asset = GraphNode.create(
            kind=GraphNodeKind.ASSET,
            natural_key="192.0.2.10",
            label="host",
            provenance=self.provenance,
        )
        missing = GraphNode.create(
            kind=GraphNodeKind.SERVICE,
            natural_key="192.0.2.10:22/tcp",
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

        builder = IdentityGraphBuilder()
        builder.add_node(asset)

        with self.assertRaisesRegex(ValueError, "target node is missing"):
            builder.add_edge(edge)

    def test_builder_enforces_hard_limits(self):
        builder = IdentityGraphBuilder(GraphBuildLimits(max_nodes=1, max_edges=0))
        first = GraphNode.create(
            kind=GraphNodeKind.ASSET,
            natural_key="192.0.2.1",
            label="first",
            provenance=self.provenance,
        )
        second = GraphNode.create(
            kind=GraphNodeKind.ASSET,
            natural_key="192.0.2.2",
            label="second",
            provenance=self.provenance,
        )

        builder.add_node(first)
        with self.assertRaisesRegex(ValueError, "node limit exceeded"):
            builder.add_node(second)


if __name__ == "__main__":
    unittest.main()
