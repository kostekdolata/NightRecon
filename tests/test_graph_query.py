"""Tests for typed deterministic identity graph queries."""

import unittest

from nightrecon.graph_builder import IdentityGraphBuilder
from nightrecon.graph_models import (
    GraphEdge,
    GraphEvidenceState,
    GraphNode,
    GraphNodeKind,
    GraphProvenance,
)
from nightrecon.graph_query import query_identity_graph


class GraphQueryTests(unittest.TestCase):
    def build_graph(self):
        provenance = (
            GraphProvenance(source_type="test", source_id="query"),
        )
        asset = GraphNode.create(
            kind=GraphNodeKind.ASSET,
            natural_key="192.0.2.100",
            label="asset",
            provenance=provenance,
        )
        service = GraphNode.create(
            kind=GraphNodeKind.SERVICE,
            natural_key="192.0.2.100:443/tcp",
            label="https",
            provenance=provenance,
        )
        vulnerability = GraphNode.create(
            kind=GraphNodeKind.VULNERABILITY,
            natural_key="nvd:CVE-2026-10000",
            label="CVE-2026-10000",
            provenance=provenance,
        )
        builder = IdentityGraphBuilder()
        for node in (asset, service, vulnerability):
            builder.add_node(node)
        builder.add_edge(
            GraphEdge.create(
                source_node_id=asset.node_id,
                target_node_id=service.node_id,
                relationship="exposes",
                evidence_state=GraphEvidenceState.OBSERVED,
                provenance=provenance,
            )
        )
        builder.add_edge(
            GraphEdge.create(
                source_node_id=service.node_id,
                target_node_id=vulnerability.node_id,
                relationship="matched-vulnerability",
                evidence_state=GraphEvidenceState.OBSERVED,
                provenance=provenance,
            )
        )
        return builder.build(), asset, service, vulnerability

    def test_query_by_node_kind_returns_induced_subset(self):
        graph, asset, service, _ = self.build_graph()

        result = query_identity_graph(
            graph,
            node_kinds=(GraphNodeKind.ASSET, GraphNodeKind.SERVICE),
        )

        self.assertEqual(
            result.nodes,
            tuple(
                node
                for node in graph.nodes
                if node.kind in {GraphNodeKind.ASSET, GraphNodeKind.SERVICE}
            ),
        )
        self.assertEqual(
            tuple(edge.relationship for edge in result.edges),
            ("exposes",),
        )

    def test_query_by_relationship_returns_linked_nodes(self):
        graph, _, service, vulnerability = self.build_graph()

        result = query_identity_graph(
            graph,
            relationship="MATCHED-VULNERABILITY",
        )

        self.assertEqual(result.nodes, (service, vulnerability))
        self.assertEqual(len(result.edges), 1)
        self.assertEqual(result.edges[0].relationship, "matched-vulnerability")

    def test_source_and_target_filters_are_explicit(self):
        graph, asset, service, _ = self.build_graph()

        result = query_identity_graph(
            graph,
            source_node_id=asset.node_id,
            target_node_id=service.node_id,
        )

        self.assertEqual(
            result.nodes,
            tuple(
                node
                for node in graph.nodes
                if node.node_id in {asset.node_id, service.node_id}
            ),
        )
        self.assertEqual(
            tuple(edge.relationship for edge in result.edges),
            ("exposes",),
        )

    def test_missing_filter_node_fails_closed(self):
        graph, _, _, _ = self.build_graph()

        with self.assertRaisesRegex(
            ValueError,
            "source node is missing",
        ):
            query_identity_graph(
                graph,
                source_node_id="missing",
            )


if __name__ == "__main__":
    unittest.main()
