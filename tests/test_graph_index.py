"""Tests for deterministic read-only identity graph indexing."""

import unittest

from nightrecon.graph_builder import IdentityGraphBuilder
from nightrecon.graph_index import IdentityGraphIndex
from nightrecon.graph_models import (
    GraphEdge,
    GraphEvidenceState,
    GraphNode,
    GraphNodeKind,
    GraphProvenance,
)


class GraphIndexTests(unittest.TestCase):
    def build_graph(self):
        provenance = (
            GraphProvenance(
                source_type="test",
                source_id="index-evidence",
            ),
        )
        asset = GraphNode.create(
            kind=GraphNodeKind.ASSET,
            natural_key="192.0.2.80",
            label="asset",
            provenance=provenance,
        )
        service = GraphNode.create(
            kind=GraphNodeKind.SERVICE,
            natural_key="192.0.2.80:443/tcp",
            label="https",
            provenance=provenance,
        )
        vulnerability = GraphNode.create(
            kind=GraphNodeKind.VULNERABILITY,
            natural_key="nvd:CVE-2026-8000",
            label="CVE-2026-8000",
            provenance=provenance,
        )
        builder = IdentityGraphBuilder()
        builder.add_node(vulnerability)
        builder.add_node(service)
        builder.add_node(asset)
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

    def test_lookup_and_kind_filter_use_stable_graph_order(self):
        graph, asset, service, _ = self.build_graph()
        index = IdentityGraphIndex(graph)

        self.assertEqual(index.node(asset.node_id), asset)
        self.assertIsNone(index.node("missing"))
        self.assertEqual(
            index.nodes_by_kind(GraphNodeKind.SERVICE),
            (service,),
        )

    def test_directional_edge_filters_are_deterministic(self):
        graph, asset, service, vulnerability = self.build_graph()
        index = IdentityGraphIndex(graph)

        self.assertEqual(
            tuple(
                edge.relationship
                for edge in index.outgoing_edges(asset.node_id)
            ),
            ("exposes",),
        )
        self.assertEqual(
            tuple(
                edge.relationship
                for edge in index.outgoing_edges(
                    service.node_id,
                    relationship="MATCHED-VULNERABILITY",
                )
            ),
            ("matched-vulnerability",),
        )
        self.assertEqual(
            tuple(
                edge.source_node_id
                for edge in index.incoming_edges(vulnerability.node_id)
            ),
            (service.node_id,),
        )

    def test_neighbors_are_unique_and_direction_aware(self):
        graph, asset, service, vulnerability = self.build_graph()
        index = IdentityGraphIndex(graph)

        self.assertEqual(
            index.neighbors(asset.node_id, direction="outgoing"),
            (service,),
        )
        self.assertEqual(
            index.neighbors(service.node_id, direction="incoming"),
            (asset,),
        )
        self.assertEqual(
            index.neighbors(service.node_id, direction="outgoing"),
            (vulnerability,),
        )
        self.assertEqual(
            index.neighbors(service.node_id, direction="both"),
            (asset, vulnerability),
        )

    def test_neighbors_reject_unknown_direction(self):
        graph, asset, _, _ = self.build_graph()
        index = IdentityGraphIndex(graph)

        with self.assertRaisesRegex(
            ValueError,
            "direction must be",
        ):
            index.neighbors(asset.node_id, direction="sideways")


if __name__ == "__main__":
    unittest.main()
