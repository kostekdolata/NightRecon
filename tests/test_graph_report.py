"""Tests for structured NightRecon identity graph reporting."""

import json
import unittest

from nightrecon.graph_builder import IdentityGraphBuilder
from nightrecon.graph_models import (
    GraphEdge,
    GraphEvidenceState,
    GraphNode,
    GraphNodeKind,
    GraphProvenance,
)
from nightrecon.graph_report import GRAPH_REPORT_SCHEMA_VERSION, IdentityGraphReport


class GraphReportTests(unittest.TestCase):
    def build_graph(self):
        provenance = (
            GraphProvenance(
                source_type="asset-inventory",
                source_id="scan-1",
                observed_at="2026-09-27T12:00:00+00:00",
            ),
        )
        asset = GraphNode.create(
            kind=GraphNodeKind.ASSET,
            natural_key="192.0.2.10",
            label="192.0.2.10",
            provenance=provenance,
            properties=(("address", "192.0.2.10"),),
        )
        service = GraphNode.create(
            kind=GraphNodeKind.SERVICE,
            natural_key="192.0.2.10:443/tcp",
            label="https",
            provenance=provenance,
            properties=(("port", "443"),),
        )
        observed = GraphEdge.create(
            source_node_id=asset.node_id,
            target_node_id=service.node_id,
            relationship="exposes",
            evidence_state=GraphEvidenceState.OBSERVED,
            provenance=provenance,
        )
        inferred = GraphEdge.create(
            source_node_id=service.node_id,
            target_node_id=asset.node_id,
            relationship="associated-with",
            evidence_state=GraphEvidenceState.INFERRED,
            provenance=provenance,
        )

        builder = IdentityGraphBuilder()
        builder.add_node(asset)
        builder.add_node(service)
        builder.add_edge(observed)
        builder.add_edge(inferred)
        return builder.build()

    def test_report_preserves_deterministic_graph_order(self):
        graph = self.build_graph()

        report = IdentityGraphReport.create(graph)
        data = report.to_dict()

        self.assertEqual(data["schema_version"], GRAPH_REPORT_SCHEMA_VERSION)
        self.assertEqual(data["summary"]["nodes"], 2)
        self.assertEqual(data["summary"]["edges"], 2)
        self.assertEqual(data["summary"]["observed_edges"], 1)
        self.assertEqual(data["summary"]["inferred_edges"], 1)
        self.assertEqual(
            tuple(item["node_id"] for item in data["nodes"]),
            tuple(node.node_id for node in graph.nodes),
        )
        self.assertEqual(
            tuple(item["edge_id"] for item in data["edges"]),
            tuple(edge.edge_id for edge in graph.edges),
        )

    def test_report_serializes_provenance_and_evidence_state(self):
        data = IdentityGraphReport.create(self.build_graph()).to_dict()

        self.assertEqual(
            data["nodes"][0]["provenance"][0]["source_type"],
            "asset-inventory",
        )
        self.assertIn(
            data["edges"][0]["evidence_state"],
            {"observed", "inferred"},
        )

    def test_report_is_json_serializable_and_secret_agnostic(self):
        payload = IdentityGraphReport.create(self.build_graph()).to_dict()

        encoded = json.dumps(payload, sort_keys=True)

        self.assertIn('"schema_version": 1', encoded)
        self.assertNotIn("password", encoded.lower())
        self.assertNotIn("authorization", encoded.lower())


if __name__ == "__main__":
    unittest.main()
