"""Tests for bounded evidence-backed graph path discovery."""

import unittest

from nightrecon.graph_builder import IdentityGraphBuilder
from nightrecon.graph_models import (
    GraphEdge,
    GraphEvidenceState,
    GraphNode,
    GraphNodeKind,
    GraphProvenance,
)
from nightrecon.graph_path import GraphPathLimits, find_identity_graph_paths


class GraphPathTests(unittest.TestCase):
    def build_graph(self):
        provenance = (
            GraphProvenance(source_type="test", source_id="path"),
        )
        identity = GraphNode.create(
            kind=GraphNodeKind.IDENTITY,
            natural_key="user:alice",
            label="Alice",
            provenance=provenance,
        )
        group = GraphNode.create(
            kind=GraphNodeKind.GROUP,
            natural_key="group:admins",
            label="Admins",
            provenance=provenance,
        )
        permission = GraphNode.create(
            kind=GraphNodeKind.PERMISSION,
            natural_key="permission:admins-asset",
            label="Administrative access",
            provenance=provenance,
        )
        asset = GraphNode.create(
            kind=GraphNodeKind.ASSET,
            natural_key="192.0.2.140",
            label="asset",
            provenance=provenance,
        )
        critical = GraphNode.create(
            kind=GraphNodeKind.CRITICAL_ASSET,
            natural_key="192.0.2.140",
            label="Critical asset",
            provenance=provenance,
        )

        builder = IdentityGraphBuilder()
        for node in (identity, group, permission, asset, critical):
            builder.add_node(node)
        relations = (
            (identity, group, "member-of", GraphEvidenceState.INFERRED),
            (group, permission, "has-permission", GraphEvidenceState.OBSERVED),
            (permission, asset, "applies-to", GraphEvidenceState.OBSERVED),
            (
                asset,
                critical,
                "classified-as-critical",
                GraphEvidenceState.OBSERVED,
            ),
        )
        for source, target, relation, state in relations:
            builder.add_edge(
                GraphEdge.create(
                    source_node_id=source.node_id,
                    target_node_id=target.node_id,
                    relationship=relation,
                    evidence_state=state,
                    provenance=provenance,
                )
            )
        return builder.build(), identity, asset, critical

    def test_finds_deterministic_evidence_backed_path(self):
        graph, identity, _, critical = self.build_graph()

        result = find_identity_graph_paths(
            graph,
            start_node_id=identity.node_id,
            target_node_id=critical.node_id,
        )

        self.assertEqual(len(result.paths), 1)
        self.assertEqual(
            tuple(edge.relationship for edge in result.paths[0].edges),
            (
                "member-of",
                "has-permission",
                "applies-to",
                "classified-as-critical",
            ),
        )
        self.assertFalse(result.truncated)

    def test_relationship_filter_can_exclude_path(self):
        graph, identity, _, critical = self.build_graph()

        result = find_identity_graph_paths(
            graph,
            start_node_id=identity.node_id,
            target_node_id=critical.node_id,
            relationships=("member-of", "has-permission"),
        )

        self.assertEqual(result.paths, ())

    def test_depth_limit_bounds_path_discovery(self):
        graph, identity, _, critical = self.build_graph()

        result = find_identity_graph_paths(
            graph,
            start_node_id=identity.node_id,
            target_node_id=critical.node_id,
            limits=GraphPathLimits(max_depth=3, max_paths=10),
        )

        self.assertEqual(result.paths, ())

    def test_missing_nodes_fail_closed(self):
        graph, identity, _, _ = self.build_graph()

        with self.assertRaisesRegex(ValueError, "target node is missing"):
            find_identity_graph_paths(
                graph,
                start_node_id=identity.node_id,
                target_node_id="missing",
            )


if __name__ == "__main__":
    unittest.main()
