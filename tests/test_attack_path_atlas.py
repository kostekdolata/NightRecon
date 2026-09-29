"""Tests for the bounded cross-domain attack path atlas."""

from __future__ import annotations

import unittest

from nightrecon_red_engine.attack_path_atlas import (
    AttackPathAtlasLimits,
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


def provenance(source_id: str):
    return (
        GraphProvenance(
            source_type="engagement-evidence",
            source_id=source_id,
            observed_at="2026-09-29T04:00:00+00:00",
        ),
    )


class AttackPathAtlasTests(unittest.TestCase):
    def build_graph(self, *, reverse: bool = False):
        alice = GraphNode.create(
            kind=GraphNodeKind.IDENTITY,
            natural_key="identity:alice",
            label="Alice",
            provenance=provenance("identity-alice"),
        )
        bob = GraphNode.create(
            kind=GraphNodeKind.IDENTITY,
            natural_key="identity:bob",
            label="Bob",
            provenance=provenance("identity-bob"),
        )
        admins = GraphNode.create(
            kind=GraphNodeKind.GROUP,
            natural_key="group:admins",
            label="Admins",
            provenance=provenance("group-admins"),
        )
        permission = GraphNode.create(
            kind=GraphNodeKind.PERMISSION,
            natural_key="permission:admin-app",
            label="Admin access",
            provenance=provenance("permission-admin"),
        )
        asset = GraphNode.create(
            kind=GraphNodeKind.ASSET,
            natural_key="10.0.0.20",
            label="Application host",
            provenance=provenance("asset-app"),
        )
        service = GraphNode.create(
            kind=GraphNodeKind.SERVICE,
            natural_key="10.0.0.20:443/tcp",
            label="HTTPS",
            provenance=provenance("service-https"),
        )
        critical = GraphNode.create(
            kind=GraphNodeKind.CRITICAL_ASSET,
            natural_key="critical:finance",
            label="Finance system",
            provenance=provenance("critical-finance"),
        )

        nodes = [alice, bob, admins, permission, asset, service, critical]
        relations = [
            (alice, admins, "member-of", GraphEvidenceState.OBSERVED, "rel-alice-admins"),
            (bob, permission, "possible-access", GraphEvidenceState.INFERRED, "rel-bob-perm"),
            (admins, permission, "has-permission", GraphEvidenceState.OBSERVED, "rel-admin-perm"),
            (permission, asset, "applies-to", GraphEvidenceState.OBSERVED, "rel-perm-asset"),
            (asset, service, "exposes", GraphEvidenceState.OBSERVED, "rel-asset-service"),
            (service, critical, "supports-critical", GraphEvidenceState.OBSERVED, "rel-service-critical"),
            (asset, critical, "classified-as-critical", GraphEvidenceState.OBSERVED, "rel-asset-critical"),
        ]

        builder = IdentityGraphBuilder()
        node_order = list(reversed(nodes)) if reverse else nodes
        relation_order = list(reversed(relations)) if reverse else relations
        for node in node_order:
            builder.add_node(node)
        for source, target, relationship, state, source_id in relation_order:
            builder.add_edge(GraphEdge.create(
                source_node_id=source.node_id,
                target_node_id=target.node_id,
                relationship=relationship,
                evidence_state=state,
                provenance=provenance(source_id),
            ))
        return builder.build(), {
            "alice": alice,
            "bob": bob,
            "admins": admins,
            "permission": permission,
            "asset": asset,
            "service": service,
            "critical": critical,
        }

    def test_cross_domain_paths_preserve_evidence_and_inference_counts(self):
        graph, nodes = self.build_graph()

        atlas = build_cross_domain_attack_path_atlas(
            graph,
            start_kinds=(GraphNodeKind.IDENTITY,),
        )

        self.assertEqual(len(atlas.paths), 4)
        self.assertFalse(atlas.truncated)
        self.assertEqual(atlas.target_node_ids, (nodes["critical"].node_id,))

        alice_paths = [
            item for item in atlas.paths
            if item.start_node_id == nodes["alice"].node_id
        ]
        self.assertEqual(len(alice_paths), 2)
        self.assertTrue(all(item.inferred_hops == 0 for item in alice_paths))
        self.assertTrue(all(item.observed_hops == item.hop_count for item in alice_paths))

        bob_paths = [
            item for item in atlas.paths
            if item.start_node_id == nodes["bob"].node_id
        ]
        self.assertEqual(len(bob_paths), 2)
        self.assertTrue(all(item.inferred_hops == 1 for item in bob_paths))
        self.assertTrue(all("rel-bob-perm" in item.evidence_ids for item in bob_paths))

        self.assertTrue(any(
            item.relationships[-1] == "supports-critical"
            for item in atlas.paths
        ))
        self.assertTrue(any(
            item.relationships[-1] == "classified-as-critical"
            for item in atlas.paths
        ))

    def test_structural_participation_is_not_a_risk_score(self):
        graph, nodes = self.build_graph()

        atlas = build_cross_domain_attack_path_atlas(
            graph,
            start_kinds=(GraphNodeKind.IDENTITY,),
        )

        node_counts = {
            item.subject_id: item.path_count
            for item in atlas.node_participation
        }
        self.assertEqual(node_counts[nodes["permission"].node_id], 4)
        self.assertEqual(node_counts[nodes["asset"].node_id], 4)
        self.assertEqual(node_counts[nodes["service"].node_id], 2)

        record = atlas.to_dict()
        rendered = str(record).lower()
        self.assertNotIn("risk_score", rendered)
        self.assertNotIn("probability", rendered)
        self.assertIn("do not establish exploitability", atlas.interpretation)

    def test_identical_graph_content_produces_identical_atlas(self):
        first, _ = self.build_graph(reverse=False)
        second, _ = self.build_graph(reverse=True)

        first_atlas = build_cross_domain_attack_path_atlas(
            first,
            start_kinds=(GraphNodeKind.IDENTITY,),
        )
        second_atlas = build_cross_domain_attack_path_atlas(
            second,
            start_kinds=(GraphNodeKind.IDENTITY,),
        )

        self.assertEqual(first_atlas.to_dict(), second_atlas.to_dict())

    def test_relationship_filter_is_explicit_and_deterministic(self):
        graph, nodes = self.build_graph()

        atlas = build_cross_domain_attack_path_atlas(
            graph,
            start_kinds=(GraphNodeKind.IDENTITY,),
            relationships=(
                "member-of",
                "has-permission",
                "applies-to",
                "classified-as-critical",
            ),
        )

        self.assertEqual(len(atlas.paths), 1)
        self.assertEqual(atlas.paths[0].start_node_id, nodes["alice"].node_id)
        self.assertEqual(
            atlas.paths[0].relationships,
            (
                "member-of",
                "has-permission",
                "applies-to",
                "classified-as-critical",
            ),
        )

    def test_global_expansion_ceiling_bounds_dense_graph(self):
        graph, _ = self.build_graph()

        atlas = build_cross_domain_attack_path_atlas(
            graph,
            start_kinds=(GraphNodeKind.IDENTITY,),
            limits=AttackPathAtlasLimits(
                max_starts=10,
                max_targets=10,
                max_depth=8,
                max_paths=100,
                max_expansions=2,
            ),
        )

        self.assertTrue(atlas.truncated)
        self.assertLessEqual(atlas.expansions, 2)
        self.assertIn(
            "global expansion ceiling reached",
            atlas.truncation_reasons,
        )

    def test_start_target_and_path_ceilings_are_explicit(self):
        graph, _ = self.build_graph()

        start_limited = build_cross_domain_attack_path_atlas(
            graph,
            start_kinds=(GraphNodeKind.IDENTITY,),
            limits=AttackPathAtlasLimits(max_starts=1),
        )
        self.assertTrue(start_limited.truncated)
        self.assertEqual(len(start_limited.start_node_ids), 1)
        self.assertIn("start node ceiling reached", start_limited.truncation_reasons)

        path_limited = build_cross_domain_attack_path_atlas(
            graph,
            start_kinds=(GraphNodeKind.IDENTITY,),
            limits=AttackPathAtlasLimits(max_paths=1),
        )
        self.assertTrue(path_limited.truncated)
        self.assertEqual(len(path_limited.paths), 1)
        self.assertIn("path count ceiling reached", path_limited.truncation_reasons)

    def test_invalid_filters_and_limits_fail_closed(self):
        graph, _ = self.build_graph()

        with self.assertRaisesRegex(ValueError, "start_kinds"):
            build_cross_domain_attack_path_atlas(graph, start_kinds=())

        with self.assertRaisesRegex(ValueError, "duplicates"):
            build_cross_domain_attack_path_atlas(
                graph,
                start_kinds=(
                    GraphNodeKind.IDENTITY,
                    GraphNodeKind.IDENTITY,
                ),
            )

        with self.assertRaisesRegex(ValueError, "relationships"):
            build_cross_domain_attack_path_atlas(
                graph,
                relationships=("member-of", "member-of"),
            )

        with self.assertRaisesRegex(ValueError, "max_expansions"):
            AttackPathAtlasLimits(max_expansions=0)


if __name__ == "__main__":
    unittest.main()
