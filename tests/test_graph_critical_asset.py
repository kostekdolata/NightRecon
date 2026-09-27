"""Tests for critical-asset graph evidence."""

import unittest

from nightrecon.asset_inventory import AssetInventory, AssetRecord
from nightrecon.graph_critical_asset import (
    CriticalAssetEvidence,
    add_critical_asset_evidence_to_identity_graph,
)
from nightrecon.graph_models import GraphEvidenceState, GraphNodeKind
from nightrecon.graph_projection import build_identity_graph_from_asset_inventory


class GraphCriticalAssetTests(unittest.TestCase):
    def base_graph(self):
        return build_identity_graph_from_asset_inventory(
            AssetInventory(
                assets=(
                    AssetRecord(
                        address="192.0.2.130",
                        first_seen="2026-09-27T19:00:00+00:00",
                        last_seen="2026-09-27T19:00:00+00:00",
                        last_checked_at="2026-09-27T19:00:00+00:00",
                        source_session_ids=("critical-base",),
                    ),
                ),
            )
        )

    def test_projects_critical_asset_marker(self):
        graph = add_critical_asset_evidence_to_identity_graph(
            self.base_graph(),
            (
                CriticalAssetEvidence(
                    asset_key="192.0.2.130",
                    label="Payment database host",
                    source_id="critical-1",
                    rationale="Business-critical payment processing.",
                ),
            ),
            observed_at="2026-09-27T19:10:00+00:00",
        )

        critical = next(
            node
            for node in graph.nodes
            if node.kind is GraphNodeKind.CRITICAL_ASSET
        )
        self.assertEqual(critical.natural_key, "192.0.2.130")
        self.assertEqual(
            dict(critical.properties)["rationale"],
            "Business-critical payment processing.",
        )
        edge = next(
            edge
            for edge in graph.edges
            if edge.relationship == "classified-as-critical"
        )
        self.assertEqual(edge.evidence_state, GraphEvidenceState.OBSERVED)

    def test_missing_asset_reference_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "critical asset reference is missing"):
            add_critical_asset_evidence_to_identity_graph(
                self.base_graph(),
                (
                    CriticalAssetEvidence(
                        asset_key="192.0.2.199",
                        label="Missing asset",
                        source_id="critical-2",
                    ),
                ),
            )


if __name__ == "__main__":
    unittest.main()
