"""Tests for descriptive KEV/EPSS graph enrichment."""

import unittest

from nightrecon.graph_builder import IdentityGraphBuilder
from nightrecon.graph_models import (
    GraphNode,
    GraphNodeKind,
    GraphProvenance,
)
from nightrecon.graph_threat_context import add_threat_context_to_identity_graph
from nightrecon.threat_context import ThreatContextResult


class GraphThreatContextTests(unittest.TestCase):
    def build_graph(self):
        provenance = (
            GraphProvenance(
                source_type="vulnerability-intelligence",
                source_id="nvd:CVE-2026-1234",
                observed_at="2026-09-27T12:00:00+00:00",
            ),
        )
        node = GraphNode.create(
            kind=GraphNodeKind.VULNERABILITY,
            natural_key="nvd:CVE-2026-1234",
            label="CVE-2026-1234",
            provenance=provenance,
            properties=(
                ("provider", "nvd"),
                ("claim", "provider-match-only"),
            ),
        )
        builder = IdentityGraphBuilder()
        builder.add_node(node)
        return builder.build()

    def test_attaches_kev_and_epss_as_descriptive_properties(self):
        graph = self.build_graph()
        context = (
            ThreatContextResult(
                vulnerability_id="CVE-2026-1234",
                known_exploited=True,
                kev_date_added="2026-09-01",
                kev_due_date="2026-09-22",
                kev_known_ransomware_campaign_use="Known",
                kev_required_action="Apply vendor mitigations.",
                epss_probability=0.42,
                epss_percentile=0.97,
                epss_date="2026-09-27",
            ),
        )

        enriched = add_threat_context_to_identity_graph(
            graph,
            context,
            observed_at="2026-09-27T17:00:00+00:00",
        )

        node = enriched.nodes[0]
        properties = dict(node.properties)

        self.assertEqual(properties["known_exploited"], "true")
        self.assertEqual(properties["kev_date_added"], "2026-09-01")
        self.assertEqual(properties["epss_probability"], "0.42")
        self.assertEqual(properties["epss_percentile"], "0.97")
        self.assertEqual(properties["claim"], "provider-match-only")
        self.assertIn(
            ("threat-context", "CVE-2026-1234"),
            tuple(
                (item.source_type, item.source_id)
                for item in node.provenance
            ),
        )

    def test_context_without_kev_or_epss_remains_descriptive(self):
        graph = self.build_graph()

        enriched = add_threat_context_to_identity_graph(
            graph,
            (
                ThreatContextResult(
                    vulnerability_id="CVE-2026-1234",
                    known_exploited=False,
                    errors=("cisa-kev: unavailable",),
                ),
            ),
        )

        properties = dict(enriched.nodes[0].properties)
        self.assertEqual(properties["known_exploited"], "false")
        self.assertNotIn("epss_probability", properties)
        self.assertNotIn("exploitability", properties)

    def test_unmatched_context_does_not_mutate_graph(self):
        graph = self.build_graph()

        enriched = add_threat_context_to_identity_graph(
            graph,
            (
                ThreatContextResult(
                    vulnerability_id="CVE-2026-9999",
                    known_exploited=True,
                ),
            ),
        )

        self.assertEqual(enriched, graph)

    def test_same_cve_enriches_provider_scoped_nodes(self):
        provenance = (
            GraphProvenance(
                source_type="vulnerability-intelligence",
                source_id="source",
            ),
        )
        first = GraphNode.create(
            kind=GraphNodeKind.VULNERABILITY,
            natural_key="nvd:CVE-2026-1234",
            label="CVE-2026-1234",
            provenance=provenance,
        )
        second = GraphNode.create(
            kind=GraphNodeKind.VULNERABILITY,
            natural_key="vendor:CVE-2026-1234",
            label="CVE-2026-1234",
            provenance=provenance,
        )
        builder = IdentityGraphBuilder()
        builder.add_node(first)
        builder.add_node(second)

        enriched = add_threat_context_to_identity_graph(
            builder.build(),
            (
                ThreatContextResult(
                    vulnerability_id="CVE-2026-1234",
                    epss_probability=0.5,
                    epss_percentile=0.9,
                ),
            ),
        )

        self.assertEqual(
            tuple(
                dict(node.properties)["epss_probability"]
                for node in enriched.nodes
            ),
            ("0.5", "0.5"),
        )


if __name__ == "__main__":
    unittest.main()
