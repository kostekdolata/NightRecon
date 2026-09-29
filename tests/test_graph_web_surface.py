"""Tests for normalized web/API origin graph evidence."""

from __future__ import annotations

import unittest

from nightrecon_red_engine.api_report import ApiInventoryReport
from nightrecon_red_engine.graph_builder import IdentityGraphBuilder
from nightrecon_red_engine.graph_models import GraphNodeKind
from nightrecon_red_engine.graph_web_surface import (
    WebSurfaceEvidence,
    add_web_surface_evidence_to_graph,
    web_surface_evidence_to_engagement_records,
    web_surface_from_api_report,
    web_surface_from_crawl_report,
    web_surface_from_graphql_report,
)
from nightrecon_red_engine.graphql_report import GraphQLSchemaReport
from nightrecon_red_engine.unified_attack_graph import build_unified_attack_graph
from nightrecon_red_engine.web_crawl import CrawlPage
from nightrecon_red_engine.web_report import WebCrawlReport


class WebSurfaceEvidenceTests(unittest.TestCase):
    def test_https_default_port_is_normalized_into_service_properties(self):
        evidence = WebSurfaceEvidence(
            origin="https://app.example.test",
            source_id="crawl-1",
            surface_type="web",
        )

        graph = add_web_surface_evidence_to_graph(
            IdentityGraphBuilder().build(),
            (evidence,),
        )

        self.assertEqual(len(graph.nodes), 1)
        node = graph.nodes[0]
        self.assertIs(node.kind, GraphNodeKind.SERVICE)
        self.assertTrue(node.natural_key.startswith("web-surface:web:"))
        self.assertEqual(node.label, "https://app.example.test")
        self.assertEqual(
            dict(node.properties),
            {
                "origin_host": "app.example.test",
                "origin_port": "443",
                "origin_scheme": "https",
                "surface_type": "web",
            },
        )

    def test_explicit_http_port_is_preserved(self):
        evidence = WebSurfaceEvidence(
            origin="http://api.example.test:8080",
            source_id="api-1",
            surface_type="api",
        )
        self.assertEqual(dict(evidence.properties)["origin_port"], "8080")

    def test_origin_must_be_canonical_and_surface_type_is_fixed(self):
        with self.assertRaisesRegex(ValueError, "normalized"):
            WebSurfaceEvidence(
                origin="HTTPS://APP.EXAMPLE.TEST/",
                source_id="source",
                surface_type="web",
            )
        with self.assertRaisesRegex(ValueError, "surface_type"):
            WebSurfaceEvidence(
                origin="https://app.example.test",
                source_id="source",
                surface_type="browser",
            )

    def test_report_adapters_use_only_normalized_origin_context(self):
        crawl = WebCrawlReport(
            session_id="crawl-session",
            created_at="2026-09-29T04:00:00+00:00",
            target="app.example.test",
            target_type="hostname",
            scope=("app.example.test",),
            status="completed",
            start_url="https://app.example.test/login",
            origin="https://app.example.test",
            max_pages=10,
            max_bytes_per_page=1000,
            pages=(
                CrawlPage(
                    url="https://app.example.test/login",
                    status=200,
                    content_type="text/html",
                    byte_count=100,
                    links=(),
                    title="Login",
                ),
            ),
        )
        api = ApiInventoryReport(
            session_id="api-session",
            created_at="2026-09-29T04:00:00+00:00",
            target="api.example.test",
            target_type="hostname",
            scope=("api.example.test",),
            status="completed",
            base_origin="https://api.example.test:8443",
            specification="openapi",
            specification_version="3.1.0",
            title="Example API",
            api_version="1",
            servers=(),
            operations=(),
            security_scheme_names=(),
            external_references_observed=(),
        )
        graphql = GraphQLSchemaReport(
            session_id="gql-session",
            created_at="2026-09-29T04:00:00+00:00",
            target="graphql.example.test",
            target_type="hostname",
            scope=("graphql.example.test",),
            status="completed",
            endpoint_url="https://graphql.example.test/graphql",
            source="live-introspection",
            query_type="Query",
            mutation_type="",
            subscription_type="",
            types=(),
        )

        web_surface = web_surface_from_crawl_report(crawl)
        api_surface = web_surface_from_api_report(api)
        gql_surface = web_surface_from_graphql_report(graphql)

        self.assertEqual(web_surface.origin, "https://app.example.test")
        self.assertEqual(api_surface.origin, "https://api.example.test:8443")
        self.assertEqual(gql_surface.origin, "https://graphql.example.test")
        self.assertEqual(
            {web_surface.surface_type, api_surface.surface_type, gql_surface.surface_type},
            {"web", "api", "graphql"},
        )

    def test_portable_records_round_trip_with_origin_properties(self):
        evidence = (
            WebSurfaceEvidence(
                origin="https://app.example.test",
                source_id="crawl-1",
                surface_type="web",
            ),
        )
        records = web_surface_evidence_to_engagement_records(
            evidence,
            engagement_id="eng-web",
            observed_at="2026-09-29T04:00:00+00:00",
        )

        result = build_unified_attack_graph(records)

        self.assertEqual(result.unresolved_records, ())
        self.assertEqual(result.ignored_records, ())
        self.assertEqual(len(result.graph.nodes), 1)
        node = result.graph.nodes[0]
        self.assertEqual(dict(node.properties)["origin_host"], "app.example.test")
        self.assertEqual(dict(node.properties)["origin_port"], "443")

    def test_surface_natural_keys_are_type_specific(self):
        web = WebSurfaceEvidence(
            origin="https://app.example.test",
            source_id="web",
            surface_type="web",
        )
        api = WebSurfaceEvidence(
            origin="https://app.example.test",
            source_id="api",
            surface_type="api",
        )
        self.assertNotEqual(web.natural_key, api.natural_key)


if __name__ == "__main__":
    unittest.main()
