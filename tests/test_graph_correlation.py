"""Cross-surface correlation must be exact, deterministic, and fail honest."""

from __future__ import annotations

import unittest

from nightrecon_red_engine.graph_builder import IdentityGraphBuilder
from nightrecon_red_engine.graph_correlation import (
    CrossSurfaceCorrelationLimits,
    correlate_exact_cross_surface_evidence,
)
from nightrecon_red_engine.graph_models import (
    GraphEvidenceState,
    GraphNode,
    GraphNodeKind,
    GraphProvenance,
)


def node(kind, key, label, properties=()):
    return GraphNode.create(
        kind=kind,
        natural_key=key,
        label=label,
        provenance=(GraphProvenance("fixture", key),),
        properties=properties,
    )


def graph(*nodes):
    builder = IdentityGraphBuilder()
    for item in nodes:
        builder.add_node(item)
    return builder.build()


class CrossSurfaceCorrelationTests(unittest.TestCase):
    def test_exact_dns_hostname_creates_inferred_identity_to_asset_edge(self):
        asset = node(
            GraphNodeKind.ASSET,
            "192.0.2.10",
            "App server",
            (("hostnames", "app.example.test"),),
        )
        identity = node(
            GraphNodeKind.IDENTITY,
            "ad:computer:opaque",
            "APP01",
            (
                ("dns_hostname", "app.example.test"),
                ("identity_type", "ad-computer"),
            ),
        )

        result = correlate_exact_cross_surface_evidence(graph(asset, identity))

        self.assertEqual(result.unresolved, ())
        self.assertEqual(len(result.correlated_edge_ids), 1)
        edge = next(
            item for item in result.graph.edges
            if item.edge_id in result.correlated_edge_ids
        )
        self.assertEqual(edge.source_node_id, identity.node_id)
        self.assertEqual(edge.target_node_id, asset.node_id)
        self.assertEqual(edge.relationship, "correlates-to")
        self.assertIs(edge.evidence_state, GraphEvidenceState.INFERRED)
        properties = dict(edge.properties)
        self.assertEqual(properties["correlation_basis"], "exact-hostname")
        self.assertEqual(properties["claim"], "exact-evidence-correlation-only")
        self.assertEqual(properties["matched_key_count"], "1")
        self.assertNotIn("app.example.test", repr(edge))

    def test_service_spn_host_can_correlate_to_network_asset(self):
        asset = node(
            GraphNodeKind.ASSET,
            "192.0.2.20",
            "Web host",
            (("hostnames", "web.example.test"),),
        )
        identity = node(
            GraphNodeKind.IDENTITY,
            "ad:service:opaque",
            "WebSvc",
            (
                ("identity_type", "ad-service"),
                ("spn_hosts", "web.example.test"),
            ),
        )

        result = correlate_exact_cross_surface_evidence(graph(identity, asset))

        self.assertEqual(len(result.correlated_edge_ids), 1)
        self.assertEqual(result.unresolved, ())

    def test_same_human_label_without_exact_property_never_correlates(self):
        asset = node(
            GraphNodeKind.ASSET,
            "192.0.2.30",
            "shared-name",
            (("hostnames", "asset.example.test"),),
        )
        identity = node(
            GraphNodeKind.IDENTITY,
            "ad:computer:opaque",
            "shared-name",
            (("identity_type", "ad-computer"),),
        )

        result = correlate_exact_cross_surface_evidence(graph(asset, identity))

        self.assertEqual(result.correlated_edge_ids, ())
        self.assertEqual(result.unresolved, ())
        self.assertEqual(result.graph.edges, ())

    def test_no_match_is_explicitly_unresolved_without_hostname_leak(self):
        identity = node(
            GraphNodeKind.IDENTITY,
            "ad:computer:opaque",
            "APP01",
            (
                ("dns_hostname", "missing.example.test"),
                ("identity_type", "ad-computer"),
            ),
        )

        result = correlate_exact_cross_surface_evidence(graph(identity))

        self.assertEqual(result.correlated_edge_ids, ())
        self.assertEqual(len(result.unresolved), 1)
        unresolved = result.unresolved[0]
        self.assertEqual(unresolved.reason, "no-exact-asset-hostname-match")
        self.assertEqual(unresolved.candidate_count, 0)
        self.assertEqual(len(unresolved.key_sha256), 64)
        self.assertNotIn("missing.example.test", repr(unresolved))

    def test_ambiguous_asset_hostname_never_generates_edge(self):
        asset_a = node(
            GraphNodeKind.ASSET,
            "192.0.2.40",
            "A",
            (("hostnames", "duplicate.example.test"),),
        )
        asset_b = node(
            GraphNodeKind.ASSET,
            "192.0.2.41",
            "B",
            (("hostnames", "duplicate.example.test"),),
        )
        identity = node(
            GraphNodeKind.IDENTITY,
            "ad:computer:opaque",
            "Duplicate",
            (("dns_hostname", "duplicate.example.test"),),
        )

        result = correlate_exact_cross_surface_evidence(
            graph(asset_b, identity, asset_a)
        )

        self.assertEqual(result.correlated_edge_ids, ())
        self.assertEqual(len(result.unresolved), 1)
        self.assertEqual(
            result.unresolved[0].reason,
            "ambiguous-asset-hostname",
        )
        self.assertEqual(result.unresolved[0].candidate_count, 2)

    def test_multiple_exact_keys_for_same_pair_collapse_to_one_edge(self):
        asset = node(
            GraphNodeKind.ASSET,
            "192.0.2.50",
            "Multi",
            (("hostnames", "a.example.test,b.example.test"),),
        )
        identity = node(
            GraphNodeKind.IDENTITY,
            "ad:computer:opaque",
            "Multi",
            (
                ("dns_hostname", "a.example.test"),
                ("spn_hosts", "a.example.test,b.example.test"),
            ),
        )

        result = correlate_exact_cross_surface_evidence(graph(asset, identity))

        self.assertEqual(len(result.correlated_edge_ids), 1)
        edge = result.graph.edges[0]
        self.assertEqual(dict(edge.properties)["matched_key_count"], "2")

    def test_correlation_is_deterministic_across_node_order(self):
        asset = node(
            GraphNodeKind.ASSET,
            "192.0.2.60",
            "Stable",
            (("hostnames", "stable.example.test"),),
        )
        identity = node(
            GraphNodeKind.IDENTITY,
            "ad:computer:opaque",
            "Stable",
            (("dns_hostname", "stable.example.test"),),
        )

        first = correlate_exact_cross_surface_evidence(graph(asset, identity))
        second = correlate_exact_cross_surface_evidence(graph(identity, asset))

        self.assertEqual(first, second)

    def test_exact_https_origin_links_network_service_to_web_surface(self):
        asset = node(
            GraphNodeKind.ASSET,
            "192.0.2.80",
            "App host",
            (
                ("address", "192.0.2.80"),
                ("hostnames", "app.example.test"),
            ),
        )
        network_service = node(
            GraphNodeKind.SERVICE,
            "192.0.2.80:443/tcp",
            "https",
            (
                ("address", "192.0.2.80"),
                ("port", "443"),
                ("protocol", "tcp"),
            ),
        )
        web_surface = node(
            GraphNodeKind.SERVICE,
            "web-surface:web:opaque",
            "https://app.example.test",
            (
                ("origin_host", "app.example.test"),
                ("origin_port", "443"),
                ("origin_scheme", "https"),
                ("surface_type", "web"),
            ),
        )

        result = correlate_exact_cross_surface_evidence(
            graph(asset, web_surface, network_service)
        )

        self.assertEqual(result.unresolved, ())
        self.assertEqual(len(result.correlated_edge_ids), 1)
        edge = next(
            item for item in result.graph.edges
            if item.edge_id in result.correlated_edge_ids
        )
        self.assertEqual(edge.source_node_id, network_service.node_id)
        self.assertEqual(edge.target_node_id, web_surface.node_id)
        self.assertEqual(
            dict(edge.properties)["correlation_basis"],
            "exact-origin-host-port",
        )
        self.assertIs(edge.evidence_state, GraphEvidenceState.INFERRED)

    def test_explicit_api_port_requires_same_observed_network_port(self):
        asset = node(
            GraphNodeKind.ASSET,
            "192.0.2.81",
            "API host",
            (
                ("address", "192.0.2.81"),
                ("hostnames", "api.example.test"),
            ),
        )
        wrong_port = node(
            GraphNodeKind.SERVICE,
            "192.0.2.81:443/tcp",
            "https",
            (
                ("address", "192.0.2.81"),
                ("port", "443"),
                ("protocol", "tcp"),
            ),
        )
        api_surface = node(
            GraphNodeKind.SERVICE,
            "web-surface:api:opaque",
            "https://api.example.test:8443",
            (
                ("origin_host", "api.example.test"),
                ("origin_port", "8443"),
                ("origin_scheme", "https"),
                ("surface_type", "api"),
            ),
        )

        result = correlate_exact_cross_surface_evidence(
            graph(asset, wrong_port, api_surface)
        )

        self.assertEqual(result.correlated_edge_ids, ())
        self.assertEqual(len(result.unresolved), 1)
        self.assertEqual(
            result.unresolved[0].reason,
            "no-exact-origin-service-match",
        )
        self.assertEqual(
            result.unresolved[0].source_kind,
            GraphNodeKind.SERVICE,
        )

    def test_ip_literal_origin_matches_exact_asset_address(self):
        asset = node(
            GraphNodeKind.ASSET,
            "192.0.2.82",
            "192.0.2.82",
            (("address", "192.0.2.82"),),
        )
        network_service = node(
            GraphNodeKind.SERVICE,
            "192.0.2.82:80/tcp",
            "http",
            (
                ("address", "192.0.2.82"),
                ("port", "80"),
                ("protocol", "tcp"),
            ),
        )
        surface = node(
            GraphNodeKind.SERVICE,
            "web-surface:web:ip",
            "http://192.0.2.82",
            (
                ("origin_host", "192.0.2.82"),
                ("origin_port", "80"),
                ("origin_scheme", "http"),
                ("surface_type", "web"),
            ),
        )

        result = correlate_exact_cross_surface_evidence(
            graph(surface, network_service, asset)
        )

        self.assertEqual(len(result.correlated_edge_ids), 1)
        self.assertEqual(result.unresolved, ())

    def test_ambiguous_origin_hostname_never_selects_an_asset(self):
        asset_a = node(
            GraphNodeKind.ASSET,
            "192.0.2.83",
            "A",
            (
                ("address", "192.0.2.83"),
                ("hostnames", "shared.example.test"),
            ),
        )
        asset_b = node(
            GraphNodeKind.ASSET,
            "192.0.2.84",
            "B",
            (
                ("address", "192.0.2.84"),
                ("hostnames", "shared.example.test"),
            ),
        )
        surface = node(
            GraphNodeKind.SERVICE,
            "web-surface:graphql:shared",
            "https://shared.example.test",
            (
                ("origin_host", "shared.example.test"),
                ("origin_port", "443"),
                ("origin_scheme", "https"),
                ("surface_type", "graphql"),
            ),
        )

        result = correlate_exact_cross_surface_evidence(
            graph(asset_a, surface, asset_b)
        )

        self.assertEqual(result.correlated_edge_ids, ())
        self.assertEqual(len(result.unresolved), 1)
        self.assertEqual(
            result.unresolved[0].reason,
            "ambiguous-origin-asset",
        )
        self.assertEqual(result.unresolved[0].candidate_count, 2)

    def test_web_surface_hostname_is_not_exposed_in_unresolved_metadata(self):
        surface = node(
            GraphNodeKind.SERVICE,
            "web-surface:web:missing",
            "https://missing.example.test",
            (
                ("origin_host", "missing.example.test"),
                ("origin_port", "443"),
                ("origin_scheme", "https"),
                ("surface_type", "web"),
            ),
        )

        result = correlate_exact_cross_surface_evidence(graph(surface))

        self.assertEqual(len(result.unresolved), 1)
        unresolved = result.unresolved[0]
        self.assertEqual(unresolved.reason, "no-exact-origin-asset-match")
        self.assertNotIn("missing.example.test", repr(unresolved))
        self.assertEqual(len(unresolved.key_sha256), 64)


    def test_exact_cloud_private_ip_links_network_asset_to_cloud_resource(self):
        network = node(
            GraphNodeKind.ASSET,
            "10.0.0.50",
            "Observed host",
            (("address", "10.0.0.50"),),
        )
        cloud = node(
            GraphNodeKind.ASSET,
            "cloud:azure:resource:vm-50",
            "Azure VM",
            (
                ("cloud_provider", "azure"),
                ("cloud_resource_id", "vm-50"),
                ("cloud_resource_kind", "virtual-machine"),
                ("private_ip", "10.0.0.50"),
            ),
        )

        result = correlate_exact_cross_surface_evidence(graph(cloud, network))

        self.assertEqual(result.unresolved, ())
        self.assertEqual(len(result.correlated_edge_ids), 1)
        edge = next(
            item for item in result.graph.edges
            if item.edge_id in result.correlated_edge_ids
        )
        self.assertEqual(edge.source_node_id, network.node_id)
        self.assertEqual(edge.target_node_id, cloud.node_id)
        self.assertEqual(
            dict(edge.properties)["correlation_basis"],
            "exact-cloud-network-key",
        )

    def test_cloud_network_multiple_exact_proofs_collapse_to_one_edge(self):
        network = node(
            GraphNodeKind.ASSET,
            "10.0.0.51",
            "Observed host",
            (
                ("address", "10.0.0.51"),
                ("hostnames", "vm51.example.test"),
            ),
        )
        cloud = node(
            GraphNodeKind.ASSET,
            "cloud:aws:resource:i-51",
            "EC2",
            (
                ("cloud_provider", "aws"),
                ("cloud_resource_id", "i-51"),
                ("cloud_resource_kind", "virtual-machine"),
                ("private_ip", "10.0.0.51"),
                ("private_dns_name", "vm51.example.test"),
            ),
        )

        result = correlate_exact_cross_surface_evidence(graph(network, cloud))

        self.assertEqual(result.unresolved, ())
        self.assertEqual(len(result.correlated_edge_ids), 1)
        edge = next(
            item for item in result.graph.edges
            if item.edge_id in result.correlated_edge_ids
        )
        self.assertEqual(dict(edge.properties)["matched_key_count"], "2")

    def test_conflicting_cloud_network_evidence_fails_closed(self):
        network_a = node(
            GraphNodeKind.ASSET,
            "10.0.0.52",
            "A",
            (
                ("address", "10.0.0.52"),
                ("hostnames", "a.example.test"),
            ),
        )
        network_b = node(
            GraphNodeKind.ASSET,
            "10.0.0.53",
            "B",
            (
                ("address", "10.0.0.53"),
                ("hostnames", "b.example.test"),
            ),
        )
        cloud = node(
            GraphNodeKind.ASSET,
            "cloud:azure:resource:vm-conflict",
            "Azure VM",
            (
                ("cloud_provider", "azure"),
                ("cloud_resource_id", "vm-conflict"),
                ("cloud_resource_kind", "virtual-machine"),
                ("private_ip", "10.0.0.52"),
                ("hostname", "b.example.test"),
            ),
        )

        result = correlate_exact_cross_surface_evidence(
            graph(network_a, cloud, network_b)
        )

        self.assertEqual(result.correlated_edge_ids, ())
        self.assertEqual(len(result.unresolved), 1)
        self.assertEqual(
            result.unresolved[0].reason,
            "conflicting-cloud-network-evidence",
        )
        self.assertEqual(result.unresolved[0].candidate_count, 2)

    def test_exact_tenant_and_object_id_links_entra_to_cloud_identity(self):
        entra = node(
            GraphNodeKind.IDENTITY,
            "entra:user:opaque",
            "Cloud User",
            (
                ("entra_tenant_id", "tenant-1"),
                ("entra_object_id", "object-1"),
            ),
        )
        cloud = node(
            GraphNodeKind.IDENTITY,
            "cloud:entra:identity:object-1",
            "Cloud User",
            (
                ("cloud_provider", "entra"),
                ("cloud_identity_id", "object-1"),
                ("entra_tenant_id", "tenant-1"),
                ("entra_object_id", "object-1"),
            ),
        )

        result = correlate_exact_cross_surface_evidence(graph(cloud, entra))

        self.assertEqual(result.unresolved, ())
        self.assertEqual(len(result.correlated_edge_ids), 1)
        edge = next(
            item for item in result.graph.edges
            if item.edge_id in result.correlated_edge_ids
        )
        self.assertEqual(edge.source_node_id, entra.node_id)
        self.assertEqual(edge.target_node_id, cloud.node_id)
        self.assertEqual(
            dict(edge.properties)["correlation_basis"],
            "exact-cloud-entra-object",
        )

    def test_cloud_identity_requires_tenant_and_object_id(self):
        cloud = node(
            GraphNodeKind.IDENTITY,
            "cloud:azure:identity:managed-1",
            "Managed identity",
            (
                ("cloud_provider", "azure"),
                ("cloud_identity_id", "managed-1"),
                ("azure_object_id", "object-1"),
            ),
        )

        result = correlate_exact_cross_surface_evidence(graph(cloud))

        self.assertEqual(result.correlated_edge_ids, ())
        self.assertEqual(len(result.unresolved), 1)
        self.assertEqual(
            result.unresolved[0].reason,
            "incomplete-cloud-identity-key",
        )

    def test_edge_limit_fails_closed(self):
        asset_a = node(
            GraphNodeKind.ASSET,
            "192.0.2.70",
            "A",
            (("hostnames", "a.example.test"),),
        )
        asset_b = node(
            GraphNodeKind.ASSET,
            "192.0.2.71",
            "B",
            (("hostnames", "b.example.test"),),
        )
        identity_a = node(
            GraphNodeKind.IDENTITY,
            "ad:computer:a",
            "A",
            (("dns_hostname", "a.example.test"),),
        )
        identity_b = node(
            GraphNodeKind.IDENTITY,
            "ad:computer:b",
            "B",
            (("dns_hostname", "b.example.test"),),
        )

        with self.assertRaisesRegex(ValueError, "edge limit exceeded"):
            correlate_exact_cross_surface_evidence(
                graph(asset_a, asset_b, identity_a, identity_b),
                limits=CrossSurfaceCorrelationLimits(max_edges=1),
            )

    def test_unresolved_limit_fails_closed(self):
        identity = node(
            GraphNodeKind.IDENTITY,
            "ad:computer:opaque",
            "Missing",
            (("dns_hostname", "missing.example.test"),),
        )

        with self.assertRaisesRegex(ValueError, "unresolved correlation limit"):
            correlate_exact_cross_surface_evidence(
                graph(identity),
                limits=CrossSurfaceCorrelationLimits(max_unresolved=0),
            )


if __name__ == "__main__":
    unittest.main()
