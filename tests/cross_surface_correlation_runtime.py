"""Deterministic no-network v0.42 cross-surface correlation benchmark."""

from __future__ import annotations

from nightrecon_red_engine.asset_inventory import (
    AssetInventory,
    AssetRecord,
    AssetServiceRecord,
)
from nightrecon_red_engine.graph_identity_evidence import (
    IdentityEvidence,
    IdentityEvidenceBundle,
)
from nightrecon_red_engine.graph_models import (
    GraphEvidenceState,
    GraphNodeKind,
)
from nightrecon_red_engine.graph_pipeline import build_correlated_identity_graph
from nightrecon_red_engine.graph_snapshot import (
    create_identity_graph_snapshot_manifest,
)
from nightrecon_red_engine.graph_web_surface import WebSurfaceEvidence


def build_result():
    inventory = AssetInventory(
        assets=(
            AssetRecord(
                address="192.0.2.100",
                first_seen="2026-09-29T04:00:00+00:00",
                last_seen="2026-09-29T04:00:00+00:00",
                last_checked_at="2026-09-29T04:00:00+00:00",
                hostnames=("app.example.test",),
                services=(
                    AssetServiceRecord(
                        port=443,
                        service="https",
                    ),
                ),
                source_session_ids=("correlation-benchmark-network",),
            ),
        ),
    )
    identities = IdentityEvidenceBundle(
        identities=(
            IdentityEvidence(
                natural_key="ad:computer:benchmark",
                label="APP01",
                source_id="correlation-benchmark-ad",
                identity_type="ad-computer",
                properties=(("dns_hostname", "app.example.test"),),
            ),
        ),
    )
    surfaces = (
        WebSurfaceEvidence(
            origin="https://app.example.test",
            source_id="correlation-benchmark-web",
            surface_type="web",
        ),
        WebSurfaceEvidence(
            origin="https://app.example.test",
            source_id="correlation-benchmark-api",
            surface_type="api",
        ),
    )
    return build_correlated_identity_graph(
        inventory=inventory,
        identity_evidence=identities,
        web_surfaces=surfaces,
    )


def main() -> None:
    first = build_result()
    second = build_result()

    assert first == second
    assert first.unresolved == ()
    assert len(first.correlated_edge_ids) == 3

    graph = first.graph
    correlated = [
        edge
        for edge in graph.edges
        if edge.edge_id in first.correlated_edge_ids
    ]
    assert all(
        edge.evidence_state is GraphEvidenceState.INFERRED
        for edge in correlated
    )
    assert {
        dict(edge.properties)["correlation_basis"]
        for edge in correlated
    } == {"exact-hostname", "exact-origin-host-port"}

    observed_exposes = [
        edge for edge in graph.edges
        if edge.relationship == "exposes"
    ]
    assert len(observed_exposes) == 1
    assert observed_exposes[0].evidence_state is GraphEvidenceState.OBSERVED

    identity = next(
        node for node in graph.nodes
        if node.kind is GraphNodeKind.IDENTITY
    )
    asset = next(
        node for node in graph.nodes
        if node.kind is GraphNodeKind.ASSET
    )
    network_service = next(
        node for node in graph.nodes
        if node.kind is GraphNodeKind.SERVICE
        and node.natural_key == "192.0.2.100:443/tcp"
    )
    web_surfaces = [
        node for node in graph.nodes
        if node.kind is GraphNodeKind.SERVICE
        and dict(node.properties).get("surface_type") in {"web", "api"}
    ]

    assert any(
        edge.source_node_id == identity.node_id
        and edge.target_node_id == asset.node_id
        for edge in correlated
    )
    assert all(
        any(
            edge.source_node_id == network_service.node_id
            and edge.target_node_id == surface.node_id
            for edge in correlated
        )
        for surface in web_surfaces
    )

    manifest = create_identity_graph_snapshot_manifest(graph)
    second_manifest = create_identity_graph_snapshot_manifest(second.graph)
    assert manifest == second_manifest
    assert len(manifest.graph_sha256) == 64
    assert manifest.node_count == 5
    assert manifest.edge_count == 4

    print(manifest.graph_sha256)


if __name__ == "__main__":
    main()
