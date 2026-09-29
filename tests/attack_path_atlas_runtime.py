"""Deterministic no-network cross-domain attack-path atlas benchmark."""

from __future__ import annotations

import json

from nightrecon_red_engine.attack_path_atlas import (
    build_cross_domain_attack_path_atlas,
)
from nightrecon_red_engine.graph_models import GraphNodeKind
from nightrecon_red_engine.unified_attack_graph import build_unified_attack_graph
from nightrecon_shared_core.contracts import EvidenceRecord


def record(evidence_id: str, evidence_type: str, data: dict[str, object]):
    return EvidenceRecord(
        engagement_id="eng-atlas-benchmark",
        evidence_id=evidence_id,
        source_night="red",
        evidence_type=evidence_type,
        observed_at="2026-09-29T04:00:00+00:00",
        provenance=f"fixture://{evidence_id}",
        data=data,
    )


def main() -> None:
    records = (
        record("identity-ad-user", "identity.observation", {
            "identity_key": "ad:user:opaque-alice",
            "label": "Alice",
        }),
        record("group-ad-admins", "group.observation", {
            "group_key": "ad:group:opaque-admins",
            "label": "Admins",
        }),
        record("permission-ad-role", "permission.observation", {
            "permission_key": "ad:role:opaque-admin",
            "label": "Administrative access",
        }),
        record("asset-onprem", "asset.observation", {
            "asset_key": "10.0.0.20",
            "label": "Application host",
        }),
        record("service-web", "service.observation", {
            "service_key": "10.0.0.20:443/tcp",
            "label": "HTTPS",
        }),
        record("asset-cloud", "asset.observation", {
            "asset_key": "cloud:azure:resource:finance-app",
            "label": "Finance application",
        }),
        record("identity-cloud", "identity.observation", {
            "identity_key": "cloud:azure:identity:automation",
            "label": "Automation identity",
        }),
        record("critical-cloud", "critical-asset.observation", {
            "asset_key": "cloud:azure:resource:finance-app",
            "critical_key": "finance-system",
            "label": "Finance system",
        }),
        record("rel-member", "graph.relationship", {
            "source_kind": "identity",
            "source_key": "ad:user:opaque-alice",
            "target_kind": "group",
            "target_key": "ad:group:opaque-admins",
            "relationship": "member-of",
            "evidence_state": "observed",
        }),
        record("rel-role", "graph.relationship", {
            "source_kind": "group",
            "source_key": "ad:group:opaque-admins",
            "target_kind": "permission",
            "target_key": "ad:role:opaque-admin",
            "relationship": "assigned-role",
            "evidence_state": "observed",
        }),
        record("rel-admin-host", "graph.relationship", {
            "source_kind": "permission",
            "source_key": "ad:role:opaque-admin",
            "target_kind": "asset",
            "target_key": "10.0.0.20",
            "relationship": "applies-to",
            "evidence_state": "observed",
        }),
        record("rel-host-service", "graph.relationship", {
            "source_kind": "asset",
            "source_key": "10.0.0.20",
            "target_kind": "service",
            "target_key": "10.0.0.20:443/tcp",
            "relationship": "exposes",
            "evidence_state": "observed",
        }),
        record("rel-service-cloud", "graph.relationship", {
            "source_kind": "service",
            "source_key": "10.0.0.20:443/tcp",
            "target_kind": "asset",
            "target_key": "cloud:azure:resource:finance-app",
            "relationship": "reaches-cloud-resource",
            "evidence_state": "inferred",
        }),
        record("rel-cloud-owner", "graph.relationship", {
            "source_kind": "identity",
            "source_key": "cloud:azure:identity:automation",
            "target_kind": "asset",
            "target_key": "cloud:azure:resource:finance-app",
            "relationship": "owns",
            "evidence_state": "observed",
        }),
    )

    built = build_unified_attack_graph(records)
    assert built.unresolved_records == ()
    assert built.ignored_records == ()

    atlas = build_cross_domain_attack_path_atlas(
        built.graph,
        start_kinds=(GraphNodeKind.IDENTITY,),
    )
    payload = atlas.to_dict()

    assert not atlas.truncated
    assert len(atlas.paths) == 2
    assert len(atlas.target_node_ids) == 1

    cross_domain = next(
        item for item in atlas.paths
        if len(item.relationships) > 2
    )
    assert cross_domain.relationships == (
        "member-of",
        "assigned-role",
        "applies-to",
        "exposes",
        "reaches-cloud-resource",
        "represents-critical-asset",
    )
    assert cross_domain.observed_hops == 5
    assert cross_domain.inferred_hops == 1
    assert set(cross_domain.evidence_ids) == {
        "rel-member",
        "rel-role",
        "rel-admin-host",
        "rel-host-service",
        "rel-service-cloud",
        "critical-cloud",
    }
    assert {
        (item.source_type, item.source_id)
        for item in cross_domain.provenance_sources
    } == {
        ("engagement-evidence", evidence_id)
        for evidence_id in cross_domain.evidence_ids
    }

    cloud_path = next(
        item for item in atlas.paths
        if item.relationships == ("owns", "represents-critical-asset")
    )
    assert cloud_path.observed_hops == 2
    assert cloud_path.inferred_hops == 0

    cloud_asset = next(
        node for node in built.graph.nodes
        if node.natural_key == "cloud:azure:resource:finance-app"
    )
    participation = {
        item.subject_id: item.path_count
        for item in atlas.node_participation
    }
    assert participation[cloud_asset.node_id] == 2

    serialized = json.dumps(payload, sort_keys=True)
    assert "risk_score" not in serialized
    assert "exploitability_probability" not in serialized
    assert "do not establish exploitability" in atlas.interpretation
    assert "Alice" not in serialized
    assert "Finance system" not in serialized

    repeat = build_cross_domain_attack_path_atlas(
        built.graph,
        start_kinds=(GraphNodeKind.IDENTITY,),
    )
    assert repeat.to_dict() == payload

    print(json.dumps(payload, sort_keys=True))


if __name__ == "__main__":
    main()
