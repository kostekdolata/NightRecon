"""Project existing NightRecon asset inventory evidence into the identity graph."""

from __future__ import annotations

from nightrecon.asset_inventory import AssetInventory, AssetRecord, AssetServiceRecord
from nightrecon.graph_builder import GraphBuildLimits, IdentityGraphBuilder
from nightrecon.graph_models import (
    GraphEdge,
    GraphEvidenceState,
    GraphNode,
    GraphNodeKind,
    GraphProvenance,
    IdentityGraph,
)
from nightrecon.vulnerability_intelligence import ServiceVulnerabilityResult


def build_identity_graph_from_asset_inventory(
    inventory: AssetInventory,
    *,
    limits: GraphBuildLimits | None = None,
) -> IdentityGraph:
    """Build a deterministic graph from persisted asset/service evidence."""

    builder = IdentityGraphBuilder(limits)

    for asset in inventory.assets:
        asset_node = _asset_node(asset)
        builder.add_node(asset_node)

        for service in asset.services:
            service_node = _service_node(asset, service)
            builder.add_node(service_node)
            builder.add_edge(
                GraphEdge.create(
                    source_node_id=asset_node.node_id,
                    target_node_id=service_node.node_id,
                    relationship="exposes",
                    evidence_state=GraphEvidenceState.OBSERVED,
                    provenance=_asset_provenance(asset),
                )
            )

    return builder.build()


def _asset_node(asset: AssetRecord) -> GraphNode:
    properties: list[tuple[str, str]] = [
        ("address", asset.address),
        ("first_seen", asset.first_seen),
        ("last_seen", asset.last_seen),
        ("last_checked_at", asset.last_checked_at),
    ]

    if asset.hostnames:
        properties.append(("hostnames", ",".join(sorted(asset.hostnames))))
    if asset.os_platform:
        properties.append(("os_platform", asset.os_platform))
    if asset.os_family:
        properties.append(("os_family", asset.os_family))
    if asset.os_confidence:
        properties.append(("os_confidence", asset.os_confidence))
    if asset.os_candidates:
        properties.append(("os_candidates", ",".join(sorted(asset.os_candidates))))
    if asset.os_evidence_count:
        properties.append(("os_evidence_count", str(asset.os_evidence_count)))
    if asset.discovery_methods:
        properties.append(
            ("discovery_methods", ",".join(sorted(asset.discovery_methods)))
        )
    if asset.last_discovery_responsive is not None:
        properties.append(
            (
                "last_discovery_responsive",
                "true" if asset.last_discovery_responsive else "false",
            )
        )

    return GraphNode.create(
        kind=GraphNodeKind.ASSET,
        natural_key=asset.address,
        label=asset.address,
        provenance=_asset_provenance(asset),
        properties=tuple(properties),
    )


def _service_node(asset: AssetRecord, service: AssetServiceRecord) -> GraphNode:
    protocol = "tcp"
    properties: list[tuple[str, str]] = [
        ("address", asset.address),
        ("port", str(service.port)),
        ("protocol", protocol),
    ]

    optional_properties = (
        ("service", service.service),
        ("product", service.product),
        ("version", service.version),
        ("protocol_version", service.protocol_version),
        ("platform", service.platform),
        ("fingerprint_source", service.fingerprint_source),
        ("fingerprint_confidence", service.fingerprint_confidence),
        ("tls_certificate_sha256", service.tls_certificate_sha256),
    )
    properties.extend(
        (key, value)
        for key, value in optional_properties
        if value
    )

    service_label = service.service or f"{service.port}/{protocol}"
    return GraphNode.create(
        kind=GraphNodeKind.SERVICE,
        natural_key=f"{asset.address}:{service.port}/{protocol}",
        label=service_label,
        provenance=_asset_provenance(asset),
        properties=tuple(properties),
    )


def _asset_provenance(asset: AssetRecord) -> tuple[GraphProvenance, ...]:
    observed_at = asset.last_checked_at or asset.last_seen or asset.first_seen
    if asset.source_session_ids:
        return tuple(
            GraphProvenance(
                source_type="asset-inventory",
                source_id=session_id,
                observed_at=observed_at,
            )
            for session_id in sorted(set(asset.source_session_ids))
        )

    return (
        GraphProvenance(
            source_type="asset-inventory",
            source_id=f"asset:{asset.address}",
            observed_at=observed_at,
        ),
    )


def add_vulnerability_evidence_to_identity_graph(
    graph: IdentityGraph,
    vulnerabilities: tuple[ServiceVulnerabilityResult, ...],
    *,
    observed_at: str = "",
    limits: GraphBuildLimits | None = None,
) -> IdentityGraph:
    """Add provider-returned vulnerability matches without claiming exploitability."""

    builder = IdentityGraphBuilder(limits)
    service_nodes_by_key: dict[str, GraphNode] = {}

    for node in graph.nodes:
        builder.add_node(node)
        if node.kind is GraphNodeKind.SERVICE:
            service_nodes_by_key[node.natural_key] = node

    for edge in graph.edges:
        builder.add_edge(edge)

    for result in vulnerabilities:
        service_key = f"{result.address}:{result.port}/tcp"
        service_node = service_nodes_by_key.get(service_key)
        if service_node is None:
            raise ValueError(
                f"vulnerability result service is missing from graph: {service_key}"
            )

        if result.lookup.error:
            continue

        for finding in result.lookup.findings:
            provenance = (
                GraphProvenance(
                    source_type="vulnerability-intelligence",
                    source_id=(
                        f"{result.lookup.provider}:"
                        f"{finding.vulnerability_id.strip().upper()}"
                    ),
                    observed_at=observed_at.strip(),
                ),
            )
            properties: list[tuple[str, str]] = [
                ("source", finding.source),
                ("provider", result.lookup.provider),
                ("summary", finding.summary),
            ]
            if finding.severity:
                properties.append(("severity", finding.severity))
            if finding.cvss_score is not None:
                properties.append(("cvss_score", str(finding.cvss_score)))
            if finding.match_basis:
                properties.append(("match_basis", finding.match_basis))
            if finding.matched_identifier:
                properties.append(
                    ("matched_identifier", finding.matched_identifier)
                )

            vulnerability_node = GraphNode.create(
                kind=GraphNodeKind.VULNERABILITY,
                natural_key=(
                    f"{result.lookup.provider}:"
                    f"{finding.vulnerability_id.strip().upper()}"
                ),
                label=finding.vulnerability_id.strip().upper(),
                provenance=provenance,
                properties=tuple(properties),
            )
            builder.add_node(vulnerability_node)
            builder.add_edge(
                GraphEdge.create(
                    source_node_id=service_node.node_id,
                    target_node_id=vulnerability_node.node_id,
                    relationship="matched-vulnerability",
                    evidence_state=GraphEvidenceState.OBSERVED,
                    provenance=provenance,
                    properties=(
                        ("claim", "provider-match-only"),
                    ),
                )
            )

    return builder.build()
