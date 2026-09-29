"""Deterministic exact cross-surface graph correlation.

This module correlates already-observed graph facts. It does not perform DNS,
network access, fuzzy matching, or exploitability analysis.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import ipaddress

from nightrecon_red_engine.graph_builder import GraphBuildLimits, IdentityGraphBuilder
from nightrecon_red_engine.graph_models import (
    GraphEdge,
    GraphEvidenceState,
    GraphNode,
    GraphNodeKind,
    GraphProvenance,
    IdentityGraph,
)


_WEB_SURFACE_TYPES = frozenset({"web", "api", "graphql"})
_CLOUD_NETWORK_IP_PROPERTIES = ("private_ip", "public_ip")
_CLOUD_NETWORK_HOST_PROPERTIES = (
    "hostname",
    "private_dns_name",
    "public_dns_name",
)


def _normalize_hostname(value: str) -> str:
    normalized = value.strip().casefold().rstrip(".")
    if not normalized or any(character.isspace() for character in normalized):
        return ""
    return normalized


def _property_map(node: GraphNode) -> dict[str, str]:
    return dict(node.properties)


def _csv_hostnames(value: str) -> tuple[str, ...]:
    if not value:
        return ()
    result = {
        normalized
        for item in value.split(",")
        if (normalized := _normalize_hostname(item))
    }
    return tuple(sorted(result))


def _asset_hostnames(node: GraphNode) -> tuple[str, ...]:
    properties = _property_map(node)
    return _csv_hostnames(properties.get("hostnames", ""))


def _asset_address(node: GraphNode) -> str:
    properties = _property_map(node)
    value = properties.get("address", node.natural_key)
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return ""


def _identity_hostnames(node: GraphNode) -> tuple[str, ...]:
    properties = _property_map(node)
    values: set[str] = set()
    dns_hostname = _normalize_hostname(properties.get("dns_hostname", ""))
    if dns_hostname:
        values.add(dns_hostname)
    values.update(_csv_hostnames(properties.get("spn_hosts", "")))
    return tuple(sorted(values))


def _cloud_network_proofs(node: GraphNode) -> tuple[tuple[str, str], ...]:
    if node.kind is not GraphNodeKind.ASSET:
        return ()
    properties = _property_map(node)
    if not properties.get("cloud_provider") or not properties.get("cloud_resource_id"):
        return ()

    proofs: list[tuple[str, str]] = []
    for key in _CLOUD_NETWORK_IP_PROPERTIES:
        value = properties.get(key, "")
        if not value:
            continue
        try:
            normalized = str(ipaddress.ip_address(value))
        except ValueError as exc:
            raise ValueError(f"cloud {key} correlation property is invalid") from exc
        if normalized != value:
            raise ValueError(f"cloud {key} correlation property is not canonical")
        proofs.append((key, normalized))

    for key in _CLOUD_NETWORK_HOST_PROPERTIES:
        value = properties.get(key, "")
        if not value:
            continue
        normalized = _normalize_hostname(value)
        if not normalized or normalized != value:
            raise ValueError(f"cloud {key} correlation property is not canonical")
        proofs.append((key, normalized))

    return tuple(sorted(proofs))


def _entra_identity_key(node: GraphNode) -> tuple[str, str] | None:
    if node.kind is not GraphNodeKind.IDENTITY:
        return None
    properties = _property_map(node)
    if properties.get("cloud_provider"):
        return None
    tenant_id = properties.get("entra_tenant_id", "")
    object_id = properties.get("entra_object_id", "")
    if not tenant_id or not object_id:
        return None
    return tenant_id, object_id


def _cloud_identity_entra_parts(node: GraphNode) -> tuple[str, str, bool]:
    if node.kind is not GraphNodeKind.IDENTITY:
        return "", "", False
    properties = _property_map(node)
    provider = properties.get("cloud_provider", "")
    if provider == "entra":
        tenant_id = properties.get("entra_tenant_id", "")
        object_id = properties.get("entra_object_id", "")
    elif provider == "azure":
        tenant_id = properties.get("azure_tenant_id", "")
        object_id = properties.get("azure_object_id", "")
    else:
        return "", "", False
    return tenant_id, object_id, bool(tenant_id or object_id)


def _network_service_endpoint(node: GraphNode) -> tuple[str, int] | None:
    if node.kind is not GraphNodeKind.SERVICE:
        return None
    properties = _property_map(node)
    if properties.get("surface_type", ""):
        return None
    if properties.get("protocol") != "tcp":
        return None
    address = properties.get("address", "")
    try:
        normalized_address = str(ipaddress.ip_address(address))
        port = int(properties.get("port", ""))
    except (ValueError, TypeError):
        return None
    if not 1 <= port <= 65535:
        return None
    return normalized_address, port


def _web_surface_endpoint(node: GraphNode) -> tuple[str, int] | None:
    if node.kind is not GraphNodeKind.SERVICE:
        return None
    properties = _property_map(node)
    if properties.get("surface_type") not in _WEB_SURFACE_TYPES:
        return None
    host = _normalize_hostname(properties.get("origin_host", ""))
    if not host:
        raise ValueError("web surface origin_host is invalid")
    try:
        port = int(properties.get("origin_port", ""))
    except (TypeError, ValueError) as exc:
        raise ValueError("web surface origin_port is invalid") from exc
    if not 1 <= port <= 65535:
        raise ValueError("web surface origin_port is invalid")
    scheme = properties.get("origin_scheme")
    if scheme not in {"http", "https"}:
        raise ValueError("web surface origin_scheme is invalid")
    return host, port


def _opaque_key(value: str) -> str:
    return sha256(value.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class CrossSurfaceCorrelationLimits:
    max_edges: int = 5_000
    max_unresolved: int = 5_000

    def __post_init__(self) -> None:
        if self.max_edges < 0:
            raise ValueError("max_edges must not be negative")
        if self.max_unresolved < 0:
            raise ValueError("max_unresolved must not be negative")


@dataclass(frozen=True)
class CrossSurfaceUnresolved:
    source_kind: GraphNodeKind
    source_key: str
    correlation_basis: str
    key_sha256: str
    reason: str
    candidate_count: int

    def __post_init__(self) -> None:
        if self.source_kind not in {
            GraphNodeKind.ASSET,
            GraphNodeKind.IDENTITY,
            GraphNodeKind.SERVICE,
        }:
            raise ValueError("unsupported unresolved correlation source kind")
        if not self.source_key.strip():
            raise ValueError("source_key must not be empty")
        if self.correlation_basis not in {
            "exact-hostname",
            "exact-origin-host-port",
            "exact-cloud-network-key",
            "exact-cloud-entra-object",
        }:
            raise ValueError("unsupported correlation basis")
        if len(self.key_sha256) != 64:
            raise ValueError("key_sha256 must be a SHA-256 hex digest")
        if self.reason not in {
            "no-exact-asset-hostname-match",
            "ambiguous-asset-hostname",
            "no-exact-origin-asset-match",
            "ambiguous-origin-asset",
            "no-exact-origin-service-match",
            "ambiguous-origin-service",
            "no-exact-cloud-network-match",
            "ambiguous-cloud-network-match",
            "conflicting-cloud-network-evidence",
            "incomplete-cloud-identity-key",
            "no-exact-cloud-identity-match",
            "ambiguous-cloud-identity-match",
        }:
            raise ValueError("unsupported unresolved correlation reason")
        if self.candidate_count < 0:
            raise ValueError("candidate_count must not be negative")

    @property
    def identity_key(self) -> str:
        """Compatibility alias for the original identity-only correlation batch."""

        return (
            self.source_key
            if self.source_kind is GraphNodeKind.IDENTITY
            else ""
        )


@dataclass(frozen=True)
class CrossSurfaceCorrelationResult:
    graph: IdentityGraph
    correlated_edge_ids: tuple[str, ...]
    unresolved: tuple[CrossSurfaceUnresolved, ...]


def correlate_exact_cross_surface_evidence(
    graph: IdentityGraph,
    *,
    limits: CrossSurfaceCorrelationLimits | None = None,
) -> CrossSurfaceCorrelationResult:
    """Correlate exact identity, network, web/API, and cloud evidence."""

    active = limits or CrossSurfaceCorrelationLimits()
    builder = IdentityGraphBuilder(
        GraphBuildLimits(
            max_nodes=max(len(graph.nodes), 1),
            max_edges=len(graph.edges) + active.max_edges,
        )
    )
    for node in graph.nodes:
        builder.add_node(node)
    for edge in graph.edges:
        builder.add_edge(edge)

    assets_by_hostname: dict[str, list[GraphNode]] = {}
    assets_by_address: dict[str, list[GraphNode]] = {}
    network_services: dict[tuple[str, int], list[GraphNode]] = {}
    entra_identities_by_key: dict[tuple[str, str], list[GraphNode]] = {}
    identities: list[GraphNode] = []
    web_surfaces: list[GraphNode] = []
    cloud_resources: list[GraphNode] = []
    cloud_identities: list[GraphNode] = []

    for node in graph.nodes:
        if node.kind is GraphNodeKind.ASSET:
            properties = _property_map(node)
            if properties.get("cloud_provider"):
                if properties.get("cloud_resource_id"):
                    cloud_resources.append(node)
                continue
            for hostname in _asset_hostnames(node):
                assets_by_hostname.setdefault(hostname, []).append(node)
            address = _asset_address(node)
            if address:
                assets_by_address.setdefault(address, []).append(node)
        elif node.kind is GraphNodeKind.IDENTITY:
            properties = _property_map(node)
            if properties.get("cloud_provider"):
                if properties.get("cloud_identity_id"):
                    cloud_identities.append(node)
                continue
            entra_key = _entra_identity_key(node)
            if entra_key is not None:
                entra_identities_by_key.setdefault(entra_key, []).append(node)
            if _identity_hostnames(node):
                identities.append(node)
        elif node.kind is GraphNodeKind.SERVICE:
            endpoint = _network_service_endpoint(node)
            if endpoint is not None:
                network_services.setdefault(endpoint, []).append(node)
            elif _web_surface_endpoint(node) is not None:
                web_surfaces.append(node)

    pair_proofs: dict[tuple[str, str, str], set[str]] = {}
    unresolved: list[CrossSurfaceUnresolved] = []

    def add_unresolved(
        *,
        source_kind: GraphNodeKind,
        source_key: str,
        basis: str,
        proof: str,
        reason: str,
        candidate_count: int,
    ) -> None:
        if len(unresolved) >= active.max_unresolved:
            raise ValueError("cross-surface unresolved correlation limit exceeded")
        unresolved.append(CrossSurfaceUnresolved(
            source_kind=source_kind,
            source_key=source_key,
            correlation_basis=basis,
            key_sha256=_opaque_key(proof),
            reason=reason,
            candidate_count=candidate_count,
        ))

    def add_pair(
        source: GraphNode,
        target: GraphNode,
        *,
        basis: str,
        proof: str,
    ) -> None:
        pair_proofs.setdefault(
            (source.node_id, target.node_id, basis),
            set(),
        ).add(_opaque_key(proof))

    for identity in sorted(identities, key=lambda item: item.node_id):
        for hostname in _identity_hostnames(identity):
            candidates = tuple(sorted(
                assets_by_hostname.get(hostname, ()),
                key=lambda item: item.node_id,
            ))
            if len(candidates) != 1:
                add_unresolved(
                    source_kind=GraphNodeKind.IDENTITY,
                    source_key=identity.natural_key,
                    basis="exact-hostname",
                    proof=hostname,
                    reason=(
                        "no-exact-asset-hostname-match"
                        if not candidates
                        else "ambiguous-asset-hostname"
                    ),
                    candidate_count=len(candidates),
                )
                continue
            add_pair(
                identity,
                candidates[0],
                basis="exact-hostname",
                proof=hostname,
            )

    for surface in sorted(web_surfaces, key=lambda item: item.node_id):
        endpoint = _web_surface_endpoint(surface)
        if endpoint is None:
            continue
        host, port = endpoint
        proof = f"{host}\x1f{port}"

        try:
            address = str(ipaddress.ip_address(host))
        except ValueError:
            asset_candidates = tuple(sorted(
                assets_by_hostname.get(host, ()),
                key=lambda item: item.node_id,
            ))
        else:
            asset_candidates = tuple(sorted(
                assets_by_address.get(address, ()),
                key=lambda item: item.node_id,
            ))

        if len(asset_candidates) != 1:
            add_unresolved(
                source_kind=GraphNodeKind.SERVICE,
                source_key=surface.natural_key,
                basis="exact-origin-host-port",
                proof=proof,
                reason=(
                    "no-exact-origin-asset-match"
                    if not asset_candidates
                    else "ambiguous-origin-asset"
                ),
                candidate_count=len(asset_candidates),
            )
            continue

        asset_address = _asset_address(asset_candidates[0])
        service_candidates = tuple(sorted(
            network_services.get((asset_address, port), ()),
            key=lambda item: item.node_id,
        ))
        if len(service_candidates) != 1:
            add_unresolved(
                source_kind=GraphNodeKind.SERVICE,
                source_key=surface.natural_key,
                basis="exact-origin-host-port",
                proof=proof,
                reason=(
                    "no-exact-origin-service-match"
                    if not service_candidates
                    else "ambiguous-origin-service"
                ),
                candidate_count=len(service_candidates),
            )
            continue

        add_pair(
            service_candidates[0],
            surface,
            basis="exact-origin-host-port",
            proof=proof,
        )


    for cloud_resource in sorted(cloud_resources, key=lambda item: item.node_id):
        proofs = _cloud_network_proofs(cloud_resource)
        if not proofs:
            continue

        resolved: dict[str, tuple[GraphNode, list[str]]] = {}
        no_matches: list[str] = []
        ambiguous = False
        for property_name, value in proofs:
            proof = f"{property_name}\x1f{value}"
            candidates = tuple(sorted(
                (
                    assets_by_address.get(value, ())
                    if property_name in _CLOUD_NETWORK_IP_PROPERTIES
                    else assets_by_hostname.get(value, ())
                ),
                key=lambda item: item.node_id,
            ))
            if not candidates:
                no_matches.append(proof)
                continue
            if len(candidates) != 1:
                add_unresolved(
                    source_kind=GraphNodeKind.ASSET,
                    source_key=cloud_resource.natural_key,
                    basis="exact-cloud-network-key",
                    proof=proof,
                    reason="ambiguous-cloud-network-match",
                    candidate_count=len(candidates),
                )
                ambiguous = True
                continue
            target = candidates[0]
            entry = resolved.setdefault(target.node_id, (target, []))
            entry[1].append(proof)

        if ambiguous:
            continue

        if len(resolved) > 1:
            add_unresolved(
                source_kind=GraphNodeKind.ASSET,
                source_key=cloud_resource.natural_key,
                basis="exact-cloud-network-key",
                proof="\x1e".join(sorted(
                    proof
                    for _target, target_proofs in resolved.values()
                    for proof in target_proofs
                )),
                reason="conflicting-cloud-network-evidence",
                candidate_count=len(resolved),
            )
            continue

        if len(resolved) == 1:
            target, target_proofs = next(iter(resolved.values()))
            for proof in sorted(target_proofs):
                add_pair(
                    target,
                    cloud_resource,
                    basis="exact-cloud-network-key",
                    proof=proof,
                )

        for proof in sorted(no_matches):
            add_unresolved(
                source_kind=GraphNodeKind.ASSET,
                source_key=cloud_resource.natural_key,
                basis="exact-cloud-network-key",
                proof=proof,
                reason="no-exact-cloud-network-match",
                candidate_count=0,
            )

    for cloud_identity in sorted(cloud_identities, key=lambda item: item.node_id):
        tenant_id, object_id, has_any_key = _cloud_identity_entra_parts(
            cloud_identity
        )
        if not has_any_key:
            continue
        proof = f"{tenant_id}\x1f{object_id}"
        if not tenant_id or not object_id:
            add_unresolved(
                source_kind=GraphNodeKind.IDENTITY,
                source_key=cloud_identity.natural_key,
                basis="exact-cloud-entra-object",
                proof=proof,
                reason="incomplete-cloud-identity-key",
                candidate_count=0,
            )
            continue

        candidates = tuple(sorted(
            entra_identities_by_key.get((tenant_id, object_id), ()),
            key=lambda item: item.node_id,
        ))
        if len(candidates) != 1:
            add_unresolved(
                source_kind=GraphNodeKind.IDENTITY,
                source_key=cloud_identity.natural_key,
                basis="exact-cloud-entra-object",
                proof=proof,
                reason=(
                    "no-exact-cloud-identity-match"
                    if not candidates
                    else "ambiguous-cloud-identity-match"
                ),
                candidate_count=len(candidates),
            )
            continue

        add_pair(
            candidates[0],
            cloud_identity,
            basis="exact-cloud-entra-object",
            proof=proof,
        )

    if len(pair_proofs) > active.max_edges:
        raise ValueError("cross-surface correlation edge limit exceeded")

    correlated: list[str] = []
    for (source_id, target_id, basis), proof_hashes in sorted(pair_proofs.items()):
        provenance = (
            GraphProvenance(
                source_type="cross-surface-correlation",
                source_id=sha256(
                    (
                        source_id
                        + "\x1f"
                        + target_id
                        + "\x1f"
                        + basis
                        + "\x1f"
                        + "\x1f".join(sorted(proof_hashes))
                    ).encode("utf-8")
                ).hexdigest(),
            ),
        )
        edge = GraphEdge.create(
            source_node_id=source_id,
            target_node_id=target_id,
            relationship="correlates-to",
            evidence_state=GraphEvidenceState.INFERRED,
            provenance=provenance,
            properties=(
                ("claim", "exact-evidence-correlation-only"),
                ("correlation_basis", basis),
                ("matched_key_count", str(len(proof_hashes))),
            ),
        )
        builder.add_edge(edge)
        correlated.append(edge.edge_id)

    return CrossSurfaceCorrelationResult(
        graph=builder.build(),
        correlated_edge_ids=tuple(sorted(correlated)),
        unresolved=tuple(sorted(
            unresolved,
            key=lambda item: (
                item.source_kind.value,
                item.source_key,
                item.key_sha256,
                item.reason,
                item.candidate_count,
            ),
        )),
    )
