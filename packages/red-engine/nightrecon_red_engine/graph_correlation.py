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
            GraphNodeKind.IDENTITY,
            GraphNodeKind.SERVICE,
        }:
            raise ValueError("unsupported unresolved correlation source kind")
        if not self.source_key.strip():
            raise ValueError("source_key must not be empty")
        if self.correlation_basis not in {
            "exact-hostname",
            "exact-origin-host-port",
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
    """Correlate exact identity/network and web-origin/network evidence."""

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
    identities: list[GraphNode] = []
    web_surfaces: list[GraphNode] = []

    for node in graph.nodes:
        if node.kind is GraphNodeKind.ASSET:
            for hostname in _asset_hostnames(node):
                assets_by_hostname.setdefault(hostname, []).append(node)
            address = _asset_address(node)
            if address:
                assets_by_address.setdefault(address, []).append(node)
        elif node.kind is GraphNodeKind.IDENTITY:
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
