"""Project normalized web/API origins into Red Night graph evidence."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from urllib.parse import urlsplit

from nightrecon_red_engine.api_report import ApiInventoryReport
from nightrecon_red_engine.graph_builder import GraphBuildLimits, IdentityGraphBuilder
from nightrecon_red_engine.graph_models import (
    GraphNode,
    GraphNodeKind,
    GraphProvenance,
    IdentityGraph,
)
from nightrecon_red_engine.graphql_report import GraphQLSchemaReport
from nightrecon_red_engine.web_crawl import url_origin
from nightrecon_red_engine.web_report import WebCrawlReport
from nightrecon_shared_core.contracts import EvidenceRecord


_VALID_SURFACE_TYPES = frozenset({"web", "api", "graphql"})


def _required_text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(f"{field} must be a nonblank, trimmed string")
    return value


def _normalized_origin(value: str) -> tuple[str, str, int]:
    normalized = url_origin(_required_text(value, "origin"))
    parsed = urlsplit(normalized)
    if not parsed.hostname:
        raise ValueError("origin must include a hostname")
    scheme = parsed.scheme
    host = parsed.hostname.casefold().rstrip(".")
    port = parsed.port
    if port is None:
        port = 443 if scheme == "https" else 80
    return normalized, host, port


@dataclass(frozen=True)
class WebSurfaceEvidence:
    """One observed HTTP(S) surface with normalized origin correlation keys."""

    origin: str
    source_id: str
    surface_type: str

    def __post_init__(self) -> None:
        normalized, _host, _port = _normalized_origin(self.origin)
        if normalized != self.origin:
            raise ValueError("origin must already be normalized")
        _required_text(self.source_id, "source_id")
        if self.surface_type not in _VALID_SURFACE_TYPES:
            raise ValueError("surface_type must be web, api, or graphql")

    @property
    def natural_key(self) -> str:
        origin_hash = sha256(self.origin.encode("utf-8")).hexdigest()
        source_hash = sha256(self.source_id.encode("utf-8")).hexdigest()[:16]
        return f"web-surface:{self.surface_type}:{origin_hash}:{source_hash}"

    @property
    def properties(self) -> tuple[tuple[str, str], ...]:
        normalized, host, port = _normalized_origin(self.origin)
        scheme = urlsplit(normalized).scheme
        return (
            ("origin_host", host),
            ("origin_port", str(port)),
            ("origin_scheme", scheme),
            ("surface_type", self.surface_type),
        )


def web_surface_from_crawl_report(report: WebCrawlReport) -> WebSurfaceEvidence:
    if not isinstance(report, WebCrawlReport):
        raise ValueError("report must be WebCrawlReport")
    return WebSurfaceEvidence(
        origin=url_origin(report.origin),
        source_id=report.session_id,
        surface_type="web",
    )


def web_surface_from_api_report(report: ApiInventoryReport) -> WebSurfaceEvidence:
    if not isinstance(report, ApiInventoryReport):
        raise ValueError("report must be ApiInventoryReport")
    return WebSurfaceEvidence(
        origin=url_origin(report.base_origin),
        source_id=report.session_id,
        surface_type="api",
    )


def web_surface_from_graphql_report(
    report: GraphQLSchemaReport,
) -> WebSurfaceEvidence:
    if not isinstance(report, GraphQLSchemaReport):
        raise ValueError("report must be GraphQLSchemaReport")
    return WebSurfaceEvidence(
        origin=url_origin(report.endpoint_url),
        source_id=report.session_id,
        surface_type="graphql",
    )


def add_web_surface_evidence_to_graph(
    graph: IdentityGraph,
    evidence: tuple[WebSurfaceEvidence, ...],
    *,
    observed_at: str = "",
    limits: GraphBuildLimits | None = None,
) -> IdentityGraph:
    """Add web/API origin nodes without performing correlation or network activity."""

    builder = IdentityGraphBuilder(limits)
    for node in graph.nodes:
        builder.add_node(node)
    for edge in graph.edges:
        builder.add_edge(edge)

    for item in sorted(
        evidence,
        key=lambda record: (record.surface_type, record.origin, record.source_id),
    ):
        node = GraphNode.create(
            kind=GraphNodeKind.SERVICE,
            natural_key=item.natural_key,
            label=item.origin,
            provenance=(
                GraphProvenance(
                    source_type="web-surface-evidence",
                    source_id=item.source_id,
                    observed_at=observed_at.strip(),
                ),
            ),
            properties=item.properties,
        )
        builder.add_node(node)

    return builder.build()


def web_surface_evidence_to_engagement_records(
    evidence: tuple[WebSurfaceEvidence, ...],
    *,
    engagement_id: str,
    observed_at: str,
) -> tuple[EvidenceRecord, ...]:
    """Convert origin observations into portable service observations."""

    _required_text(engagement_id, "engagement_id")
    _required_text(observed_at, "observed_at")
    records: list[EvidenceRecord] = []
    for item in evidence:
        material = (
            f"{engagement_id}:{item.natural_key}:{observed_at}:{item.source_id}"
        )
        records.append(EvidenceRecord(
            engagement_id=engagement_id,
            evidence_id=(
                "red-web-surface-"
                + sha256(material.encode("utf-8")).hexdigest()
            ),
            source_night="red",
            evidence_type="service.observation",
            observed_at=observed_at,
            provenance=item.source_id,
            data={
                "service_key": item.natural_key,
                "label": item.origin,
                "properties": dict(item.properties),
            },
            limitations=(
                "Observed HTTP(S) origin metadata only.",
                "Origin correlation does not independently prove host ownership, "
                "access, exploitability, or compromise.",
            ),
        ))
    return tuple(sorted(records, key=lambda record: record.evidence_id))
