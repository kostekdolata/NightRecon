"""High-level evidence completeness for Red Night network assessments."""

from __future__ import annotations

from dataclasses import dataclass

from nightrecon_red_engine.service_detection import ServiceDetectionResult
from nightrecon_red_engine.tcp_scanner import TcpPortResult
from nightrecon_red_engine.vulnerability_intelligence import (
    ServiceVulnerabilityResult,
)
from nightrecon_red_engine.threat_context import ThreatContextResult


@dataclass(frozen=True)
class NetworkEvidenceCompleteness:
    """Describe which assessment evidence layers are actually present."""

    level: str
    summary: str
    completed_layers: tuple[str, ...]
    missing_layers: tuple[str, ...]
    evidence_notes: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "level": self.level,
            "summary": self.summary,
            "completed_layers": list(self.completed_layers),
            "missing_layers": list(self.missing_layers),
            "evidence_notes": list(self.evidence_notes),
        }


def build_network_evidence_completeness(
    *,
    tcp_results: tuple[TcpPortResult, ...] = (),
    services: tuple[ServiceDetectionResult, ...] = (),
    vulnerability_intelligence_enabled: bool = False,
    vulnerabilities: tuple[ServiceVulnerabilityResult, ...] = (),
    threat_context_enabled: bool = False,
    threat_context: tuple[ThreatContextResult, ...] = (),
) -> NetworkEvidenceCompleteness:
    """Summarize coverage without treating missing evidence as a clean result."""

    completed: list[str] = []
    missing: list[str] = []
    notes: list[str] = []

    if tcp_results:
        completed.append("network-exposure")
        notes.append(
            f"Network exposure evidence includes {len(tcp_results)} TCP result(s)."
        )
    else:
        missing.append("network-exposure")

    open_tcp = tuple(item for item in tcp_results if item.is_open)
    identified_ports = {
        item.port for item in services if item.error_code == 0
    }
    unidentified_open = {
        item.port for item in open_tcp
    } - identified_ports

    if open_tcp and not unidentified_open:
        completed.append("service-identification")
    elif open_tcp:
        missing.append("service-identification")
        notes.append(
            f"{len(unidentified_open)} responsive TCP port(s) lack successful "
            "service identification."
        )
    elif tcp_results:
        completed.append("service-identification")
        notes.append(
            "No responsive TCP port required service identification in the "
            "supplied evidence."
        )
    else:
        missing.append("service-identification")

    if vulnerability_intelligence_enabled:
        completed.append("vulnerability-intelligence")
        if not vulnerabilities:
            notes.append(
                "Vulnerability intelligence was enabled but produced no "
                "service lookup results."
            )
    else:
        missing.append("vulnerability-intelligence")

    if threat_context_enabled:
        completed.append("threat-context")
        if not threat_context:
            notes.append(
                "Threat-context enrichment was enabled but produced no "
                "enriched records."
            )
    else:
        missing.append("threat-context")

    total_layers = 4
    completed_count = len(completed)
    if completed_count == total_layers:
        level = "comprehensive"
        summary = (
            "All core network evidence layers are represented in the supplied "
            "assessment data."
        )
    elif completed_count >= 2:
        level = "partial"
        summary = (
            "The assessment has useful network evidence but one or more "
            "higher-level evidence layers are incomplete or unavailable."
        )
    else:
        level = "limited"
        summary = (
            "The supplied assessment evidence is limited and should not be "
            "treated as a complete network security view."
        )

    return NetworkEvidenceCompleteness(
        level=level,
        summary=summary,
        completed_layers=tuple(completed),
        missing_layers=tuple(missing),
        evidence_notes=tuple(notes),
    )
