"""Structured scan reports for NightRecon."""

from __future__ import annotations

from dataclasses import asdict, dataclass

from nightrecon.os_fingerprint import (
    HostOperatingSystemFingerprint,
)
from nightrecon.assessment_engine import (
    ServiceAssessmentResult,
    summarize_assessments,
)
from nightrecon.service_detection import ServiceDetectionResult
from nightrecon.session import ScanSession
from nightrecon.tcp_scanner import TcpPortResult
from nightrecon.threat_context import (
    ThreatContextResult,
    summarize_threat_context,
)
from nightrecon.vulnerability_intelligence import (
    ServiceVulnerabilityResult,
    summarize_vulnerabilities,
)


@dataclass(frozen=True)
class TcpScanReport:
    """Complete result of a NightRecon TCP scan."""

    session_id: str
    created_at: str
    target: str
    target_type: str
    scope: tuple[str, ...]
    status: str
    resolved_addresses: tuple[str, ...]
    ports_requested: tuple[int, ...]
    results: tuple[TcpPortResult, ...]
    services: tuple[ServiceDetectionResult, ...] = ()
    operating_system_fingerprints: tuple[
        HostOperatingSystemFingerprint,
        ...,
    ] = ()
    assessment_enabled: bool = False
    assessment_catalog_errors: tuple[str, ...] = ()
    assessments: tuple[ServiceAssessmentResult, ...] = ()
    vulnerability_intelligence_enabled: bool = False
    vulnerabilities: tuple[ServiceVulnerabilityResult, ...] = ()
    threat_context_enabled: bool = False
    threat_context: tuple[ThreatContextResult, ...] = ()

    @classmethod
    def create(
        cls,
        session: ScanSession,
        resolved_addresses: tuple[str, ...],
        ports_requested: tuple[int, ...],
        results: tuple[TcpPortResult, ...],
        services: tuple[ServiceDetectionResult, ...] = (),
        operating_system_fingerprints: tuple[
            HostOperatingSystemFingerprint,
            ...,
        ] = (),
        assessment_enabled: bool = False,
        assessment_catalog_errors: tuple[str, ...] = (),
        assessments: tuple[ServiceAssessmentResult, ...] = (),
        vulnerability_intelligence_enabled: bool = False,
        vulnerabilities: tuple[ServiceVulnerabilityResult, ...] = (),
        threat_context_enabled: bool = False,
        threat_context: tuple[ThreatContextResult, ...] = (),
    ) -> "TcpScanReport":
        return cls(
            session_id=session.session_id,
            created_at=session.created_at,
            target=session.target,
            target_type=session.target_type,
            scope=session.scope,
            status="completed",
            resolved_addresses=resolved_addresses,
            ports_requested=ports_requested,
            results=results,
            services=services,
            operating_system_fingerprints=(
                operating_system_fingerprints
            ),
            assessment_enabled=assessment_enabled,
            assessment_catalog_errors=assessment_catalog_errors,
            assessments=assessments,
            vulnerability_intelligence_enabled=(
                vulnerability_intelligence_enabled
            ),
            vulnerabilities=vulnerabilities,
            threat_context_enabled=threat_context_enabled,
            threat_context=threat_context,
        )

    @property
    def open_ports(self) -> tuple[TcpPortResult, ...]:
        return tuple(
            result
            for result in self.results
            if result.is_open
        )

    def to_dict(self) -> dict:
        data = asdict(self)

        data["results"] = [
            asdict(result)
            for result in self.results
        ]

        data["services"] = [
            asdict(service)
            for service in self.services
        ]

        data["assessment_summary"] = (
            asdict(
                summarize_assessments(
                    self.assessments
                )
            )
            if self.assessment_enabled
            else None
        )

        data["vulnerability_summary"] = (
            asdict(
                summarize_vulnerabilities(
                    self.vulnerabilities
                )
            )
            if self.vulnerability_intelligence_enabled
            else None
        )

        data["threat_context_summary"] = (
            asdict(
                summarize_threat_context(
                    self.threat_context
                )
            )
            if self.threat_context_enabled
            else None
        )

        return data