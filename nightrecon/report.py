"""Structured scan reports for NightRecon."""

from __future__ import annotations

from dataclasses import asdict, dataclass

from nightrecon.service_detection import ServiceDetectionResult
from nightrecon.session import ScanSession
from nightrecon.tcp_scanner import TcpPortResult
from nightrecon.vulnerability_intelligence import (
    ServiceVulnerabilityResult,
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
    vulnerabilities: tuple[ServiceVulnerabilityResult, ...] = ()

    @classmethod
    def create(
        cls,
        session: ScanSession,
        resolved_addresses: tuple[str, ...],
        ports_requested: tuple[int, ...],
        results: tuple[TcpPortResult, ...],
        services: tuple[ServiceDetectionResult, ...] = (),
        vulnerabilities: tuple[ServiceVulnerabilityResult, ...] = (),
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
            vulnerabilities=vulnerabilities,
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

        return data