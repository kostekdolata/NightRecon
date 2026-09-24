"""Structured host-discovery reports for NightRecon."""

from __future__ import annotations

from dataclasses import asdict, dataclass

from nightrecon.host_discovery import HostDiscoveryResult
from nightrecon.session import ScanSession


@dataclass(frozen=True)
class HostDiscoveryReport:
    """Complete result of one NightRecon host-discovery run."""

    session_id: str
    created_at: str
    target: str
    target_type: str
    scope: tuple[str, ...]
    status: str
    ports_requested: tuple[int, ...]
    max_hosts: int
    results: tuple[HostDiscoveryResult, ...]

    @classmethod
    def create(
        cls,
        *,
        session: ScanSession,
        ports_requested: tuple[int, ...],
        max_hosts: int,
        results: tuple[HostDiscoveryResult, ...],
    ) -> "HostDiscoveryReport":
        return cls(
            session_id=session.session_id,
            created_at=session.created_at,
            target=session.target,
            target_type=session.target_type,
            scope=session.scope,
            status="completed",
            ports_requested=ports_requested,
            max_hosts=max_hosts,
            results=results,
        )

    @property
    def responsive_hosts(
        self,
    ) -> tuple[HostDiscoveryResult, ...]:
        return tuple(
            result
            for result in self.results
            if result.responsive
        )

    def to_dict(self) -> dict:
        data = asdict(self)
        responsive_count = len(
            self.responsive_hosts
        )
        tested_count = len(
            self.results
        )

        data["results"] = [
            asdict(result)
            for result in self.results
        ]
        data["summary"] = {
            "hosts_tested": tested_count,
            "responsive_hosts": responsive_count,
            "unresponsive_hosts": (
                tested_count - responsive_count
            ),
        }

        return data
