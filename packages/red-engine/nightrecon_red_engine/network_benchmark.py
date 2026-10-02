"""Deterministic fixture-based network assessment benchmark evidence.

The benchmark compares Red Night observations with an explicit authorized lab
expectation. It measures coverage, misses, unexpected observations, ambiguity,
scope behavior, and externally measured runtime. It does not establish parity
with Nmap or any other specialist product.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import ipaddress
import json

from nightrecon_red_engine.os_fingerprint import HostOperatingSystemFingerprint
from nightrecon_red_engine.service_detection import ServiceDetectionResult
from nightrecon_red_engine.tcp_scanner import TcpPortResult
from nightrecon_red_engine.udp_scanner import UdpPortResult


NETWORK_BENCHMARK_INTERPRETATION = (
    "Authorized fixture/lab comparison only. Metrics describe exact expected "
    "versus observed Red Night evidence and do not establish feature parity, "
    "exploitability, compromise, likelihood, impact, or risk."
)


@dataclass(frozen=True, order=True)
class ExpectedTcpExposure:
    address: str
    port: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "address", str(ipaddress.ip_address(self.address)))
        if isinstance(self.port, bool) or not 1 <= self.port <= 65535:
            raise ValueError("TCP benchmark port must be between 1 and 65535")


@dataclass(frozen=True, order=True)
class ExpectedUdpExposure:
    address: str
    port: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "address", str(ipaddress.ip_address(self.address)))
        if isinstance(self.port, bool) or not 1 <= self.port <= 65535:
            raise ValueError("UDP benchmark port must be between 1 and 65535")


@dataclass(frozen=True, order=True)
class ExpectedService:
    address: str
    port: int
    service: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "address", str(ipaddress.ip_address(self.address)))
        if isinstance(self.port, bool) or not 1 <= self.port <= 65535:
            raise ValueError("service benchmark port must be between 1 and 65535")
        if not isinstance(self.service, str) or not self.service.strip():
            raise ValueError("service benchmark name must be nonblank")
        object.__setattr__(self, "service", self.service.strip().lower())


@dataclass(frozen=True, order=True)
class ExpectedOperatingSystem:
    address: str
    platform: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "address", str(ipaddress.ip_address(self.address)))
        if not isinstance(self.platform, str) or not self.platform.strip():
            raise ValueError("OS benchmark platform must be nonblank")
        object.__setattr__(self, "platform", self.platform.strip())


@dataclass(frozen=True)
class NetworkBenchmarkExpectation:
    authorized_addresses: tuple[str, ...]
    tcp_open: tuple[ExpectedTcpExposure, ...] = ()
    udp_open: tuple[ExpectedUdpExposure, ...] = ()
    services: tuple[ExpectedService, ...] = ()
    operating_systems: tuple[ExpectedOperatingSystem, ...] = ()

    def __post_init__(self) -> None:
        if not self.authorized_addresses:
            raise ValueError("authorized_addresses must not be empty")
        normalized = tuple(str(ipaddress.ip_address(item)) for item in self.authorized_addresses)
        if len(normalized) != len(set(normalized)):
            raise ValueError("authorized_addresses must not contain duplicates")
        object.__setattr__(self, "authorized_addresses", tuple(sorted(
            normalized, key=ipaddress.ip_address
        )))
        for field_name in ("tcp_open", "udp_open", "services", "operating_systems"):
            values = getattr(self, field_name)
            if len(values) != len(set(values)):
                raise ValueError(f"{field_name} expectations must be unique")
            for item in values:
                if item.address not in self.authorized_addresses:
                    raise ValueError(
                        f"{field_name} expectation is outside authorized_addresses"
                    )


@dataclass(frozen=True)
class NetworkBenchmarkResult:
    expected_tcp_open: int
    matched_tcp_open: int
    missed_tcp_open: int
    invented_tcp_open: int
    expected_udp_open: int
    matched_udp_open: int
    missed_udp_open: int
    invented_udp_open: int
    ambiguous_udp_expected_open: int
    expected_services: int
    matched_services: int
    missed_services: int
    invented_services: int
    expected_operating_systems: int
    matched_operating_systems: int
    missed_operating_systems: int
    conflicting_operating_systems: int
    scope_violation_count: int
    scope_violations: tuple[str, ...]
    duration_ms: float
    comparison_sha256: str
    interpretation: str = NETWORK_BENCHMARK_INTERPRETATION

    @property
    def expected_coverage_complete(self) -> bool:
        return (
            self.missed_tcp_open == 0
            and self.missed_udp_open == 0
            and self.missed_services == 0
            and self.missed_operating_systems == 0
        )

    @property
    def unexpected_evidence_present(self) -> bool:
        return (
            self.invented_tcp_open > 0
            or self.invented_udp_open > 0
            or self.invented_services > 0
            or self.conflicting_operating_systems > 0
            or self.scope_violation_count > 0
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "expected_tcp_open": self.expected_tcp_open,
            "matched_tcp_open": self.matched_tcp_open,
            "missed_tcp_open": self.missed_tcp_open,
            "invented_tcp_open": self.invented_tcp_open,
            "expected_udp_open": self.expected_udp_open,
            "matched_udp_open": self.matched_udp_open,
            "missed_udp_open": self.missed_udp_open,
            "invented_udp_open": self.invented_udp_open,
            "ambiguous_udp_expected_open": self.ambiguous_udp_expected_open,
            "expected_services": self.expected_services,
            "matched_services": self.matched_services,
            "missed_services": self.missed_services,
            "invented_services": self.invented_services,
            "expected_operating_systems": self.expected_operating_systems,
            "matched_operating_systems": self.matched_operating_systems,
            "missed_operating_systems": self.missed_operating_systems,
            "conflicting_operating_systems": self.conflicting_operating_systems,
            "scope_violation_count": self.scope_violation_count,
            "scope_violations": list(self.scope_violations),
            "duration_ms": self.duration_ms,
            "comparison_sha256": self.comparison_sha256,
            "expected_coverage_complete": self.expected_coverage_complete,
            "unexpected_evidence_present": self.unexpected_evidence_present,
            "interpretation": self.interpretation,
        }


def _canonical_address(address: str) -> str:
    return str(ipaddress.ip_address(address))


def _sorted_pairs(values):
    return sorted(values, key=lambda item: tuple(str(part) for part in item))


def benchmark_network_observations(
    expectation: NetworkBenchmarkExpectation,
    *,
    tcp_results: tuple[TcpPortResult, ...] = (),
    udp_results: tuple[UdpPortResult, ...] = (),
    services: tuple[ServiceDetectionResult, ...] = (),
    operating_system_fingerprints: tuple[HostOperatingSystemFingerprint, ...] = (),
    duration_ms: float = 0.0,
) -> NetworkBenchmarkResult:
    """Compare observations with an explicit expected lab state."""

    if isinstance(duration_ms, bool) or not isinstance(duration_ms, (int, float)):
        raise ValueError("duration_ms must be numeric")
    if duration_ms < 0:
        raise ValueError("duration_ms must not be negative")

    authorized = set(expectation.authorized_addresses)
    scope_violations: set[str] = set()

    def checked(address: str, kind: str) -> str:
        canonical = _canonical_address(address)
        if canonical not in authorized:
            scope_violations.add(f"{kind}:{canonical}")
        return canonical

    expected_tcp = {(item.address, item.port) for item in expectation.tcp_open}
    checked_tcp = tuple(
        (checked(item.address, "tcp"), item)
        for item in tcp_results
    )
    actual_tcp = {
        (address, item.port)
        for address, item in checked_tcp
        if item.is_open
    }

    expected_udp = {(item.address, item.port) for item in expectation.udp_open}
    actual_udp = set()
    ambiguous_udp = set()
    for item in udp_results:
        key = (checked(item.address, "udp"), item.port)
        if item.state == "open":
            actual_udp.add(key)
        elif item.state == "open|filtered":
            ambiguous_udp.add(key)

    expected_services = {
        (item.address, item.port, item.service.strip().lower())
        for item in expectation.services
    }
    actual_services = {
        (checked(item.address, "service"), item.port, item.service.strip().lower())
        for item in services
        if item.error_code == 0 and item.service.strip()
    }

    expected_os = {
        item.address: item.platform.strip().lower()
        for item in expectation.operating_systems
    }
    actual_os: dict[str, str] = {}
    conflicting_os = 0
    for item in operating_system_fingerprints:
        address = checked(item.address, "os")
        fingerprint = item.fingerprint
        if fingerprint.confidence == "conflicting":
            conflicting_os += 1
            continue
        if fingerprint.platform.strip():
            actual_os[address] = fingerprint.platform.strip().lower()

    matched_os = sum(
        actual_os.get(address) == platform
        for address, platform in expected_os.items()
    )
    missed_os = sum(
        actual_os.get(address) != platform
        for address, platform in expected_os.items()
    )

    fingerprint_payload = {
        "expectation": {
            "authorized_addresses": list(expectation.authorized_addresses),
            "tcp_open": _sorted_pairs(expected_tcp),
            "udp_open": _sorted_pairs(expected_udp),
            "services": _sorted_pairs(expected_services),
            "operating_systems": sorted(expected_os.items()),
        },
        "observed": {
            "tcp_open": _sorted_pairs(actual_tcp),
            "udp_open": _sorted_pairs(actual_udp),
            "udp_open_filtered": _sorted_pairs(ambiguous_udp),
            "services": _sorted_pairs(actual_services),
            "operating_systems": sorted(actual_os.items()),
            "conflicting_operating_systems": conflicting_os,
            "scope_violations": sorted(scope_violations),
        },
    }
    comparison_sha256 = sha256(
        json.dumps(
            fingerprint_payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()

    return NetworkBenchmarkResult(
        expected_tcp_open=len(expected_tcp),
        matched_tcp_open=len(expected_tcp & actual_tcp),
        missed_tcp_open=len(expected_tcp - actual_tcp),
        invented_tcp_open=len(actual_tcp - expected_tcp),
        expected_udp_open=len(expected_udp),
        matched_udp_open=len(expected_udp & actual_udp),
        missed_udp_open=len(expected_udp - actual_udp),
        invented_udp_open=len(actual_udp - expected_udp),
        ambiguous_udp_expected_open=len(expected_udp & ambiguous_udp),
        expected_services=len(expected_services),
        matched_services=len(expected_services & actual_services),
        missed_services=len(expected_services - actual_services),
        invented_services=len(actual_services - expected_services),
        expected_operating_systems=len(expected_os),
        matched_operating_systems=matched_os,
        missed_operating_systems=missed_os,
        conflicting_operating_systems=conflicting_os,
        scope_violation_count=len(scope_violations),
        scope_violations=tuple(sorted(scope_violations)),
        duration_ms=float(duration_ms),
        comparison_sha256=comparison_sha256,
    )
