"""Bounded UDP port scanning primitives for authorized Red Night assessments.

UDP scanning is inherently ambiguous when a target does not respond.  This
module preserves that uncertainty instead of treating silence as proof that a
port is open.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
import errno
import ipaddress
import socket


MAX_UDP_PORTS_PER_SCAN = 256
MAX_UDP_WORKERS = 64
MAX_UDP_PROBE_BYTES = 512
MAX_UDP_RETRIES = 2
MAX_UDP_ATTEMPTS_PER_SCAN = 384

COMMON_UDP_SERVICES = {
    53: "dns",
    67: "dhcp-server",
    68: "dhcp-client",
    69: "tftp",
    123: "ntp",
    137: "netbios-ns",
    138: "netbios-dgm",
    161: "snmp",
    162: "snmp-trap",
    500: "isakmp",
    514: "syslog",
    520: "rip",
    1900: "ssdp",
    4500: "ipsec-nat-t",
    5353: "mdns",
}

UDP_PROBE_PROFILES = {
    53: b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x10\x00\x01",
    123: b"\x1b" + (b"\x00" * 47),
}

_CLOSED_ERROR_CODES = {
    errno.ECONNREFUSED,
    getattr(errno, "WSAECONNREFUSED", 10061),
    getattr(errno, "WSAECONNRESET", 10054),
}


@dataclass(frozen=True)
class UdpPortResult:
    """Observed result for one bounded UDP probe."""

    address: str
    port: int
    state: str
    response_size: int = 0
    error_code: int | None = None
    service_hint: str = "unknown"
    confidence: str = "low"
    evidence: str = ""
    protocol_match: bool | None = None
    attempts: int = 1

    @property
    def is_open(self) -> bool:
        """Return True only when a response positively proves the port open."""

        return self.state == "open"


@dataclass(frozen=True)
class UdpScanSummary:
    """Deterministic aggregate metadata for one completed UDP result set."""

    total_results: int
    total_attempts: int
    open_count: int
    open_filtered_count: int
    closed_count: int
    error_count: int
    protocol_confirmed_count: int
    service_hint_counts: tuple[tuple[str, int], ...]


def summarize_udp_results(
    results: tuple[UdpPortResult, ...],
) -> UdpScanSummary:
    """Summarize completed UDP results without changing scan behavior."""

    state_counts = {
        "open": 0,
        "open|filtered": 0,
        "closed": 0,
        "error": 0,
    }
    service_counts: dict[str, int] = {}
    total_attempts = 0
    protocol_confirmed_count = 0

    for result in results:
        if not isinstance(result, UdpPortResult):
            raise TypeError("results must contain only UdpPortResult values.")

        if result.state not in state_counts:
            raise ValueError(f"Unsupported UDP result state: {result.state!r}.")

        if result.attempts < 1:
            raise ValueError("UDP result attempts must be at least 1.")

        state_counts[result.state] += 1
        total_attempts += result.attempts

        if result.protocol_match is True:
            protocol_confirmed_count += 1

        service_counts[result.service_hint] = (
            service_counts.get(result.service_hint, 0) + 1
        )

    return UdpScanSummary(
        total_results=len(results),
        total_attempts=total_attempts,
        open_count=state_counts["open"],
        open_filtered_count=state_counts["open|filtered"],
        closed_count=state_counts["closed"],
        error_count=state_counts["error"],
        protocol_confirmed_count=protocol_confirmed_count,
        service_hint_counts=tuple(sorted(service_counts.items())),
    )


def identify_udp_service(port: int) -> str:
    """Return a deterministic well-known UDP service hint."""

    _validate_port(port)
    return COMMON_UDP_SERVICES.get(port, "unknown")


def _metadata_for_state(
    *,
    port: int,
    state: str,
    response_size: int = 0,
    error_code: int | None = None,
) -> tuple[str, str, str]:
    service_hint = identify_udp_service(port)

    if state == "open":
        return (
            service_hint,
            "high",
            f"received {response_size} UDP response bytes",
        )

    if state == "closed":
        return (
            service_hint,
            "high",
            f"socket refusal/error code {error_code}",
        )

    if state == "open|filtered":
        return (
            service_hint,
            "low",
            "no UDP response before timeout; open versus filtered is unresolved",
        )

    return (
        service_hint,
        "low",
        f"UDP probe failed with socket error code {error_code}",
    )


def udp_probe_payload_for_port(port: int) -> bytes:
    """Return a conservative protocol-aware UDP probe when one is defined."""

    _validate_port(port)
    return UDP_PROBE_PROFILES.get(port, b"")


def validate_udp_response(
    port: int,
    response: bytes,
) -> tuple[bool | None, str]:
    """Validate a bounded response against conservative known-service structure."""

    _validate_port(port)

    if not isinstance(response, bytes):
        raise TypeError("UDP response must be bytes.")

    if port == 53:
        if len(response) < 12:
            return False, "DNS response shorter than 12-byte header"

        is_response = bool(response[2] & 0x80)
        return (
            is_response,
            (
                "DNS QR response bit set"
                if is_response
                else "DNS QR response bit not set"
            ),
        )

    if port == 123:
        if len(response) < 48:
            return False, "NTP response shorter than 48 bytes"

        mode = response[0] & 0x07
        matched = mode in {4, 5}
        return (
            matched,
            (
                f"NTP response mode {mode} is server/broadcast"
                if matched
                else f"NTP response mode {mode} is not server/broadcast"
            ),
        )

    return None, "no protocol response validator defined"


def scan_udp_port(
    address: str,
    port: int,
    timeout: float,
    *,
    payload: bytes | None = None,
    retries: int = 0,
) -> UdpPortResult:
    """Send one bounded UDP datagram and preserve open/filtered ambiguity."""

    ip = ipaddress.ip_address(address)
    _validate_port(port)

    if timeout <= 0:
        raise ValueError("Timeout must be greater than 0.")

    if retries < 0 or retries > MAX_UDP_RETRIES:
        raise ValueError(
            f"retries must be between 0 and {MAX_UDP_RETRIES}."
        )

    if payload is None:
        payload = udp_probe_payload_for_port(port)

    if not isinstance(payload, bytes):
        raise TypeError("UDP payload must be bytes or None.")

    if len(payload) > MAX_UDP_PROBE_BYTES:
        raise ValueError(
            f"UDP payload exceeds {MAX_UDP_PROBE_BYTES} bytes."
        )

    family = (
        socket.AF_INET6
        if isinstance(ip, ipaddress.IPv6Address)
        else socket.AF_INET
    )
    sock = socket.socket(
        family,
        socket.SOCK_DGRAM,
    )

    try:
        sock.settimeout(timeout)

        destination = (
            (address, port, 0, 0)
            if family == socket.AF_INET6
            else (address, port)
        )
        sock.connect(destination)

        response: bytes | None = None
        attempts = 0

        for attempt in range(retries + 1):
            attempts = attempt + 1

            try:
                sock.send(payload)
                response = sock.recv(MAX_UDP_PROBE_BYTES)
                break
            except socket.timeout:
                if attempt < retries:
                    continue

                service_hint, confidence, evidence = _metadata_for_state(
                    port=port,
                    state="open|filtered",
                )
                return UdpPortResult(
                    address=address,
                    port=port,
                    state="open|filtered",
                    service_hint=service_hint,
                    confidence=confidence,
                    evidence=f"{evidence}; {attempts} attempts",
                    attempts=attempts,
                )
            except OSError as exc:
                error_code = (
                    exc.errno
                    if isinstance(exc.errno, int)
                    else None
                )
                state = (
                    "closed"
                    if error_code in _CLOSED_ERROR_CODES
                    else "error"
                )
                service_hint, confidence, evidence = _metadata_for_state(
                    port=port,
                    state=state,
                    error_code=error_code,
                )
                return UdpPortResult(
                    address=address,
                    port=port,
                    state=state,
                    error_code=error_code,
                    service_hint=service_hint,
                    confidence=confidence,
                    evidence=f"{evidence}; {attempts} attempts",
                    attempts=attempts,
                )

        assert response is not None

        service_hint, _, base_evidence = _metadata_for_state(
            port=port,
            state="open",
            response_size=len(response),
            error_code=0,
        )
        protocol_match, protocol_evidence = validate_udp_response(
            port,
            response,
        )
        confidence = (
            "high"
            if protocol_match is True
            else "medium"
        )
        evidence = (
            f"{base_evidence}; {protocol_evidence}"
        )
        return UdpPortResult(
            address=address,
            port=port,
            state="open",
            response_size=len(response),
            error_code=0,
            service_hint=service_hint,
            confidence=confidence,
            evidence=evidence,
            protocol_match=protocol_match,
            attempts=attempts,
        )
    finally:
        sock.close()


def scan_udp_ports(
    address: str,
    ports: tuple[int, ...],
    timeout: float,
    *,
    max_workers: int = 32,
    payload: bytes | None = None,
    retries: int = 0,
) -> tuple[UdpPortResult, ...]:
    """Probe an explicit bounded UDP port set concurrently."""

    if not ports:
        raise ValueError("At least one UDP port is required.")

    if len(ports) > MAX_UDP_PORTS_PER_SCAN:
        raise ValueError(
            "UDP port count exceeds "
            f"MAX_UDP_PORTS_PER_SCAN={MAX_UDP_PORTS_PER_SCAN}."
        )

    if max_workers < 1 or max_workers > MAX_UDP_WORKERS:
        raise ValueError(
            f"max_workers must be between 1 and {MAX_UDP_WORKERS}."
        )

    if timeout <= 0:
        raise ValueError("Timeout must be greater than 0.")

    if retries < 0 or retries > MAX_UDP_RETRIES:
        raise ValueError(
            f"retries must be between 0 and {MAX_UDP_RETRIES}."
        )

    if len(set(ports)) != len(ports):
        raise ValueError("UDP port list must not contain duplicates.")

    planned_attempts = len(ports) * (retries + 1)
    if planned_attempts > MAX_UDP_ATTEMPTS_PER_SCAN:
        raise ValueError(
            "UDP attempt budget exceeds "
            f"MAX_UDP_ATTEMPTS_PER_SCAN={MAX_UDP_ATTEMPTS_PER_SCAN}."
        )

    if payload is not None and not isinstance(payload, bytes):
        raise TypeError("UDP payload must be bytes or None.")

    if payload is not None and len(payload) > MAX_UDP_PROBE_BYTES:
        raise ValueError(
            f"UDP payload exceeds {MAX_UDP_PROBE_BYTES} bytes."
        )

    for port in ports:
        _validate_port(port)

    results: list[UdpPortResult] = []

    with ThreadPoolExecutor(
        max_workers=min(max_workers, len(ports)),
    ) as executor:
        futures = {
            executor.submit(
                scan_udp_port,
                address,
                port,
                timeout,
                payload=payload,
                retries=retries,
            ): port
            for port in ports
        }

        for future in as_completed(futures):
            port = futures[future]

            try:
                results.append(future.result())
            except OSError as exc:
                error_code = (
                    exc.errno
                    if isinstance(exc.errno, int)
                    else None
                )
                service_hint, confidence, evidence = _metadata_for_state(
                    port=port,
                    state="error",
                    error_code=error_code,
                )
                results.append(
                    UdpPortResult(
                        address=address,
                        port=port,
                        state="error",
                        error_code=error_code,
                        service_hint=service_hint,
                        confidence=confidence,
                        evidence=evidence,
                    )
                )

    return tuple(
        sorted(
            results,
            key=lambda result: result.port,
        )
    )


def _validate_port(port: int) -> None:
    if (
        isinstance(port, bool)
        or not isinstance(port, int)
        or not 1 <= port <= 65535
    ):
        raise ValueError("Port must be between 1 and 65535.")
