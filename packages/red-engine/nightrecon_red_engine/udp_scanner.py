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

    @property
    def is_open(self) -> bool:
        """Return True only when a response positively proves the port open."""

        return self.state == "open"


def scan_udp_port(
    address: str,
    port: int,
    timeout: float,
    *,
    payload: bytes = b"",
) -> UdpPortResult:
    """Send one bounded UDP datagram and preserve open/filtered ambiguity."""

    ip = ipaddress.ip_address(address)
    _validate_port(port)

    if timeout <= 0:
        raise ValueError("Timeout must be greater than 0.")

    if not isinstance(payload, bytes):
        raise TypeError("UDP payload must be bytes.")

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

        try:
            sock.send(payload)
            response = sock.recv(MAX_UDP_PROBE_BYTES)
        except socket.timeout:
            return UdpPortResult(
                address=address,
                port=port,
                state="open|filtered",
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
            return UdpPortResult(
                address=address,
                port=port,
                state=state,
                error_code=error_code,
            )

        return UdpPortResult(
            address=address,
            port=port,
            state="open",
            response_size=len(response),
            error_code=0,
        )
    finally:
        sock.close()


def scan_udp_ports(
    address: str,
    ports: tuple[int, ...],
    timeout: float,
    *,
    max_workers: int = 32,
    payload: bytes = b"",
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

    if not isinstance(payload, bytes):
        raise TypeError("UDP payload must be bytes.")

    if len(payload) > MAX_UDP_PROBE_BYTES:
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
            ): port
            for port in ports
        }

        for future in as_completed(futures):
            port = futures[future]

            try:
                results.append(future.result())
            except OSError as exc:
                results.append(
                    UdpPortResult(
                        address=address,
                        port=port,
                        state="error",
                        error_code=(
                            exc.errno
                            if isinstance(exc.errno, int)
                            else None
                        ),
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
