"""TCP connect scanning engine for NightRecon."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
import errno
import ipaddress
import socket


_CLOSED_ERROR_CODES = {
    errno.ECONNREFUSED,
    getattr(errno, "WSAECONNREFUSED", 10061),
}

_FILTERED_ERROR_CODES = {
    errno.ETIMEDOUT,
    getattr(errno, "WSAETIMEDOUT", 10060),
}


@dataclass(frozen=True)
class TcpPortResult:
    """Observed result for one TCP connection attempt."""

    address: str
    port: int
    is_open: bool
    error_code: int
    state: str = ""
    confidence: str = ""
    evidence: str = ""
    attempts: int = 1


def scan_tcp_port(
    address: str,
    port: int,
    timeout: float,
) -> TcpPortResult:
    """Perform a TCP connect check against one IP address and port."""

    ip = ipaddress.ip_address(address)

    if port < 1 or port > 65535:
        raise ValueError("Port must be between 1 and 65535.")

    if timeout <= 0:
        raise ValueError("Timeout must be greater than 0.")

    family = (
        socket.AF_INET6
        if isinstance(ip, ipaddress.IPv6Address)
        else socket.AF_INET
    )

    sock = socket.socket(
        family,
        socket.SOCK_STREAM,
    )

    try:
        sock.settimeout(timeout)

        if family == socket.AF_INET6:
            result = sock.connect_ex(
                (address, port, 0, 0)
            )
        else:
            result = sock.connect_ex(
                (address, port)
            )

        if result == 0:
            state = "open"
            confidence = "high"
            evidence = "TCP connection completed successfully"
        elif result in _CLOSED_ERROR_CODES:
            state = "closed"
            confidence = "high"
            evidence = f"TCP connection refused with socket error code {result}"
        elif result in _FILTERED_ERROR_CODES:
            state = "filtered"
            confidence = "medium"
            evidence = f"TCP connection timed out with socket error code {result}"
        else:
            state = "error"
            confidence = "low"
            evidence = f"TCP connection failed with socket error code {result}"

        return TcpPortResult(
            address=address,
            port=port,
            is_open=state == "open",
            error_code=result,
            state=state,
            confidence=confidence,
            evidence=evidence,
            attempts=1,
        )

    finally:
        sock.close()


def scan_tcp_ports(
    address: str,
    ports: tuple[int, ...],
    timeout: float,
    max_workers: int = 50,
) -> tuple[TcpPortResult, ...]:
    """Perform concurrent TCP connect checks against multiple ports."""

    if not ports:
        raise ValueError("At least one TCP port is required.")

    if max_workers < 1:
        raise ValueError("max_workers must be at least 1.")

    results: list[TcpPortResult] = []

    with ThreadPoolExecutor(
        max_workers=min(max_workers, len(ports)),
    ) as executor:
        futures = {
            executor.submit(
                scan_tcp_port,
                address,
                port,
                timeout,
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
                    else -1
                )

                results.append(
                    TcpPortResult(
                        address=address,
                        port=port,
                        is_open=False,
                        error_code=error_code,
                    )
                )

    return tuple(
        sorted(
            results,
            key=lambda result: result.port,
        )
    )