"""TCP connect scanning engine for NightRecon."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
import ipaddress
import socket


@dataclass(frozen=True)
class TcpPortResult:
    """Result of a single TCP connection attempt."""

    address: str
    port: int
    is_open: bool
    error_code: int


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

        return TcpPortResult(
            address=address,
            port=port,
            is_open=result == 0,
            error_code=result,
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
            results.append(future.result())

    return tuple(
        sorted(
            results,
            key=lambda result: result.port,
        )
    )
