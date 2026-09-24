"""Bounded TCP host discovery for authorized NightRecon networks."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
import errno
import ipaddress
import itertools
import socket


_REFUSED_CODES = {
    errno.ECONNREFUSED,
    getattr(errno, "WSAECONNREFUSED", 10061),
}


@dataclass(frozen=True)
class HostDiscoveryResult:
    """Observed host reachability evidence from bounded TCP probing."""

    address: str
    responsive: bool
    method: str
    port: int | None
    observation: str
    error_code: int | None = None


def probe_host(
    *,
    address: str,
    ports: tuple[int, ...],
    timeout: float,
) -> HostDiscoveryResult:
    """Probe one IP address using bounded TCP connect evidence."""

    _validate_ports(ports)

    if timeout <= 0:
        raise ValueError("timeout must be greater than 0.")

    ip = ipaddress.ip_address(address)
    family = (
        socket.AF_INET
        if ip.version == 4
        else socket.AF_INET6
    )
    last_error: int | None = None

    for port in ports:
        sock = socket.socket(
            family,
            socket.SOCK_STREAM,
        )

        try:
            sock.settimeout(timeout)
            code = sock.connect_ex(
                (address, port)
            )
            last_error = code

            if code == 0:
                return HostDiscoveryResult(
                    address=address,
                    responsive=True,
                    method="tcp-connect",
                    port=port,
                    observation="tcp-open",
                    error_code=0,
                )

            if code in _REFUSED_CODES:
                return HostDiscoveryResult(
                    address=address,
                    responsive=True,
                    method="tcp-connect",
                    port=port,
                    observation="tcp-refused",
                    error_code=code,
                )
        except (OSError, socket.timeout) as exc:
            last_error = getattr(
                exc,
                "errno",
                None,
            )
        finally:
            try:
                sock.close()
            except OSError:
                pass

    return HostDiscoveryResult(
        address=address,
        responsive=False,
        method="tcp-connect",
        port=None,
        observation="no-response",
        error_code=last_error,
    )


def discover_hosts(
    *,
    cidr: str,
    ports: tuple[int, ...],
    timeout: float = 1.0,
    max_workers: int = 100,
    max_hosts: int = 1024,
) -> tuple[HostDiscoveryResult, ...]:
    """Discover hosts in one authorized CIDR with explicit resource bounds."""

    if timeout <= 0:
        raise ValueError("timeout must be greater than 0.")

    if max_workers < 1:
        raise ValueError("max_workers must be at least 1.")

    if max_hosts < 1:
        raise ValueError("max_hosts must be at least 1.")

    _validate_ports(ports)

    try:
        network = ipaddress.ip_network(
            cidr,
            strict=False,
        )
    except ValueError as exc:
        raise ValueError(
            f"Invalid CIDR target: {cidr}"
        ) from exc

    candidates = tuple(
        str(address)
        for address in itertools.islice(
            network.hosts(),
            max_hosts + 1,
        )
    )

    if len(candidates) > max_hosts:
        raise ValueError(
            f"CIDR host count exceeds max_hosts={max_hosts}."
        )

    if not candidates:
        return ()

    results: list[HostDiscoveryResult] = []

    with ThreadPoolExecutor(
        max_workers=min(
            max_workers,
            len(candidates),
        )
    ) as executor:
        futures = {
            executor.submit(
                probe_host,
                address=address,
                ports=ports,
                timeout=timeout,
            ): address
            for address in candidates
        }

        for future in as_completed(futures):
            address = futures[future]

            try:
                result = future.result()
            except Exception as exc:
                result = HostDiscoveryResult(
                    address=address,
                    responsive=False,
                    method="tcp-connect",
                    port=None,
                    observation="probe-error",
                    error_code=getattr(
                        exc,
                        "errno",
                        None,
                    ),
                )

            results.append(result)

    return tuple(
        sorted(
            results,
            key=lambda item: ipaddress.ip_address(
                item.address
            ),
        )
    )


def _validate_ports(
    ports: tuple[int, ...],
) -> None:
    if not ports:
        raise ValueError(
            "At least one discovery port is required."
        )

    for port in ports:
        if (
            isinstance(port, bool)
            or not isinstance(port, int)
            or not 1 <= port <= 65535
        ):
            raise ValueError(
                f"Invalid TCP port: {port}"
            )
