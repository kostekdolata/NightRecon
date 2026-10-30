"""TCP connect scanning engine for NightRecon."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
import errno
import ipaddress
import socket
import time


MAX_TCP_PORTS_PER_SCAN = 4096
MAX_TCP_WORKERS = 256
MAX_TCP_RETRIES = 2
MAX_TCP_ATTEMPTS_PER_SCAN = 8192

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


@dataclass(frozen=True)
class TcpScanSummary:
    """Deterministic aggregate metadata for one completed TCP result set."""

    total_results: int
    total_attempts: int
    open_count: int
    closed_count: int
    filtered_count: int
    error_count: int


def summarize_tcp_results(
    results: tuple[TcpPortResult, ...],
) -> TcpScanSummary:
    """Summarize completed TCP results without changing scan behavior."""

    state_counts = {
        "open": 0,
        "closed": 0,
        "filtered": 0,
        "error": 0,
    }
    total_attempts = 0

    for result in results:
        if not isinstance(result, TcpPortResult):
            raise TypeError("results must contain only TcpPortResult values.")

        if result.state not in state_counts:
            raise ValueError(f"Unsupported TCP result state: {result.state!r}.")

        if result.attempts < 1:
            raise ValueError("TCP result attempts must be at least 1.")

        state_counts[result.state] += 1
        total_attempts += result.attempts

    return TcpScanSummary(
        total_results=len(results),
        total_attempts=total_attempts,
        open_count=state_counts["open"],
        closed_count=state_counts["closed"],
        filtered_count=state_counts["filtered"],
        error_count=state_counts["error"],
    )


def _classify_tcp_error(error_code: int) -> tuple[str, str, str]:
    if error_code == 0:
        return (
            "open",
            "high",
            "TCP connection completed successfully",
        )

    if error_code in _CLOSED_ERROR_CODES:
        return (
            "closed",
            "high",
            f"TCP connection refused with socket error code {error_code}",
        )

    if error_code in _FILTERED_ERROR_CODES:
        return (
            "filtered",
            "medium",
            f"TCP connection timed out with socket error code {error_code}",
        )

    return (
        "error",
        "low",
        f"TCP connection failed with socket error code {error_code}",
    )


def scan_tcp_port(
    address: str,
    port: int,
    timeout: float,
    *,
    retries: int = 0,
) -> TcpPortResult:
    """Perform bounded TCP connect checks against one IP address and port."""

    ip = ipaddress.ip_address(address)

    if (
        isinstance(port, bool)
        or not isinstance(port, int)
        or port < 1
        or port > 65535
    ):
        raise ValueError("Port must be between 1 and 65535.")

    if timeout <= 0:
        raise ValueError("Timeout must be greater than 0.")

    if retries < 0 or retries > MAX_TCP_RETRIES:
        raise ValueError(
            f"retries must be between 0 and {MAX_TCP_RETRIES}."
        )

    family = (
        socket.AF_INET6
        if isinstance(ip, ipaddress.IPv6Address)
        else socket.AF_INET
    )

    last_error = -1

    for attempt in range(retries + 1):
        sock = socket.socket(
            family,
            socket.SOCK_STREAM,
        )

        try:
            sock.settimeout(timeout)

            try:
                if family == socket.AF_INET6:
                    error_code = sock.connect_ex(
                        (address, port, 0, 0)
                    )
                else:
                    error_code = sock.connect_ex(
                        (address, port)
                    )
            except socket.timeout:
                error_code = getattr(
                    errno,
                    "WSAETIMEDOUT",
                    errno.ETIMEDOUT,
                )
            except OSError as exc:
                error_code = (
                    exc.errno
                    if isinstance(exc.errno, int)
                    else -1
                )

            last_error = error_code
            state, confidence, evidence = _classify_tcp_error(
                error_code
            )
            attempts = attempt + 1

            if state == "filtered" and attempt < retries:
                continue

            return TcpPortResult(
                address=address,
                port=port,
                is_open=state == "open",
                error_code=error_code,
                state=state,
                confidence=confidence,
                evidence=f"{evidence}; {attempts} attempts",
                attempts=attempts,
            )

        finally:
            sock.close()

    state, confidence, evidence = _classify_tcp_error(
        last_error
    )
    return TcpPortResult(
        address=address,
        port=port,
        is_open=False,
        error_code=last_error,
        state=state,
        confidence=confidence,
        evidence=f"{evidence}; {retries + 1} attempts",
        attempts=retries + 1,
    )


def scan_tcp_ports(
    address: str,
    ports: tuple[int, ...],
    timeout: float,
    max_workers: int = 50,
    *,
    retries: int = 0,
    max_probes_per_second: int | None = None,
) -> tuple[TcpPortResult, ...]:
    """Perform bounded concurrent TCP connect checks against multiple ports."""

    if not ports:
        raise ValueError("At least one TCP port is required.")

    if len(ports) > MAX_TCP_PORTS_PER_SCAN:
        raise ValueError(
            "TCP port count exceeds "
            f"MAX_TCP_PORTS_PER_SCAN={MAX_TCP_PORTS_PER_SCAN}."
        )

    if len(set(ports)) != len(ports):
        raise ValueError("TCP port list must not contain duplicates.")

    for port in ports:
        if (
            isinstance(port, bool)
            or not isinstance(port, int)
            or port < 1
            or port > 65535
        ):
            raise ValueError("Port must be between 1 and 65535.")

    if timeout <= 0:
        raise ValueError("Timeout must be greater than 0.")

    if max_workers < 1 or max_workers > MAX_TCP_WORKERS:
        raise ValueError(
            f"max_workers must be between 1 and {MAX_TCP_WORKERS}."
        )

    if retries < 0 or retries > MAX_TCP_RETRIES:
        raise ValueError(
            f"retries must be between 0 and {MAX_TCP_RETRIES}."
        )

    if (
        max_probes_per_second is not None
        and (
            isinstance(max_probes_per_second, bool)
            or not isinstance(max_probes_per_second, int)
            or not 1 <= max_probes_per_second <= 1000
        )
    ):
        raise ValueError(
            "max_probes_per_second must be between 1 and 1000."
        )

    planned_attempts = len(ports) * (retries + 1)
    if planned_attempts > MAX_TCP_ATTEMPTS_PER_SCAN:
        raise ValueError(
            "TCP attempt budget exceeds "
            f"MAX_TCP_ATTEMPTS_PER_SCAN={MAX_TCP_ATTEMPTS_PER_SCAN}."
        )

    results: list[TcpPortResult] = []

    with ThreadPoolExecutor(
        max_workers=min(max_workers, len(ports)),
    ) as executor:
        futures = {}
        interval = (
            0.0
            if max_probes_per_second is None
            else 1.0 / max_probes_per_second
        )
        next_submit_at = time.monotonic()

        for port in ports:
            if interval:
                now = time.monotonic()
                delay = next_submit_at - now
                if delay > 0:
                    time.sleep(delay)
                next_submit_at = max(next_submit_at + interval, time.monotonic())

            if retries == 0:
                future = executor.submit(
                    scan_tcp_port,
                    address,
                    port,
                    timeout,
                )
            else:
                future = executor.submit(
                    scan_tcp_port,
                    address,
                    port,
                    timeout,
                    retries=retries,
                )
            futures[future] = port

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
                state, confidence, evidence = _classify_tcp_error(
                    error_code
                )
                results.append(
                    TcpPortResult(
                        address=address,
                        port=port,
                        is_open=False,
                        error_code=error_code,
                        state=state,
                        confidence=confidence,
                        evidence=evidence,
                        attempts=1,
                    )
                )

    return tuple(
        sorted(
            results,
            key=lambda result: result.port,
        )
    )
