"""Bounded TCP SYN scanning for explicitly authorized IP targets.

This module intentionally omits spoofing, decoys, fragmentation, source-port
manipulation, and other evasion features.
"""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import time

from nightrecon_shared_core.authorization import Scope, parse_target


MAX_SYN_PORTS_PER_SCAN = 1024
MAX_SYN_RETRIES = 2
MAX_SYN_RATE_PER_SECOND = 250


class SynRuntimeUnavailable(RuntimeError):
    pass


@dataclass(frozen=True)
class SynPortResult:
    address: str
    port: int
    state: str
    confidence: str
    evidence: str
    attempts: int = 1


def _authorize_ip(address: str, scope: Scope) -> None:
    ipaddress.ip_address(address)
    target = parse_target(address)
    if not scope.is_authorized(target):
        raise PermissionError(
            f"Target '{address}' is outside the authorized scope."
        )


def classify_syn_response(response: object | None) -> tuple[str, str, str]:
    """Classify a Scapy-like response using only TCP flags/ICMP type-code."""
    if response is None:
        return (
            "filtered",
            "medium",
            "no SYN response before timeout",
        )

    haslayer = getattr(response, "haslayer", None)
    getlayer = getattr(response, "getlayer", None)
    if not callable(haslayer) or not callable(getlayer):
        return ("error", "low", "unrecognized SYN response object")

    try:
        from scapy.layers.inet import ICMP, TCP
    except Exception as exc:
        raise SynRuntimeUnavailable(
            "Scapy is required for TCP SYN response classification."
        ) from exc

    if response.haslayer(TCP):
        tcp = response.getlayer(TCP)
        flags = int(tcp.flags)
        if flags & 0x12 == 0x12:
            return ("open", "high", "received TCP SYN-ACK")
        if flags & 0x04:
            return ("closed", "high", "received TCP RST")

    if response.haslayer(ICMP):
        icmp = response.getlayer(ICMP)
        if int(icmp.type) == 3:
            return (
                "filtered",
                "high",
                f"received ICMP unreachable type 3 code {int(icmp.code)}",
            )

    return ("error", "low", "response did not establish a TCP port state")


def scan_syn_ports(
    *,
    address: str,
    ports: tuple[int, ...],
    scope: Scope,
    timeout: float = 1.0,
    retries: int = 0,
    max_probes_per_second: int = 100,
) -> tuple[SynPortResult, ...]:
    """Perform a bounded authorized SYN scan against one literal IP address."""
    _authorize_ip(address, scope)

    if not ports:
        raise ValueError("At least one SYN port is required.")
    if len(ports) > MAX_SYN_PORTS_PER_SCAN:
        raise ValueError(
            f"SYN port count exceeds MAX_SYN_PORTS_PER_SCAN={MAX_SYN_PORTS_PER_SCAN}."
        )
    if len(set(ports)) != len(ports):
        raise ValueError("SYN port list must not contain duplicates.")
    if any(
        isinstance(port, bool)
        or not isinstance(port, int)
        or not 1 <= port <= 65535
        for port in ports
    ):
        raise ValueError("SYN ports must be integers between 1 and 65535.")
    if timeout <= 0:
        raise ValueError("timeout must be greater than 0.")
    if retries < 0 or retries > MAX_SYN_RETRIES:
        raise ValueError(
            f"retries must be between 0 and {MAX_SYN_RETRIES}."
        )
    if (
        max_probes_per_second < 1
        or max_probes_per_second > MAX_SYN_RATE_PER_SECOND
    ):
        raise ValueError(
            f"max_probes_per_second must be between 1 and {MAX_SYN_RATE_PER_SECOND}."
        )

    try:
        from scapy.layers.inet import IP, TCP
        from scapy.layers.inet6 import IPv6
        from scapy.sendrecv import sr1
    except Exception as exc:
        raise SynRuntimeUnavailable(
            "Scapy is required for TCP SYN scanning."
        ) from exc

    ip = ipaddress.ip_address(address)
    interval = 1.0 / max_probes_per_second
    results: list[SynPortResult] = []

    for port in sorted(ports):
        final: SynPortResult | None = None
        for attempt in range(retries + 1):
            network = IPv6(dst=address) if ip.version == 6 else IP(dst=address)
            packet = network / TCP(dport=port, flags="S")
            response = sr1(
                packet,
                timeout=timeout,
                verbose=0,
            )
            state, confidence, evidence = classify_syn_response(response)
            attempts = attempt + 1
            final = SynPortResult(
                address=address,
                port=port,
                state=state,
                confidence=confidence,
                evidence=f"{evidence}; {attempts} attempts",
                attempts=attempts,
            )
            if state != "filtered" or attempt >= retries:
                break
            time.sleep(interval)
        assert final is not None
        results.append(final)
        time.sleep(interval)

    return tuple(results)
