"""Hostname resolution for NightRecon."""

from __future__ import annotations

from dataclasses import dataclass
import socket

from nightrecon.targets import Target, TargetType


@dataclass(frozen=True)
class ResolutionResult:
    target: str
    addresses: tuple[str, ...]


def resolve_target(target: Target) -> ResolutionResult:
    """Resolve an authorized NightRecon target to IP addresses."""

    if target.target_type in (TargetType.IPV4, TargetType.IPV6):
        return ResolutionResult(
            target=target.value,
            addresses=(target.value,),
        )

    if target.target_type == TargetType.CIDR:
        raise ValueError("CIDR targets cannot be resolved as a single host.")

    try:
        records = socket.getaddrinfo(
            target.value,
            None,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror as exc:
        raise ValueError(
            f"Unable to resolve target: {target.value}"
        ) from exc

    addresses = sorted(
        {
            record[4][0]
            for record in records
            if record[4]
        }
    )

    if not addresses:
        raise ValueError(
            f"No IP addresses found for target: {target.value}"
        )

    return ResolutionResult(
        target=target.value,
        addresses=tuple(addresses),
    )
