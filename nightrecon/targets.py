"""Target parsing and validation for NightRecon."""

from dataclasses import dataclass
from enum import Enum
import ipaddress
import re


class TargetType(str, Enum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    CIDR = "cidr"
    HOSTNAME = "hostname"


@dataclass(frozen=True)
class Target:
    value: str
    target_type: TargetType


_HOSTNAME_PATTERN = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:"
    r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)\."
    r")*"
    r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)$"
)


def parse_target(value: str) -> Target:
    """Validate and classify a NightRecon target."""

    value = value.strip()

    if not value:
        raise ValueError("Target cannot be empty.")

    if "/" in value:
        try:
            ipaddress.ip_network(value, strict=False)
            return Target(value=value, target_type=TargetType.CIDR)
        except ValueError as exc:
            raise ValueError(f"Invalid CIDR target: {value}") from exc

    try:
        address = ipaddress.ip_address(value)

        if isinstance(address, ipaddress.IPv4Address):
            return Target(value=value, target_type=TargetType.IPV4)

        return Target(value=value, target_type=TargetType.IPV6)

    except ValueError:
        pass

    if _HOSTNAME_PATTERN.fullmatch(value):
        return Target(value=value.lower(), target_type=TargetType.HOSTNAME)

    raise ValueError(f"Invalid target: {value}")
