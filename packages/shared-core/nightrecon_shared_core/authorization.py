"""Network-free target parsing and explicit scope authorization primitives."""

from __future__ import annotations

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


@dataclass(frozen=True)
class Scope:
    rules: tuple[Target, ...]

    @classmethod
    def from_values(cls, values: list[str]) -> "Scope":
        if not values:
            raise ValueError("At least one scope rule is required.")
        return cls(tuple(parse_target(value) for value in values))

    def is_authorized(self, target: Target) -> bool:
        return any(self._matches(rule, target) for rule in self.rules)

    @staticmethod
    def _matches(rule: Target, target: Target) -> bool:
        if target.target_type == TargetType.HOSTNAME:
            return rule.target_type == TargetType.HOSTNAME and rule.value == target.value

        if target.target_type in (TargetType.IPV4, TargetType.IPV6):
            target_ip = ipaddress.ip_address(target.value)
            if rule.target_type in (TargetType.IPV4, TargetType.IPV6):
                return ipaddress.ip_address(rule.value) == target_ip
            if rule.target_type == TargetType.CIDR:
                return target_ip in ipaddress.ip_network(rule.value, strict=False)
            return False

        if target.target_type == TargetType.CIDR:
            target_network = ipaddress.ip_network(target.value, strict=False)
            if rule.target_type != TargetType.CIDR:
                return False
            rule_network = ipaddress.ip_network(rule.value, strict=False)
            if rule_network.version != target_network.version:
                return False
            return target_network.subnet_of(rule_network)

        return False
