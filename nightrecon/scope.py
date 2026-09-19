"""Scope authorization for NightRecon."""

from dataclasses import dataclass
import ipaddress

from nightrecon.targets import Target, TargetType, parse_target


@dataclass(frozen=True)
class Scope:
    """Defines targets that NightRecon is authorized to assess."""

    rules: tuple[Target, ...]

    @classmethod
    def from_values(cls, values: list[str]) -> "Scope":
        if not values:
            raise ValueError("At least one scope rule is required.")

        return cls(tuple(parse_target(value) for value in values))

    def is_authorized(self, target: Target) -> bool:
        """Return True only when the target is explicitly within scope."""

        for rule in self.rules:
            if self._matches(rule, target):
                return True

        return False

    @staticmethod
    def _matches(rule: Target, target: Target) -> bool:
        # Hostnames require an exact match.
        if target.target_type == TargetType.HOSTNAME:
            return (
                rule.target_type == TargetType.HOSTNAME
                and rule.value == target.value
            )

        # Single IP target.
        if target.target_type in (TargetType.IPV4, TargetType.IPV6):
            target_ip = ipaddress.ip_address(target.value)

            if rule.target_type in (TargetType.IPV4, TargetType.IPV6):
                return ipaddress.ip_address(rule.value) == target_ip

            if rule.target_type == TargetType.CIDR:
                rule_network = ipaddress.ip_network(rule.value, strict=False)
                return target_ip in rule_network

            return False

        # CIDR targets must be fully contained inside an authorized CIDR.
        if target.target_type == TargetType.CIDR:
            target_network = ipaddress.ip_network(target.value, strict=False)

            if rule.target_type == TargetType.CIDR:
                rule_network = ipaddress.ip_network(rule.value, strict=False)

                if rule_network.version != target_network.version:
                    return False

                return target_network.subnet_of(rule_network)

            return False

        return False
