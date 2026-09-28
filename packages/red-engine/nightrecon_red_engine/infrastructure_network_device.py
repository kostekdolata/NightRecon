"""Protocol-neutral read-only network-device evidence contract.

This module defines bounded non-secret management profile metadata and
normalization of already-observed device/interface evidence. It performs no
authentication, socket activity, NETCONF/RPC execution, CLI command execution,
configuration access, configuration change, file access, or network traffic.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import re

from nightrecon_red_engine.infrastructure_execution import InfrastructureFact


_TEXT_PATTERN = re.compile(r"^[^\x00-\x1f\x7f]{1,255}$")
_INTERFACE_NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")

_ALLOWED_ACTIONS = (
    "network_device.system_identity",
    "network_device.interface_inventory",
)


class NetworkDeviceManagementProtocol(str, Enum):
    """Structured management protocols admitted by the evidence contract."""

    NETCONF_SSH = "netconf-ssh"


class NetworkDeviceInterfaceState(str, Enum):
    """Bounded normalized administrative/operational states."""

    UP = "up"
    DOWN = "down"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class NetworkDeviceConnectionProfile:
    """Non-secret structured-management connection metadata."""

    protocol: NetworkDeviceManagementProtocol
    username: str
    port: int = 830
    connect_timeout: float = 5.0
    operation_timeout: float = 5.0
    max_interfaces: int = 1024
    verify_host_identity: bool = True

    def __post_init__(self) -> None:
        if not isinstance(
            self.protocol,
            NetworkDeviceManagementProtocol,
        ):
            raise ValueError(
                "Network-device management protocol is invalid."
            )

        username = _normalize_text(
            self.username,
            field_name="username",
        )

        if not 1 <= self.port <= 65_535:
            raise ValueError(
                "Network-device port must be between 1 and 65535."
            )
        if self.connect_timeout <= 0:
            raise ValueError(
                "connect_timeout must be greater than 0."
            )
        if self.operation_timeout <= 0:
            raise ValueError(
                "operation_timeout must be greater than 0."
            )
        if not 1 <= self.max_interfaces <= 8192:
            raise ValueError(
                "max_interfaces must be between 1 and 8192."
            )
        if not self.verify_host_identity:
            raise ValueError(
                "Network-device assessment requires host identity verification."
            )

        object.__setattr__(self, "username", username)


@dataclass(frozen=True)
class NetworkDeviceSystemObservation:
    """Already-observed bounded device identity metadata."""

    vendor: str
    model: str
    operating_system: str
    version: str


@dataclass(frozen=True)
class NetworkDeviceInterfaceObservation:
    """Already-observed bounded interface state metadata."""

    name: str
    administrative_state: NetworkDeviceInterfaceState
    operational_state: NetworkDeviceInterfaceState


def supported_network_device_actions() -> tuple[str, ...]:
    """Return the exact read-only network-device action IDs."""

    return _ALLOWED_ACTIONS


def validate_network_device_action(action_id: str) -> str:
    """Validate one exact symbolic network-device action ID."""

    normalized = action_id.strip()
    if normalized not in _ALLOWED_ACTIONS:
        raise ValueError(
            "Unsupported network-device action."
        )
    return normalized


def _normalize_text(value: str, *, field_name: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field_name} is invalid.")

    normalized = value.strip()
    if not _TEXT_PATTERN.fullmatch(normalized):
        raise ValueError(f"{field_name} is invalid.")
    return normalized


def build_network_device_system_identity_facts(
    observation: NetworkDeviceSystemObservation,
) -> tuple[InfrastructureFact, ...]:
    """Normalize already-observed network-device identity metadata."""

    values = (
        ("network_device.vendor", observation.vendor, "vendor"),
        ("network_device.model", observation.model, "model"),
        (
            "network_device.operating_system",
            observation.operating_system,
            "operating_system",
        ),
        ("network_device.version", observation.version, "version"),
    )

    return tuple(
        InfrastructureFact(
            key=key,
            value=_normalize_text(value, field_name=field_name),
        )
        for key, value, field_name in values
    )


def build_network_device_interface_inventory_facts(
    interfaces: tuple[NetworkDeviceInterfaceObservation, ...],
    *,
    max_interfaces: int,
) -> tuple[InfrastructureFact, ...]:
    """Normalize deterministic bounded interface observations."""

    if not 1 <= max_interfaces <= 8192:
        raise ValueError(
            "max_interfaces must be between 1 and 8192."
        )
    if len(interfaces) > max_interfaces:
        raise ValueError(
            "Observed network-device interfaces exceed max_interfaces."
        )

    normalized: dict[
        str,
        tuple[
            str,
            NetworkDeviceInterfaceState,
            NetworkDeviceInterfaceState,
        ],
    ] = {}

    for interface in interfaces:
        if not isinstance(interface.name, str):
            raise ValueError("interface name is invalid.")

        name = interface.name.strip()
        if not _INTERFACE_NAME_PATTERN.fullmatch(name):
            raise ValueError("interface name is invalid.")

        if not isinstance(
            interface.administrative_state,
            NetworkDeviceInterfaceState,
        ):
            raise ValueError(
                "interface administrative state is invalid."
            )
        if not isinstance(
            interface.operational_state,
            NetworkDeviceInterfaceState,
        ):
            raise ValueError(
                "interface operational state is invalid."
            )

        key = name.casefold()
        if key in normalized:
            raise ValueError(
                "Duplicate network-device interface observation."
            )

        normalized[key] = (
            name,
            interface.administrative_state,
            interface.operational_state,
        )

    ordered = tuple(
        sorted(
            normalized.values(),
            key=lambda item: (
                item[0].casefold(),
                item[0],
            ),
        )
    )
    facts: list[InfrastructureFact] = [
        InfrastructureFact(
            key="network_device.interface_count",
            value=str(len(ordered)),
        )
    ]

    for index, (
        name,
        administrative_state,
        operational_state,
    ) in enumerate(ordered, start=1):
        prefix = f"network_device.interface_{index:04d}"
        facts.extend(
            (
                InfrastructureFact(
                    key=f"{prefix}.name",
                    value=name,
                ),
                InfrastructureFact(
                    key=f"{prefix}.administrative_state",
                    value=administrative_state.value,
                ),
                InfrastructureFact(
                    key=f"{prefix}.operational_state",
                    value=operational_state.value,
                ),
            )
        )

    return tuple(facts)
