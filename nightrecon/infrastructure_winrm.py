"""Read-only WinRM evidence contract for NightRecon v0.30.

This module defines bounded non-secret WinRM connection metadata and
normalization of already-observed Windows identity/patch metadata. It performs
no WinRM authentication, HTTP(S) activity, PowerShell execution, command
execution, registry access, WMI calls, or network traffic.
"""

from __future__ import annotations

from dataclasses import dataclass
import re

from nightrecon.infrastructure_execution import (
    InfrastructureFact,
)


_TEXT_PATTERN = re.compile(
    r"^[^\x00-\x1f\x7f]{1,255}$"
)

_HOTFIX_PATTERN = re.compile(
    r"^(?:KB)?[0-9]{4,12}$",
    re.IGNORECASE,
)

_ALLOWED_ACTIONS = (
    "winrm.system_identity",
    "winrm.patch_inventory",
)


@dataclass(frozen=True)
class WinRmConnectionProfile:
    """Non-secret HTTPS-only WinRM connection settings."""

    username: str
    port: int = 5986
    connect_timeout: float = 5.0
    operation_timeout: float = 5.0
    max_patches: int = 512
    use_tls: bool = True
    validate_server_certificate: bool = True

    def __post_init__(
        self,
    ) -> None:
        username = self.username.strip()

        if not _TEXT_PATTERN.fullmatch(
            username
        ):
            raise ValueError(
                "WinRM username is invalid."
            )

        if not (
            1 <= self.port <= 65_535
        ):
            raise ValueError(
                "WinRM port must be between 1 and 65535."
            )

        if self.connect_timeout <= 0:
            raise ValueError(
                "connect_timeout must be greater than 0."
            )

        if self.operation_timeout <= 0:
            raise ValueError(
                "operation_timeout must be greater than 0."
            )

        if not (
            1 <= self.max_patches <= 4096
        ):
            raise ValueError(
                "max_patches must be between 1 and 4096."
            )

        if not self.use_tls:
            raise ValueError(
                "WinRM assessment requires TLS."
            )

        if not self.validate_server_certificate:
            raise ValueError(
                "WinRM assessment requires server certificate validation."
            )

        object.__setattr__(
            self,
            "username",
            username,
        )


@dataclass(frozen=True)
class WinRmSystemObservation:
    """Already-observed Windows system identity metadata."""

    hostname: str
    os_name: str
    os_version: str
    architecture: str


@dataclass(frozen=True)
class WinRmPatchObservation:
    """Already-observed Windows patch metadata."""

    hotfix_id: str


def supported_winrm_actions(
) -> tuple[str, ...]:
    """Return the fixed read-only WinRM action IDs."""

    return _ALLOWED_ACTIONS


def validate_winrm_action(
    action_id: str,
) -> str:
    """Validate one exact symbolic WinRM action ID."""

    normalized = action_id.strip()

    if normalized not in (
        _ALLOWED_ACTIONS
    ):
        raise ValueError(
            "Unsupported WinRM action."
        )

    return normalized


def _normalize_text(
    value: str,
    *,
    field_name: str,
) -> str:
    normalized = value.strip()

    if not _TEXT_PATTERN.fullmatch(
        normalized
    ):
        raise ValueError(
            f"{field_name} is invalid."
        )

    return normalized


def build_winrm_system_identity_facts(
    observation: WinRmSystemObservation,
) -> tuple[InfrastructureFact, ...]:
    """Normalize bounded Windows system identity metadata."""

    hostname = _normalize_text(
        observation.hostname,
        field_name="hostname",
    )
    os_name = _normalize_text(
        observation.os_name,
        field_name="os_name",
    )
    os_version = _normalize_text(
        observation.os_version,
        field_name="os_version",
    )
    architecture = _normalize_text(
        observation.architecture,
        field_name="architecture",
    )

    return (
        InfrastructureFact(
            key="windows.hostname",
            value=hostname,
        ),
        InfrastructureFact(
            key="windows.os_name",
            value=os_name,
        ),
        InfrastructureFact(
            key="windows.os_version",
            value=os_version,
        ),
        InfrastructureFact(
            key="windows.architecture",
            value=architecture,
        ),
    )


def build_winrm_patch_inventory_facts(
    patches: tuple[
        WinRmPatchObservation,
        ...
    ],
    *,
    max_patches: int,
) -> tuple[InfrastructureFact, ...]:
    """Normalize bounded patch observations into deterministic facts."""

    if not (
        1 <= max_patches <= 4096
    ):
        raise ValueError(
            "max_patches must be between 1 and 4096."
        )

    if len(patches) > max_patches:
        raise ValueError(
            "Observed WinRM patches exceed max_patches."
        )

    normalized: dict[
        str,
        str,
    ] = {}

    for patch in patches:
        value = (
            patch.hotfix_id.strip().upper()
        )

        if not _HOTFIX_PATTERN.fullmatch(
            value
        ):
            raise ValueError(
                "WinRM hotfix ID is invalid."
            )

        if not value.startswith(
            "KB"
        ):
            value = f"KB{value}"

        key = value.casefold()

        if key in normalized:
            raise ValueError(
                "Duplicate WinRM patch observation."
            )

        normalized[
            key
        ] = value

    ordered = tuple(
        sorted(
            normalized.values()
        )
    )

    facts: list[
        InfrastructureFact
    ] = [
        InfrastructureFact(
            key="windows.patch_count",
            value=str(
                len(
                    ordered
                )
            ),
        )
    ]

    for index, hotfix_id in enumerate(
        ordered,
        start=1,
    ):
        facts.append(
            InfrastructureFact(
                key=f"windows.patch_{index:04d}.hotfix_id",
                value=hotfix_id,
            )
        )

    return tuple(
        facts
    )
