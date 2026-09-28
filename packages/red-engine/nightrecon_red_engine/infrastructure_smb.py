"""Read-only SMB evidence contract for NightRecon v0.30.

This module contains connection metadata validation and bounded normalization of
already-observed SMB identity/share metadata. It performs no SMB authentication,
socket activity, RPC calls, file access, or network execution.
"""

from __future__ import annotations

from dataclasses import dataclass
import re

from nightrecon_red_engine.infrastructure_execution import (
    InfrastructureFact,
)


_NAME_PATTERN = re.compile(
    r"^[^\x00-\x1f\x7f]{1,255}$"
)

_ALLOWED_ACTIONS = (
    "smb.server_identity",
    "smb.share_inventory",
)

_ALLOWED_SHARE_TYPES = {
    "disk",
    "ipc",
    "print",
    "device",
    "unknown",
}


@dataclass(frozen=True)
class SmbConnectionProfile:
    """Non-secret SMB connection settings."""

    username: str
    domain: str = ""
    port: int = 445
    connect_timeout: float = 5.0
    operation_timeout: float = 5.0
    max_shares: int = 128

    def __post_init__(self) -> None:
        username = self.username.strip()

        if not _NAME_PATTERN.fullmatch(
            username
        ):
            raise ValueError(
                "SMB username is invalid."
            )

        if not (
            1 <= self.port <= 65_535
        ):
            raise ValueError(
                "SMB port must be between 1 and 65535."
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
            1 <= self.max_shares <= 1024
        ):
            raise ValueError(
                "max_shares must be between 1 and 1024."
            )

        domain = self.domain.strip()

        if domain and not _NAME_PATTERN.fullmatch(
            domain
        ):
            raise ValueError(
                "SMB domain is invalid."
            )

        object.__setattr__(
            self,
            "username",
            username,
        )
        object.__setattr__(
            self,
            "domain",
            domain,
        )


@dataclass(frozen=True)
class SmbShareObservation:
    """Bounded non-secret SMB share metadata."""

    name: str
    share_type: str

    def __post_init__(self) -> None:
        name = self.name.strip()
        share_type = (
            self.share_type.strip().lower()
        )

        if not _NAME_PATTERN.fullmatch(
            name
        ):
            raise ValueError(
                "SMB share name is invalid."
            )

        if share_type not in (
            _ALLOWED_SHARE_TYPES
        ):
            raise ValueError(
                "SMB share type is invalid."
            )

        object.__setattr__(
            self,
            "name",
            name,
        )
        object.__setattr__(
            self,
            "share_type",
            share_type,
        )


def supported_smb_actions(
) -> tuple[str, ...]:
    """Return the fixed read-only SMB action IDs."""

    return _ALLOWED_ACTIONS


def validate_smb_action(
    action_id: str,
) -> str:
    """Validate one exact symbolic SMB action ID."""

    normalized = action_id.strip()

    if normalized not in (
        _ALLOWED_ACTIONS
    ):
        raise ValueError(
            "Unsupported SMB action."
        )

    return normalized


def _normalize_fact_value(
    value: str,
    *,
    field_name: str,
) -> str:
    normalized = value.strip()

    if not _NAME_PATTERN.fullmatch(
        normalized
    ):
        raise ValueError(
            f"{field_name} is invalid."
        )

    return normalized


def build_smb_server_identity_facts(
    *,
    server_name: str,
    domain_name: str,
    dialect: str,
    signing_required: bool,
) -> tuple[InfrastructureFact, ...]:
    """Normalize already-observed SMB server metadata into typed facts."""

    server = _normalize_fact_value(
        server_name,
        field_name="server_name",
    )
    domain = domain_name.strip()

    if domain and not _NAME_PATTERN.fullmatch(
        domain
    ):
        raise ValueError(
            "domain_name is invalid."
        )

    normalized_dialect = (
        _normalize_fact_value(
            dialect,
            field_name="dialect",
        )
    )

    facts = [
        InfrastructureFact(
            key="smb.server_name",
            value=server,
        ),
    ]

    if domain:
        facts.append(
            InfrastructureFact(
                key="smb.domain_name",
                value=domain,
            )
        )

    facts.extend(
        (
            InfrastructureFact(
                key="smb.dialect",
                value=normalized_dialect,
            ),
            InfrastructureFact(
                key="smb.signing_required",
                value=(
                    "true"
                    if signing_required
                    else "false"
                ),
            ),
        )
    )

    return tuple(
        facts
    )


def build_smb_share_inventory_facts(
    shares: tuple[
        SmbShareObservation,
        ...
    ],
    *,
    max_shares: int,
) -> tuple[InfrastructureFact, ...]:
    """Normalize bounded SMB share observations into deterministic facts."""

    if not (
        1 <= max_shares <= 1024
    ):
        raise ValueError(
            "max_shares must be between 1 and 1024."
        )

    if len(shares) > max_shares:
        raise ValueError(
            "Observed SMB shares exceed max_shares."
        )

    deduplicated: dict[
        str,
        SmbShareObservation,
    ] = {}

    for share in shares:
        key = share.name.casefold()

        if key in deduplicated:
            raise ValueError(
                "Duplicate SMB share observation."
            )

        deduplicated[
            key
        ] = share

    ordered = tuple(
        sorted(
            deduplicated.values(),
            key=lambda item: (
                item.name.casefold(),
                item.name,
            ),
        )
    )

    facts: list[
        InfrastructureFact
    ] = [
        InfrastructureFact(
            key="smb.share_count",
            value=str(
                len(
                    ordered
                )
            ),
        )
    ]

    for index, share in enumerate(
        ordered,
        start=1,
    ):
        prefix = (
            f"smb.share_{index:03d}"
        )
        facts.extend(
            (
                InfrastructureFact(
                    key=f"{prefix}.name",
                    value=share.name,
                ),
                InfrastructureFact(
                    key=f"{prefix}.type",
                    value=share.share_type,
                ),
            )
        )

    return tuple(
        facts
    )
