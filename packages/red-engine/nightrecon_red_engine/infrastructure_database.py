"""Read-only database evidence contract for NightRecon v0.30.

This module defines bounded non-secret database connection metadata and
normalization of already-observed server/schema metadata. It performs no
database authentication, socket activity, SQL execution, query generation,
catalog access, file access, or network traffic.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import re

from nightrecon_red_engine.infrastructure_execution import (
    InfrastructureFact,
)


_TEXT_PATTERN = re.compile(
    r"^[^\x00-\x1f\x7f]{1,255}$"
)

_ALLOWED_ACTIONS = (
    "database.server_identity",
    "database.schema_inventory",
)


class DatabaseEngine(str, Enum):
    """Database engines supported by the v0.30 evidence contract."""

    POSTGRESQL = "postgresql"
    MYSQL = "mysql"


@dataclass(frozen=True)
class DatabaseConnectionProfile:
    """Non-secret TLS-only database connection settings."""

    engine: DatabaseEngine
    username: str
    database_name: str
    port: int
    connect_timeout: float = 5.0
    operation_timeout: float = 5.0
    max_schemas: int = 512
    use_tls: bool = True
    validate_server_certificate: bool = True

    def __post_init__(
        self,
    ) -> None:
        if not isinstance(
            self.engine,
            DatabaseEngine,
        ):
            raise ValueError(
                "Database engine is invalid."
            )

        username = _normalize_text(
            self.username,
            field_name="username",
        )
        database_name = _normalize_text(
            self.database_name,
            field_name="database_name",
        )

        if not (
            1 <= self.port <= 65_535
        ):
            raise ValueError(
                "Database port must be between 1 and 65535."
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
            1 <= self.max_schemas <= 4096
        ):
            raise ValueError(
                "max_schemas must be between 1 and 4096."
            )

        if not self.use_tls:
            raise ValueError(
                "Database assessment requires TLS."
            )

        if not self.validate_server_certificate:
            raise ValueError(
                "Database assessment requires server certificate validation."
            )

        object.__setattr__(
            self,
            "username",
            username,
        )
        object.__setattr__(
            self,
            "database_name",
            database_name,
        )


@dataclass(frozen=True)
class DatabaseServerObservation:
    """Already-observed non-secret database server identity metadata."""

    engine: DatabaseEngine
    product: str
    version: str


@dataclass(frozen=True)
class DatabaseSchemaObservation:
    """Already-observed bounded database schema metadata."""

    name: str


def supported_database_actions(
) -> tuple[str, ...]:
    """Return the fixed read-only database action IDs."""

    return _ALLOWED_ACTIONS


def validate_database_action(
    action_id: str,
) -> str:
    """Validate one exact symbolic database action ID."""

    normalized = action_id.strip()

    if normalized not in (
        _ALLOWED_ACTIONS
    ):
        raise ValueError(
            "Unsupported database action."
        )

    return normalized


def _normalize_text(
    value: str,
    *,
    field_name: str,
) -> str:
    if not isinstance(
        value,
        str,
    ):
        raise ValueError(
            f"{field_name} is invalid."
        )

    normalized = value.strip()

    if not _TEXT_PATTERN.fullmatch(
        normalized
    ):
        raise ValueError(
            f"{field_name} is invalid."
        )

    return normalized


def build_database_server_identity_facts(
    observation: DatabaseServerObservation,
) -> tuple[InfrastructureFact, ...]:
    """Normalize already-observed database server identity metadata."""

    if not isinstance(
        observation.engine,
        DatabaseEngine,
    ):
        raise ValueError(
            "Database engine is invalid."
        )

    product = _normalize_text(
        observation.product,
        field_name="product",
    )
    version = _normalize_text(
        observation.version,
        field_name="version",
    )

    return (
        InfrastructureFact(
            key="database.engine",
            value=observation.engine.value,
        ),
        InfrastructureFact(
            key="database.product",
            value=product,
        ),
        InfrastructureFact(
            key="database.version",
            value=version,
        ),
    )


def build_database_schema_inventory_facts(
    schemas: tuple[
        DatabaseSchemaObservation,
        ...
    ],
    *,
    max_schemas: int,
) -> tuple[InfrastructureFact, ...]:
    """Normalize bounded schema observations into deterministic facts."""

    if not (
        1 <= max_schemas <= 4096
    ):
        raise ValueError(
            "max_schemas must be between 1 and 4096."
        )

    if len(
        schemas
    ) > max_schemas:
        raise ValueError(
            "Observed database schemas exceed max_schemas."
        )

    deduplicated: dict[
        str,
        str,
    ] = {}

    for schema in schemas:
        name = _normalize_text(
            schema.name,
            field_name="schema name",
        )

        if name in deduplicated:
            raise ValueError(
                "Duplicate database schema observation."
            )

        deduplicated[
            name
        ] = name

    ordered = tuple(
        sorted(
            deduplicated.values(),
            key=lambda value: (
                value.casefold(),
                value,
            ),
        )
    )

    facts: list[
        InfrastructureFact
    ] = [
        InfrastructureFact(
            key="database.schema_count",
            value=str(
                len(
                    ordered
                )
            ),
        )
    ]

    for index, name in enumerate(
        ordered,
        start=1,
    ):
        facts.append(
            InfrastructureFact(
                key=(
                    f"database.schema_{index:04d}.name"
                ),
                value=name,
            )
        )

    return tuple(
        facts
    )
