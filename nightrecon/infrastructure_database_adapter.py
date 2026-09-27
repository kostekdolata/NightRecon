"""Injectable read-only database adapter boundary for NightRecon v0.30.

This module defines a protocol-neutral boundary around an injected database
runtime. It performs no authentication, socket activity, SQL execution, query
generation, catalog access, file access, or network traffic by itself.
"""

from __future__ import annotations

from typing import Protocol

from nightrecon.credential_resolution import ResolvedCredential
from nightrecon.infrastructure_database import (
    DatabaseConnectionProfile,
    DatabaseSchemaObservation,
    DatabaseServerObservation,
    build_database_schema_inventory_facts,
    build_database_server_identity_facts,
    validate_database_action,
)
from nightrecon.infrastructure_execution import InfrastructureAdapterOutcome
from nightrecon.infrastructure_models import (
    CredentialKind,
    InfrastructureTransport,
)


class DatabaseRuntimeSession(Protocol):
    """Minimal fixed-action read-only database runtime session."""

    def server_identity(self) -> DatabaseServerObservation:
        ...

    def list_schemas(
        self,
        *,
        max_schemas: int,
    ) -> tuple[DatabaseSchemaObservation, ...]:
        ...

    def close(self) -> None:
        ...


class DatabaseRuntimeFactory(Protocol):
    """Factory for a bounded authenticated database runtime session."""

    def connect(
        self,
        *,
        target: str,
        profile: DatabaseConnectionProfile,
        credential: ResolvedCredential,
    ) -> DatabaseRuntimeSession:
        ...


class DatabaseReadOnlyAdapter:
    """Read-only database adapter over an explicitly injected runtime."""

    transport = InfrastructureTransport.DATABASE

    def __init__(
        self,
        profile: DatabaseConnectionProfile,
        runtime_factory: DatabaseRuntimeFactory,
    ) -> None:
        self.profile = profile
        self._runtime_factory = runtime_factory

    def __repr__(self) -> str:
        return (
            "DatabaseReadOnlyAdapter("
            f"engine={self.profile.engine.value!r}, "
            f"username={self.profile.username!r}, "
            f"database_name={self.profile.database_name!r}, "
            f"port={self.profile.port}, "
            f"max_schemas={self.profile.max_schemas}, "
            "tls='required', "
            "certificate_validation='required', "
            "actions='fixed-read-only', "
            "runtime='injected')"
        )

    def execute(
        self,
        *,
        target: str,
        action_id: str,
        credential: ResolvedCredential,
    ) -> InfrastructureAdapterOutcome:
        try:
            normalized_action = validate_database_action(action_id)
        except ValueError:
            return InfrastructureAdapterOutcome(
                success=False,
                reason="unsupported_action",
            )

        if credential.reference.kind != CredentialKind.PASSWORD:
            return InfrastructureAdapterOutcome(
                success=False,
                reason="credential_kind_not_supported",
            )

        if not credential.material.active:
            return InfrastructureAdapterOutcome(
                success=False,
                reason="credential_unavailable",
            )

        session: DatabaseRuntimeSession | None = None

        try:
            session = self._runtime_factory.connect(
                target=target,
                profile=self.profile,
                credential=credential,
            )

            if normalized_action == "database.server_identity":
                facts = build_database_server_identity_facts(
                    session.server_identity()
                )
            else:
                facts = build_database_schema_inventory_facts(
                    session.list_schemas(
                        max_schemas=self.profile.max_schemas,
                    ),
                    max_schemas=self.profile.max_schemas,
                )

            return InfrastructureAdapterOutcome(
                success=True,
                reason="completed",
                facts=facts,
            )
        except ValueError:
            return InfrastructureAdapterOutcome(
                success=False,
                reason="evidence_invalid",
            )
        except Exception:
            return InfrastructureAdapterOutcome(
                success=False,
                reason="database_failed",
            )
        finally:
            if session is not None:
                try:
                    session.close()
                except Exception:
                    pass
