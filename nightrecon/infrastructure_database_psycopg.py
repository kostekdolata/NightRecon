"""Narrow psycopg PostgreSQL runtime for NightRecon v0.30.

Only fixed internal read-only metadata operations are exposed through the
verified database adapter boundary. Callers cannot supply SQL, parameters,
connection strings, TLS modes, or transaction settings.
"""

from __future__ import annotations

from dataclasses import dataclass
import math
from typing import Any

from nightrecon.credential_resolution import ResolvedCredential
from nightrecon.infrastructure_database import (
    DatabaseConnectionProfile,
    DatabaseEngine,
    DatabaseSchemaObservation,
    DatabaseServerObservation,
)
from nightrecon.infrastructure_database_adapter import DatabaseRuntimeSession


_SERVER_VERSION_QUERY = "SHOW server_version"
_SCHEMA_INVENTORY_QUERY = (
    "SELECT schema_name FROM information_schema.schemata "
    "ORDER BY schema_name"
)


class PsycopgRuntimeUnavailable(RuntimeError):
    """Raised when the optional PostgreSQL runtime is unavailable."""


class PsycopgConnectionError(RuntimeError):
    """Secret-safe PostgreSQL connection/authentication failure."""


@dataclass(frozen=True)
class _PsycopgSymbols:
    connect: Any


def _load_psycopg_symbols() -> _PsycopgSymbols:
    try:
        import psycopg
    except ImportError as exc:
        raise PsycopgRuntimeUnavailable(
            "PostgreSQL assessment requires the NightRecon postgres extra."
        ) from exc

    return _PsycopgSymbols(connect=psycopg.connect)


class _PsycopgSession:
    """Internal session exposing only fixed PostgreSQL metadata collectors."""

    def __init__(
        self,
        connection: Any,
    ) -> None:
        self._connection = connection
        self._closed = False

    def _fetch_rows(
        self,
        query: str,
        *,
        row_limit: int,
    ) -> list[Any]:
        cursor = self._connection.cursor()

        try:
            cursor.execute(query)
            rows = cursor.fetchmany(row_limit + 1)
        finally:
            try:
                cursor.close()
            except Exception:
                pass

        if len(rows) > row_limit:
            raise ValueError(
                "PostgreSQL runtime returned more rows than allowed."
            )

        return list(rows)

    def server_identity(self) -> DatabaseServerObservation:
        rows = self._fetch_rows(
            _SERVER_VERSION_QUERY,
            row_limit=1,
        )

        if len(rows) != 1 or len(rows[0]) != 1:
            raise ValueError(
                "PostgreSQL server identity response is malformed."
            )

        return DatabaseServerObservation(
            engine=DatabaseEngine.POSTGRESQL,
            product="PostgreSQL",
            version=str(rows[0][0]),
        )

    def list_schemas(
        self,
        *,
        max_schemas: int,
    ) -> tuple[DatabaseSchemaObservation, ...]:
        rows = self._fetch_rows(
            _SCHEMA_INVENTORY_QUERY,
            row_limit=max_schemas,
        )
        observations: list[DatabaseSchemaObservation] = []

        for row in rows:
            if len(row) != 1 or not isinstance(row[0], str):
                raise ValueError(
                    "PostgreSQL schema inventory response is malformed."
                )
            observations.append(
                DatabaseSchemaObservation(name=row[0])
            )

        return tuple(observations)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._connection.close()
        except Exception:
            pass


class PsycopgRuntimeFactory:
    """Create one TLS-verified, read-only PostgreSQL connection."""

    def __init__(
        self,
        *,
        symbols: _PsycopgSymbols | None = None,
    ) -> None:
        self._symbols = symbols

    def __repr__(self) -> str:
        return (
            "PsycopgRuntimeFactory("
            "engine='postgresql', "
            "tls='verify-full', "
            "transactions='read-only', "
            "operations='fixed-metadata-only')"
        )

    def _runtime(self) -> _PsycopgSymbols:
        return self._symbols if self._symbols is not None else _load_psycopg_symbols()

    def connect(
        self,
        *,
        target: str,
        profile: DatabaseConnectionProfile,
        credential: ResolvedCredential,
    ) -> DatabaseRuntimeSession:
        if profile.engine != DatabaseEngine.POSTGRESQL:
            raise PsycopgConnectionError(
                "PostgreSQL runtime received an unsupported database engine."
            )

        statement_timeout_ms = max(
            1,
            math.ceil(profile.operation_timeout * 1000),
        )

        try:
            with credential.material.reveal_text() as password:
                connection = self._runtime().connect(
                    host=target,
                    port=profile.port,
                    user=profile.username,
                    password=password,
                    dbname=profile.database_name,
                    connect_timeout=max(1, math.ceil(profile.connect_timeout)),
                    sslmode="verify-full",
                    options=(
                        "-c default_transaction_read_only=on "
                        f"-c statement_timeout={statement_timeout_ms}"
                    ),
                    autocommit=True,
                )
            return _PsycopgSession(connection)
        except PsycopgConnectionError:
            raise
        except Exception:
            raise PsycopgConnectionError(
                "PostgreSQL runtime connection or authentication failed."
            ) from None
