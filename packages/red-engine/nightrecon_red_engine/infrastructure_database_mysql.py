"""Narrow mysql-connector runtime for NightRecon v0.30.

Only fixed internal read-only metadata operations are exposed through the
verified database adapter boundary. Callers cannot supply SQL, parameters,
connection strings, TLS modes, or transaction settings.
"""

from __future__ import annotations

from dataclasses import dataclass
import math
from typing import Any

from nightrecon_red_engine.credential_resolution import ResolvedCredential
from nightrecon_red_engine.infrastructure_database import (
    DatabaseConnectionProfile,
    DatabaseEngine,
    DatabaseSchemaObservation,
    DatabaseServerObservation,
)
from nightrecon_red_engine.infrastructure_database_adapter import DatabaseRuntimeSession


_READ_ONLY_SESSION_QUERY = "SET SESSION TRANSACTION READ ONLY"
_SERVER_VERSION_QUERY = "SELECT VERSION()"
_SCHEMA_INVENTORY_QUERY = (
    "SELECT schema_name FROM information_schema.schemata "
    "ORDER BY schema_name"
)


class MySqlRuntimeUnavailable(RuntimeError):
    """Raised when the optional MySQL runtime is unavailable."""


class MySqlConnectionError(RuntimeError):
    """Secret-safe MySQL connection/authentication failure."""


@dataclass(frozen=True)
class _MySqlSymbols:
    connect: Any


def _load_mysql_symbols() -> _MySqlSymbols:
    try:
        import mysql.connector
    except ImportError as exc:
        raise MySqlRuntimeUnavailable(
            "MySQL assessment requires the NightRecon mysql extra."
        ) from exc

    return _MySqlSymbols(connect=mysql.connector.connect)


class _MySqlSession:
    """Internal session exposing only fixed MySQL metadata collectors."""

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
            rows = cursor.fetchmany(size=row_limit + 1)
        finally:
            try:
                cursor.close()
            except Exception:
                pass

        if len(rows) > row_limit:
            raise ValueError(
                "MySQL runtime returned more rows than allowed."
            )

        return list(rows)

    def server_identity(self) -> DatabaseServerObservation:
        rows = self._fetch_rows(
            _SERVER_VERSION_QUERY,
            row_limit=1,
        )

        if len(rows) != 1 or len(rows[0]) != 1:
            raise ValueError(
                "MySQL server identity response is malformed."
            )

        return DatabaseServerObservation(
            engine=DatabaseEngine.MYSQL,
            product="MySQL",
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
                    "MySQL schema inventory response is malformed."
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


class MySqlRuntimeFactory:
    """Create one TLS-verified, read-only MySQL connection."""

    def __init__(
        self,
        *,
        symbols: _MySqlSymbols | None = None,
    ) -> None:
        self._symbols = symbols

    def __repr__(self) -> str:
        return (
            "MySqlRuntimeFactory("
            "engine='mysql', "
            "tls='identity-verified', "
            "transactions='read-only', "
            "operations='fixed-metadata-only')"
        )

    def _runtime(self) -> _MySqlSymbols:
        return self._symbols if self._symbols is not None else _load_mysql_symbols()

    def connect(
        self,
        *,
        target: str,
        profile: DatabaseConnectionProfile,
        credential: ResolvedCredential,
    ) -> DatabaseRuntimeSession:
        if profile.engine != DatabaseEngine.MYSQL:
            raise MySqlConnectionError(
                "MySQL runtime received an unsupported database engine."
            )

        timeout = max(1, math.ceil(profile.operation_timeout))
        connection = None

        try:
            with credential.material.reveal_text() as password:
                connection = self._runtime().connect(
                    host=target,
                    port=profile.port,
                    user=profile.username,
                    password=password,
                    database=profile.database_name,
                    connection_timeout=max(
                        1,
                        math.ceil(profile.connect_timeout),
                    ),
                    read_timeout=timeout,
                    write_timeout=timeout,
                    ssl_disabled=False,
                    ssl_verify_cert=True,
                    ssl_verify_identity=True,
                    autocommit=True,
                    use_pure=True,
                )

            cursor = connection.cursor()
            try:
                cursor.execute(_READ_ONLY_SESSION_QUERY)
            finally:
                try:
                    cursor.close()
                except Exception:
                    pass

            return _MySqlSession(connection)
        except Exception:
            if connection is not None:
                try:
                    connection.close()
                except Exception:
                    pass
            raise MySqlConnectionError(
                "MySQL runtime connection or authentication failed."
            ) from None
