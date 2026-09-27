"""Tests for the narrow psycopg PostgreSQL runtime."""

from __future__ import annotations

import unittest

from nightrecon.credential_resolution import CredentialBinding, resolve_credential
from nightrecon.infrastructure_database import DatabaseConnectionProfile, DatabaseEngine
from nightrecon.infrastructure_database_psycopg import (
    PsycopgConnectionError,
    PsycopgRuntimeFactory,
    _PsycopgSymbols,
    _SCHEMA_INVENTORY_QUERY,
    _SERVER_VERSION_QUERY,
)
from nightrecon.infrastructure_models import (
    CredentialKind,
    CredentialReference,
    CredentialSourceKind,
)


_SECRET = "postgres-password-secret"


def _credential():
    return resolve_credential(
        CredentialBinding(
            reference=CredentialReference(
                credential_id="postgres-readonly",
                kind=CredentialKind.PASSWORD,
                source_kind=CredentialSourceKind.ENVIRONMENT,
            ),
            source_name="NIGHTRECON_POSTGRES_PASSWORD",
        ),
        environment={"NIGHTRECON_POSTGRES_PASSWORD": _SECRET},
    )


class _FakeCursor:
    def __init__(self, responses):
        self.responses = responses
        self.query = None
        self.fetch_limit = None
        self.closed = False

    def execute(self, query):
        self.query = query

    def fetchmany(self, limit):
        self.fetch_limit = limit
        response = self.responses[self.query]
        if isinstance(response, BaseException):
            raise response
        return response[:limit]

    def close(self):
        self.closed = True


class _FakeConnection:
    def __init__(self, responses):
        self.responses = responses
        self.cursors = []
        self.closed = False

    def cursor(self):
        cursor = _FakeCursor(self.responses)
        self.cursors.append(cursor)
        return cursor

    def close(self):
        self.closed = True


class _FakeConnect:
    def __init__(self, responses=None, error=None):
        self.responses = responses or {
            _SERVER_VERSION_QUERY: [("17.2",)],
            _SCHEMA_INVENTORY_QUERY: [("audit",), ("public",)],
        }
        self.error = error
        self.calls = []
        self.connection = None

    def __call__(self, **kwargs):
        self.calls.append(kwargs)
        if self.error is not None:
            raise self.error
        self.connection = _FakeConnection(self.responses)
        return self.connection


class PsycopgRuntimeTests(unittest.TestCase):
    def _profile(self, **overrides):
        values = {
            "engine": DatabaseEngine.POSTGRESQL,
            "username": "audit-user",
            "database_name": "postgres",
            "port": 5432,
            "connect_timeout": 3.2,
            "operation_timeout": 4.1,
            "max_schemas": 8,
            "use_tls": True,
            "validate_server_certificate": True,
        }
        values.update(overrides)
        return DatabaseConnectionProfile(**values)

    def test_factory_forces_verified_tls_and_read_only_timeouts(self):
        connect = _FakeConnect()
        factory = PsycopgRuntimeFactory(
            symbols=_PsycopgSymbols(connect=connect)
        )
        credential = _credential()

        session = factory.connect(
            target="db01.example.test",
            profile=self._profile(),
            credential=credential,
        )

        call = connect.calls[0]
        self.assertEqual(call["host"], "db01.example.test")
        self.assertEqual(call["password"], _SECRET)
        self.assertEqual(call["sslmode"], "verify-full")
        self.assertEqual(call["connect_timeout"], 4)
        self.assertTrue(call["autocommit"])
        self.assertIn("default_transaction_read_only=on", call["options"])
        self.assertIn("statement_timeout=4100", call["options"])
        self.assertNotIn(_SECRET, repr(factory))

        session.close()
        credential.clear()
        self.assertTrue(connect.connection.closed)

    def test_server_identity_uses_only_fixed_internal_query(self):
        connect = _FakeConnect()
        credential = _credential()
        session = PsycopgRuntimeFactory(
            symbols=_PsycopgSymbols(connect=connect)
        ).connect(
            target="db01.example.test",
            profile=self._profile(),
            credential=credential,
        )

        observation = session.server_identity()

        self.assertEqual(observation.engine, DatabaseEngine.POSTGRESQL)
        self.assertEqual(observation.product, "PostgreSQL")
        self.assertEqual(observation.version, "17.2")
        cursor = connect.connection.cursors[0]
        self.assertEqual(cursor.query, _SERVER_VERSION_QUERY)
        self.assertEqual(cursor.fetch_limit, 2)
        self.assertTrue(cursor.closed)
        self.assertNotIn(_SECRET, _SERVER_VERSION_QUERY)
        session.close()
        credential.clear()

    def test_schema_inventory_uses_fixed_query_and_bound(self):
        connect = _FakeConnect()
        credential = _credential()
        session = PsycopgRuntimeFactory(
            symbols=_PsycopgSymbols(connect=connect)
        ).connect(
            target="db01.example.test",
            profile=self._profile(),
            credential=credential,
        )

        observations = session.list_schemas(max_schemas=4)

        self.assertEqual(
            tuple(item.name for item in observations),
            ("audit", "public"),
        )
        cursor = connect.connection.cursors[0]
        self.assertEqual(cursor.query, _SCHEMA_INVENTORY_QUERY)
        self.assertEqual(cursor.fetch_limit, 5)
        session.close()
        credential.clear()

    def test_row_ceiling_and_malformed_rows_fail_closed(self):
        connect = _FakeConnect(
            responses={
                _SERVER_VERSION_QUERY: [("17.2",)],
                _SCHEMA_INVENTORY_QUERY: [("a",), ("b",)],
            }
        )
        credential = _credential()
        session = PsycopgRuntimeFactory(
            symbols=_PsycopgSymbols(connect=connect)
        ).connect(
            target="db01.example.test",
            profile=self._profile(),
            credential=credential,
        )
        with self.assertRaisesRegex(ValueError, "more rows"):
            session.list_schemas(max_schemas=1)
        session.close()
        credential.clear()

        malformed = _FakeConnect(
            responses={
                _SERVER_VERSION_QUERY: [("17", "extra")],
                _SCHEMA_INVENTORY_QUERY: [(123,)],
            }
        )
        credential = _credential()
        session = PsycopgRuntimeFactory(
            symbols=_PsycopgSymbols(connect=malformed)
        ).connect(
            target="db01.example.test",
            profile=self._profile(),
            credential=credential,
        )
        with self.assertRaisesRegex(ValueError, "identity"):
            session.server_identity()
        with self.assertRaisesRegex(ValueError, "schema"):
            session.list_schemas(max_schemas=2)
        session.close()
        credential.clear()

    def test_non_postgresql_engine_fails_before_connect(self):
        connect = _FakeConnect()
        credential = _credential()
        factory = PsycopgRuntimeFactory(
            symbols=_PsycopgSymbols(connect=connect)
        )
        with self.assertRaises(PsycopgConnectionError):
            factory.connect(
                target="db01.example.test",
                profile=self._profile(
                    engine=DatabaseEngine.MYSQL,
                    port=3306,
                ),
                credential=credential,
            )
        self.assertEqual(connect.calls, [])
        credential.clear()

    def test_connection_failure_is_sanitized(self):
        connect = _FakeConnect(
            error=RuntimeError("driver detail " + _SECRET)
        )
        credential = _credential()
        factory = PsycopgRuntimeFactory(
            symbols=_PsycopgSymbols(connect=connect)
        )
        with self.assertRaises(PsycopgConnectionError) as context:
            factory.connect(
                target="db01.example.test",
                profile=self._profile(),
                credential=credential,
            )
        self.assertNotIn(_SECRET, str(context.exception))
        self.assertNotIn(_SECRET, repr(context.exception))
        credential.clear()


if __name__ == "__main__":
    unittest.main()
