"""Tests for the narrow mysql-connector runtime."""

from __future__ import annotations

import unittest

from nightrecon.credential_resolution import CredentialBinding, resolve_credential
from nightrecon.infrastructure_database import DatabaseConnectionProfile, DatabaseEngine
from nightrecon.infrastructure_database_mysql import (
    MySqlConnectionError,
    MySqlRuntimeFactory,
    _MySqlSymbols,
    _READ_ONLY_SESSION_QUERY,
    _SCHEMA_INVENTORY_QUERY,
    _SERVER_VERSION_QUERY,
)
from nightrecon.infrastructure_models import (
    CredentialKind,
    CredentialReference,
    CredentialSourceKind,
)


_SECRET = "mysql-password-secret"


def _credential():
    return resolve_credential(
        CredentialBinding(
            reference=CredentialReference(
                credential_id="mysql-readonly",
                kind=CredentialKind.PASSWORD,
                source_kind=CredentialSourceKind.ENVIRONMENT,
            ),
            source_name="NIGHTRECON_MYSQL_PASSWORD",
        ),
        environment={"NIGHTRECON_MYSQL_PASSWORD": _SECRET},
    )


class _FakeCursor:
    def __init__(self, responses):
        self.responses = responses
        self.query = None
        self.fetch_limit = None
        self.closed = False

    def execute(self, query):
        self.query = query
        response = self.responses.get(query)
        if isinstance(response, BaseException):
            raise response

    def fetchmany(self, *, size):
        self.fetch_limit = size
        return self.responses[self.query][:size]

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
            _READ_ONLY_SESSION_QUERY: None,
            _SERVER_VERSION_QUERY: [("9.0.1",)],
            _SCHEMA_INVENTORY_QUERY: [("audit",), ("information_schema",)],
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


class MySqlRuntimeTests(unittest.TestCase):
    def _profile(self, **overrides):
        values = {
            "engine": DatabaseEngine.MYSQL,
            "username": "audit-user",
            "database_name": "mysql",
            "port": 3306,
            "connect_timeout": 3.2,
            "operation_timeout": 4.1,
            "max_schemas": 8,
            "use_tls": True,
            "validate_server_certificate": True,
        }
        values.update(overrides)
        return DatabaseConnectionProfile(**values)

    def test_factory_forces_tls_identity_and_read_only_session(self):
        connect = _FakeConnect()
        factory = MySqlRuntimeFactory(
            symbols=_MySqlSymbols(connect=connect)
        )
        credential = _credential()

        session = factory.connect(
            target="db02.example.test",
            profile=self._profile(),
            credential=credential,
        )

        call = connect.calls[0]
        self.assertEqual(call["host"], "db02.example.test")
        self.assertEqual(call["password"], _SECRET)
        self.assertFalse(call["ssl_disabled"])
        self.assertTrue(call["ssl_verify_cert"])
        self.assertTrue(call["ssl_verify_identity"])
        self.assertEqual(call["connection_timeout"], 4)
        self.assertEqual(call["read_timeout"], 5)
        self.assertEqual(call["write_timeout"], 5)
        self.assertTrue(call["autocommit"])
        self.assertTrue(call["use_pure"])
        self.assertEqual(
            connect.connection.cursors[0].query,
            _READ_ONLY_SESSION_QUERY,
        )
        self.assertNotIn(_SECRET, repr(factory))

        session.close()
        credential.clear()
        self.assertTrue(connect.connection.closed)

    def test_server_identity_uses_only_fixed_internal_query(self):
        connect = _FakeConnect()
        credential = _credential()
        session = MySqlRuntimeFactory(
            symbols=_MySqlSymbols(connect=connect)
        ).connect(
            target="db02.example.test",
            profile=self._profile(),
            credential=credential,
        )

        observation = session.server_identity()

        self.assertEqual(observation.engine, DatabaseEngine.MYSQL)
        self.assertEqual(observation.product, "MySQL")
        self.assertEqual(observation.version, "9.0.1")
        cursor = connect.connection.cursors[1]
        self.assertEqual(cursor.query, _SERVER_VERSION_QUERY)
        self.assertEqual(cursor.fetch_limit, 2)
        self.assertTrue(cursor.closed)
        self.assertNotIn(_SECRET, _SERVER_VERSION_QUERY)
        session.close()
        credential.clear()

    def test_schema_inventory_uses_fixed_query_and_bound(self):
        connect = _FakeConnect()
        credential = _credential()
        session = MySqlRuntimeFactory(
            symbols=_MySqlSymbols(connect=connect)
        ).connect(
            target="db02.example.test",
            profile=self._profile(),
            credential=credential,
        )

        observations = session.list_schemas(max_schemas=4)

        self.assertEqual(
            tuple(item.name for item in observations),
            ("audit", "information_schema"),
        )
        cursor = connect.connection.cursors[1]
        self.assertEqual(cursor.query, _SCHEMA_INVENTORY_QUERY)
        self.assertEqual(cursor.fetch_limit, 5)
        session.close()
        credential.clear()

    def test_row_ceiling_and_malformed_rows_fail_closed(self):
        connect = _FakeConnect(
            responses={
                _READ_ONLY_SESSION_QUERY: None,
                _SERVER_VERSION_QUERY: [("9.0.1",)],
                _SCHEMA_INVENTORY_QUERY: [("a",), ("b",)],
            }
        )
        credential = _credential()
        session = MySqlRuntimeFactory(
            symbols=_MySqlSymbols(connect=connect)
        ).connect(
            target="db02.example.test",
            profile=self._profile(),
            credential=credential,
        )
        with self.assertRaisesRegex(ValueError, "more rows"):
            session.list_schemas(max_schemas=1)
        session.close()
        credential.clear()

        malformed = _FakeConnect(
            responses={
                _READ_ONLY_SESSION_QUERY: None,
                _SERVER_VERSION_QUERY: [("9", "extra")],
                _SCHEMA_INVENTORY_QUERY: [(123,)],
            }
        )
        credential = _credential()
        session = MySqlRuntimeFactory(
            symbols=_MySqlSymbols(connect=malformed)
        ).connect(
            target="db02.example.test",
            profile=self._profile(),
            credential=credential,
        )
        with self.assertRaisesRegex(ValueError, "identity"):
            session.server_identity()
        with self.assertRaisesRegex(ValueError, "schema"):
            session.list_schemas(max_schemas=2)
        session.close()
        credential.clear()

    def test_non_mysql_engine_fails_before_connect(self):
        connect = _FakeConnect()
        credential = _credential()
        factory = MySqlRuntimeFactory(
            symbols=_MySqlSymbols(connect=connect)
        )
        with self.assertRaises(MySqlConnectionError):
            factory.connect(
                target="db02.example.test",
                profile=self._profile(
                    engine=DatabaseEngine.POSTGRESQL,
                    port=5432,
                ),
                credential=credential,
            )
        self.assertEqual(connect.calls, [])
        credential.clear()

    def test_connection_and_read_only_setup_failures_are_sanitized(self):
        for responses, error in (
            (None, RuntimeError("connect " + _SECRET)),
            (
                {
                    _READ_ONLY_SESSION_QUERY: RuntimeError("setup " + _SECRET),
                    _SERVER_VERSION_QUERY: [("9.0.1",)],
                    _SCHEMA_INVENTORY_QUERY: [],
                },
                None,
            ),
        ):
            connect = _FakeConnect(responses=responses, error=error)
            credential = _credential()
            factory = MySqlRuntimeFactory(
                symbols=_MySqlSymbols(connect=connect)
            )
            with self.assertRaises(MySqlConnectionError) as context:
                factory.connect(
                    target="db02.example.test",
                    profile=self._profile(),
                    credential=credential,
                )
            self.assertNotIn(_SECRET, str(context.exception))
            self.assertNotIn(_SECRET, repr(context.exception))
            if connect.connection is not None:
                self.assertTrue(connect.connection.closed)
            credential.clear()


if __name__ == "__main__":
    unittest.main()
