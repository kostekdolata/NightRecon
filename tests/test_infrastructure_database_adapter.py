"""Tests for the injectable read-only database adapter boundary."""

from __future__ import annotations

import unittest

from nightrecon.credential_resolution import CredentialBinding, resolve_credential
from nightrecon.infrastructure_database import (
    DatabaseConnectionProfile,
    DatabaseEngine,
    DatabaseSchemaObservation,
    DatabaseServerObservation,
)
from nightrecon.infrastructure_database_adapter import DatabaseReadOnlyAdapter
from nightrecon.infrastructure_models import (
    CredentialKind,
    CredentialReference,
    CredentialSourceKind,
)


_SECRET = "database-password-secret"


def _credential(*, kind=CredentialKind.PASSWORD):
    return resolve_credential(
        CredentialBinding(
            reference=CredentialReference(
                credential_id="database-readonly",
                kind=kind,
                source_kind=CredentialSourceKind.ENVIRONMENT,
            ),
            source_name="NIGHTRECON_DATABASE_PASSWORD",
        ),
        environment={"NIGHTRECON_DATABASE_PASSWORD": _SECRET},
    )


class _FakeSession:
    def __init__(
        self,
        *,
        identity=None,
        schemas=(),
        identity_error=None,
        schemas_error=None,
        close_error=None,
    ):
        self.identity = identity or DatabaseServerObservation(
            engine=DatabaseEngine.POSTGRESQL,
            product="PostgreSQL",
            version="17.2",
        )
        self.schemas = schemas
        self.identity_error = identity_error
        self.schemas_error = schemas_error
        self.close_error = close_error
        self.max_schemas_seen = None
        self.closed = False

    def server_identity(self):
        if self.identity_error is not None:
            raise self.identity_error
        return self.identity

    def list_schemas(self, *, max_schemas):
        self.max_schemas_seen = max_schemas
        if self.schemas_error is not None:
            raise self.schemas_error
        return self.schemas

    def close(self):
        self.closed = True
        if self.close_error is not None:
            raise self.close_error


class _FakeFactory:
    def __init__(self, session=None, *, connect_error=None):
        self.session = session or _FakeSession()
        self.connect_error = connect_error
        self.calls = []

    def connect(self, *, target, profile, credential):
        with credential.material.reveal_text() as value:
            secret_matches = value == _SECRET
        self.calls.append(
            {
                "target": target,
                "engine": profile.engine,
                "username": profile.username,
                "database_name": profile.database_name,
                "use_tls": profile.use_tls,
                "validate_server_certificate": profile.validate_server_certificate,
                "credential_id": credential.reference.credential_id,
                "secret_matches": secret_matches,
            }
        )
        if self.connect_error is not None:
            raise self.connect_error
        return self.session


class DatabaseAdapterBoundaryTests(unittest.TestCase):
    def _profile(self, **overrides):
        values = {
            "engine": DatabaseEngine.POSTGRESQL,
            "username": "audit-user",
            "database_name": "postgres",
            "port": 5432,
            "connect_timeout": 3.0,
            "operation_timeout": 4.0,
            "max_schemas": 8,
            "use_tls": True,
            "validate_server_certificate": True,
        }
        values.update(overrides)
        return DatabaseConnectionProfile(**values)

    def test_server_identity_uses_injected_runtime_and_typed_facts(self):
        session = _FakeSession()
        factory = _FakeFactory(session)
        adapter = DatabaseReadOnlyAdapter(self._profile(), factory)
        credential = _credential()

        outcome = adapter.execute(
            target="db01.example.test",
            action_id="database.server_identity",
            credential=credential,
        )

        self.assertTrue(outcome.success)
        self.assertEqual(outcome.reason, "completed")
        self.assertEqual(
            tuple((fact.key, fact.value) for fact in outcome.facts),
            (
                ("database.engine", "postgresql"),
                ("database.product", "PostgreSQL"),
                ("database.version", "17.2"),
            ),
        )
        self.assertTrue(factory.calls[0]["secret_matches"])
        self.assertTrue(factory.calls[0]["use_tls"])
        self.assertTrue(factory.calls[0]["validate_server_certificate"])
        self.assertTrue(session.closed)
        self.assertNotIn(_SECRET, repr(adapter))
        self.assertNotIn(_SECRET, repr(outcome))
        credential.clear()

    def test_schema_inventory_respects_limit_and_closes_session(self):
        session = _FakeSession(
            schemas=(
                DatabaseSchemaObservation(name="public"),
                DatabaseSchemaObservation(name="audit"),
            )
        )
        adapter = DatabaseReadOnlyAdapter(
            self._profile(max_schemas=4),
            _FakeFactory(session),
        )
        credential = _credential()

        outcome = adapter.execute(
            target="db01.example.test",
            action_id="database.schema_inventory",
            credential=credential,
        )

        self.assertTrue(outcome.success)
        self.assertEqual(session.max_schemas_seen, 4)
        self.assertTrue(session.closed)
        self.assertEqual(outcome.facts[0].key, "database.schema_count")
        self.assertEqual(outcome.facts[0].value, "2")
        credential.clear()

    def test_unsupported_action_and_wrong_kind_fail_before_connect(self):
        factory = _FakeFactory()
        adapter = DatabaseReadOnlyAdapter(self._profile(), factory)

        credential = _credential()
        unsupported = adapter.execute(
            target="db01.example.test",
            action_id="database.run_query",
            credential=credential,
        )
        credential.clear()

        wrong_credential = _credential(kind=CredentialKind.TOKEN)
        wrong_kind = adapter.execute(
            target="db01.example.test",
            action_id="database.server_identity",
            credential=wrong_credential,
        )
        wrong_credential.clear()

        self.assertEqual(unsupported.reason, "unsupported_action")
        self.assertEqual(wrong_kind.reason, "credential_kind_not_supported")
        self.assertEqual(factory.calls, [])

    def test_cleared_credential_fails_before_connect(self):
        factory = _FakeFactory()
        adapter = DatabaseReadOnlyAdapter(self._profile(), factory)
        credential = _credential()
        credential.clear()

        outcome = adapter.execute(
            target="db01.example.test",
            action_id="database.server_identity",
            credential=credential,
        )

        self.assertEqual(outcome.reason, "credential_unavailable")
        self.assertEqual(factory.calls, [])

    def test_invalid_evidence_is_sanitized_and_session_closed(self):
        session = _FakeSession(
            identity=DatabaseServerObservation(
                engine=DatabaseEngine.POSTGRESQL,
                product="BAD\nPRODUCT",
                version="17",
            )
        )
        adapter = DatabaseReadOnlyAdapter(
            self._profile(),
            _FakeFactory(session),
        )
        credential = _credential()

        outcome = adapter.execute(
            target="db01.example.test",
            action_id="database.server_identity",
            credential=credential,
        )

        self.assertEqual(outcome.reason, "evidence_invalid")
        self.assertEqual(outcome.facts, ())
        self.assertTrue(session.closed)
        self.assertNotIn("BAD", repr(outcome))
        credential.clear()

    def test_runtime_and_close_failures_are_sanitized(self):
        session = _FakeSession(
            identity_error=RuntimeError("runtime " + _SECRET),
            close_error=RuntimeError("close " + _SECRET),
        )
        adapter = DatabaseReadOnlyAdapter(
            self._profile(),
            _FakeFactory(session),
        )
        credential = _credential()

        outcome = adapter.execute(
            target="db01.example.test",
            action_id="database.server_identity",
            credential=credential,
        )

        self.assertEqual(outcome.reason, "database_failed")
        self.assertTrue(session.closed)
        self.assertNotIn(_SECRET, repr(outcome))
        credential.clear()

    def test_connect_failure_is_sanitized(self):
        adapter = DatabaseReadOnlyAdapter(
            self._profile(),
            _FakeFactory(
                connect_error=RuntimeError("connect " + _SECRET)
            ),
        )
        credential = _credential()

        outcome = adapter.execute(
            target="db01.example.test",
            action_id="database.server_identity",
            credential=credential,
        )

        self.assertEqual(outcome.reason, "database_failed")
        self.assertNotIn(_SECRET, repr(outcome))
        credential.clear()


if __name__ == "__main__":
    unittest.main()
