"""Tests for NightRecon injectable read-only SMB adapter boundary."""

from __future__ import annotations

import unittest

from nightrecon.credential_resolution import (
    CredentialBinding,
    resolve_credential,
)
from nightrecon.infrastructure_models import (
    CredentialKind,
    CredentialReference,
    CredentialSourceKind,
)
from nightrecon.infrastructure_smb import (
    SmbConnectionProfile,
    SmbShareObservation,
)
from nightrecon.infrastructure_smb_adapter import (
    SmbReadOnlyAdapter,
    SmbServerObservation,
)


_SECRET = "smb-password-secret"


def _credential(
    *,
    kind=CredentialKind.PASSWORD,
):
    reference = CredentialReference(
        credential_id="smb-readonly",
        kind=kind,
        source_kind=CredentialSourceKind.ENVIRONMENT,
    )

    return resolve_credential(
        CredentialBinding(
            reference=reference,
            source_name="NIGHTRECON_SMB_PASSWORD",
        ),
        environment={
            "NIGHTRECON_SMB_PASSWORD": _SECRET,
        },
    )


class _FakeSession:
    def __init__(
        self,
        *,
        identity=None,
        shares=(),
        identity_error=None,
        shares_error=None,
        close_error=None,
    ):
        self.identity = (
            identity
            if identity is not None
            else SmbServerObservation(
                server_name="FILE01",
                domain_name="EXAMPLE",
                dialect="3.1.1",
                signing_required=True,
            )
        )
        self.shares = shares
        self.identity_error = identity_error
        self.shares_error = shares_error
        self.close_error = close_error
        self.max_shares_seen = None
        self.closed = False

    def server_identity(
        self,
    ):
        if self.identity_error is not None:
            raise self.identity_error

        return self.identity

    def list_shares(
        self,
        *,
        max_shares,
    ):
        self.max_shares_seen = (
            max_shares
        )

        if self.shares_error is not None:
            raise self.shares_error

        return self.shares

    def close(
        self,
    ):
        self.closed = True

        if self.close_error is not None:
            raise self.close_error


class _FakeFactory:
    def __init__(
        self,
        session=None,
        *,
        connect_error=None,
    ):
        self.session = (
            session
            if session is not None
            else _FakeSession()
        )
        self.connect_error = (
            connect_error
        )
        self.calls = []

    def connect(
        self,
        *,
        target,
        profile,
        credential,
    ):
        observed_secret = None

        with credential.material.reveal_text() as value:
            observed_secret = value

        self.calls.append(
            {
                "target": target,
                "username": (
                    profile.username
                ),
                "port": profile.port,
                "credential_id": (
                    credential.reference.credential_id
                ),
                "secret_matches": (
                    observed_secret
                    == _SECRET
                ),
            }
        )

        if self.connect_error is not None:
            raise self.connect_error

        return self.session


class SmbAdapterBoundaryTests(unittest.TestCase):
    def _profile(
        self,
        **overrides,
    ):
        values = {
            "username": "audit-user",
            "port": 445,
            "connect_timeout": 3.0,
            "operation_timeout": 4.0,
            "max_shares": 8,
        }
        values.update(
            overrides
        )
        return SmbConnectionProfile(
            **values
        )

    def test_server_identity_uses_injected_runtime_and_typed_facts(self):
        session = _FakeSession()
        factory = _FakeFactory(
            session
        )
        adapter = SmbReadOnlyAdapter(
            self._profile(),
            factory,
        )
        credential = _credential()

        outcome = adapter.execute(
            target="fileserver.example.test",
            action_id="smb.server_identity",
            credential=credential,
        )

        self.assertTrue(
            outcome.success
        )
        self.assertEqual(
            outcome.reason,
            "completed",
        )
        self.assertEqual(
            tuple(
                (
                    fact.key,
                    fact.value,
                )
                for fact in outcome.facts
            ),
            (
                (
                    "smb.server_name",
                    "FILE01",
                ),
                (
                    "smb.domain_name",
                    "EXAMPLE",
                ),
                (
                    "smb.dialect",
                    "3.1.1",
                ),
                (
                    "smb.signing_required",
                    "true",
                ),
            ),
        )
        self.assertEqual(
            factory.calls,
            [
                {
                    "target": "fileserver.example.test",
                    "username": "audit-user",
                    "port": 445,
                    "credential_id": "smb-readonly",
                    "secret_matches": True,
                }
            ],
        )
        self.assertTrue(
            session.closed
        )
        self.assertNotIn(
            _SECRET,
            repr(
                adapter
            ),
        )
        self.assertNotIn(
            _SECRET,
            repr(
                outcome
            ),
        )
        credential.clear()

    def test_share_inventory_respects_profile_limit_and_closes_session(self):
        session = _FakeSession(
            shares=(
                SmbShareObservation(
                    name="Public",
                    share_type="disk",
                ),
                SmbShareObservation(
                    name="IPC$",
                    share_type="ipc",
                ),
            )
        )
        factory = _FakeFactory(
            session
        )
        adapter = SmbReadOnlyAdapter(
            self._profile(
                max_shares=4
            ),
            factory,
        )
        credential = _credential()

        outcome = adapter.execute(
            target="fileserver.example.test",
            action_id="smb.share_inventory",
            credential=credential,
        )

        self.assertTrue(
            outcome.success
        )
        self.assertEqual(
            session.max_shares_seen,
            4,
        )
        self.assertTrue(
            session.closed
        )
        self.assertEqual(
            outcome.facts[0].key,
            "smb.share_count",
        )
        self.assertEqual(
            outcome.facts[0].value,
            "2",
        )
        credential.clear()

    def test_unsupported_action_and_wrong_credential_kind_fail_before_connect(self):
        factory = _FakeFactory()
        adapter = SmbReadOnlyAdapter(
            self._profile(),
            factory,
        )

        credential = _credential()
        unsupported = adapter.execute(
            target="fileserver.example.test",
            action_id="smb.write_file",
            credential=credential,
        )
        credential.clear()

        key_credential = _credential(
            kind=CredentialKind.SSH_KEY
        )
        wrong_kind = adapter.execute(
            target="fileserver.example.test",
            action_id="smb.server_identity",
            credential=key_credential,
        )
        key_credential.clear()

        self.assertFalse(
            unsupported.success
        )
        self.assertEqual(
            unsupported.reason,
            "unsupported_action",
        )
        self.assertFalse(
            wrong_kind.success
        )
        self.assertEqual(
            wrong_kind.reason,
            "credential_kind_not_supported",
        )
        self.assertEqual(
            factory.calls,
            [],
        )

    def test_cleared_credential_fails_before_connect(self):
        factory = _FakeFactory()
        adapter = SmbReadOnlyAdapter(
            self._profile(),
            factory,
        )
        credential = _credential()
        credential.clear()

        outcome = adapter.execute(
            target="fileserver.example.test",
            action_id="smb.server_identity",
            credential=credential,
        )

        self.assertFalse(
            outcome.success
        )
        self.assertEqual(
            outcome.reason,
            "credential_unavailable",
        )
        self.assertEqual(
            factory.calls,
            [],
        )

    def test_invalid_runtime_evidence_is_sanitized_and_session_is_closed(self):
        session = _FakeSession(
            identity=SmbServerObservation(
                server_name="BAD\nNAME",
                domain_name="EXAMPLE",
                dialect="3.1.1",
                signing_required=True,
            )
        )
        factory = _FakeFactory(
            session
        )
        adapter = SmbReadOnlyAdapter(
            self._profile(),
            factory,
        )
        credential = _credential()

        outcome = adapter.execute(
            target="fileserver.example.test",
            action_id="smb.server_identity",
            credential=credential,
        )

        self.assertFalse(
            outcome.success
        )
        self.assertEqual(
            outcome.reason,
            "evidence_invalid",
        )
        self.assertEqual(
            outcome.facts,
            (),
        )
        self.assertTrue(
            session.closed
        )
        self.assertNotIn(
            "BAD",
            repr(
                outcome
            ),
        )
        credential.clear()

    def test_runtime_failures_do_not_leak_exception_or_secret(self):
        errors = (
            RuntimeError(
                "runtime detail " + _SECRET
            ),
            OSError(
                "network detail " + _SECRET
            ),
        )

        for error in errors:
            with self.subTest(
                error=type(
                    error
                ).__name__
            ):
                factory = _FakeFactory(
                    connect_error=error
                )
                adapter = SmbReadOnlyAdapter(
                    self._profile(),
                    factory,
                )
                credential = _credential()

                outcome = adapter.execute(
                    target="fileserver.example.test",
                    action_id="smb.server_identity",
                    credential=credential,
                )

                self.assertFalse(
                    outcome.success
                )
                self.assertEqual(
                    outcome.reason,
                    "smb_failed",
                )
                self.assertNotIn(
                    _SECRET,
                    repr(
                        outcome
                    ),
                )
                credential.clear()

    def test_session_failure_and_close_failure_are_sanitized(self):
        session = _FakeSession(
            identity_error=RuntimeError(
                "identity failure "
                + _SECRET
            ),
            close_error=RuntimeError(
                "close failure "
                + _SECRET
            ),
        )
        factory = _FakeFactory(
            session
        )
        adapter = SmbReadOnlyAdapter(
            self._profile(),
            factory,
        )
        credential = _credential()

        outcome = adapter.execute(
            target="fileserver.example.test",
            action_id="smb.server_identity",
            credential=credential,
        )

        self.assertFalse(
            outcome.success
        )
        self.assertEqual(
            outcome.reason,
            "smb_failed",
        )
        self.assertTrue(
            session.closed
        )
        self.assertNotIn(
            _SECRET,
            repr(
                outcome
            ),
        )
        credential.clear()


if __name__ == "__main__":
    unittest.main()
