"""Tests for NightRecon injectable read-only WinRM adapter boundary."""

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
from nightrecon.infrastructure_winrm import (
    WinRmConnectionProfile,
    WinRmPatchObservation,
    WinRmSystemObservation,
)
from nightrecon.infrastructure_winrm_adapter import (
    WinRmReadOnlyAdapter,
)


_SECRET = "winrm-password-secret"


def _credential(
    *,
    kind=CredentialKind.PASSWORD,
):
    reference = CredentialReference(
        credential_id="winrm-readonly",
        kind=kind,
        source_kind=CredentialSourceKind.ENVIRONMENT,
    )

    return resolve_credential(
        CredentialBinding(
            reference=reference,
            source_name="NIGHTRECON_WINRM_PASSWORD",
        ),
        environment={
            "NIGHTRECON_WINRM_PASSWORD": _SECRET,
        },
    )


class _FakeSession:
    def __init__(
        self,
        *,
        identity=None,
        patches=(),
        identity_error=None,
        patches_error=None,
        close_error=None,
    ):
        self.identity = (
            identity
            if identity is not None
            else WinRmSystemObservation(
                hostname="WIN01",
                os_name="Windows Server 2025",
                os_version="10.0.26100",
                architecture="64-bit",
            )
        )
        self.patches = patches
        self.identity_error = identity_error
        self.patches_error = patches_error
        self.close_error = close_error
        self.max_patches_seen = None
        self.closed = False

    def system_identity(
        self,
    ):
        if self.identity_error is not None:
            raise self.identity_error

        return self.identity

    def list_patches(
        self,
        *,
        max_patches,
    ):
        self.max_patches_seen = (
            max_patches
        )

        if self.patches_error is not None:
            raise self.patches_error

        return self.patches

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
        self.connect_error = connect_error
        self.calls = []

    def connect(
        self,
        *,
        target,
        profile,
        credential,
    ):
        with credential.material.reveal_text() as value:
            secret_matches = (
                value == _SECRET
            )

        self.calls.append(
            {
                "target": target,
                "username": profile.username,
                "port": profile.port,
                "use_tls": profile.use_tls,
                "validate_server_certificate": (
                    profile.validate_server_certificate
                ),
                "credential_id": (
                    credential.reference.credential_id
                ),
                "secret_matches": secret_matches,
            }
        )

        if self.connect_error is not None:
            raise self.connect_error

        return self.session


class WinRmAdapterBoundaryTests(unittest.TestCase):
    def _profile(
        self,
        **overrides,
    ):
        values = {
            "username": "audit-user",
            "port": 5986,
            "connect_timeout": 3.0,
            "operation_timeout": 4.0,
            "max_patches": 8,
            "use_tls": True,
            "validate_server_certificate": True,
        }
        values.update(
            overrides
        )
        return WinRmConnectionProfile(
            **values
        )

    def test_system_identity_uses_injected_runtime_and_typed_facts(self):
        session = _FakeSession()
        factory = _FakeFactory(
            session
        )
        adapter = WinRmReadOnlyAdapter(
            self._profile(),
            factory,
        )
        credential = _credential()

        outcome = adapter.execute(
            target="win01.example.test",
            action_id="winrm.system_identity",
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
                    "windows.hostname",
                    "WIN01",
                ),
                (
                    "windows.os_name",
                    "Windows Server 2025",
                ),
                (
                    "windows.os_version",
                    "10.0.26100",
                ),
                (
                    "windows.architecture",
                    "64-bit",
                ),
            ),
        )
        self.assertEqual(
            factory.calls[0]["secret_matches"],
            True,
        )
        self.assertTrue(
            factory.calls[0]["use_tls"]
        )
        self.assertTrue(
            factory.calls[0]["validate_server_certificate"]
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

    def test_patch_inventory_respects_limit_and_closes_session(self):
        session = _FakeSession(
            patches=(
                WinRmPatchObservation(
                    hotfix_id="KB5031234",
                ),
                WinRmPatchObservation(
                    hotfix_id="5035678",
                ),
            )
        )
        factory = _FakeFactory(
            session
        )
        adapter = WinRmReadOnlyAdapter(
            self._profile(
                max_patches=4
            ),
            factory,
        )
        credential = _credential()

        outcome = adapter.execute(
            target="win01.example.test",
            action_id="winrm.patch_inventory",
            credential=credential,
        )

        self.assertTrue(
            outcome.success
        )
        self.assertEqual(
            session.max_patches_seen,
            4,
        )
        self.assertTrue(
            session.closed
        )
        self.assertEqual(
            outcome.facts[0].key,
            "windows.patch_count",
        )
        self.assertEqual(
            outcome.facts[0].value,
            "2",
        )
        credential.clear()

    def test_unsupported_action_and_wrong_credential_kind_fail_before_connect(self):
        factory = _FakeFactory()
        adapter = WinRmReadOnlyAdapter(
            self._profile(),
            factory,
        )

        credential = _credential()
        unsupported = adapter.execute(
            target="win01.example.test",
            action_id="winrm.run_powershell",
            credential=credential,
        )
        credential.clear()

        key_credential = _credential(
            kind=CredentialKind.SSH_KEY
        )
        wrong_kind = adapter.execute(
            target="win01.example.test",
            action_id="winrm.system_identity",
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
        adapter = WinRmReadOnlyAdapter(
            self._profile(),
            factory,
        )
        credential = _credential()
        credential.clear()

        outcome = adapter.execute(
            target="win01.example.test",
            action_id="winrm.system_identity",
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
            identity=WinRmSystemObservation(
                hostname="BAD\nNAME",
                os_name="Windows Server",
                os_version="10.0",
                architecture="64-bit",
            )
        )
        adapter = WinRmReadOnlyAdapter(
            self._profile(),
            _FakeFactory(
                session
            ),
        )
        credential = _credential()

        outcome = adapter.execute(
            target="win01.example.test",
            action_id="winrm.system_identity",
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

    def test_runtime_and_close_failures_are_sanitized(self):
        session = _FakeSession(
            identity_error=RuntimeError(
                "identity detail " + _SECRET
            ),
            close_error=RuntimeError(
                "close detail " + _SECRET
            ),
        )
        adapter = WinRmReadOnlyAdapter(
            self._profile(),
            _FakeFactory(
                session
            ),
        )
        credential = _credential()

        outcome = adapter.execute(
            target="win01.example.test",
            action_id="winrm.system_identity",
            credential=credential,
        )

        self.assertFalse(
            outcome.success
        )
        self.assertEqual(
            outcome.reason,
            "winrm_failed",
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

    def test_connect_failure_is_sanitized_without_secret_leak(self):
        factory = _FakeFactory(
            connect_error=RuntimeError(
                "connect detail " + _SECRET
            )
        )
        adapter = WinRmReadOnlyAdapter(
            self._profile(),
            factory,
        )
        credential = _credential()

        outcome = adapter.execute(
            target="win01.example.test",
            action_id="winrm.system_identity",
            credential=credential,
        )

        self.assertFalse(
            outcome.success
        )
        self.assertEqual(
            outcome.reason,
            "winrm_failed",
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
