"""Tests for NightRecon narrow pywinrm runtime wrapper."""

from __future__ import annotations

import json
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
)
from nightrecon.infrastructure_winrm_pywinrm import (
    PyWinRmConnectionError,
    PyWinRmRuntimeFactory,
    _PATCH_INVENTORY_SCRIPT,
    _PyWinRmSymbols,
    _SYSTEM_IDENTITY_SCRIPT,
)


_SECRET = "pywinrm-password-secret"


def _credential():
    return resolve_credential(
        CredentialBinding(
            reference=CredentialReference(
                credential_id="winrm-readonly",
                kind=CredentialKind.PASSWORD,
                source_kind=CredentialSourceKind.ENVIRONMENT,
            ),
            source_name="NIGHTRECON_WINRM_PASSWORD",
        ),
        environment={
            "NIGHTRECON_WINRM_PASSWORD": _SECRET,
        },
    )


class _FakeRequestsSession:
    def __init__(
        self,
    ):
        self.closed = False

    def close(
        self,
    ):
        self.closed = True


class _FakeTransport:
    def __init__(
        self,
    ):
        self.session = (
            _FakeRequestsSession()
        )


class _FakeProtocol:
    def __init__(
        self,
    ):
        self.transport = (
            _FakeTransport()
        )


class _FakeResponse:
    def __init__(
        self,
        *,
        status_code=0,
        stdout=b"{}",
        stderr=b"",
    ):
        self.status_code = status_code
        self.std_out = stdout
        self.std_err = stderr


class _FakeSession:
    calls = []
    responses = []

    def __init__(
        self,
        target,
        auth,
        **kwargs,
    ):
        self.target = target
        self.auth = auth
        self.kwargs = kwargs
        self.protocol = _FakeProtocol()
        self.scripts = []
        type(
            self
        ).calls.append(
            {
                "target": target,
                "auth": auth,
                "kwargs": kwargs,
                "instance": self,
            }
        )

    def run_ps(
        self,
        script,
    ):
        self.scripts.append(
            script
        )

        if not type(
            self
        ).responses:
            raise RuntimeError(
                "missing fake response"
            )

        response = type(
            self
        ).responses.pop(
            0
        )

        if isinstance(
            response,
            BaseException,
        ):
            raise response

        return response


class _ExplodingSession:
    def __init__(
        self,
        target,
        auth,
        **kwargs,
    ):
        raise RuntimeError(
            "constructor failure "
            + _SECRET
        )


class PyWinRmRuntimeTests(unittest.TestCase):
    def setUp(
        self,
    ):
        _FakeSession.calls = []
        _FakeSession.responses = []

    def _profile(
        self,
        **overrides,
    ):
        values = {
            "username": "audit-user",
            "port": 5986,
            "connect_timeout": 3.2,
            "operation_timeout": 4.1,
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

    def _factory(
        self,
    ):
        return PyWinRmRuntimeFactory(
            symbols=_PyWinRmSymbols(
                Session=_FakeSession
            )
        )

    def test_factory_builds_https_validated_ntlm_session_without_proxy(self):
        credential = _credential()
        runtime = self._factory()

        session = runtime.connect(
            target="win01.example.test",
            profile=self._profile(),
            credential=credential,
        )

        self.assertEqual(
            len(
                _FakeSession.calls
            ),
            1,
        )
        call = _FakeSession.calls[0]
        self.assertEqual(
            call["target"],
            "https://win01.example.test:5986/wsman",
        )
        self.assertEqual(
            call["auth"],
            (
                "audit-user",
                _SECRET,
            ),
        )
        self.assertEqual(
            call["kwargs"]["transport"],
            "ntlm",
        )
        self.assertEqual(
            call["kwargs"]["server_cert_validation"],
            "validate",
        )
        self.assertIsNone(
            call["kwargs"]["proxy"]
        )
        self.assertEqual(
            call["kwargs"]["operation_timeout_sec"],
            5,
        )
        self.assertEqual(
            call["kwargs"]["read_timeout_sec"],
            6,
        )
        self.assertNotIn(
            _SECRET,
            repr(
                runtime
            ),
        )

        session.close()
        credential.clear()

        self.assertTrue(
            call["instance"]
            .protocol.transport.session.closed
        )

    def test_system_identity_uses_only_fixed_internal_script(self):
        _FakeSession.responses = [
            _FakeResponse(
                stdout=json.dumps(
                    {
                        "hostname": "WIN01",
                        "os_name": "Windows Server 2025",
                        "os_version": "10.0.26100",
                        "architecture": "64-bit",
                    }
                ).encode(
                    "utf-8"
                )
            )
        ]
        credential = _credential()
        session = self._factory().connect(
            target="win01.example.test",
            profile=self._profile(),
            credential=credential,
        )

        observation = (
            session.system_identity()
        )

        self.assertEqual(
            observation.hostname,
            "WIN01",
        )
        self.assertEqual(
            observation.os_name,
            "Windows Server 2025",
        )
        self.assertEqual(
            _FakeSession.calls[0][
                "instance"
            ].scripts,
            [
                _SYSTEM_IDENTITY_SCRIPT,
            ],
        )
        self.assertNotIn(
            "audit-user",
            _SYSTEM_IDENTITY_SCRIPT,
        )
        self.assertNotIn(
            _SECRET,
            _SYSTEM_IDENTITY_SCRIPT,
        )

        session.close()
        credential.clear()

    def test_patch_inventory_uses_only_fixed_script_and_preserves_bound(self):
        _FakeSession.responses = [
            _FakeResponse(
                stdout=json.dumps(
                    [
                        "KB5031234",
                        "KB5035678",
                    ]
                ).encode(
                    "utf-8"
                )
            )
        ]
        credential = _credential()
        session = self._factory().connect(
            target="win01.example.test",
            profile=self._profile(),
            credential=credential,
        )

        observations = (
            session.list_patches(
                max_patches=4
            )
        )

        self.assertEqual(
            tuple(
                item.hotfix_id
                for item in observations
            ),
            (
                "KB5031234",
                "KB5035678",
            ),
        )
        self.assertEqual(
            _FakeSession.calls[0][
                "instance"
            ].scripts,
            [
                _PATCH_INVENTORY_SCRIPT,
            ],
        )

        session.close()
        credential.clear()

    def test_single_patch_json_value_is_normalized_to_one_observation(self):
        _FakeSession.responses = [
            _FakeResponse(
                stdout=b'"KB5031234"'
            )
        ]
        credential = _credential()
        session = self._factory().connect(
            target="win01.example.test",
            profile=self._profile(),
            credential=credential,
        )

        observations = (
            session.list_patches(
                max_patches=4
            )
        )

        self.assertEqual(
            len(
                observations
            ),
            1,
        )
        self.assertEqual(
            observations[0].hotfix_id,
            "KB5031234",
        )

        session.close()
        credential.clear()

    def test_patch_count_and_json_byte_limits_fail_closed(self):
        _FakeSession.responses = [
            _FakeResponse(
                stdout=json.dumps(
                    [
                        "KB5031234",
                        "KB5035678",
                    ]
                ).encode(
                    "utf-8"
                )
            ),
            _FakeResponse(
                stdout=(
                    b'"'
                    + b"A" * 262_145
                    + b'"'
                )
            ),
        ]
        credential = _credential()
        session = self._factory().connect(
            target="win01.example.test",
            profile=self._profile(),
            credential=credential,
        )

        with self.assertRaisesRegex(
            ValueError,
            "more patches",
        ):
            session.list_patches(
                max_patches=1
            )

        with self.assertRaisesRegex(
            ValueError,
            "bounded JSON output limit",
        ):
            session.system_identity()

        session.close()
        credential.clear()

    def test_nonzero_status_and_malformed_json_do_not_expose_stderr(self):
        _FakeSession.responses = [
            _FakeResponse(
                status_code=1,
                stderr=(
                    "remote detail "
                    + _SECRET
                ).encode(
                    "utf-8"
                ),
            ),
            _FakeResponse(
                stdout=b"{not-json",
            ),
        ]
        credential = _credential()
        session = self._factory().connect(
            target="win01.example.test",
            profile=self._profile(),
            credential=credential,
        )

        with self.assertRaises(
            RuntimeError
        ) as status_error:
            session.system_identity()

        self.assertNotIn(
            _SECRET,
            str(
                status_error.exception
            ),
        )

        with self.assertRaisesRegex(
            ValueError,
            "valid JSON",
        ):
            session.system_identity()

        session.close()
        credential.clear()

    def test_constructor_failure_is_sanitized(self):
        credential = _credential()
        factory = PyWinRmRuntimeFactory(
            symbols=_PyWinRmSymbols(
                Session=_ExplodingSession
            )
        )

        with self.assertRaises(
            PyWinRmConnectionError
        ) as context:
            factory.connect(
                target="win01.example.test",
                profile=self._profile(),
                credential=credential,
            )

        self.assertNotIn(
            _SECRET,
            str(
                context.exception
            ),
        )
        self.assertNotIn(
            _SECRET,
            repr(
                context.exception
            ),
        )
        credential.clear()


if __name__ == "__main__":
    unittest.main()
