"""Tests for NightRecon narrow Impacket SMB runtime wrapper."""

from __future__ import annotations

from types import SimpleNamespace
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
)
from nightrecon.infrastructure_smb_impacket import (
    ImpacketSmbConnectionError,
    ImpacketSmbRuntimeFactory,
    _ImpacketSymbols,
    _dialect_name,
    _share_type_name,
    _signing_required,
)


_SECRET = "runtime-password-secret"


class _FakeConnection:
    instances = []
    login_error = None
    dialect = 0x0311
    server_security_mode = 0x0001
    public_signing_required = True
    raw_shares = ()

    def __init__(
        self,
        *,
        remoteName,
        remoteHost,
        sess_port,
        timeout,
    ):
        self.remote_name = remoteName
        self.remote_host = remoteHost
        self.sess_port = sess_port
        self.timeout = timeout
        self.operation_timeout = None
        self.login_args = None
        self.closed = False
        self._SMBConnection = SimpleNamespace(
            _Connection={
                "ServerSecurityMode": (
                    self.server_security_mode
                ),
            }
        )
        type(self).instances.append(
            self
        )

    def login(
        self,
        username,
        password,
        domain,
        lmhash,
        nthash,
        ntlmFallback,
    ):
        self.login_args = (
            username,
            password,
            domain,
            lmhash,
            nthash,
            ntlmFallback,
        )

        if self.login_error is not None:
            raise self.login_error

    def setTimeout(
        self,
        timeout,
    ):
        self.operation_timeout = timeout

    def getServerName(self):
        return "FILE01"

    def getServerDomain(self):
        return "EXAMPLE"

    def getDialect(self):
        return self.dialect

    def isSigningRequired(self):
        return self.public_signing_required

    def listShares(self):
        return list(
            self.raw_shares
        )

    def close(self):
        self.closed = True


def _symbols():
    return _ImpacketSymbols(
        SMBConnection=_FakeConnection,
        SMB_DIALECT="NT LM 0.12",
        SMB2_DIALECT_002=0x0202,
        SMB2_DIALECT_21=0x0210,
        SMB2_DIALECT_30=0x0300,
        SMB2_DIALECT_302=0x0302,
        SMB2_DIALECT_311=0x0311,
        SMB2_NEGOTIATE_SIGNING_REQUIRED=0x0002,
        STYPE_DISKTREE=0,
        STYPE_PRINTQ=1,
        STYPE_DEVICE=2,
        STYPE_IPC=3,
        STYPE_MASK=0xFF,
    )


def _credential():
    reference = CredentialReference(
        credential_id="smb-readonly",
        kind=CredentialKind.PASSWORD,
        source_kind=CredentialSourceKind.ENVIRONMENT,
    )
    return resolve_credential(
        CredentialBinding(
            reference=reference,
            source_name="NIGHTRECON_SMB_RUNTIME_PASSWORD",
        ),
        environment={
            "NIGHTRECON_SMB_RUNTIME_PASSWORD": _SECRET,
        },
    )


class ImpacketSmbRuntimeTests(unittest.TestCase):
    def setUp(self):
        _FakeConnection.instances = []
        _FakeConnection.login_error = None
        _FakeConnection.dialect = 0x0311
        _FakeConnection.server_security_mode = 0x0001
        _FakeConnection.public_signing_required = True
        _FakeConnection.raw_shares = ()

    def _profile(self):
        return SmbConnectionProfile(
            username="audit-user",
            domain="EXAMPLE",
            port=445,
            connect_timeout=3.0,
            operation_timeout=4.0,
            max_shares=8,
        )

    def test_factory_uses_password_only_and_disables_ntlmv1_fallback(self):
        credential = _credential()
        factory = ImpacketSmbRuntimeFactory(
            symbols=_symbols()
        )

        session = factory.connect(
            target="fileserver.example.test",
            profile=self._profile(),
            credential=credential,
        )

        connection = (
            _FakeConnection.instances[0]
        )
        self.assertEqual(
            connection.remote_name,
            "fileserver.example.test",
        )
        self.assertEqual(
            connection.remote_host,
            "fileserver.example.test",
        )
        self.assertEqual(
            connection.sess_port,
            445,
        )
        self.assertEqual(
            connection.timeout,
            3.0,
        )
        self.assertEqual(
            connection.operation_timeout,
            4.0,
        )
        self.assertEqual(
            connection.login_args,
            (
                "audit-user",
                _SECRET,
                "EXAMPLE",
                "",
                "",
                False,
            ),
        )
        self.assertNotIn(
            _SECRET,
            repr(
                factory
            ),
        )

        session.close()
        credential.clear()

        self.assertTrue(
            connection.closed
        )

    def test_smb311_signing_uses_negotiated_server_security_mode(self):
        connection = _FakeConnection(
            remoteName="server",
            remoteHost="server",
            sess_port=445,
            timeout=3.0,
        )
        symbols = _symbols()

        connection._SMBConnection._Connection[
            "ServerSecurityMode"
        ] = 0x0001
        connection.public_signing_required = (
            True
        )
        self.assertFalse(
            _signing_required(
                connection,
                symbols,
            )
        )

        connection._SMBConnection._Connection[
            "ServerSecurityMode"
        ] = 0x0003
        self.assertTrue(
            _signing_required(
                connection,
                symbols,
            )
        )

    def test_older_dialect_signing_uses_public_runtime_method(self):
        connection = _FakeConnection(
            remoteName="server",
            remoteHost="server",
            sess_port=445,
            timeout=3.0,
        )
        connection.dialect = 0x0210
        connection.public_signing_required = (
            False
        )

        self.assertFalse(
            _signing_required(
                connection,
                _symbols(),
            )
        )

        connection.public_signing_required = (
            True
        )
        self.assertTrue(
            _signing_required(
                connection,
                _symbols(),
            )
        )

    def test_server_identity_maps_dialect_and_optional_domain(self):
        credential = _credential()
        session = ImpacketSmbRuntimeFactory(
            symbols=_symbols()
        ).connect(
            target="fileserver.example.test",
            profile=self._profile(),
            credential=credential,
        )

        observation = (
            session.server_identity()
        )

        self.assertEqual(
            observation.server_name,
            "FILE01",
        )
        self.assertEqual(
            observation.domain_name,
            "EXAMPLE",
        )
        self.assertEqual(
            observation.dialect,
            "3.1.1",
        )
        self.assertFalse(
            observation.signing_required
        )

        session.close()
        credential.clear()

    def test_share_enumeration_strips_terminators_and_maps_types(self):
        _FakeConnection.raw_shares = (
            {
                "shi1_netname": (
                    "Public"
                    + chr(
                        0
                    )
                ),
                "shi1_type": 0,
            },
            {
                "shi1_netname": "IPC$",
                "shi1_type": 3,
            },
            {
                "shi1_netname": "Odd",
                "shi1_type": 99,
            },
        )
        credential = _credential()
        session = ImpacketSmbRuntimeFactory(
            symbols=_symbols()
        ).connect(
            target="fileserver.example.test",
            profile=self._profile(),
            credential=credential,
        )

        shares = session.list_shares(
            max_shares=8
        )

        self.assertEqual(
            tuple(
                (
                    item.name,
                    item.share_type,
                )
                for item in shares
            ),
            (
                (
                    "Public",
                    "disk",
                ),
                (
                    "IPC$",
                    "ipc",
                ),
                (
                    "Odd",
                    "unknown",
                ),
            ),
        )

        session.close()
        credential.clear()

    def test_share_runtime_limit_fails_closed(self):
        _FakeConnection.raw_shares = (
            {
                "shi1_netname": "A",
                "shi1_type": 0,
            },
            {
                "shi1_netname": "B",
                "shi1_type": 0,
            },
        )
        credential = _credential()
        session = ImpacketSmbRuntimeFactory(
            symbols=_symbols()
        ).connect(
            target="fileserver.example.test",
            profile=self._profile(),
            credential=credential,
        )

        with self.assertRaisesRegex(
            ValueError,
            "more shares than allowed",
        ):
            session.list_shares(
                max_shares=1
            )

        session.close()
        credential.clear()

    def test_login_failure_closes_connection_and_sanitizes_exception(self):
        _FakeConnection.login_error = (
            RuntimeError(
                "backend leaked "
                + _SECRET
            )
        )
        credential = _credential()
        factory = ImpacketSmbRuntimeFactory(
            symbols=_symbols()
        )

        with self.assertRaises(
            ImpacketSmbConnectionError
        ) as context:
            factory.connect(
                target="fileserver.example.test",
                profile=self._profile(),
                credential=credential,
            )

        self.assertNotIn(
            _SECRET,
            str(
                context.exception
            ),
        )
        self.assertTrue(
            _FakeConnection.instances[
                0
            ].closed
        )
        credential.clear()

    def test_dialect_and_share_type_helpers_are_deterministic(self):
        symbols = _symbols()

        self.assertEqual(
            _dialect_name(
                "NT LM 0.12",
                symbols,
            ),
            "1.0",
        )
        self.assertEqual(
            _dialect_name(
                0x0202,
                symbols,
            ),
            "2.0.2",
        )
        self.assertEqual(
            _dialect_name(
                0x0210,
                symbols,
            ),
            "2.1",
        )
        self.assertEqual(
            _dialect_name(
                0x0300,
                symbols,
            ),
            "3.0",
        )
        self.assertEqual(
            _dialect_name(
                0x0302,
                symbols,
            ),
            "3.0.2",
        )
        self.assertEqual(
            _dialect_name(
                0x0311,
                symbols,
            ),
            "3.1.1",
        )
        self.assertEqual(
            _share_type_name(
                0x80000000,
                symbols,
            ),
            "disk",
        )
        self.assertEqual(
            _share_type_name(
                "bad",
                symbols,
            ),
            "unknown",
        )


if __name__ == "__main__":
    unittest.main()
