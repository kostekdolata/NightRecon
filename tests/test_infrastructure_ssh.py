"""Tests for NightRecon strict read-only SSH adapter."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from nightrecon.credential_resolution import (
    CredentialBinding,
    resolve_credential,
)
from nightrecon.infrastructure_execution import (
    InfrastructureFact,
)
from nightrecon.infrastructure_models import (
    CredentialKind,
    CredentialReference,
    CredentialSourceKind,
)
from nightrecon.infrastructure_ssh import (
    SshConnectionProfile,
    SshReadOnlyAdapter,
)


_SECRET = "ssh-password-secret"


class _FakeChannel:
    def __init__(
        self,
        status=0,
    ):
        self.status = status

    def recv_exit_status(self):
        return self.status


class _FakeStream:
    def __init__(
        self,
        data=b"",
        *,
        status=0,
    ):
        self.data = data
        self.channel = _FakeChannel(
            status
        )
        self.closed = False

    def read(
        self,
        limit,
    ):
        return self.data[
            :limit
        ]

    def close(self):
        self.closed = True


class _FakeSshClient:
    def __init__(
        self,
        *,
        stdout=b"Linux 6.8.0 x86_64\n",
        stderr=b"",
        status=0,
        connect_error=None,
    ):
        self.stdout_data = stdout
        self.stderr_data = stderr
        self.status = status
        self.connect_error = connect_error
        self.host_keys = None
        self.policy = None
        self.connect_kwargs = None
        self.command = None
        self.command_timeout = None
        self.get_pty = None
        self.closed = False
        self.stdin = None

    def load_host_keys(
        self,
        path,
    ):
        self.host_keys = path

    def set_missing_host_key_policy(
        self,
        policy,
    ):
        self.policy = policy

    def connect(
        self,
        **kwargs,
    ):
        self.connect_kwargs = kwargs

        if self.connect_error is not None:
            raise self.connect_error

    def exec_command(
        self,
        command,
        *,
        timeout,
        get_pty,
    ):
        self.command = command
        self.command_timeout = timeout
        self.get_pty = get_pty
        self.stdin = _FakeStream()

        return (
            self.stdin,
            _FakeStream(
                self.stdout_data,
                status=self.status,
            ),
            _FakeStream(
                self.stderr_data,
                status=self.status,
            ),
        )

    def close(self):
        self.closed = True


class _BadHostKey(Exception):
    pass


class _Authentication(Exception):
    pass


class _SshException(Exception):
    pass


class _RejectPolicy:
    pass


def _runtime(
    client,
):
    return SimpleNamespace(
        SSHClient=lambda: client,
        RejectPolicy=_RejectPolicy,
        BadHostKeyException=_BadHostKey,
        AuthenticationException=_Authentication,
        SSHException=_SshException,
    )


def _credential(
    *,
    kind=CredentialKind.PASSWORD,
):
    reference = CredentialReference(
        credential_id="ssh-readonly",
        kind=kind,
        source_kind=CredentialSourceKind.ENVIRONMENT,
    )

    return resolve_credential(
        CredentialBinding(
            reference=reference,
            source_name="NIGHTRECON_SSH_PASSWORD",
        ),
        environment={
            "NIGHTRECON_SSH_PASSWORD": _SECRET,
        },
    )


class SshAdapterTests(unittest.TestCase):
    def _profile(
        self,
        path,
        **overrides,
    ):
        values = {
            "username": "audit-user",
            "known_hosts_file": str(
                path
            ),
            "port": 22,
            "connect_timeout": 3.0,
            "command_timeout": 4.0,
            "max_output_bytes": 1024,
        }
        values.update(
            overrides
        )
        return SshConnectionProfile(
            **values
        )

    def test_profile_validation_fails_closed(self):
        with self.assertRaises(
            ValueError
        ):
            SshConnectionProfile(
                username="",
                known_hosts_file="known_hosts",
            )

        with self.assertRaises(
            ValueError
        ):
            SshConnectionProfile(
                username="audit-user",
                known_hosts_file="",
            )

        with self.assertRaises(
            ValueError
        ):
            SshConnectionProfile(
                username="audit-user",
                known_hosts_file="known_hosts",
                port=0,
            )

        with self.assertRaises(
            ValueError
        ):
            SshConnectionProfile(
                username="audit-user\nroot",
                known_hosts_file="known_hosts",
            )

    def test_system_identity_uses_fixed_command_and_strict_connection_settings(self):
        client = _FakeSshClient()

        with tempfile.TemporaryDirectory() as temp_dir:
            known_hosts = Path(
                temp_dir
            ) / "known_hosts"
            known_hosts.write_text(
                "placeholder\n",
                encoding="utf-8",
            )
            adapter = SshReadOnlyAdapter(
                self._profile(
                    known_hosts
                )
            )
            credential = _credential()

            with patch.object(
                adapter,
                "_runtime",
                return_value=_runtime(
                    client
                ),
            ):
                outcome = adapter.execute(
                    target="server.example.test",
                    action_id="ssh.system_identity",
                    credential=credential,
                )

            credential.clear()

        self.assertTrue(
            outcome.success
        )
        self.assertEqual(
            outcome.reason,
            "completed",
        )
        self.assertEqual(
            outcome.facts,
            (
                InfrastructureFact(
                    key="system.name",
                    value="Linux",
                ),
                InfrastructureFact(
                    key="system.release",
                    value="6.8.0",
                ),
                InfrastructureFact(
                    key="system.machine",
                    value="x86_64",
                ),
            ),
        )
        self.assertEqual(
            client.command,
            "uname -srm",
        )
        self.assertFalse(
            client.get_pty
        )
        self.assertTrue(
            client.stdin.closed
        )
        self.assertTrue(
            client.closed
        )
        self.assertEqual(
            client.connect_kwargs[
                "hostname"
            ],
            "server.example.test",
        )
        self.assertEqual(
            client.connect_kwargs[
                "username"
            ],
            "audit-user",
        )
        self.assertEqual(
            client.connect_kwargs[
                "password"
            ],
            _SECRET,
        )
        self.assertFalse(
            client.connect_kwargs[
                "allow_agent"
            ]
        )
        self.assertFalse(
            client.connect_kwargs[
                "look_for_keys"
            ]
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

    def test_os_inventory_keeps_only_approved_fields(self):
        payload = (
            b'NAME="Example Linux"\n'
            b'VERSION_ID="24.04"\n'
            b'ID=example\n'
            b'PRETTY_NAME="Example Linux 24.04"\n'
            b'SECRET_TOKEN=must-not-persist\n'
        )
        client = _FakeSshClient(
            stdout=payload
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            known_hosts = Path(
                temp_dir
            ) / "known_hosts"
            known_hosts.write_text(
                "placeholder\n",
                encoding="utf-8",
            )
            adapter = SshReadOnlyAdapter(
                self._profile(
                    known_hosts
                )
            )
            credential = _credential()

            with patch.object(
                adapter,
                "_runtime",
                return_value=_runtime(
                    client
                ),
            ):
                outcome = adapter.execute(
                    target="server.example.test",
                    action_id="ssh.os_inventory",
                    credential=credential,
                )

            credential.clear()

        self.assertTrue(
            outcome.success
        )
        serialized = repr(
            outcome
        )
        self.assertIn(
            "Example Linux",
            serialized,
        )
        self.assertNotIn(
            "must-not-persist",
            serialized,
        )
        self.assertEqual(
            client.command,
            "cat /etc/os-release",
        )

    def test_unknown_action_and_wrong_credential_kind_fail_before_network(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            known_hosts = Path(
                temp_dir
            ) / "known_hosts"
            known_hosts.write_text(
                "placeholder\n",
                encoding="utf-8",
            )
            adapter = SshReadOnlyAdapter(
                self._profile(
                    known_hosts
                )
            )

            client = _FakeSshClient()

            with patch.object(
                adapter,
                "_runtime",
                return_value=_runtime(
                    client
                ),
            ):
                password = _credential()
                unsupported = adapter.execute(
                    target="server.example.test",
                    action_id="ssh.arbitrary",
                    credential=password,
                )
                password.clear()

                key_credential = _credential(
                    kind=CredentialKind.SSH_KEY
                )
                wrong_kind = adapter.execute(
                    target="server.example.test",
                    action_id="ssh.system_identity",
                    credential=key_credential,
                )
                key_credential.clear()

        self.assertEqual(
            unsupported.reason,
            "unsupported_action",
        )
        self.assertEqual(
            wrong_kind.reason,
            "credential_kind_not_supported",
        )
        self.assertIsNone(
            client.connect_kwargs
        )

    def test_missing_known_hosts_fails_before_runtime_or_network(self):
        adapter = SshReadOnlyAdapter(
            SshConnectionProfile(
                username="audit-user",
                known_hosts_file="definitely-missing-nightrecon-known-hosts",
            )
        )
        credential = _credential()

        with patch.object(
            adapter,
            "_runtime"
        ) as runtime:
            outcome = adapter.execute(
                target="server.example.test",
                action_id="ssh.system_identity",
                credential=credential,
            )

        credential.clear()

        self.assertFalse(
            outcome.success
        )
        self.assertEqual(
            outcome.reason,
            "known_hosts_unavailable",
        )
        runtime.assert_not_called()

    def test_output_limit_and_nonzero_exit_fail_without_raw_output(self):
        client = _FakeSshClient(
            stdout=b"X" * 128
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            known_hosts = Path(
                temp_dir
            ) / "known_hosts"
            known_hosts.write_text(
                "placeholder\n",
                encoding="utf-8",
            )
            adapter = SshReadOnlyAdapter(
                self._profile(
                    known_hosts,
                    max_output_bytes=16,
                )
            )
            credential = _credential()

            with patch.object(
                adapter,
                "_runtime",
                return_value=_runtime(
                    client
                ),
            ):
                limited = adapter.execute(
                    target="server.example.test",
                    action_id="ssh.system_identity",
                    credential=credential,
                )

            credential.clear()

            failure_client = _FakeSshClient(
                stdout=b"error-detail",
                status=1,
            )
            adapter = SshReadOnlyAdapter(
                self._profile(
                    known_hosts
                )
            )
            credential = _credential()

            with patch.object(
                adapter,
                "_runtime",
                return_value=_runtime(
                    failure_client
                ),
            ):
                failed = adapter.execute(
                    target="server.example.test",
                    action_id="ssh.system_identity",
                    credential=credential,
                )

            credential.clear()

        self.assertEqual(
            limited.reason,
            "output_limit_exceeded",
        )
        self.assertNotIn(
            "X" * 16,
            repr(
                limited
            ),
        )
        self.assertEqual(
            failed.reason,
            "command_failed",
        )
        self.assertNotIn(
            "error-detail",
            repr(
                failed
            ),
        )

    def test_authentication_and_host_key_failures_are_sanitized(self):
        cases = (
            (
                _Authentication(
                    "password was " + _SECRET
                ),
                "authentication_failed",
            ),
            (
                _BadHostKey(
                    "bad key with " + _SECRET
                ),
                "host_key_verification_failed",
            ),
            (
                _SshException(
                    "ssh detail " + _SECRET
                ),
                "ssh_failed",
            ),
            (
                OSError(
                    "network detail " + _SECRET
                ),
                "connection_failed",
            ),
        )

        for error, reason in cases:
            with self.subTest(
                reason=reason
            ):
                client = _FakeSshClient(
                    connect_error=error
                )

                with tempfile.TemporaryDirectory() as temp_dir:
                    known_hosts = Path(
                        temp_dir
                    ) / "known_hosts"
                    known_hosts.write_text(
                        "placeholder\n",
                        encoding="utf-8",
                    )
                    adapter = SshReadOnlyAdapter(
                        self._profile(
                            known_hosts
                        )
                    )
                    credential = _credential()

                    with patch.object(
                        adapter,
                        "_runtime",
                        return_value=_runtime(
                            client
                        ),
                    ):
                        outcome = adapter.execute(
                            target="server.example.test",
                            action_id="ssh.system_identity",
                            credential=credential,
                        )

                    credential.clear()

                self.assertEqual(
                    outcome.reason,
                    reason,
                )
                self.assertNotIn(
                    _SECRET,
                    repr(
                        outcome
                    ),
                )
                self.assertTrue(
                    client.closed
                )


if __name__ == "__main__":
    unittest.main()
