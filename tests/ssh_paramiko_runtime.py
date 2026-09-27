"""Runtime compatibility checks for NightRecon Paramiko SSH support."""

from __future__ import annotations

import inspect
import tempfile
from pathlib import Path

import paramiko

from nightrecon.credential_resolution import (
    CredentialBinding,
    resolve_credential,
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


def main() -> int:
    connect_parameters = set(
        inspect.signature(
            paramiko.SSHClient.connect
        ).parameters
    )
    required_connect = {
        "hostname",
        "port",
        "username",
        "password",
        "timeout",
        "allow_agent",
        "look_for_keys",
        "banner_timeout",
        "auth_timeout",
        "channel_timeout",
    }

    if not required_connect.issubset(
        connect_parameters
    ):
        raise AssertionError(
            "Installed Paramiko SSHClient.connect API is incompatible."
        )

    exec_parameters = set(
        inspect.signature(
            paramiko.SSHClient.exec_command
        ).parameters
    )

    if not {
        "command",
        "timeout",
        "get_pty",
    }.issubset(
        exec_parameters
    ):
        raise AssertionError(
            "Installed Paramiko exec_command API is incompatible."
        )

    if not issubclass(
        paramiko.RejectPolicy,
        paramiko.MissingHostKeyPolicy,
    ):
        raise AssertionError(
            "Paramiko RejectPolicy contract is unavailable."
        )

    with tempfile.TemporaryDirectory() as temp_dir:
        known_hosts = Path(
            temp_dir
        ) / "known_hosts"
        known_hosts.write_text(
            "",
            encoding="utf-8",
        )
        profile = SshConnectionProfile(
            username="audit-user",
            known_hosts_file=str(
                known_hosts
            ),
        )
        adapter = SshReadOnlyAdapter(
            profile
        )
        credential = resolve_credential(
            CredentialBinding(
                reference=CredentialReference(
                    credential_id="runtime-readonly",
                    kind=CredentialKind.PASSWORD,
                    source_kind=(
                        CredentialSourceKind.ENVIRONMENT
                    ),
                ),
                source_name="NIGHTRECON_RUNTIME_SECRET",
            ),
            environment={
                "NIGHTRECON_RUNTIME_SECRET": "runtime-only-secret",
            },
        )

        if adapter.transport.value != "ssh":
            raise AssertionError(
                "SSH adapter transport contract changed."
            )

        credential.clear()

    print(
        "Paramiko SSH runtime compatibility: PASSED"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(
        main()
    )
