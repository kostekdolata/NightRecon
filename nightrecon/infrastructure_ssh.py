"""Strict read-only SSH infrastructure adapter for NightRecon.

The adapter supports fixed symbolic actions only. It never accepts arbitrary
command text, never opens a shell or SFTP session, rejects unknown host keys,
and converts remote output into bounded typed facts.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re

from nightrecon.credential_resolution import (
    ResolvedCredential,
)
from nightrecon.infrastructure_execution import (
    InfrastructureAdapterOutcome,
    InfrastructureFact,
)
from nightrecon.infrastructure_models import (
    CredentialKind,
    InfrastructureTransport,
)


_USERNAME_PATTERN = re.compile(
    r"^[^\x00-\x1f\x7f]{1,255}$"
)

_COMMANDS = {
    "ssh.system_identity": "uname -srm",
    "ssh.os_inventory": "cat /etc/os-release",
}


class SshRuntimeUnavailable(RuntimeError):
    """Raised when the optional SSH runtime is not installed."""


@dataclass(frozen=True)
class SshConnectionProfile:
    """Non-secret SSH connection settings."""

    username: str
    known_hosts_file: str
    port: int = 22
    connect_timeout: float = 5.0
    command_timeout: float = 5.0
    max_output_bytes: int = 65_536

    def __post_init__(self) -> None:
        username = self.username.strip()

        if not _USERNAME_PATTERN.fullmatch(
            username
        ):
            raise ValueError(
                "SSH username is invalid."
            )

        known_hosts = (
            self.known_hosts_file.strip()
        )

        if not known_hosts:
            raise ValueError(
                "known_hosts_file must be non-empty."
            )

        if not (
            1 <= self.port <= 65_535
        ):
            raise ValueError(
                "SSH port must be between 1 and 65535."
            )

        if self.connect_timeout <= 0:
            raise ValueError(
                "connect_timeout must be greater than 0."
            )

        if self.command_timeout <= 0:
            raise ValueError(
                "command_timeout must be greater than 0."
            )

        if self.max_output_bytes < 1:
            raise ValueError(
                "max_output_bytes must be at least 1."
            )

        object.__setattr__(
            self,
            "username",
            username,
        )
        object.__setattr__(
            self,
            "known_hosts_file",
            known_hosts,
        )


class SshReadOnlyAdapter:
    """Password-authenticated SSH adapter with fixed read-only actions."""

    transport = InfrastructureTransport.SSH

    def __init__(
        self,
        profile: SshConnectionProfile,
    ) -> None:
        self.profile = profile

    def __repr__(self) -> str:
        return (
            "SshReadOnlyAdapter("
            f"username={self.profile.username!r}, "
            f"port={self.profile.port}, "
            "host_key_policy='reject', "
            "commands='fixed-read-only')"
        )

    @staticmethod
    def _runtime():
        try:
            import paramiko
        except ImportError as exc:
            raise SshRuntimeUnavailable(
                "SSH assessment requires the NightRecon ssh extra."
            ) from exc

        return paramiko

    def _read_bounded(
        self,
        stdout,
        stderr,
    ) -> tuple[
        bytes,
        bytes,
    ] | None:
        limit = (
            self.profile.max_output_bytes
        )
        stdout_data = stdout.read(
            limit + 1
        )

        if len(
            stdout_data
        ) > limit:
            return None

        remaining = (
            limit
            - len(
                stdout_data
            )
        )
        stderr_data = stderr.read(
            remaining + 1
        )

        if (
            len(stdout_data)
            + len(stderr_data)
            > limit
        ):
            return None

        return (
            stdout_data,
            stderr_data,
        )

    @staticmethod
    def _parse_system_identity(
        payload: bytes,
    ) -> tuple[
        InfrastructureFact,
        ...
    ]:
        text = payload.decode(
            "utf-8",
            errors="replace",
        ).strip()
        parts = text.split()

        if len(parts) < 3:
            return ()

        return (
            InfrastructureFact(
                key="system.name",
                value=parts[0],
            ),
            InfrastructureFact(
                key="system.release",
                value=parts[1],
            ),
            InfrastructureFact(
                key="system.machine",
                value=parts[2],
            ),
        )

    @staticmethod
    def _parse_os_inventory(
        payload: bytes,
    ) -> tuple[
        InfrastructureFact,
        ...
    ]:
        allowed = {
            "ID": "os.id",
            "VERSION_ID": "os.version_id",
            "NAME": "os.name",
            "PRETTY_NAME": "os.pretty_name",
        }
        values: dict[
            str,
            InfrastructureFact,
        ] = {}

        text = payload.decode(
            "utf-8",
            errors="replace",
        )

        for line in text.splitlines():
            if "=" not in line:
                continue

            key, raw_value = line.split(
                "=",
                1,
            )

            if key not in allowed:
                continue

            value = raw_value.strip()

            if (
                len(value) >= 2
                and value[0]
                == value[-1]
                and value[0]
                in {
                    '"',
                    "'",
                }
            ):
                value = value[
                    1:-1
                ]

            if not value:
                continue

            try:
                fact = InfrastructureFact(
                    key=allowed[
                        key
                    ],
                    value=value,
                )
            except ValueError:
                continue

            values[
                fact.key
            ] = fact

        return tuple(
            values[key]
            for key in sorted(
                values
            )
        )

    def execute(
        self,
        *,
        target: str,
        action_id: str,
        credential: ResolvedCredential,
    ) -> InfrastructureAdapterOutcome:
        command = _COMMANDS.get(
            action_id
        )

        if command is None:
            return InfrastructureAdapterOutcome(
                success=False,
                reason="unsupported_action",
            )

        if (
            credential.reference.kind
            != CredentialKind.PASSWORD
        ):
            return InfrastructureAdapterOutcome(
                success=False,
                reason="credential_kind_not_supported",
            )

        known_hosts = Path(
            self.profile.known_hosts_file
        )

        if not known_hosts.is_file():
            return InfrastructureAdapterOutcome(
                success=False,
                reason="known_hosts_unavailable",
            )

        paramiko = self._runtime()
        client = paramiko.SSHClient()
        client.load_host_keys(
            str(
                known_hosts
            )
        )
        client.set_missing_host_key_policy(
            paramiko.RejectPolicy()
        )

        try:
            with credential.material.reveal_text() as password:
                client.connect(
                    hostname=target,
                    port=self.profile.port,
                    username=self.profile.username,
                    password=password,
                    timeout=self.profile.connect_timeout,
                    banner_timeout=self.profile.connect_timeout,
                    auth_timeout=self.profile.connect_timeout,
                    channel_timeout=self.profile.command_timeout,
                    allow_agent=False,
                    look_for_keys=False,
                )

                stdin, stdout, stderr = (
                    client.exec_command(
                        command,
                        timeout=(
                            self.profile.command_timeout
                        ),
                        get_pty=False,
                    )
                )

                try:
                    stdin.close()
                except Exception:
                    pass

                bounded = self._read_bounded(
                    stdout,
                    stderr,
                )

                if bounded is None:
                    return InfrastructureAdapterOutcome(
                        success=False,
                        reason="output_limit_exceeded",
                    )

                stdout_data, _ = bounded
                exit_status = (
                    stdout.channel.recv_exit_status()
                )

            if exit_status != 0:
                return InfrastructureAdapterOutcome(
                    success=False,
                    reason="command_failed",
                )

            if (
                action_id
                == "ssh.system_identity"
            ):
                facts = (
                    self._parse_system_identity(
                        stdout_data
                    )
                )
            else:
                facts = (
                    self._parse_os_inventory(
                        stdout_data
                    )
                )

            if not facts:
                return InfrastructureAdapterOutcome(
                    success=False,
                    reason="parse_failed",
                )

            return InfrastructureAdapterOutcome(
                success=True,
                reason="completed",
                facts=facts,
            )

        except paramiko.BadHostKeyException:
            return InfrastructureAdapterOutcome(
                success=False,
                reason="host_key_verification_failed",
            )
        except paramiko.AuthenticationException:
            return InfrastructureAdapterOutcome(
                success=False,
                reason="authentication_failed",
            )
        except paramiko.SSHException:
            return InfrastructureAdapterOutcome(
                success=False,
                reason="ssh_failed",
            )
        except OSError:
            return InfrastructureAdapterOutcome(
                success=False,
                reason="connection_failed",
            )
        finally:
            client.close()
