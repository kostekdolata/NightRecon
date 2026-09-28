"""Injectable read-only SMB adapter boundary for NightRecon v0.30.

This module defines the transport adapter contract around an injected SMB runtime.
NightRecon does not ship a concrete SMB runtime in this batch, so this module has
no socket/network implementation by itself.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from nightrecon_red_engine.credential_resolution import (
    ResolvedCredential,
)
from nightrecon_red_engine.infrastructure_execution import (
    InfrastructureAdapterOutcome,
)
from nightrecon_red_engine.infrastructure_models import (
    CredentialKind,
    InfrastructureTransport,
)
from nightrecon_red_engine.infrastructure_smb import (
    SmbConnectionProfile,
    SmbShareObservation,
    build_smb_server_identity_facts,
    build_smb_share_inventory_facts,
    validate_smb_action,
)


@dataclass(frozen=True)
class SmbServerObservation:
    """Already-observed SMB server identity metadata."""

    server_name: str
    domain_name: str
    dialect: str
    signing_required: bool


class SmbRuntimeSession(Protocol):
    """Minimal read-only SMB runtime session boundary."""

    def server_identity(
        self,
    ) -> SmbServerObservation:
        ...

    def list_shares(
        self,
        *,
        max_shares: int,
    ) -> tuple[
        SmbShareObservation,
        ...
    ]:
        ...

    def close(
        self,
    ) -> None:
        ...


class SmbRuntimeFactory(Protocol):
    """Factory for a bounded authenticated SMB runtime session."""

    def connect(
        self,
        *,
        target: str,
        profile: SmbConnectionProfile,
        credential: ResolvedCredential,
    ) -> SmbRuntimeSession:
        ...


class SmbReadOnlyAdapter:
    """Read-only SMB adapter over an explicitly injected runtime factory."""

    transport = InfrastructureTransport.SMB

    def __init__(
        self,
        profile: SmbConnectionProfile,
        runtime_factory: SmbRuntimeFactory,
    ) -> None:
        self.profile = profile
        self._runtime_factory = runtime_factory

    def __repr__(
        self,
    ) -> str:
        return (
            "SmbReadOnlyAdapter("
            f"username={self.profile.username!r}, "
            f"port={self.profile.port}, "
            f"max_shares={self.profile.max_shares}, "
            "actions='fixed-read-only', "
            "runtime='injected')"
        )

    def execute(
        self,
        *,
        target: str,
        action_id: str,
        credential: ResolvedCredential,
    ) -> InfrastructureAdapterOutcome:
        try:
            normalized_action = validate_smb_action(
                action_id
            )
        except ValueError:
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

        if not credential.material.active:
            return InfrastructureAdapterOutcome(
                success=False,
                reason="credential_unavailable",
            )

        session: SmbRuntimeSession | None = None

        try:
            session = (
                self._runtime_factory.connect(
                    target=target,
                    profile=self.profile,
                    credential=credential,
                )
            )

            if (
                normalized_action
                == "smb.server_identity"
            ):
                observation = (
                    session.server_identity()
                )
                facts = (
                    build_smb_server_identity_facts(
                        server_name=(
                            observation.server_name
                        ),
                        domain_name=(
                            observation.domain_name
                        ),
                        dialect=(
                            observation.dialect
                        ),
                        signing_required=(
                            observation.signing_required
                        ),
                    )
                )
            else:
                shares = session.list_shares(
                    max_shares=(
                        self.profile.max_shares
                    )
                )
                facts = (
                    build_smb_share_inventory_facts(
                        shares,
                        max_shares=(
                            self.profile.max_shares
                        ),
                    )
                )

            return InfrastructureAdapterOutcome(
                success=True,
                reason="completed",
                facts=facts,
            )

        except ValueError:
            return InfrastructureAdapterOutcome(
                success=False,
                reason="evidence_invalid",
            )
        except Exception:
            return InfrastructureAdapterOutcome(
                success=False,
                reason="smb_failed",
            )
        finally:
            if session is not None:
                try:
                    session.close()
                except Exception:
                    pass
