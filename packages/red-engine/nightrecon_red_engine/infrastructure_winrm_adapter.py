"""Injectable read-only WinRM adapter boundary for NightRecon v0.30.

This module defines the transport adapter contract around an injected WinRM
runtime. It performs no WinRM authentication, HTTP(S) activity, PowerShell
execution, command execution, registry access, WMI calls, or network traffic by
itself.
"""

from __future__ import annotations

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
from nightrecon_red_engine.infrastructure_winrm import (
    WinRmConnectionProfile,
    WinRmPatchObservation,
    WinRmSystemObservation,
    build_winrm_patch_inventory_facts,
    build_winrm_system_identity_facts,
    validate_winrm_action,
)


class WinRmRuntimeSession(Protocol):
    """Minimal read-only WinRM runtime session boundary."""

    def system_identity(
        self,
    ) -> WinRmSystemObservation:
        ...

    def list_patches(
        self,
        *,
        max_patches: int,
    ) -> tuple[
        WinRmPatchObservation,
        ...
    ]:
        ...

    def close(
        self,
    ) -> None:
        ...


class WinRmRuntimeFactory(Protocol):
    """Factory for a bounded authenticated WinRM runtime session."""

    def connect(
        self,
        *,
        target: str,
        profile: WinRmConnectionProfile,
        credential: ResolvedCredential,
    ) -> WinRmRuntimeSession:
        ...


class WinRmReadOnlyAdapter:
    """Read-only WinRM adapter over an explicitly injected runtime factory."""

    transport = InfrastructureTransport.WINRM

    def __init__(
        self,
        profile: WinRmConnectionProfile,
        runtime_factory: WinRmRuntimeFactory,
    ) -> None:
        self.profile = profile
        self._runtime_factory = runtime_factory

    def __repr__(
        self,
    ) -> str:
        return (
            "WinRmReadOnlyAdapter("
            f"username={self.profile.username!r}, "
            f"port={self.profile.port}, "
            f"max_patches={self.profile.max_patches}, "
            "tls='required', "
            "certificate_validation='required', "
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
            normalized_action = validate_winrm_action(
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

        session: WinRmRuntimeSession | None = None

        try:
            session = self._runtime_factory.connect(
                target=target,
                profile=self.profile,
                credential=credential,
            )

            if (
                normalized_action
                == "winrm.system_identity"
            ):
                observation = (
                    session.system_identity()
                )
                facts = (
                    build_winrm_system_identity_facts(
                        observation
                    )
                )
            else:
                patches = session.list_patches(
                    max_patches=(
                        self.profile.max_patches
                    )
                )
                facts = (
                    build_winrm_patch_inventory_facts(
                        patches,
                        max_patches=(
                            self.profile.max_patches
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
                reason="winrm_failed",
            )
        finally:
            if session is not None:
                try:
                    session.close()
                except Exception:
                    pass
