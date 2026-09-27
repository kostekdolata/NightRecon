"""Credentialed infrastructure assessment models for NightRecon.

These models intentionally contain no secret values, command text, or
network-execution capability.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class CredentialKind(str, Enum):
    PASSWORD = "password"
    SSH_KEY = "ssh-key"
    TOKEN = "token"
    INTEGRATED = "integrated"


class CredentialSourceKind(str, Enum):
    ENVIRONMENT = "environment"
    EXTERNAL_SECRET = "external-secret"
    OS_CREDENTIAL_STORE = "os-credential-store"


class InfrastructureTransport(str, Enum):
    SSH = "ssh"
    SMB = "smb"
    WINRM = "winrm"
    DATABASE = "database"


class InfrastructureActionCategory(str, Enum):
    IDENTITY = "identity"
    INVENTORY = "inventory"
    CONFIGURATION = "configuration"
    PATCH = "patch"


@dataclass(frozen=True)
class CredentialReference:
    """Opaque credential metadata with no secret material."""

    credential_id: str
    kind: CredentialKind
    source_kind: CredentialSourceKind


@dataclass(frozen=True)
class InfrastructureActionDefinition:
    """Symbolic allowlisted infrastructure action."""

    action_id: str
    transport: InfrastructureTransport
    category: InfrastructureActionCategory
    description: str
    mutating: bool = False


@dataclass(frozen=True)
class InfrastructureAction:
    """One proposed credentialed infrastructure action."""

    target: str
    transport: InfrastructureTransport
    action_id: str
    credential_id: str


@dataclass(frozen=True)
class InfrastructureActionState:
    """Immutable credentialed-action accounting."""

    actions_used: int
    max_actions: int

    @property
    def actions_remaining(self) -> int:
        return max(
            self.max_actions
            - self.actions_used,
            0,
        )


@dataclass(frozen=True)
class InfrastructureActionDecision:
    """Pre-execution authorization decision with no secret fields."""

    allowed: bool
    reason: str
    target: str
    transport: InfrastructureTransport
    action_id: str
    credential_id: str
