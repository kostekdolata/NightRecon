"""Approval-friendly controlled read-only agent sessions.

This intentionally provides a session abstraction over Red Night's existing
fixed SSH actions. It does not expose arbitrary command text, an interactive
shell, SFTP, persistence, or credential harvesting.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from nightrecon_red_engine.credential_resolution import ResolvedCredential
from nightrecon_red_engine.infrastructure_execution import InfrastructureAdapterOutcome
from nightrecon_red_engine.infrastructure_ssh import SshReadOnlyAdapter


class ControlledAgentState(str, Enum):
    CREATED = "created"
    ACTIVE = "active"
    CLOSED = "closed"


_ALLOWED_ACTIONS = frozenset({
    "ssh.system_identity",
    "ssh.os_inventory",
})


@dataclass(frozen=True)
class ControlledAgentSession:
    session_id: str
    target: str
    state: ControlledAgentState = ControlledAgentState.CREATED
    actions_used: int = 0
    max_actions: int = 4

    def activate(self) -> "ControlledAgentSession":
        if self.state is not ControlledAgentState.CREATED:
            raise ValueError("only a created agent session can be activated")
        return ControlledAgentSession(
            session_id=self.session_id,
            target=self.target,
            state=ControlledAgentState.ACTIVE,
            actions_used=self.actions_used,
            max_actions=self.max_actions,
        )

    def close(self) -> "ControlledAgentSession":
        if self.state is ControlledAgentState.CLOSED:
            return self
        return ControlledAgentSession(
            session_id=self.session_id,
            target=self.target,
            state=ControlledAgentState.CLOSED,
            actions_used=self.actions_used,
            max_actions=self.max_actions,
        )

    def execute(
        self,
        *,
        adapter: SshReadOnlyAdapter,
        action_id: str,
        credential: ResolvedCredential,
    ) -> tuple["ControlledAgentSession", InfrastructureAdapterOutcome]:
        if self.state is not ControlledAgentState.ACTIVE:
            raise ValueError("controlled agent session is not active")
        if action_id not in _ALLOWED_ACTIONS:
            raise ValueError("controlled agent action is not reviewed")
        if self.actions_used >= self.max_actions:
            raise ValueError("controlled agent action budget exhausted")

        outcome = adapter.execute(
            target=self.target,
            action_id=action_id,
            credential=credential,
        )
        updated = ControlledAgentSession(
            session_id=self.session_id,
            target=self.target,
            state=self.state,
            actions_used=self.actions_used + 1,
            max_actions=self.max_actions,
        )
        return updated, outcome
