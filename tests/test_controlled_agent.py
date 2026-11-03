"""Tests for controlled read-only agent session bounds."""

import unittest
from unittest.mock import MagicMock

from nightrecon_red_engine.controlled_agent import (
    ControlledAgentSession,
    ControlledAgentState,
)


class ControlledAgentTests(unittest.TestCase):
    def test_session_requires_activation_and_rejects_unreviewed_actions(self):
        session = ControlledAgentSession(
            session_id="agent-1",
            target="192.0.2.10",
        )
        self.assertEqual(session.state, ControlledAgentState.CREATED)
        session = session.activate()

        with self.assertRaises(ValueError):
            session.execute(
                adapter=MagicMock(),
                action_id="ssh.arbitrary_command",
                credential=MagicMock(),
            )

    def test_closed_session_cannot_execute(self):
        session = ControlledAgentSession(
            session_id="agent-1",
            target="192.0.2.10",
        ).activate().close()

        with self.assertRaises(ValueError):
            session.execute(
                adapter=MagicMock(),
                action_id="ssh.system_identity",
                credential=MagicMock(),
            )


if __name__ == "__main__":
    unittest.main()
