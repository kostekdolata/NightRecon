"""Tests for reviewed validation registry and cyber-range simulation."""

import unittest

from nightrecon_red_engine.cyber_range_simulation import (
    CyberRange,
    RangeAction,
    SimulatedAgentSession,
    VirtualHost,
    build_simulation_payload,
)
from nightrecon_red_engine.validation_module_registry import (
    evaluate_validation_eligibility,
    get_validation_module,
)


class ValidationRegistryTests(unittest.TestCase):
    def test_range_module_requires_snapshot_and_sandbox(self):
        module = get_validation_module(
            "range.post-exploitation-simulation"
        )
        result = evaluate_validation_eligibility(
            module,
            {
                "sandbox": True,
                "snapshot": True,
                "explicit-scenario": False,
            },
        )
        self.assertFalse(result.eligible)
        self.assertEqual(result.missing, ("explicit-scenario",))


class CyberRangeSimulationTests(unittest.TestCase):
    def test_high_impact_sequence_is_simulated_and_rolled_back(self):
        range_ = CyberRange((
            VirtualHost("operator", compromised=True, privileged=True),
            VirtualHost("server"),
        ))
        payload = build_simulation_payload(
            scenario_id="post-exploitation-demo",
            allowed_actions=(
                RangeAction.LATERAL_MOVEMENT,
                RangeAction.PRIVILEGE_ESCALATION,
                RangeAction.CREDENTIAL_ACCESS,
                RangeAction.PERSISTENCE,
                RangeAction.DESTRUCTIVE_IMPACT,
                RangeAction.PROPAGATION,
            ),
            max_steps=8,
        )
        before = range_.snapshot()

        report = range_.run_scenario(
            payload=payload,
            steps=(
                ("operator", "server", RangeAction.LATERAL_MOVEMENT),
                ("server", "server", RangeAction.PRIVILEGE_ESCALATION),
                ("server", "server", RangeAction.CREDENTIAL_ACCESS),
                ("server", "server", RangeAction.PERSISTENCE),
                ("server", "server", RangeAction.DESTRUCTIVE_IMPACT),
            ),
            rollback=True,
        )

        self.assertTrue(report.cleaned)
        self.assertEqual(len(report.events), 5)
        self.assertEqual(range_.snapshot(), before)
        self.assertTrue(all(
            event.outcome == "simulated"
            for event in report.events
        ))

    def test_simulation_payload_cannot_run_unapproved_action(self):
        range_ = CyberRange((
            VirtualHost("a", compromised=True),
            VirtualHost("b"),
        ))
        payload = build_simulation_payload(
            scenario_id="limited",
            allowed_actions=(RangeAction.COLLECTION,),
        )
        with self.assertRaises(PermissionError):
            range_.execute(
                payload=payload,
                source_host="a",
                target_host="b",
                action=RangeAction.PROPAGATION,
            )

    def test_agent_is_allowlisted_and_nonarbitrary(self):
        host = VirtualHost(
            "server",
            compromised=True,
            privileged=True,
        )
        session = SimulatedAgentSession("server")
        self.assertEqual(session.run("whoami", host), "administrator")
        with self.assertRaises(ValueError):
            session.run("arbitrary-shell-command", host)
        closed = session.close()
        with self.assertRaises(ValueError):
            closed.run("status", host)


if __name__ == "__main__":
    unittest.main()
