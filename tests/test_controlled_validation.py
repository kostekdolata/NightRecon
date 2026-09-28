"""Controlled validation is approval-gated, bounded, and evidence-safe."""

from __future__ import annotations

from datetime import datetime, timezone
import tempfile
import unittest

from nightrecon_red_engine.controlled_validation import (
    ControlledValidationResult,
    ValidationDefinition,
    ValidationObservation,
    ValidationState,
    run_controlled_validation,
)
from nightrecon_shared_core.contracts import EngagementMetadata
from nightrecon_shared_core.engagement_policy import EngagementExecutionPolicy
from nightrecon_shared_core.workspace import LocalWorkspace


class FakeAdapter:
    def __init__(self, observation=None, error=None):
        self.observation = observation
        self.error = error
        self.calls = 0

    def execute(self, definition):
        self.calls += 1
        if self.error is not None:
            raise self.error
        return self.observation


def make_workspace(root, *, capabilities=("validation.run",), approvals=()):
    ws = LocalWorkspace(root)
    ws.create_engagement(EngagementMetadata(
        engagement_id="eng-validation",
        name="Validation lab",
        created_at="2026-09-28T00:00:00+00:00",
        authorization_reference="approval://eng-validation",
        status="active",
    ))
    ws.set_execution_policy(EngagementExecutionPolicy(
        engagement_id="eng-validation",
        scope=("192.0.2.0/24",),
        valid_from="2026-09-28T00:00:00+00:00",
        valid_until="2026-09-29T00:00:00+00:00",
        max_actions=3,
        permitted_capabilities=capabilities,
        approval_required_capabilities=approvals,
    ))
    return ws


class ControlledValidationTests(unittest.TestCase):
    def test_confirmed_validation_records_structured_proof(self):
        with tempfile.TemporaryDirectory() as root:
            adapter = FakeAdapter(ValidationObservation(
                confirmed=True,
                summary="Expected protocol property was observed.",
                evidence={"protocol": "https", "status": 200},
                limitations=("Read-only proof only",),
            ))
            result = run_controlled_validation(
                make_workspace(root), adapter,
                ValidationDefinition(
                    "tls-safe-proof", "192.0.2.10", "TLS property validation"
                ),
                engagement_id="eng-validation",
                now=datetime(2026, 9, 28, 12, 0, tzinfo=timezone.utc),
            )
            self.assertEqual(result.state, ValidationState.CONFIRMED)
            self.assertEqual(result.reason_code, "validated")
            self.assertEqual(adapter.calls, 1)
            self.assertEqual(result.actions_used, 1)

    def test_out_of_scope_denial_never_calls_adapter(self):
        with tempfile.TemporaryDirectory() as root:
            adapter = FakeAdapter(ValidationObservation(False, "unused", {}))
            result = run_controlled_validation(
                make_workspace(root), adapter,
                ValidationDefinition("proof", "198.51.100.10", "Proof"),
                engagement_id="eng-validation",
                now=datetime(2026, 9, 28, 12, 0, tzinfo=timezone.utc),
            )
            self.assertEqual(result.state, ValidationState.DENIED)
            self.assertEqual(result.reason_code, "target_out_of_scope")
            self.assertEqual(adapter.calls, 0)

    def test_high_impact_requires_approval_before_adapter(self):
        with tempfile.TemporaryDirectory() as root:
            adapter = FakeAdapter(ValidationObservation(True, "approved proof", {}))
            result = run_controlled_validation(
                make_workspace(root), adapter,
                ValidationDefinition("high-proof", "192.0.2.10", "High proof", impact="high"),
                engagement_id="eng-validation",
                now=datetime(2026, 9, 28, 12, 0, tzinfo=timezone.utc),
            )
            self.assertEqual(result.state, ValidationState.DENIED)
            self.assertEqual(result.reason_code, "approval_required")
            self.assertEqual(adapter.calls, 0)

    def test_adapter_error_is_evidence_safe(self):
        with tempfile.TemporaryDirectory() as root:
            adapter = FakeAdapter(error=RuntimeError("sensitive detail"))
            result = run_controlled_validation(
                make_workspace(root), adapter,
                ValidationDefinition("proof", "192.0.2.10", "Proof"),
                engagement_id="eng-validation",
                now=datetime(2026, 9, 28, 12, 0, tzinfo=timezone.utc),
            )
            self.assertEqual(result.state, ValidationState.ERROR)
            self.assertNotIn("sensitive detail", result.summary)
            self.assertEqual(result.evidence, {})

    def test_secret_like_evidence_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "secret-like"):
            ValidationObservation(True, "bad", {"api_token": "x"})


if __name__ == "__main__":
    unittest.main()
