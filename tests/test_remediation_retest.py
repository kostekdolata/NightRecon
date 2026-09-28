"""Remediation/retest lifecycle closes findings only on conclusive proof."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import tempfile
import unittest

from nightrecon_red_engine.controlled_validation import (
    ControlledValidationResult,
    ValidationState,
)
from nightrecon_red_engine.remediation_retest import (
    RemediationStatus,
    RemediationStore,
)


def result(state):
    return ControlledValidationResult(
        engagement_id="eng-rem",
        validation_id="val-1",
        target="192.0.2.10",
        state=state,
        reason_code="test",
        summary="test",
        evidence={},
        limitations=(),
        actions_used=1,
        remaining_actions=1,
    )


class RemediationRetestTests(unittest.TestCase):
    def test_not_confirmed_retest_verifies_fix_and_persists(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "remediation.json"
            store = RemediationStore(path)
            store.create(
                engagement_id="eng-rem", finding_id="finding-1",
                title="Finding", remediation="Apply the approved fix.",
                now=datetime(2026, 9, 28, 12, 0, tzinfo=timezone.utc),
            )
            store.transition("finding-1", RemediationStatus.IN_PROGRESS)
            store.transition("finding-1", RemediationStatus.READY_FOR_RETEST)
            outcome = store.record_retest(
                "finding-1", result(ValidationState.NOT_CONFIRMED)
            )
            self.assertTrue(outcome.conclusive)
            self.assertEqual(outcome.resulting_status, "verified")
            self.assertEqual(
                RemediationStore(path).get("finding-1").status,
                RemediationStatus.VERIFIED,
            )

    def test_confirmed_retest_marks_regressed_not_closed(self):
        with tempfile.TemporaryDirectory() as root:
            store = RemediationStore(Path(root) / "remediation.json")
            store.create(
                engagement_id="eng-rem", finding_id="finding-1",
                title="Finding", remediation="Fix it.",
            )
            store.transition("finding-1", RemediationStatus.IN_PROGRESS)
            store.transition("finding-1", RemediationStatus.READY_FOR_RETEST)
            outcome = store.record_retest(
                "finding-1", result(ValidationState.CONFIRMED)
            )
            self.assertEqual(outcome.resulting_status, "regressed")
            self.assertEqual(
                store.get("finding-1").status, RemediationStatus.REGRESSED
            )

    def test_denied_or_error_retest_is_inconclusive(self):
        for state in (ValidationState.DENIED, ValidationState.ERROR):
            with self.subTest(state=state):
                with tempfile.TemporaryDirectory() as root:
                    store = RemediationStore(Path(root) / "remediation.json")
                    store.create(
                        engagement_id="eng-rem", finding_id="finding-1",
                        title="Finding", remediation="Fix it.",
                    )
                    store.transition("finding-1", RemediationStatus.IN_PROGRESS)
                    store.transition("finding-1", RemediationStatus.READY_FOR_RETEST)
                    outcome = store.record_retest("finding-1", result(state))
                    self.assertFalse(outcome.conclusive)
                    self.assertEqual(
                        store.get("finding-1").status,
                        RemediationStatus.READY_FOR_RETEST,
                    )

    def test_retest_requires_ready_state_and_same_engagement(self):
        with tempfile.TemporaryDirectory() as root:
            store = RemediationStore(Path(root) / "remediation.json")
            store.create(
                engagement_id="eng-rem", finding_id="finding-1",
                title="Finding", remediation="Fix it.",
            )
            with self.assertRaisesRegex(ValueError, "ready-for-retest"):
                store.record_retest(
                    "finding-1", result(ValidationState.NOT_CONFIRMED)
                )

    def test_invalid_lifecycle_transition_fails_closed(self):
        with tempfile.TemporaryDirectory() as root:
            store = RemediationStore(Path(root) / "remediation.json")
            store.create(
                engagement_id="eng-rem", finding_id="finding-1",
                title="Finding", remediation="Fix it.",
            )
            with self.assertRaisesRegex(ValueError, "invalid remediation transition"):
                store.transition("finding-1", RemediationStatus.VERIFIED)


if __name__ == "__main__":
    unittest.main()
