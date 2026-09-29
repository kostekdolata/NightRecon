"""White Night Batch 5 approval workflow tests."""

from __future__ import annotations

import copy
from dataclasses import FrozenInstanceError
import unittest

from nightrecon_white_engine.approval_engine import (
    ApprovalPolicy,
    ApprovalPrincipal,
    ApprovalRequest,
    ApprovalWorkflow,
    ApprovalWorkflowError,
)


POLICY_FP = "1" * 64


def principals():
    return (
        ApprovalPrincipal("requester", ("operator",)),
        ApprovalPrincipal("alice", ("approver",)),
        ApprovalPrincipal("bob", ("approver",)),
        ApprovalPrincipal("carol", ("approver", "senior")),
        ApprovalPrincipal("dave", ("observer",)),
    )


def request(
    *,
    mode="single",
    required=1,
    requester_may_approve=False,
    allow_delegation=True,
    escalation_after=600,
    eligible_roles=("approver",),
):
    return ApprovalRequest(
        request_id="approval-001",
        engagement_id="eng-001",
        policy_bundle_fingerprint=POLICY_FP,
        requested_at="2026-09-29T16:00:00+00:00",
        expires_at="2026-09-29T18:00:00+00:00",
        requested_by="requester",
        principals=principals(),
        capability="discovery",
        target="APP.EXAMPLE.TEST",
        impact="standard",
        reason="Validate approved action",
        policy=ApprovalPolicy(
            mode=mode,
            required_approvals=required,
            eligible_roles=tuple(eligible_roles),
            requester_may_approve=requester_may_approve,
            allow_delegation=allow_delegation,
            escalation_after_seconds=escalation_after,
            escalation_roles=("senior",),
        ),
        operation_id="operation-001",
    )


def workflow(**kwargs):
    return ApprovalWorkflow.create(
        request(**kwargs),
        event_id="evt-requested",
    )


class WhiteApprovalWorkflowTests(unittest.TestCase):
    def test_models_are_immutable_and_target_is_normalized(self) -> None:
        item = request()
        self.assertEqual(item.target, "app.example.test")
        with self.assertRaises(FrozenInstanceError):
            item.reason = "changed"  # type: ignore[misc]

    def test_single_approval_produces_bound_grant(self) -> None:
        item = workflow().approve(
            event_id="evt-a1",
            actor_id="alice",
            occurred_at="2026-09-29T16:05:00+00:00",
            reason="Approved",
        )
        self.assertEqual(
            item.status("2026-09-29T16:06:00+00:00"),
            "approved",
        )
        grant = item.grant("2026-09-29T16:06:00+00:00")
        self.assertTrue(item.grant_matches(
            grant,
            engagement_id="eng-001",
            policy_bundle_fingerprint=POLICY_FP,
            capability="discovery",
            target="app.example.test",
            impact="standard",
            at="2026-09-29T16:06:00+00:00",
        ))

    def test_status_projection_respects_query_time_and_expiry(self) -> None:
        item = workflow().approve(
            event_id="evt-a1",
            actor_id="alice",
            occurred_at="2026-09-29T16:05:00+00:00",
            reason="Approved",
        )
        self.assertEqual(
            item.status("2026-09-29T16:04:59+00:00"),
            "pending",
        )
        self.assertEqual(
            item.status("2026-09-29T16:05:00+00:00"),
            "approved",
        )
        self.assertEqual(
            item.status("2026-09-29T18:00:00+00:00"),
            "expired",
        )

    def test_grant_cannot_be_replayed_across_context(self) -> None:
        item = workflow().approve(
            event_id="evt-a1",
            actor_id="alice",
            occurred_at="2026-09-29T16:05:00+00:00",
            reason="Approved",
        )
        grant = item.grant("2026-09-29T16:06:00+00:00")
        variants = (
            dict(engagement_id="eng-other"),
            dict(policy_bundle_fingerprint="2" * 64),
            dict(capability="web.safe-active"),
            dict(target="other.example.test"),
            dict(impact="high"),
        )
        base = dict(
            engagement_id="eng-001",
            policy_bundle_fingerprint=POLICY_FP,
            capability="discovery",
            target="app.example.test",
            impact="standard",
            at="2026-09-29T16:06:00+00:00",
        )
        for override in variants:
            with self.subTest(override=override):
                args = dict(base)
                args.update(override)
                self.assertFalse(item.grant_matches(grant, **args))

    def test_dual_control_requires_two_distinct_approvers(self) -> None:
        item = workflow(mode="dual", required=2)
        item = item.approve(
            event_id="evt-a1",
            actor_id="alice",
            occurred_at="2026-09-29T16:05:00+00:00",
            reason="First approval",
        )
        self.assertEqual(
            item.status("2026-09-29T16:06:00+00:00"),
            "pending",
        )
        with self.assertRaisesRegex(ApprovalWorkflowError, "already approved"):
            item.approve(
                event_id="evt-a1-duplicate",
                actor_id="alice",
                occurred_at="2026-09-29T16:07:00+00:00",
                reason="Duplicate",
            )
        item = item.approve(
            event_id="evt-a2",
            actor_id="bob",
            occurred_at="2026-09-29T16:08:00+00:00",
            reason="Second approval",
        )
        self.assertEqual(
            item.status("2026-09-29T16:09:00+00:00"),
            "approved",
        )
        self.assertEqual(
            item.grant("2026-09-29T16:09:00+00:00").approver_ids,
            ("alice", "bob"),
        )

    def test_quorum_requires_configured_count(self) -> None:
        item = workflow(mode="quorum", required=3)
        for index, actor in enumerate(("alice", "bob"), start=1):
            item = item.approve(
                event_id=f"evt-q{index}",
                actor_id=actor,
                occurred_at=f"2026-09-29T16:0{index}:00+00:00",
                reason="Quorum approval",
            )
        self.assertEqual(
            item.status("2026-09-29T16:04:00+00:00"),
            "pending",
        )
        item = item.approve(
            event_id="evt-q3",
            actor_id="carol",
            occurred_at="2026-09-29T16:05:00+00:00",
            reason="Quorum complete",
        )
        self.assertEqual(
            item.status("2026-09-29T16:06:00+00:00"),
            "approved",
        )

    def test_separation_of_duties_blocks_requester(self) -> None:
        req = ApprovalRequest(
            request_id="approval-sod",
            engagement_id="eng-001",
            policy_bundle_fingerprint=POLICY_FP,
            requested_at="2026-09-29T16:00:00+00:00",
            expires_at="2026-09-29T18:00:00+00:00",
            requested_by="alice",
            principals=principals(),
            capability="discovery",
            target="app.example.test",
            impact="standard",
            reason="Test separation",
            policy=ApprovalPolicy(
                mode="single",
                required_approvals=1,
                eligible_roles=("approver",),
                requester_may_approve=False,
            ),
        )
        item = ApprovalWorkflow.create(req, event_id="evt-request")
        with self.assertRaisesRegex(ApprovalWorkflowError, "requester cannot approve"):
            item.approve(
                event_id="evt-self",
                actor_id="alice",
                occurred_at="2026-09-29T16:05:00+00:00",
                reason="Self approval",
            )

    def test_rejection_is_terminal(self) -> None:
        item = workflow().reject(
            event_id="evt-reject",
            actor_id="alice",
            occurred_at="2026-09-29T16:05:00+00:00",
            reason="Insufficient justification",
        )
        self.assertEqual(
            item.status("2026-09-29T16:06:00+00:00"),
            "rejected",
        )
        with self.assertRaisesRegex(ApprovalWorkflowError, "not pending"):
            item.approve(
                event_id="evt-late",
                actor_id="bob",
                occurred_at="2026-09-29T16:07:00+00:00",
                reason="Too late",
            )

    def test_expiry_blocks_decisions_and_grants(self) -> None:
        item = workflow()
        self.assertEqual(
            item.status("2026-09-29T18:00:00+00:00"),
            "expired",
        )
        with self.assertRaisesRegex(ApprovalWorkflowError, "not pending"):
            item.approve(
                event_id="evt-expired",
                actor_id="alice",
                occurred_at="2026-09-29T18:00:00+00:00",
                reason="Expired",
            )
        with self.assertRaisesRegex(ApprovalWorkflowError, "unavailable"):
            item.grant("2026-09-29T18:00:00+00:00")

    def test_delegation_is_request_bound_and_expires(self) -> None:
        item = workflow()
        item = item.delegate(
            event_id="evt-delegate",
            delegator_id="alice",
            delegate_id="dave",
            delegated_role="approver",
            occurred_at="2026-09-29T16:05:00+00:00",
            valid_until="2026-09-29T16:20:00+00:00",
            reason="Temporary cover",
        )
        item = item.approve(
            event_id="evt-delegate-approve",
            actor_id="dave",
            occurred_at="2026-09-29T16:10:00+00:00",
            reason="Approved under delegation",
        )
        self.assertEqual(
            item.status("2026-09-29T16:11:00+00:00"),
            "approved",
        )

        expired = workflow().delegate(
            event_id="evt-delegate-exp",
            delegator_id="alice",
            delegate_id="dave",
            delegated_role="approver",
            occurred_at="2026-09-29T16:05:00+00:00",
            valid_until="2026-09-29T16:10:00+00:00",
            reason="Short cover",
        )
        with self.assertRaisesRegex(ApprovalWorkflowError, "eligible approval authority"):
            expired.approve(
                event_id="evt-after-delegation",
                actor_id="dave",
                occurred_at="2026-09-29T16:10:00+00:00",
                reason="Too late",
            )

    def test_delegation_cannot_outlive_request_or_chain_from_delegate(self) -> None:
        item = workflow()
        with self.assertRaisesRegex(ApprovalWorkflowError, "outlive"):
            item.delegate(
                event_id="evt-long",
                delegator_id="alice",
                delegate_id="dave",
                delegated_role="approver",
                occurred_at="2026-09-29T16:05:00+00:00",
                valid_until="2026-09-29T19:00:00+00:00",
                reason="Too long",
            )
        item = item.delegate(
            event_id="evt-good",
            delegator_id="alice",
            delegate_id="dave",
            delegated_role="approver",
            occurred_at="2026-09-29T16:05:00+00:00",
            valid_until="2026-09-29T17:00:00+00:00",
            reason="Temporary",
        )
        with self.assertRaisesRegex(ApprovalWorkflowError, "directly hold"):
            item.delegate(
                event_id="evt-chain",
                delegator_id="dave",
                delegate_id="bob",
                delegated_role="approver",
                occurred_at="2026-09-29T16:10:00+00:00",
                valid_until="2026-09-29T16:30:00+00:00",
                reason="Forbidden chain",
            )

    def test_escalation_is_due_once(self) -> None:
        item = workflow(escalation_after=600)
        self.assertFalse(item.escalation_due("2026-09-29T16:09:59+00:00"))
        self.assertTrue(item.escalation_due("2026-09-29T16:10:00+00:00"))
        item = item.escalate(
            event_id="evt-escalate",
            actor_id="requester",
            occurred_at="2026-09-29T16:10:00+00:00",
            reason="Approval overdue",
        )
        self.assertTrue(item.escalated())
        self.assertFalse(item.escalation_due("2026-09-29T16:20:00+00:00"))
        with self.assertRaisesRegex(ApprovalWorkflowError, "not due"):
            item.escalate(
                event_id="evt-escalate-2",
                actor_id="requester",
                occurred_at="2026-09-29T16:20:00+00:00",
                reason="Duplicate escalation",
            )

    def test_revocation_invalidates_previous_grant(self) -> None:
        approved = workflow().approve(
            event_id="evt-approve",
            actor_id="alice",
            occurred_at="2026-09-29T16:05:00+00:00",
            reason="Approved",
        )
        grant = approved.grant("2026-09-29T16:06:00+00:00")
        revoked = approved.revoke(
            event_id="evt-revoke",
            actor_id="carol",
            occurred_at="2026-09-29T16:10:00+00:00",
            reason="Authorization withdrawn",
        )
        self.assertEqual(
            revoked.status("2026-09-29T16:11:00+00:00"),
            "revoked",
        )
        self.assertFalse(revoked.grant_matches(
            grant,
            engagement_id="eng-001",
            policy_bundle_fingerprint=POLICY_FP,
            capability="discovery",
            target="app.example.test",
            impact="standard",
            at="2026-09-29T16:11:00+00:00",
        ))

    def test_workflow_round_trip_and_hash_chain_tamper_detection(self) -> None:
        item = workflow(mode="dual", required=2)
        item = item.approve(
            event_id="evt-a1",
            actor_id="alice",
            occurred_at="2026-09-29T16:05:00+00:00",
            reason="First",
        )
        rebuilt = ApprovalWorkflow.from_json(item.to_json())
        self.assertEqual(rebuilt, item)
        self.assertEqual(rebuilt.fingerprint, item.fingerprint)

        tampered = copy.deepcopy(item.to_dict())
        tampered["events"][1]["reason"] = "Tampered"
        with self.assertRaisesRegex(
            ApprovalWorkflowError,
            "fingerprint verification failed",
        ):
            ApprovalWorkflow.from_dict(tampered)

    def test_invalid_quorum_or_insufficient_authorities_fail_closed(self) -> None:
        with self.assertRaisesRegex(ApprovalWorkflowError, "at least two"):
            request(mode="quorum", required=1)
        with self.assertRaisesRegex(ApprovalWorkflowError, "not enough eligible"):
            ApprovalRequest(
                request_id="approval-impossible",
                engagement_id="eng-001",
                policy_bundle_fingerprint=POLICY_FP,
                requested_at="2026-09-29T16:00:00+00:00",
                expires_at="2026-09-29T18:00:00+00:00",
                requested_by="requester",
                principals=principals(),
                capability="discovery",
                target="app.example.test",
                impact="standard",
                reason="Impossible approval",
                policy=ApprovalPolicy(
                    mode="quorum",
                    required_approvals=4,
                    eligible_roles=("approver",),
                ),
            )


if __name__ == "__main__":
    unittest.main()
