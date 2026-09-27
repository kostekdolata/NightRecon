"""Tests for NightRecon deterministic DAST request budgeting."""

import unittest

from nightrecon.dast_policy import (
    DastBudgetPolicy,
    DastBudgetState,
    DastCheckDefinition,
    authorize_dast_request,
    reserve_dast_request,
)


def _check(
    *,
    check_id="web.test",
    family="web-diff",
    max_requests=2,
    methods=("GET", "HEAD"),
):
    return DastCheckDefinition(
        check_id=check_id,
        name="Test check",
        family=family,
        description="Test deterministic DAST check.",
        max_requests=max_requests,
        allowed_methods=methods,
    )


class DastPolicyTests(unittest.TestCase):
    def test_safe_get_is_authorized_and_reserved_immutably(self):
        policy = DastBudgetPolicy(
            max_total_requests=5,
            default_family_requests=3,
        )
        state = DastBudgetState()
        check = _check()

        decision = authorize_dast_request(
            check=check,
            method="get",
            policy=policy,
            state=state,
        )

        self.assertTrue(
            decision.allowed
        )
        self.assertEqual(
            decision.reason,
            "authorized",
        )
        self.assertEqual(
            decision.method,
            "GET",
        )

        reserved = reserve_dast_request(
            state=state,
            decision=decision,
        )

        self.assertEqual(
            state.total_used,
            0,
        )
        self.assertEqual(
            reserved.total_used,
            1,
        )
        self.assertEqual(
            dict(reserved.check_usage),
            {
                "web.test": 1,
            },
        )
        self.assertEqual(
            dict(reserved.family_usage),
            {
                "web-diff": 1,
            },
        )

    def test_check_budget_exhaustion_fails_closed(self):
        check = _check(
            max_requests=1
        )
        policy = DastBudgetPolicy(
            max_total_requests=10,
            default_family_requests=10,
        )
        state = DastBudgetState(
            total_used=1,
            check_usage=(
                (
                    "web.test",
                    1,
                ),
            ),
            family_usage=(
                (
                    "web-diff",
                    1,
                ),
            ),
        )

        decision = authorize_dast_request(
            check=check,
            method="GET",
            policy=policy,
            state=state,
        )

        self.assertFalse(
            decision.allowed
        )
        self.assertEqual(
            decision.reason,
            "check_request_budget_exhausted",
        )

    def test_family_budget_exhaustion_blocks_other_check_in_same_family(self):
        policy = DastBudgetPolicy(
            max_total_requests=10,
            default_family_requests=10,
            family_limits=(
                (
                    "web-diff",
                    2,
                ),
            ),
        )
        state = DastBudgetState(
            total_used=2,
            check_usage=(
                (
                    "web.one",
                    1,
                ),
                (
                    "web.two",
                    1,
                ),
            ),
            family_usage=(
                (
                    "web-diff",
                    2,
                ),
            ),
        )

        decision = authorize_dast_request(
            check=_check(
                check_id="web.three",
                max_requests=3,
            ),
            method="GET",
            policy=policy,
            state=state,
        )

        self.assertFalse(
            decision.allowed
        )
        self.assertEqual(
            decision.reason,
            "family_request_budget_exhausted",
        )

    def test_total_budget_exhaustion_has_highest_budget_precedence(self):
        policy = DastBudgetPolicy(
            max_total_requests=2,
            default_family_requests=5,
        )
        state = DastBudgetState(
            total_used=2,
            check_usage=(
                (
                    "web.one",
                    1,
                ),
                (
                    "web.two",
                    1,
                ),
            ),
            family_usage=(
                (
                    "web-diff",
                    2,
                ),
            ),
        )

        decision = authorize_dast_request(
            check=_check(
                check_id="web.three",
                max_requests=5,
            ),
            method="GET",
            policy=policy,
            state=state,
        )

        self.assertFalse(
            decision.allowed
        )
        self.assertEqual(
            decision.reason,
            "total_request_budget_exhausted",
        )

    def test_mutating_methods_cannot_be_declared_safe_active(self):
        for method in (
            "POST",
            "PUT",
            "PATCH",
            "DELETE",
        ):
            with self.subTest(
                method=method
            ):
                with self.assertRaises(
                    ValueError
                ):
                    _check(
                        methods=(
                            "GET",
                            method,
                        )
                    )

    def test_method_not_declared_by_check_is_blocked(self):
        decision = authorize_dast_request(
            check=_check(
                methods=("GET",),
            ),
            method="HEAD",
            policy=DastBudgetPolicy(),
            state=DastBudgetState(),
        )

        self.assertFalse(
            decision.allowed
        )
        self.assertEqual(
            decision.reason,
            "method_not_allowed",
        )

    def test_stale_decision_cannot_be_reserved(self):
        policy = DastBudgetPolicy(
            max_total_requests=5,
            default_family_requests=5,
        )
        check = _check()
        original = DastBudgetState()
        decision = authorize_dast_request(
            check=check,
            method="GET",
            policy=policy,
            state=original,
        )
        newer = DastBudgetState(
            total_used=1,
            check_usage=(
                (
                    "other.check",
                    1,
                ),
            ),
            family_usage=(
                (
                    "other-family",
                    1,
                ),
            ),
        )

        with self.assertRaises(
            PermissionError
        ):
            reserve_dast_request(
                state=newer,
                decision=decision,
            )

    def test_denied_decision_cannot_reserve(self):
        decision = authorize_dast_request(
            check=_check(
                methods=("GET",),
            ),
            method="HEAD",
            policy=DastBudgetPolicy(),
            state=DastBudgetState(),
        )

        with self.assertRaises(
            PermissionError
        ):
            reserve_dast_request(
                state=DastBudgetState(),
                decision=decision,
            )

    def test_inconsistent_or_duplicate_accounting_is_rejected(self):
        with self.assertRaises(
            ValueError
        ):
            DastBudgetState(
                total_used=1,
                check_usage=(),
                family_usage=(
                    (
                        "web",
                        1,
                    ),
                ),
            )

        with self.assertRaises(
            ValueError
        ):
            DastBudgetState(
                total_used=2,
                check_usage=(
                    (
                        "one",
                        1,
                    ),
                    (
                        "one",
                        1,
                    ),
                ),
                family_usage=(
                    (
                        "web",
                        2,
                    ),
                ),
            )

    def test_custom_family_limit_is_deterministic(self):
        policy = DastBudgetPolicy(
            family_limits=(
                (
                    "zeta",
                    8,
                ),
                (
                    "alpha",
                    3,
                ),
            ),
        )

        self.assertEqual(
            policy.family_limits,
            (
                (
                    "alpha",
                    3,
                ),
                (
                    "zeta",
                    8,
                ),
            ),
        )
        self.assertEqual(
            policy.family_limit(
                "alpha"
            ),
            3,
        )
        self.assertEqual(
            policy.family_limit(
                "unknown"
            ),
            10,
        )


if __name__ == "__main__":
    unittest.main()
