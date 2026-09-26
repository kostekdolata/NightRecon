"""Tests for NightRecon fail-closed API request policy."""

import unittest

from nightrecon.api_policy import (
    ApiRequest,
    ApiRequestPolicy,
    ApiRequestState,
    authorize_api_request,
    reserve_api_request,
)


class ApiPolicyTests(unittest.TestCase):
    def test_same_origin_get_is_authorized(self):
        policy = ApiRequestPolicy(
            origin="https://example.test",
            max_requests=3,
        )
        state = ApiRequestState(
            requests_used=0,
            max_requests=3,
        )
        request = ApiRequest(
            url="https://example.test/api/users#frag",
            method="get",
            operation_id="listUsers",
        )

        decision = authorize_api_request(
            request=request,
            policy=policy,
            state=state,
        )

        self.assertTrue(
            decision.allowed
        )
        self.assertEqual(
            decision.normalized_url,
            "https://example.test/api/users",
        )
        self.assertEqual(
            decision.method,
            "GET",
        )
        self.assertEqual(
            decision.operation_id,
            "listUsers",
        )

    def test_cross_origin_is_rejected(self):
        decision = authorize_api_request(
            request=ApiRequest(
                url="https://outside.test/api",
                method="GET",
            ),
            policy=ApiRequestPolicy(
                origin="https://example.test",
            ),
            state=ApiRequestState(
                requests_used=0,
                max_requests=25,
            ),
        )

        self.assertFalse(
            decision.allowed
        )
        self.assertEqual(
            decision.reason,
            "outside_authorized_origin",
        )

    def test_mutating_methods_are_blocked_by_default(self):
        policy = ApiRequestPolicy(
            origin="https://example.test",
        )

        for method in (
            "POST",
            "PUT",
            "PATCH",
            "DELETE",
        ):
            with self.subTest(
                method=method
            ):
                decision = authorize_api_request(
                    request=ApiRequest(
                        url="https://example.test/api",
                        method=method,
                    ),
                    policy=policy,
                    state=ApiRequestState(
                        requests_used=0,
                        max_requests=25,
                    ),
                )

                self.assertFalse(
                    decision.allowed
                )
                self.assertEqual(
                    decision.reason,
                    "method_not_allowed",
                )

    def test_request_budget_is_enforced(self):
        policy = ApiRequestPolicy(
            origin="https://example.test",
            max_requests=2,
        )
        decision = authorize_api_request(
            request=ApiRequest(
                url="https://example.test/api",
                method="GET",
            ),
            policy=policy,
            state=ApiRequestState(
                requests_used=2,
                max_requests=2,
            ),
        )

        self.assertFalse(
            decision.allowed
        )
        self.assertEqual(
            decision.reason,
            "request_budget_exhausted",
        )

    def test_reservation_advances_immutable_state_only_after_allow(self):
        state = ApiRequestState(
            requests_used=0,
            max_requests=2,
        )
        decision = authorize_api_request(
            request=ApiRequest(
                url="https://example.test/api",
                method="GET",
            ),
            policy=ApiRequestPolicy(
                origin="https://example.test",
                max_requests=2,
            ),
            state=state,
        )

        reserved = reserve_api_request(
            state=state,
            decision=decision,
        )

        self.assertEqual(
            state.requests_used,
            0,
        )
        self.assertEqual(
            reserved.requests_used,
            1,
        )
        self.assertEqual(
            reserved.requests_remaining,
            1,
        )

    def test_denied_request_cannot_reserve_budget(self):
        state = ApiRequestState(
            requests_used=0,
            max_requests=2,
        )
        decision = authorize_api_request(
            request=ApiRequest(
                url="https://outside.test/api",
                method="GET",
            ),
            policy=ApiRequestPolicy(
                origin="https://example.test",
                max_requests=2,
            ),
            state=state,
        )

        with self.assertRaises(
            PermissionError
        ):
            reserve_api_request(
                state=state,
                decision=decision,
            )

        self.assertEqual(
            state.requests_used,
            0,
        )

    def test_invalid_policy_and_state_fail_closed(self):
        with self.assertRaises(ValueError):
            ApiRequestPolicy(
                origin="https://example.test",
                max_requests=0,
            )

        with self.assertRaises(ValueError):
            ApiRequestPolicy(
                origin="https://example.test",
                allowed_methods=(),
            )

        with self.assertRaises(ValueError):
            authorize_api_request(
                request=ApiRequest(
                    url="https://example.test/api",
                    method="GET",
                ),
                policy=ApiRequestPolicy(
                    origin="https://example.test",
                ),
                state=ApiRequestState(
                    requests_used=-1,
                    max_requests=25,
                ),
            )

    def test_explicit_method_expansion_is_possible_but_not_default(self):
        policy = ApiRequestPolicy(
            origin="https://example.test",
            allowed_methods=(
                "GET",
                "HEAD",
                "OPTIONS",
            ),
        )
        decision = authorize_api_request(
            request=ApiRequest(
                url="https://example.test/api",
                method="OPTIONS",
            ),
            policy=policy,
            state=ApiRequestState(
                requests_used=0,
                max_requests=25,
            ),
        )

        self.assertTrue(
            decision.allowed
        )


if __name__ == "__main__":
    unittest.main()
