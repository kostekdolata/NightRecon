"""Tests for bounded NightRecon API execution."""

import unittest
from email.message import Message
from urllib.error import HTTPError
from unittest.mock import patch

from nightrecon.api_execution import (
    execute_api_request,
)
from nightrecon.api_policy import (
    ApiRequest,
    ApiRequestDecision,
    ApiRequestState,
)


class _FakeResponse:
    def __init__(
        self,
        *,
        status=200,
        body=b"{}",
        content_type="application/json",
    ):
        self.status = status
        self._body = body
        self.headers = Message()
        self.headers["Content-Type"] = content_type

    def __enter__(self):
        return self

    def __exit__(
        self,
        exc_type,
        exc,
        tb,
    ):
        return False

    def read(
        self,
        limit,
    ):
        return self._body[:limit]


class _FakeOpener:
    def __init__(
        self,
        result,
    ):
        self.result = result
        self.requests = []

    def open(
        self,
        request,
        timeout,
    ):
        self.requests.append(
            (
                request,
                timeout,
            )
        )

        if isinstance(
            self.result,
            BaseException,
        ):
            raise self.result

        return self.result


def _request(
    *,
    method="GET",
    url="https://example.test/api/status",
):
    return ApiRequest(
        url=url,
        method=method,
        operation_id="status",
    )


def _decision(
    *,
    method="GET",
    url="https://example.test/api/status",
):
    return ApiRequestDecision(
        allowed=True,
        reason="authorized",
        normalized_url=url,
        method=method,
        operation_id="status",
    )


def _state():
    return ApiRequestState(
        requests_used=0,
        max_requests=3,
    )


class ApiExecutionTests(unittest.TestCase):
    def test_get_is_bounded_and_does_not_retain_authorization(self):
        opener = _FakeOpener(
            _FakeResponse(
                body=b'{"status":"ok"}',
            )
        )
        secret = (
            "Bearer api-secret-value"
        )

        with patch(
            "nightrecon.api_execution.build_opener",
            return_value=opener,
        ):
            result = execute_api_request(
                request=_request(),
                decision=_decision(),
                state=_state(),
                origin="https://example.test",
                authorized=True,
                timeout=2.0,
                max_response_bytes=1024,
                authorization=secret,
            )

        self.assertTrue(
            result.success
        )
        self.assertEqual(
            result.reason,
            "completed",
        )
        self.assertEqual(
            result.status,
            200,
        )
        self.assertEqual(
            result.content_type,
            "application/json",
        )
        self.assertEqual(
            result.byte_count,
            len(b'{"status":"ok"}'),
        )
        self.assertEqual(
            result.state.requests_used,
            1,
        )
        request, timeout = (
            opener.requests[0]
        )
        self.assertEqual(
            timeout,
            2.0,
        )
        self.assertEqual(
            request.get_method(),
            "GET",
        )
        self.assertEqual(
            request.headers["Authorization"],
            secret,
        )
        self.assertNotIn(
            "api-secret-value",
            repr(result),
        )

    def test_head_never_reads_response_body(self):
        opener = _FakeOpener(
            _FakeResponse(
                body=b"ignored",
            )
        )

        with patch(
            "nightrecon.api_execution.build_opener",
            return_value=opener,
        ):
            result = execute_api_request(
                request=_request(
                    method="HEAD",
                ),
                decision=_decision(
                    method="HEAD",
                ),
                state=_state(),
                origin="https://example.test",
                authorized=True,
            )

        self.assertTrue(
            result.success
        )
        self.assertEqual(
            result.byte_count,
            0,
        )

    def test_oversized_response_fails_but_consumes_attempt_budget(self):
        opener = _FakeOpener(
            _FakeResponse(
                body=b"X" * 64,
            )
        )

        with patch(
            "nightrecon.api_execution.build_opener",
            return_value=opener,
        ):
            result = execute_api_request(
                request=_request(),
                decision=_decision(),
                state=_state(),
                origin="https://example.test",
                authorized=True,
                max_response_bytes=16,
            )

        self.assertFalse(
            result.success
        )
        self.assertEqual(
            result.reason,
            "response_byte_limit_exceeded",
        )
        self.assertEqual(
            result.byte_count,
            16,
        )
        self.assertEqual(
            result.state.requests_used,
            1,
        )

    def test_http_error_consumes_attempt_budget_without_body_retention(self):
        opener = _FakeOpener(
            HTTPError(
                url="https://example.test/api/status",
                code=403,
                msg="Forbidden",
                hdrs=Message(),
                fp=None,
            )
        )

        with patch(
            "nightrecon.api_execution.build_opener",
            return_value=opener,
        ):
            result = execute_api_request(
                request=_request(),
                decision=_decision(),
                state=_state(),
                origin="https://example.test",
                authorized=True,
            )

        self.assertFalse(
            result.success
        )
        self.assertEqual(
            result.reason,
            "http_error",
        )
        self.assertEqual(
            result.status,
            403,
        )
        self.assertEqual(
            result.state.requests_used,
            1,
        )

    def test_mutating_method_is_rejected_before_network(self):
        with patch(
            "nightrecon.api_execution.build_opener"
        ) as build:
            with self.assertRaises(
                PermissionError
            ):
                execute_api_request(
                    request=_request(
                        method="POST",
                    ),
                    decision=_decision(
                        method="POST",
                    ),
                    state=_state(),
                    origin="https://example.test",
                    authorized=True,
                )

        build.assert_not_called()

    def test_cross_origin_and_denied_decisions_fail_before_network(self):
        with patch(
            "nightrecon.api_execution.build_opener"
        ) as build:
            with self.assertRaises(
                PermissionError
            ):
                execute_api_request(
                    request=_request(
                        url="https://outside.test/api/status",
                    ),
                    decision=_decision(
                        url="https://outside.test/api/status",
                    ),
                    state=_state(),
                    origin="https://example.test",
                    authorized=True,
                )

            with self.assertRaises(
                PermissionError
            ):
                execute_api_request(
                    request=_request(),
                    decision=ApiRequestDecision(
                        allowed=False,
                        reason="method_not_allowed",
                        normalized_url=(
                            "https://example.test/api/status"
                        ),
                        method="GET",
                        operation_id="status",
                    ),
                    state=_state(),
                    origin="https://example.test",
                    authorized=True,
                )

        build.assert_not_called()


if __name__ == "__main__":
    unittest.main()
