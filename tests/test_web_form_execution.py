"""Tests for bounded NightRecon form submission execution."""

import unittest
from email.message import Message
from http.cookiejar import CookieJar
from urllib.error import HTTPError
from unittest.mock import patch

from nightrecon.web_form_execution import (
    execute_form_submission,
)
from nightrecon.web_form_intent import (
    WorkflowFieldClass,
    WorkflowFormFieldIntent,
    WorkflowFormIntent,
)
from nightrecon.web_form_submission import (
    FormSubmissionDecision,
)
from nightrecon.web_workflow import WorkflowState


class _FakeResponse:
    def __init__(self, *, status=200, body=b"ok"):
        self.status = status
        self._body = body

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read(self, limit):
        return self._body[:limit]


class _FakeOpener:
    def __init__(self, response):
        self.response = response
        self.requests = []

    def open(self, request, timeout):
        self.requests.append(
            (request, timeout)
        )

        if isinstance(
            self.response,
            BaseException,
        ):
            raise self.response

        return self.response


def _intent():
    return WorkflowFormIntent(
        source_url="https://example.test/login",
        action_url="https://example.test/session",
        method="POST",
        action_same_origin=True,
        fields=(
            WorkflowFormFieldIntent(
                name="username",
                input_type="text",
                field_class=WorkflowFieldClass.ORDINARY,
                sensitive=False,
            ),
            WorkflowFormFieldIntent(
                name="csrf_token",
                input_type="hidden",
                field_class=WorkflowFieldClass.ANTI_CSRF,
                sensitive=True,
            ),
        ),
        submission_enabled=False,
    )


def _decision():
    return FormSubmissionDecision(
        allowed=True,
        reason="authorized",
        action_url="https://example.test/session",
        method="POST",
        approved_fields=(
            "username",
            "csrf_token",
        ),
        submissions_used=0,
        max_submissions=1,
    )


def _state():
    return WorkflowState(
        current_url="https://example.test/login",
        visited_urls=(
            "https://example.test/login",
        ),
        actions_used=0,
        max_actions=3,
    )


class FormExecutionTests(unittest.TestCase):
    def test_approved_fields_are_posted_with_bounded_form_encoding(self):
        opener = _FakeOpener(
            _FakeResponse(
                status=200,
                body=b"done",
            )
        )

        with patch(
            "nightrecon.web_form_execution.build_opener",
            return_value=opener,
        ):
            result = execute_form_submission(
                intent=_intent(),
                decision=_decision(),
                state=_state(),
                field_values={
                    "username": "alice",
                    "csrf_token": "ephemeral-token",
                },
                submissions_used=0,
                origin="https://example.test",
                authorized=True,
                timeout=2.0,
                max_body_bytes=1024,
                max_response_bytes=128,
            )

        self.assertTrue(result.success)
        self.assertEqual(
            result.status,
            200,
        )
        self.assertEqual(
            result.byte_count,
            4,
        )
        self.assertEqual(
            result.submissions_used,
            1,
        )
        self.assertEqual(
            result.state.actions_used,
            1,
        )
        self.assertEqual(
            result.state.current_url,
            "https://example.test/session",
        )
        request, timeout = opener.requests[0]
        self.assertEqual(timeout, 2.0)
        self.assertEqual(
            request.get_method(),
            "POST",
        )
        body = request.data.decode("utf-8")
        self.assertIn(
            "username=alice",
            body,
        )
        self.assertIn(
            "csrf_token=ephemeral-token",
            body,
        )
        self.assertEqual(
            request.headers["Content-type"],
            "application/x-www-form-urlencoded",
        )
        self.assertNotIn(
            "ephemeral-token",
            repr(result),
        )

    def test_denied_decision_stops_before_network(self):
        decision = FormSubmissionDecision(
            allowed=False,
            reason="form_field_not_allowlisted",
            action_url="https://example.test/session",
            method="POST",
            approved_fields=(),
            submissions_used=0,
            max_submissions=1,
        )

        with patch(
            "nightrecon.web_form_execution.build_opener"
        ) as build:
            with self.assertRaises(PermissionError):
                execute_form_submission(
                    intent=_intent(),
                    decision=decision,
                    state=_state(),
                    field_values={},
                    submissions_used=0,
                    origin="https://example.test",
                    authorized=True,
                )

        build.assert_not_called()

    def test_extra_or_missing_fields_are_rejected_before_network(self):
        with patch(
            "nightrecon.web_form_execution.build_opener"
        ) as build:
            with self.assertRaises(PermissionError):
                execute_form_submission(
                    intent=_intent(),
                    decision=_decision(),
                    state=_state(),
                    field_values={
                        "username": "alice",
                        "csrf_token": "token",
                        "extra": "blocked",
                    },
                    submissions_used=0,
                    origin="https://example.test",
                    authorized=True,
                )

            with self.assertRaises(PermissionError):
                execute_form_submission(
                    intent=_intent(),
                    decision=_decision(),
                    state=_state(),
                    field_values={
                        "username": "alice",
                    },
                    submissions_used=0,
                    origin="https://example.test",
                    authorized=True,
                )

        build.assert_not_called()

    def test_non_string_value_and_oversized_body_fail_before_network(self):
        with patch(
            "nightrecon.web_form_execution.build_opener"
        ) as build:
            with self.assertRaises(ValueError):
                execute_form_submission(
                    intent=_intent(),
                    decision=_decision(),
                    state=_state(),
                    field_values={
                        "username": "alice",
                        "csrf_token": 123,
                    },
                    submissions_used=0,
                    origin="https://example.test",
                    authorized=True,
                )

            with self.assertRaises(ValueError):
                execute_form_submission(
                    intent=_intent(),
                    decision=_decision(),
                    state=_state(),
                    field_values={
                        "username": "A" * 100,
                        "csrf_token": "B" * 100,
                    },
                    submissions_used=0,
                    origin="https://example.test",
                    authorized=True,
                    max_body_bytes=16,
                )

        build.assert_not_called()

    def test_cross_origin_and_non_post_intents_fail_before_network(self):
        cross_origin = WorkflowFormIntent(
            source_url="https://example.test/login",
            action_url="https://other.test/session",
            method="POST",
            action_same_origin=False,
            fields=_intent().fields,
        )
        cross_decision = FormSubmissionDecision(
            allowed=True,
            reason="authorized",
            action_url="https://other.test/session",
            method="POST",
            approved_fields=(
                "username",
                "csrf_token",
            ),
        )
        get_intent = WorkflowFormIntent(
            source_url="https://example.test/login",
            action_url="https://example.test/session",
            method="GET",
            action_same_origin=True,
            fields=_intent().fields,
        )
        get_decision = FormSubmissionDecision(
            allowed=True,
            reason="authorized",
            action_url="https://example.test/session",
            method="GET",
            approved_fields=(
                "username",
                "csrf_token",
            ),
        )

        with patch(
            "nightrecon.web_form_execution.build_opener"
        ) as build:
            with self.assertRaises(PermissionError):
                execute_form_submission(
                    intent=cross_origin,
                    decision=cross_decision,
                    state=_state(),
                    field_values={
                        "username": "alice",
                        "csrf_token": "token",
                    },
                    submissions_used=0,
                    origin="https://example.test",
                    authorized=True,
                )

            with self.assertRaises(PermissionError):
                execute_form_submission(
                    intent=get_intent,
                    decision=get_decision,
                    state=_state(),
                    field_values={
                        "username": "alice",
                        "csrf_token": "token",
                    },
                    submissions_used=0,
                    origin="https://example.test",
                    authorized=True,
                )

        build.assert_not_called()

    def test_http_error_does_not_advance_state_or_submission_budget(self):
        error = HTTPError(
            url="https://example.test/session",
            code=403,
            msg="Forbidden",
            hdrs=Message(),
            fp=None,
        )
        opener = _FakeOpener(error)
        state = _state()

        with patch(
            "nightrecon.web_form_execution.build_opener",
            return_value=opener,
        ):
            result = execute_form_submission(
                intent=_intent(),
                decision=_decision(),
                state=state,
                field_values={
                    "username": "alice",
                    "csrf_token": "token",
                },
                submissions_used=0,
                origin="https://example.test",
                authorized=True,
            )

        self.assertFalse(result.success)
        self.assertEqual(
            result.reason,
            "http_error",
        )
        self.assertEqual(
            result.status,
            403,
        )
        self.assertIs(
            result.state,
            state,
        )
        self.assertEqual(
            result.submissions_used,
            0,
        )

    def test_ephemeral_auth_context_is_not_retained_in_result(self):
        opener = _FakeOpener(
            _FakeResponse()
        )
        cookie_jar = CookieJar()
        secret = "Bearer submit-auth-secret"

        with patch(
            "nightrecon.web_form_execution.build_opener",
            return_value=opener,
        ):
            result = execute_form_submission(
                intent=_intent(),
                decision=_decision(),
                state=_state(),
                field_values={
                    "username": "alice",
                    "csrf_token": "submit-csrf-secret",
                },
                submissions_used=0,
                origin="https://example.test",
                authorized=True,
                authorization=secret,
                cookie_jar=cookie_jar,
            )

        request, _ = opener.requests[0]
        self.assertEqual(
            request.headers["Authorization"],
            secret,
        )
        self.assertNotIn(
            "submit-auth-secret",
            repr(result),
        )
        self.assertNotIn(
            "submit-csrf-secret",
            repr(result),
        )
        self.assertNotIn(
            "CookieJar",
            repr(result),
        )

    def test_stale_approval_is_rejected_before_network(self):
        with patch(
            "nightrecon.web_form_execution.build_opener"
        ) as build:
            with self.assertRaises(PermissionError):
                execute_form_submission(
                    intent=_intent(),
                    decision=_decision(),
                    state=_state(),
                    field_values={
                        "username": "alice",
                        "csrf_token": "token",
                    },
                    submissions_used=1,
                    origin="https://example.test",
                    authorized=True,
                )

        build.assert_not_called()

    def test_action_budget_and_invalid_limits_fail_closed(self):
        exhausted = WorkflowState(
            current_url="https://example.test/login",
            visited_urls=(),
            actions_used=3,
            max_actions=3,
        )

        with patch(
            "nightrecon.web_form_execution.build_opener"
        ) as build:
            with self.assertRaises(PermissionError):
                execute_form_submission(
                    intent=_intent(),
                    decision=_decision(),
                    state=exhausted,
                    field_values={
                        "username": "alice",
                        "csrf_token": "token",
                    },
                    submissions_used=0,
                    origin="https://example.test",
                    authorized=True,
                )

            with self.assertRaises(ValueError):
                execute_form_submission(
                    intent=_intent(),
                    decision=_decision(),
                    state=_state(),
                    field_values={
                        "username": "alice",
                        "csrf_token": "token",
                    },
                    submissions_used=0,
                    origin="https://example.test",
                    authorized=True,
                    max_response_bytes=0,
                )

        build.assert_not_called()


if __name__ == "__main__":
    unittest.main()
