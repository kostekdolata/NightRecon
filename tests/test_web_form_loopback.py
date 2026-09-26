"""Loopback integration tests for bounded NightRecon form submission."""

from __future__ import annotations

import threading
import unittest
from http.cookiejar import CookieJar
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from nightrecon.web_form_execution import (
    execute_form_submission,
)
from nightrecon.web_form_intent import (
    WorkflowFieldClass,
    WorkflowFormFieldIntent,
    WorkflowFormIntent,
)
from nightrecon.web_form_submission import (
    FormSubmissionPolicy,
    authorize_form_submission,
)
from nightrecon.web_workflow import (
    WorkflowAction,
    WorkflowActionKind,
    WorkflowPolicy,
    WorkflowState,
    authorize_workflow_action,
)
from nightrecon.web_workflow_execution import (
    execute_workflow_navigation,
)


class _FormLabHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        return

    def do_GET(self):
        self.server.get_paths.append(self.path)

        if self.path == "/seed":
            body = b"<html><body>seed</body></html>"
            self.send_response(200)
            self.send_header(
                "Set-Cookie",
                "session=post-loopback-cookie-secret; Path=/; HttpOnly",
            )
            self.send_header(
                "Content-Type",
                "text/html; charset=utf-8",
            )
            self.send_header(
                "Content-Length",
                str(len(body)),
            )
            self.end_headers()
            self.wfile.write(body)
            return

        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        length = int(
            self.headers.get(
                "Content-Length",
                "0",
            )
        )
        body = self.rfile.read(length)

        self.server.post_requests.append(
            {
                "path": self.path,
                "content_type": self.headers.get(
                    "Content-Type",
                    "",
                ),
                "authorization": self.headers.get(
                    "Authorization",
                    "",
                ),
                "cookie": self.headers.get(
                    "Cookie",
                    "",
                ),
                "body": body.decode(
                    "utf-8"
                ),
            }
        )

        if self.path == "/submit-redirect":
            self.send_response(302)
            self.send_header(
                "Location",
                "http://127.0.0.1:1/outside",
            )
            self.end_headers()
            return

        if self.path != "/session":
            self.send_response(404)
            self.end_headers()
            return

        body_text = body.decode(
            "utf-8"
        )

        if (
            "username=alice" not in body_text
            or "csrf_token=loopback-csrf-secret" not in body_text
            or "session=post-loopback-cookie-secret"
            not in self.headers.get("Cookie", "")
            or self.headers.get("Authorization", "")
            != "Bearer loopback-submit-auth"
        ):
            self.send_response(403)
            self.end_headers()
            return

        response = b"accepted"
        self.send_response(200)
        self.send_header(
            "Content-Type",
            "text/plain",
        )
        self.send_header(
            "Content-Length",
            str(len(response)),
        )
        self.end_headers()
        self.wfile.write(response)


class FormLoopbackIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.server = ThreadingHTTPServer(
            ("127.0.0.1", 0),
            _FormLabHandler,
        )
        self.server.get_paths = []
        self.server.post_requests = []
        self.thread = threading.Thread(
            target=self.server.serve_forever,
            daemon=True,
        )
        self.thread.start()

        host, port = self.server.server_address
        self.origin = f"http://{host}:{port}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def _state(self):
        return WorkflowState(
            current_url=f"{self.origin}/start",
            visited_urls=(
                f"{self.origin}/start",
            ),
            actions_used=0,
            max_actions=4,
        )

    def _form_intent(
        self,
        path="/session",
    ):
        return WorkflowFormIntent(
            source_url=f"{self.origin}/seed",
            action_url=f"{self.origin}{path}",
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
        )

    def _policy(
        self,
        *,
        allow_destructive=False,
    ):
        return FormSubmissionPolicy(
            origin=self.origin,
            enabled=True,
            max_submissions=1,
            allowed_fields=(
                "username",
                "csrf_token",
            ),
            allowed_sensitive_classes=(
                WorkflowFieldClass.ANTI_CSRF,
            ),
            allow_destructive_actions=allow_destructive,
        )

    def test_explicit_post_reuses_ephemeral_auth_and_cookie_context(self):
        cookie_jar = CookieJar()
        state = self._state()

        navigation_policy = WorkflowPolicy(
            origin=self.origin,
            max_actions=4,
        )
        seed_action = WorkflowAction(
            kind=WorkflowActionKind.NAVIGATE,
            source_url=f"{self.origin}/start",
            target_url=f"{self.origin}/seed",
            method="GET",
        )
        seed_decision = authorize_workflow_action(
            action=seed_action,
            policy=navigation_policy,
            actions_used=state.actions_used,
        )
        seed_result = execute_workflow_navigation(
            action=seed_action,
            decision=seed_decision,
            state=state,
            origin=self.origin,
            authorized=True,
            cookie_jar=cookie_jar,
        )

        self.assertTrue(seed_result.success)

        intent = self._form_intent()
        decision = authorize_form_submission(
            intent=intent,
            policy=self._policy(),
            provided_field_names=(
                "username",
                "csrf_token",
            ),
            submissions_used=0,
        )

        self.assertTrue(decision.allowed)

        result = execute_form_submission(
            intent=intent,
            decision=decision,
            state=seed_result.state,
            field_values={
                "username": "alice",
                "csrf_token": "loopback-csrf-secret",
            },
            submissions_used=0,
            origin=self.origin,
            authorized=True,
            authorization="Bearer loopback-submit-auth",
            cookie_jar=cookie_jar,
            max_body_bytes=1024,
            max_response_bytes=32,
        )

        self.assertTrue(result.success)
        self.assertEqual(
            result.status,
            200,
        )
        self.assertEqual(
            result.byte_count,
            len(b"accepted"),
        )
        self.assertEqual(
            result.submissions_used,
            1,
        )
        self.assertEqual(
            result.state.actions_used,
            2,
        )
        self.assertEqual(
            self.server.get_paths,
            ["/seed"],
        )
        self.assertEqual(
            len(self.server.post_requests),
            1,
        )

        request = self.server.post_requests[0]
        self.assertEqual(
            request["path"],
            "/session",
        )
        self.assertEqual(
            request["content_type"],
            "application/x-www-form-urlencoded",
        )
        self.assertEqual(
            request["authorization"],
            "Bearer loopback-submit-auth",
        )
        self.assertIn(
            "session=post-loopback-cookie-secret",
            request["cookie"],
        )
        self.assertIn(
            "username=alice",
            request["body"],
        )
        self.assertIn(
            "csrf_token=loopback-csrf-secret",
            request["body"],
        )

        self.assertNotIn(
            "loopback-csrf-secret",
            repr(result),
        )
        self.assertNotIn(
            "loopback-submit-auth",
            repr(result),
        )
        self.assertNotIn(
            "post-loopback-cookie-secret",
            repr(result),
        )

    def test_destructive_form_is_denied_before_real_post(self):
        intent = self._form_intent(
            "/account/delete"
        )
        decision = authorize_form_submission(
            intent=intent,
            policy=self._policy(),
            provided_field_names=(
                "username",
                "csrf_token",
            ),
            submissions_used=0,
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(
            decision.reason,
            "destructive_form_action_blocked",
        )

        with self.assertRaises(PermissionError):
            execute_form_submission(
                intent=intent,
                decision=decision,
                state=self._state(),
                field_values={},
                submissions_used=0,
                origin=self.origin,
                authorized=True,
            )

        self.assertEqual(
            self.server.post_requests,
            [],
        )

    def test_post_redirect_is_not_followed_and_state_does_not_advance(self):
        intent = self._form_intent(
            "/submit-redirect"
        )
        decision = authorize_form_submission(
            intent=intent,
            policy=self._policy(),
            provided_field_names=(
                "username",
                "csrf_token",
            ),
            submissions_used=0,
        )
        self.assertTrue(decision.allowed)
        state = self._state()

        result = execute_form_submission(
            intent=intent,
            decision=decision,
            state=state,
            field_values={
                "username": "alice",
                "csrf_token": "loopback-csrf-secret",
            },
            submissions_used=0,
            origin=self.origin,
            authorized=True,
        )

        self.assertFalse(result.success)
        self.assertEqual(
            result.reason,
            "http_error",
        )
        self.assertEqual(
            result.status,
            302,
        )
        self.assertEqual(
            len(self.server.post_requests),
            1,
        )
        self.assertIs(
            result.state,
            state,
        )
        self.assertEqual(
            result.submissions_used,
            0,
        )


if __name__ == "__main__":
    unittest.main()
