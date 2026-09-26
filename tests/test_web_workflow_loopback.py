"""Loopback integration tests for NightRecon workflow navigation."""

from __future__ import annotations

import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

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


class _WorkflowLabHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        return

    def do_GET(self):
        self.server.get_paths.append(self.path)

        if self.path == "/redirect":
            self.send_response(302)
            self.send_header(
                "Location",
                "http://127.0.0.1:1/outside",
            )
            self.end_headers()
            return

        if self.path == "/large":
            body = (
                "<html><body>"
                + ("X" * 4096)
                + "</body></html>"
            ).encode("utf-8")
        else:
            body = b"""
            <html>
              <body>
                <form action="/danger" method="post">
                  <input name="csrf_token" type="hidden">
                </form>
                <a href="/next">Next</a>
              </body>
            </html>
            """

        self.send_response(200)
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

    def do_POST(self):
        self.server.post_paths.append(self.path)
        self.send_response(204)
        self.end_headers()


class WorkflowLoopbackIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.server = ThreadingHTTPServer(
            ("127.0.0.1", 0),
            _WorkflowLabHandler,
        )
        self.server.get_paths = []
        self.server.post_paths = []
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
            max_actions=3,
        )

    def _navigation(self, target_path):
        policy = WorkflowPolicy(
            origin=self.origin,
            max_actions=3,
        )
        action = WorkflowAction(
            kind=WorkflowActionKind.NAVIGATE,
            source_url=f"{self.origin}/start",
            target_url=f"{self.origin}{target_path}",
            method="GET",
        )
        decision = authorize_workflow_action(
            action=action,
            policy=policy,
            actions_used=0,
        )
        return action, decision

    def test_real_get_navigation_never_submits_observed_form(self):
        action, decision = self._navigation(
            "/dashboard"
        )

        result = execute_workflow_navigation(
            action=action,
            decision=decision,
            state=self._state(),
            origin=self.origin,
            authorized=True,
            max_bytes=4096,
        )

        self.assertTrue(result.success)
        self.assertEqual(
            self.server.get_paths,
            ["/dashboard"],
        )
        self.assertEqual(
            self.server.post_paths,
            [],
        )
        self.assertIsNotNone(result.page)
        self.assertEqual(
            len(result.page.forms),
            1,
        )
        self.assertEqual(
            result.page.forms[0].method,
            "POST",
        )
        self.assertEqual(
            result.state.current_url,
            f"{self.origin}/dashboard",
        )
        self.assertEqual(
            result.state.actions_used,
            1,
        )

    def test_form_submission_is_blocked_before_real_network_request(self):
        policy = WorkflowPolicy(
            origin=self.origin,
            allow_form_submission=True,
            allowed_methods=("GET", "POST"),
        )
        action = WorkflowAction(
            kind=WorkflowActionKind.SUBMIT_FORM,
            source_url=f"{self.origin}/dashboard",
            target_url=f"{self.origin}/danger",
            method="POST",
        )
        decision = authorize_workflow_action(
            action=action,
            policy=policy,
            actions_used=0,
        )
        self.assertTrue(decision.allowed)

        with self.assertRaises(PermissionError):
            execute_workflow_navigation(
                action=action,
                decision=decision,
                state=self._state(),
                origin=self.origin,
                authorized=True,
            )

        self.assertEqual(
            self.server.get_paths,
            [],
        )
        self.assertEqual(
            self.server.post_paths,
            [],
        )

    def test_cross_origin_redirect_is_blocked_without_followup_request(self):
        action, decision = self._navigation(
            "/redirect"
        )
        state = self._state()

        result = execute_workflow_navigation(
            action=action,
            decision=decision,
            state=state,
            origin=self.origin,
            authorized=True,
        )

        self.assertFalse(result.success)
        self.assertEqual(
            result.reason,
            "navigation_failed",
        )
        self.assertEqual(
            self.server.get_paths,
            ["/redirect"],
        )
        self.assertEqual(
            self.server.post_paths,
            [],
        )
        self.assertIs(
            result.state,
            state,
        )
        self.assertIn(
            "Cross-origin redirect blocked",
            result.page.error,
        )

    def test_real_response_respects_hard_byte_limit(self):
        action, decision = self._navigation(
            "/large"
        )

        result = execute_workflow_navigation(
            action=action,
            decision=decision,
            state=self._state(),
            origin=self.origin,
            authorized=True,
            max_bytes=128,
        )

        self.assertTrue(result.success)
        self.assertEqual(
            self.server.get_paths,
            ["/large"],
        )
        self.assertEqual(
            result.page.byte_count,
            128,
        )


if __name__ == "__main__":
    unittest.main()
