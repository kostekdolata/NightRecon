"""Loopback integration tests for NightRecon safe API execution."""

from __future__ import annotations

import threading
import unittest
from http.server import (
    BaseHTTPRequestHandler,
    ThreadingHTTPServer,
)

from nightrecon.api_execution import (
    execute_api_request,
)
from nightrecon.api_policy import (
    ApiRequest,
    ApiRequestPolicy,
    ApiRequestState,
    authorize_api_request,
)


class _ApiLabHandler(
    BaseHTTPRequestHandler
):
    def log_message(
        self,
        format,
        *args,
    ):
        return

    def do_GET(self):
        self.server.requests.append(
            (
                "GET",
                self.path,
                self.headers.get(
                    "Authorization",
                    "",
                ),
            )
        )

        if self.path == "/redirect":
            self.send_response(302)
            self.send_header(
                "Location",
                "http://127.0.0.1:1/outside",
            )
            self.end_headers()
            return

        if self.path == "/large":
            body = b"X" * 4096
        else:
            body = b'{"ok":true}'

        self.send_response(200)
        self.send_header(
            "Content-Type",
            "application/json",
        )
        self.send_header(
            "Content-Length",
            str(
                len(body)
            ),
        )
        self.end_headers()
        self.wfile.write(
            body
        )

    def do_HEAD(self):
        self.server.requests.append(
            (
                "HEAD",
                self.path,
                self.headers.get(
                    "Authorization",
                    "",
                ),
            )
        )
        self.send_response(200)
        self.send_header(
            "Content-Type",
            "application/json",
        )
        self.end_headers()

    def do_POST(self):
        self.server.requests.append(
            (
                "POST",
                self.path,
                "",
            )
        )
        self.send_response(204)
        self.end_headers()


class ApiLoopbackTests(unittest.TestCase):
    def setUp(self):
        self.server = ThreadingHTTPServer(
            (
                "127.0.0.1",
                0,
            ),
            _ApiLabHandler,
        )
        self.server.requests = []
        self.thread = threading.Thread(
            target=self.server.serve_forever,
            daemon=True,
        )
        self.thread.start()

        host, port = (
            self.server.server_address
        )
        self.origin = (
            f"http://{host}:{port}"
        )

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(
            timeout=2,
        )

    def _execute(
        self,
        *,
        path="/status",
        method="GET",
        state=None,
        max_response_bytes=1024,
        authorization=None,
    ):
        policy = ApiRequestPolicy(
            origin=self.origin,
            max_requests=3,
        )
        request = ApiRequest(
            url=f"{self.origin}{path}",
            method=method,
            operation_id="testOperation",
        )
        current = (
            state
            if state is not None
            else ApiRequestState(
                requests_used=0,
                max_requests=3,
            )
        )
        decision = authorize_api_request(
            request=request,
            policy=policy,
            state=current,
        )

        return execute_api_request(
            request=request,
            decision=decision,
            state=current,
            origin=self.origin,
            authorized=True,
            max_response_bytes=max_response_bytes,
            authorization=authorization,
        )

    def test_real_get_and_head_requests_are_bounded(self):
        get_result = self._execute(
            authorization=(
                "Bearer loopback-api-secret"
            )
        )
        head_result = self._execute(
            method="HEAD",
            state=get_result.state,
        )

        self.assertTrue(
            get_result.success
        )
        self.assertTrue(
            head_result.success
        )
        self.assertEqual(
            get_result.byte_count,
            len(b'{"ok":true}'),
        )
        self.assertEqual(
            head_result.byte_count,
            0,
        )
        self.assertEqual(
            head_result.state.requests_used,
            2,
        )
        self.assertEqual(
            self.server.requests[0],
            (
                "GET",
                "/status",
                "Bearer loopback-api-secret",
            ),
        )
        self.assertEqual(
            self.server.requests[1][0:2],
            (
                "HEAD",
                "/status",
            ),
        )
        self.assertNotIn(
            "loopback-api-secret",
            repr(get_result),
        )

    def test_redirect_is_not_followed(self):
        result = self._execute(
            path="/redirect",
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
            302,
        )
        self.assertEqual(
            self.server.requests,
            [
                (
                    "GET",
                    "/redirect",
                    "",
                )
            ],
        )

    def test_response_byte_ceiling_is_enforced(self):
        result = self._execute(
            path="/large",
            max_response_bytes=64,
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
            64,
        )

    def test_post_is_blocked_before_real_network_request(self):
        policy = ApiRequestPolicy(
            origin=self.origin,
        )
        request = ApiRequest(
            url=f"{self.origin}/mutate",
            method="POST",
            operation_id="mutate",
        )
        state = ApiRequestState(
            requests_used=0,
            max_requests=25,
        )
        decision = authorize_api_request(
            request=request,
            policy=policy,
            state=state,
        )

        self.assertFalse(
            decision.allowed
        )

        with self.assertRaises(
            PermissionError
        ):
            execute_api_request(
                request=request,
                decision=decision,
                state=state,
                origin=self.origin,
                authorized=True,
            )

        self.assertEqual(
            self.server.requests,
            [],
        )


if __name__ == "__main__":
    unittest.main()
