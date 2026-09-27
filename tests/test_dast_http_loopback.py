"""Loopback integration tests for bounded NightRecon DAST HTTP transport."""

from __future__ import annotations

import threading
import unittest
from http.cookiejar import CookieJar
from http.server import (
    BaseHTTPRequestHandler,
    ThreadingHTTPServer,
)

from nightrecon.dast_http import (
    execute_dast_http_request,
)
from nightrecon.dast_policy import (
    DastBudgetPolicy,
    DastBudgetState,
    DastCheckDefinition,
)


class _DastLabHandler(
    BaseHTTPRequestHandler
):
    def log_message(
        self,
        format,
        *args,
    ):
        return

    def _record(self):
        self.server.requests.append(
            {
                "method": self.command,
                "path": self.path,
                "origin": self.headers.get(
                    "Origin",
                    "",
                ),
                "acr_method": self.headers.get(
                    "Access-Control-Request-Method",
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
            }
        )

    def do_GET(self):
        self._record()

        if self.path == "/seed":
            body = b"seed"
            self.send_response(200)
            self.send_header(
                "Set-Cookie",
                "session=loopback-cookie-secret; Path=/; HttpOnly",
            )
            self.send_header(
                "Content-Type",
                "text/plain",
            )
            self.send_header(
                "Content-Length",
                str(len(body)),
            )
            self.end_headers()
            self.wfile.write(body)
            return

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
            body = b"ok"

        self.send_response(200)
        self.send_header(
            "Content-Type",
            "text/plain",
        )
        self.send_header(
            "Content-Length",
            str(len(body)),
        )
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self._record()
        body = b"preflight"
        self.send_response(200)
        self.send_header(
            "Content-Type",
            "text/plain",
        )
        self.send_header(
            "Access-Control-Allow-Origin",
            self.headers.get(
                "Origin",
                "",
            ),
        )
        self.send_header(
            "Access-Control-Allow-Credentials",
            "true",
        )
        self.send_header(
            "Vary",
            "Origin",
        )
        self.send_header(
            "Content-Length",
            str(len(body)),
        )
        self.end_headers()
        self.wfile.write(body)


class DastHttpLoopbackTests(unittest.TestCase):
    def setUp(self):
        self.server = ThreadingHTTPServer(
            (
                "127.0.0.1",
                0,
            ),
            _DastLabHandler,
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
        self.check = DastCheckDefinition(
            check_id="web.loopback",
            name="Loopback",
            family="web-loopback",
            description="Loopback DAST transport test.",
            max_requests=5,
            allowed_methods=(
                "GET",
                "OPTIONS",
            ),
        )
        self.policy = DastBudgetPolicy(
            max_total_requests=5,
            default_family_requests=5,
        )

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(
            timeout=2,
        )

    def test_real_get_and_options_share_budget_and_ephemeral_cookie_context(self):
        cookie_jar = CookieJar()
        first = execute_dast_http_request(
            check=self.check,
            url=f"{self.origin}/seed",
            method="GET",
            origin=self.origin,
            policy=self.policy,
            state=DastBudgetState(),
            authorized=True,
            cookie_jar=cookie_jar,
        )
        second = execute_dast_http_request(
            check=self.check,
            url=f"{self.origin}/cors",
            method="OPTIONS",
            origin=self.origin,
            policy=self.policy,
            state=first.state,
            authorized=True,
            cookie_jar=cookie_jar,
            authorization=(
                "Bearer loopback-dast-secret"
            ),
            synthetic_headers=(
                (
                    "Origin",
                    "https://nightrecon.invalid",
                ),
                (
                    "Access-Control-Request-Method",
                    "GET",
                ),
            ),
        )

        self.assertTrue(
            first.success
        )
        self.assertTrue(
            second.success
        )
        self.assertEqual(
            second.state.total_used,
            2,
        )
        self.assertEqual(
            dict(
                second.response_headers
            )[
                "access-control-allow-origin"
            ],
            "https://nightrecon.invalid",
        )
        self.assertEqual(
            len(self.server.requests),
            2,
        )
        request = (
            self.server.requests[1]
        )
        self.assertEqual(
            request["method"],
            "OPTIONS",
        )
        self.assertEqual(
            request["origin"],
            "https://nightrecon.invalid",
        )
        self.assertEqual(
            request["acr_method"],
            "GET",
        )
        self.assertEqual(
            request["authorization"],
            "Bearer loopback-dast-secret",
        )
        self.assertIn(
            "session=loopback-cookie-secret",
            request["cookie"],
        )
        self.assertNotIn(
            "loopback-dast-secret",
            repr(second),
        )
        self.assertNotIn(
            "loopback-cookie-secret",
            repr(second),
        )

    def test_redirect_is_not_followed_and_attempt_consumes_budget(self):
        result = execute_dast_http_request(
            check=self.check,
            url=f"{self.origin}/redirect",
            method="GET",
            origin=self.origin,
            policy=self.policy,
            state=DastBudgetState(),
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
            302,
        )
        self.assertEqual(
            result.state.total_used,
            1,
        )
        self.assertEqual(
            len(self.server.requests),
            1,
        )

    def test_response_limit_is_enforced_on_real_request(self):
        result = execute_dast_http_request(
            check=self.check,
            url=f"{self.origin}/large",
            method="GET",
            origin=self.origin,
            policy=self.policy,
            state=DastBudgetState(),
            authorized=True,
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
            result.state.total_used,
            1,
        )


if __name__ == "__main__":
    unittest.main()
