"""Real Chromium loopback integration tests for NightRecon browser discovery.

This file is intentionally not named test_*.py so the normal lightweight
unit-test matrix does not require Playwright or a browser installation.
"""

from __future__ import annotations

import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from nightrecon.browser_playwright import discover_with_playwright
from nightrecon.browser_policy import BrowserDiscoveryPolicy


class _PrimaryHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        return

    def do_GET(self):
        self.server.get_paths.append(self.path)

        if self.path == "/":
            outside_origin = self.server.outside_origin
            body = f"""
            <html>
              <head>
                <title>NightRecon Browser Lab</title>
                <script src="/app.js"></script>
                <script src="{outside_origin}/blocked.js"></script>
              </head>
              <body>
                <form action="/session" method="post">
                  <input name="username" type="text">
                  <input name="csrf_token" type="hidden">
                </form>
                <script>
                  fetch("/api/data");
                  fetch("/api/update", {{
                    method: "POST",
                    body: "blocked=yes"
                  }});
                </script>
              </body>
            </html>
            """.encode("utf-8")
            self._send(200, body, "text/html; charset=utf-8")
            return

        if self.path == "/app.js":
            body = b"""
            window.addEventListener("DOMContentLoaded", () => {
              const link = document.createElement("a");
              link.href = "/spa-route";
              link.textContent = "SPA Route";
              document.body.appendChild(link);
            });
            """
            self._send(
                200,
                body,
                "application/javascript",
            )
            return

        if self.path == "/api/data":
            self._send(
                200,
                b'{"ok":true}',
                "application/json",
            )
            return

        if self.path == "/redirect":
            self.send_response(302)
            self.send_header(
                "Location",
                f"{self.server.outside_origin}/escaped",
            )
            self.end_headers()
            return

        self._send(
            404,
            b"not found",
            "text/plain",
        )

    def do_POST(self):
        self.server.post_paths.append(self.path)
        self._send(
            204,
            b"",
            "text/plain",
        )

    def _send(self, status, body, content_type):
        self.send_response(status)
        self.send_header(
            "Content-Type",
            content_type,
        )
        self.send_header(
            "Content-Length",
            str(len(body)),
        )
        self.end_headers()

        if body:
            self.wfile.write(body)


class _OutsideHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        return

    def do_GET(self):
        self.server.get_paths.append(self.path)
        body = b"outside"
        self.send_response(200)
        self.send_header(
            "Content-Length",
            str(len(body)),
        )
        self.end_headers()
        self.wfile.write(body)


class BrowserPlaywrightRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.outside = ThreadingHTTPServer(
            ("127.0.0.1", 0),
            _OutsideHandler,
        )
        self.outside.get_paths = []
        outside_host, outside_port = (
            self.outside.server_address
        )
        self.outside_origin = (
            f"http://{outside_host}:{outside_port}"
        )

        self.primary = ThreadingHTTPServer(
            ("127.0.0.1", 0),
            _PrimaryHandler,
        )
        self.primary.get_paths = []
        self.primary.post_paths = []
        self.primary.outside_origin = (
            self.outside_origin
        )
        host, port = self.primary.server_address
        self.origin = f"http://{host}:{port}"

        self.outside_thread = threading.Thread(
            target=self.outside.serve_forever,
            daemon=True,
        )
        self.primary_thread = threading.Thread(
            target=self.primary.serve_forever,
            daemon=True,
        )
        self.outside_thread.start()
        self.primary_thread.start()

    def tearDown(self):
        self.primary.shutdown()
        self.outside.shutdown()
        self.primary.server_close()
        self.outside.server_close()
        self.primary_thread.join(timeout=2)
        self.outside_thread.join(timeout=2)

    def _policy(self):
        return BrowserDiscoveryPolicy(
            origin=self.origin,
            max_requests=10,
            max_pages=2,
            max_runtime_seconds=10.0,
            max_response_bytes=1_048_576,
            max_dom_bytes=65_536,
            max_dom_items=100,
        )

    def test_real_chromium_discovers_dynamic_dom_and_blocks_unsafe_requests(self):
        result = discover_with_playwright(
            start_url=f"{self.origin}/",
            policy=self._policy(),
            headless=True,
        )

        self.assertIsNone(
            result.error,
            msg=result.error,
        )
        self.assertIsNotNone(
            result.page,
        )
        self.assertEqual(
            result.page.title,
            "NightRecon Browser Lab",
        )
        self.assertIn(
            f"{self.origin}/spa-route",
            result.page.links,
        )
        self.assertEqual(
            len(result.page.forms),
            1,
        )
        self.assertEqual(
            result.page.forms[0].action,
            f"{self.origin}/session",
        )
        self.assertEqual(
            self.outside.get_paths,
            [],
        )
        self.assertEqual(
            self.primary.post_paths,
            [],
        )
        self.assertIn(
            "/app.js",
            self.primary.get_paths,
        )

        reasons = tuple(
            observation.reason
            for observation in result.snapshot.requests
            if not observation.allowed
        )
        self.assertIn(
            "outside_authorized_origin",
            reasons,
        )
        self.assertIn(
            "method_not_allowed",
            reasons,
        )

    def test_real_chromium_blocks_cross_origin_redirect(self):
        result = discover_with_playwright(
            start_url=f"{self.origin}/redirect",
            policy=self._policy(),
            headless=True,
        )

        self.assertIsNone(
            result.page,
        )
        self.assertIsNotNone(
            result.error,
        )
        self.assertEqual(
            self.outside.get_paths,
            [],
        )
        self.assertTrue(
            any(
                (
                    observation.status == 302
                    and observation.capture_allowed
                )
                for observation
                in result.snapshot.responses
            )
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
