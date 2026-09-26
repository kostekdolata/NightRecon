"""Loopback tests for fixed NightRecon GraphQL introspection."""

from __future__ import annotations

import json
import threading
import unittest
from http.server import (
    BaseHTTPRequestHandler,
    ThreadingHTTPServer,
)

from nightrecon.api_graphql import (
    execute_graphql_introspection,
)


_SCHEMA = {
    "data": {
        "__schema": {
            "queryType": {
                "name": "Query",
            },
            "mutationType": None,
            "subscriptionType": None,
            "types": [
                {
                    "kind": "OBJECT",
                    "name": "Query",
                    "fields": [
                        {
                            "name": "status",
                            "args": [],
                            "type": {
                                "kind": "SCALAR",
                                "name": "String",
                            },
                        }
                    ],
                }
            ],
        }
    }
}


class _GraphQLLabHandler(
    BaseHTTPRequestHandler
):
    def log_message(
        self,
        format,
        *args,
    ):
        return

    def do_POST(self):
        length = int(
            self.headers.get(
                "Content-Length",
                "0",
            )
        )
        body = self.rfile.read(
            length
        )
        self.server.requests.append(
            {
                "path": self.path,
                "authorization": self.headers.get(
                    "Authorization",
                    "",
                ),
                "body": body.decode(
                    "utf-8"
                ),
            }
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
            payload = b"X" * 4096
        else:
            payload = json.dumps(
                _SCHEMA
            ).encode(
                "utf-8"
            )

        self.send_response(200)
        self.send_header(
            "Content-Type",
            "application/json",
        )
        self.send_header(
            "Content-Length",
            str(
                len(payload)
            ),
        )
        self.end_headers()
        self.wfile.write(
            payload
        )


class GraphQLLoopbackTests(unittest.TestCase):
    def setUp(self):
        self.server = ThreadingHTTPServer(
            (
                "127.0.0.1",
                0,
            ),
            _GraphQLLabHandler,
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

    def test_real_introspection_is_one_fixed_post(self):
        secret = (
            "Bearer loopback-graphql-secret"
        )
        result = execute_graphql_introspection(
            endpoint_url=(
                f"{self.origin}/graphql"
            ),
            origin=self.origin,
            authorized=True,
            authorization=secret,
            max_response_bytes=8192,
        )

        self.assertTrue(
            result.success
        )
        self.assertEqual(
            len(self.server.requests),
            1,
        )
        request = (
            self.server.requests[0]
        )
        self.assertEqual(
            request["path"],
            "/graphql",
        )
        self.assertEqual(
            request["authorization"],
            secret,
        )
        body = json.loads(
            request["body"]
        )
        self.assertEqual(
            body["operationName"],
            "NightReconIntrospection",
        )
        self.assertIn(
            "__schema",
            body["query"],
        )
        self.assertNotIn(
            "loopback-graphql-secret",
            repr(result),
        )

    def test_redirect_is_not_followed(self):
        result = execute_graphql_introspection(
            endpoint_url=(
                f"{self.origin}/redirect"
            ),
            origin=self.origin,
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
            len(self.server.requests),
            1,
        )

    def test_response_ceiling_is_enforced(self):
        result = execute_graphql_introspection(
            endpoint_url=(
                f"{self.origin}/large"
            ),
            origin=self.origin,
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
            result.byte_count,
            64,
        )


if __name__ == "__main__":
    unittest.main()
