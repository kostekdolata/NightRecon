"""Loopback tests for NightRecon credentialed CORS reflection DAST."""

from __future__ import annotations

import threading
import unittest
from http.server import (
    BaseHTTPRequestHandler,
    ThreadingHTTPServer,
)

from nightrecon.dast_cors import (
    assess_credentialed_cors,
)
from nightrecon.dast_policy import (
    DastBudgetPolicy,
    DastBudgetState,
)


class _CorsLabHandler(
    BaseHTTPRequestHandler
):
    def log_message(
        self,
        format,
        *args,
    ):
        return

    def do_OPTIONS(self):
        origin = self.headers.get(
            "Origin",
            "",
        )
        self.server.requests.append(
            {
                "path": self.path,
                "origin": origin,
                "acr_method": self.headers.get(
                    "Access-Control-Request-Method",
                    "",
                ),
            }
        )

        self.send_response(204)
        self.send_header(
            "Vary",
            "Origin",
        )

        if (
            self.path.startswith(
                "/reflect"
            )
            and origin
        ):
            self.send_header(
                "Access-Control-Allow-Origin",
                origin,
            )
            self.send_header(
                "Access-Control-Allow-Credentials",
                "true",
            )
            self.send_header(
                "Access-Control-Allow-Methods",
                "GET",
            )
        elif (
            self.path.startswith(
                "/wildcard"
            )
            and origin
        ):
            self.send_header(
                "Access-Control-Allow-Origin",
                "*",
            )
            self.send_header(
                "Access-Control-Allow-Credentials",
                "true",
            )
        elif (
            self.path.startswith(
                "/nocreds"
            )
            and origin
        ):
            self.send_header(
                "Access-Control-Allow-Origin",
                origin,
            )

        self.end_headers()


class DastCorsTests(unittest.TestCase):
    def setUp(self):
        self.server = ThreadingHTTPServer(
            (
                "127.0.0.1",
                0,
            ),
            _CorsLabHandler,
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

    def _policy(
        self,
        *,
        total=20,
        family=20,
    ):
        return DastBudgetPolicy(
            max_total_requests=total,
            default_family_requests=family,
        )

    def test_reflected_synthetic_origin_with_credentials_is_reported(self):
        result = assess_credentialed_cors(
            urls=(
                (
                    f"{self.origin}/reflect"
                    "?token=hidden#fragment"
                ),
            ),
            origin=self.origin,
            policy=self._policy(),
            state=DastBudgetState(),
            authorized=True,
            max_targets=1,
        )

        self.assertEqual(
            result.requests_attempted,
            2,
        )
        self.assertEqual(
            result.targets_attempted,
            1,
        )
        self.assertEqual(
            len(result.findings),
            1,
        )
        finding = (
            result.findings[0]
        )
        self.assertEqual(
            finding.check_id,
            "web.cors.credentialed-origin-reflection",
        )
        self.assertEqual(
            finding.severity,
            "medium",
        )
        self.assertEqual(
            finding.target_url,
            f"{self.origin}/reflect",
        )
        self.assertIn(
            (
                "synthetic_origin_reflected="
                "https://nightrecon.invalid"
            ),
            finding.evidence,
        )
        self.assertIn(
            "access_control_allow_credentials=true",
            finding.evidence,
        )
        self.assertIsNotNone(
            finding.retest
        )
        self.assertNotIn(
            "token=hidden",
            repr(result),
        )

        self.assertEqual(
            len(self.server.requests),
            2,
        )
        baseline = (
            self.server.requests[0]
        )
        probe = (
            self.server.requests[1]
        )
        self.assertEqual(
            baseline["origin"],
            "",
        )
        self.assertEqual(
            probe["origin"],
            "https://nightrecon.invalid",
        )
        self.assertEqual(
            probe["acr_method"],
            "GET",
        )

    def test_wildcard_with_credentials_is_not_misreported_as_reflection(self):
        result = assess_credentialed_cors(
            urls=(
                f"{self.origin}/wildcard",
            ),
            origin=self.origin,
            policy=self._policy(),
            state=DastBudgetState(),
            authorized=True,
            max_targets=1,
        )

        self.assertEqual(
            result.findings,
            (),
        )
        self.assertEqual(
            len(
                result.evidence_records
            ),
            1,
        )

    def test_reflection_without_credentials_is_not_reported(self):
        result = assess_credentialed_cors(
            urls=(
                f"{self.origin}/nocreds",
            ),
            origin=self.origin,
            policy=self._policy(),
            state=DastBudgetState(),
            authorized=True,
            max_targets=1,
        )

        self.assertEqual(
            result.findings,
            (),
        )

    def test_cross_origin_and_duplicate_targets_do_not_create_requests(self):
        result = assess_credentialed_cors(
            urls=(
                "https://outside.test/reflect",
                f"{self.origin}/reflect",
                f"{self.origin}/reflect",
            ),
            origin=self.origin,
            policy=self._policy(),
            state=DastBudgetState(),
            authorized=True,
            max_targets=3,
        )

        self.assertEqual(
            result.targets_attempted,
            1,
        )
        self.assertEqual(
            result.requests_attempted,
            2,
        )
        self.assertEqual(
            len(self.server.requests),
            2,
        )
        self.assertIn(
            "outside_authorized_origin",
            result.errors,
        )

    def test_family_budget_can_stop_between_baseline_and_probe(self):
        result = assess_credentialed_cors(
            urls=(
                f"{self.origin}/reflect",
            ),
            origin=self.origin,
            policy=self._policy(
                total=5,
                family=1,
            ),
            state=DastBudgetState(),
            authorized=True,
            max_targets=1,
        )

        self.assertEqual(
            result.requests_attempted,
            1,
        )
        self.assertEqual(
            result.findings,
            (),
        )
        self.assertEqual(
            result.evidence_records,
            (),
        )
        self.assertIn(
            "probe_request_not_authorized",
            result.errors,
        )
        self.assertEqual(
            len(self.server.requests),
            1,
        )

    def test_max_target_ceiling_is_enforced_before_requests(self):
        with self.assertRaises(
            ValueError
        ):
            assess_credentialed_cors(
                urls=(
                    f"{self.origin}/reflect",
                ),
                origin=self.origin,
                policy=self._policy(),
                state=DastBudgetState(),
                authorized=True,
                max_targets=6,
            )

        self.assertEqual(
            self.server.requests,
            [],
        )

    def test_explicit_authorization_is_required(self):
        with self.assertRaises(
            PermissionError
        ):
            assess_credentialed_cors(
                urls=(
                    f"{self.origin}/reflect",
                ),
                origin=self.origin,
                policy=self._policy(),
                state=DastBudgetState(),
                authorized=False,
                max_targets=1,
            )

        self.assertEqual(
            self.server.requests,
            [],
        )


if __name__ == "__main__":
    unittest.main()
