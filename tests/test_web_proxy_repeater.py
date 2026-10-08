"""Tests for HTTP request intelligence and bounded repeater records."""

import unittest

from nightrecon_red_engine.web_proxy_repeater import (
    BoundedInterceptProxy,
    RepeaterResponse,
    analyze_set_cookie,
    build_exchange_record,
    discover_parameters,
)
from nightrecon_shared_core.authorization import Scope


class WebProxyRepeaterTests(unittest.TestCase):
    def test_parameter_discovery_covers_query_form_and_json(self):
        query = discover_parameters(
            url="http://example.test/path?a=1&b=2",
        )
        self.assertEqual(
            {(item.location, item.name) for item in query},
            {("query", "a"), ("query", "b")},
        )

        form = discover_parameters(
            url="http://example.test/path",
            content_type="application/x-www-form-urlencoded",
            body=b"user=a&mode=test",
        )
        self.assertIn(("body-form", "user"), {
            (item.location, item.name) for item in form
        })

        js = discover_parameters(
            url="http://example.test/path",
            content_type="application/json",
            body=b'{"name":"x","enabled":true}',
        )
        self.assertIn(("body-json", "name"), {
            (item.location, item.name) for item in js
        })

    def test_cookie_analysis_reports_missing_flags_without_values(self):
        cookies = analyze_set_cookie((
            ("Set-Cookie", "session=secret; Path=/; HttpOnly"),
        ))
        self.assertEqual(cookies[0].name, "session")
        self.assertIn("missing Secure", cookies[0].issue)
        self.assertNotIn("secret", str(cookies[0]))

    def test_https_intercept_proxy_exposes_local_ca_without_auto_trust(self):
        scope = Scope.from_values(["example.test"])
        proxy = BoundedInterceptProxy(
            scope=scope,
            https_intercept=True,
        )
        try:
            self.assertTrue(proxy.ca_certificate_path)
            self.assertEqual(len(proxy.ca_fingerprint_sha256), 64)
        finally:
            proxy.close()

    def test_exchange_record_excludes_secret_header_names(self):
        response = RepeaterResponse(
            status=200,
            reason="OK",
            headers=(("Set-Cookie", "sid=x; Secure"), ("Server", "test")),
            body=b"ok",
            truncated=False,
        )
        record = build_exchange_record(
            method="POST",
            url="http://example.test/login?next=/",
            request_headers=(
                ("Authorization", "Bearer secret"),
                ("Content-Type", "application/json"),
            ),
            request_body=b'{"user":"alice"}',
            response=response,
        )
        self.assertNotIn("authorization", record.request_header_names)
        self.assertNotIn("set-cookie", record.response_header_names)
        self.assertTrue(record.parameters)
        self.assertEqual(record.url, "http://example.test/login")
        self.assertNotIn("next=", record.url)


if __name__ == "__main__":
    unittest.main()
