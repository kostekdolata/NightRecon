"""Tests for NightRecon bounded safe-active DAST HTTP transport."""

import unittest
from email.message import Message
from http.cookiejar import CookieJar
from urllib.error import HTTPError
from urllib.request import HTTPCookieProcessor
from unittest.mock import patch

from nightrecon.dast_http import (
    execute_dast_http_request,
)
from nightrecon.dast_policy import (
    DastBudgetPolicy,
    DastBudgetState,
    DastCheckDefinition,
)


class _FakeResponse:
    def __init__(
        self,
        *,
        status=200,
        body=b"ok",
        content_type="text/plain",
        headers=(),
    ):
        self.status = status
        self._body = body
        self.headers = Message()
        self.headers[
            "Content-Type"
        ] = content_type

        for name, value in headers:
            self.headers[
                name
            ] = value

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
        return self._body[
            :limit
        ]


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


def _check(
    *,
    methods=(
        "GET",
        "HEAD",
        "OPTIONS",
    ),
):
    return DastCheckDefinition(
        check_id="web.test",
        name="Test DAST check",
        family="web-test",
        description="Test safe-active transport.",
        max_requests=3,
        allowed_methods=methods,
    )


def _policy():
    return DastBudgetPolicy(
        max_total_requests=5,
        default_family_requests=4,
    )


class DastHttpTests(unittest.TestCase):
    def test_get_returns_bounded_fingerprint_and_retained_headers(self):
        opener = _FakeOpener(
            _FakeResponse(
                body=b"hello",
                content_type="text/plain",
                headers=(
                    (
                        "Access-Control-Allow-Origin",
                        "https://client.test",
                    ),
                    (
                        "Set-Cookie",
                        "secret=value",
                    ),
                ),
            )
        )

        with patch(
            "nightrecon.dast_http.build_opener",
            return_value=opener,
        ):
            result = execute_dast_http_request(
                check=_check(),
                url=(
                    "https://example.test/path"
                    "?token=hidden#fragment"
                ),
                method="GET",
                origin="https://example.test",
                policy=_policy(),
                state=DastBudgetState(),
                authorized=True,
                max_response_bytes=64,
                max_fingerprint_bytes=4,
            )

        self.assertTrue(
            result.success
        )
        self.assertEqual(
            result.url,
            "https://example.test/path",
        )
        self.assertEqual(
            result.state.total_used,
            1,
        )
        self.assertIsNotNone(
            result.fingerprint
        )
        self.assertEqual(
            result.fingerprint.sample_byte_count,
            4,
        )
        self.assertEqual(
            result.response_headers,
            (
                (
                    "access-control-allow-origin",
                    "https://client.test",
                ),
            ),
        )
        self.assertNotIn(
            "secret=value",
            repr(result),
        )
        self.assertNotIn(
            "token=hidden",
            repr(result),
        )

    def test_transient_authorization_and_cookie_jar_are_not_retained(self):
        opener = _FakeOpener(
            _FakeResponse()
        )
        cookie_jar = CookieJar()
        secret = (
            "Bearer dast-secret"
        )

        with patch(
            "nightrecon.dast_http.build_opener",
            return_value=opener,
        ) as build:
            result = execute_dast_http_request(
                check=_check(),
                url="https://example.test/",
                method="GET",
                origin="https://example.test",
                policy=_policy(),
                state=DastBudgetState(),
                authorized=True,
                authorization=secret,
                cookie_jar=cookie_jar,
            )

        request, _ = (
            opener.requests[0]
        )
        self.assertEqual(
            request.headers[
                "Authorization"
            ],
            secret,
        )
        processors = tuple(
            handler
            for handler in build.call_args.args
            if isinstance(
                handler,
                HTTPCookieProcessor,
            )
        )
        self.assertEqual(
            len(processors),
            1,
        )
        self.assertIs(
            processors[0].cookiejar,
            cookie_jar,
        )
        self.assertNotIn(
            "dast-secret",
            repr(result),
        )
        self.assertNotIn(
            "CookieJar",
            repr(result),
        )

    def test_synthetic_headers_are_strictly_allowlisted(self):
        opener = _FakeOpener(
            _FakeResponse()
        )

        with patch(
            "nightrecon.dast_http.build_opener",
            return_value=opener,
        ):
            result = execute_dast_http_request(
                check=_check(),
                url="https://example.test/",
                method="OPTIONS",
                origin="https://example.test",
                policy=_policy(),
                state=DastBudgetState(),
                authorized=True,
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

        request, _ = (
            opener.requests[0]
        )
        self.assertEqual(
            request.headers["Origin"],
            "https://nightrecon.invalid",
        )
        self.assertEqual(
            request.headers[
                "Access-control-request-method"
            ],
            "GET",
        )
        self.assertTrue(
            result.success
        )

        with patch(
            "nightrecon.dast_http.build_opener"
        ) as build:
            with self.assertRaises(
                ValueError
            ):
                execute_dast_http_request(
                    check=_check(),
                    url="https://example.test/",
                    method="GET",
                    origin="https://example.test",
                    policy=_policy(),
                    state=DastBudgetState(),
                    authorized=True,
                    synthetic_headers=(
                        (
                            "Host",
                            "outside.test",
                        ),
                    ),
                )

        build.assert_not_called()

    def test_outside_origin_and_unauthorized_fail_before_network(self):
        with patch(
            "nightrecon.dast_http.build_opener"
        ) as build:
            with self.assertRaises(
                PermissionError
            ):
                execute_dast_http_request(
                    check=_check(),
                    url="https://outside.test/",
                    method="GET",
                    origin="https://example.test",
                    policy=_policy(),
                    state=DastBudgetState(),
                    authorized=True,
                )

            with self.assertRaises(
                PermissionError
            ):
                execute_dast_http_request(
                    check=_check(),
                    url="https://example.test/",
                    method="GET",
                    origin="https://example.test",
                    policy=_policy(),
                    state=DastBudgetState(),
                    authorized=False,
                )

        build.assert_not_called()

    def test_method_and_budget_denials_fail_before_network(self):
        with patch(
            "nightrecon.dast_http.build_opener"
        ) as build:
            with self.assertRaises(
                PermissionError
            ):
                execute_dast_http_request(
                    check=_check(
                        methods=("GET",),
                    ),
                    url="https://example.test/",
                    method="OPTIONS",
                    origin="https://example.test",
                    policy=_policy(),
                    state=DastBudgetState(),
                    authorized=True,
                )

            exhausted = DastBudgetState(
                total_used=1,
                check_usage=(
                    (
                        "web.test",
                        1,
                    ),
                ),
                family_usage=(
                    (
                        "web-test",
                        1,
                    ),
                ),
            )

            with self.assertRaises(
                PermissionError
            ):
                execute_dast_http_request(
                    check=DastCheckDefinition(
                        check_id="web.test",
                        name="One request",
                        family="web-test",
                        description="One request only.",
                        max_requests=1,
                        allowed_methods=("GET",),
                    ),
                    url="https://example.test/",
                    method="GET",
                    origin="https://example.test",
                    policy=_policy(),
                    state=exhausted,
                    authorized=True,
                )

        build.assert_not_called()

    def test_http_error_consumes_reserved_budget(self):
        error = HTTPError(
            url="https://example.test/",
            code=403,
            msg="Forbidden",
            hdrs=Message(),
            fp=None,
        )
        opener = _FakeOpener(
            error
        )

        with patch(
            "nightrecon.dast_http.build_opener",
            return_value=opener,
        ):
            result = execute_dast_http_request(
                check=_check(),
                url="https://example.test/",
                method="GET",
                origin="https://example.test",
                policy=_policy(),
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
            403,
        )
        self.assertEqual(
            result.state.total_used,
            1,
        )
        self.assertIsNone(
            result.fingerprint
        )

    def test_oversized_response_consumes_budget_without_body_retention(self):
        opener = _FakeOpener(
            _FakeResponse(
                body=b"X" * 64
            )
        )

        with patch(
            "nightrecon.dast_http.build_opener",
            return_value=opener,
        ):
            result = execute_dast_http_request(
                check=_check(),
                url="https://example.test/",
                method="GET",
                origin="https://example.test",
                policy=_policy(),
                state=DastBudgetState(),
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
            result.state.total_used,
            1,
        )
        self.assertIsNone(
            result.fingerprint
        )


if __name__ == "__main__":
    unittest.main()
