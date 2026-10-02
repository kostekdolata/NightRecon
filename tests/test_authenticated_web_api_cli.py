"""CLI contract tests for authenticated web/API continuity."""

import unittest

from nightrecon.cli import build_parser


class AuthenticatedWebApiCliContractTests(unittest.TestCase):
    def test_api_probe_exposes_explicit_session_cookie_opt_in(self):
        args = build_parser().parse_args(
            (
                "api",
                "probe",
                "openapi.json",
                "--base-url",
                "https://example.test/api",
                "--scope",
                "example.test",
                "--operation",
                "status",
                "--session-cookies",
            )
        )

        self.assertTrue(args.session_cookies)
        self.assertEqual(args.api_command, "probe")

    def test_browser_auth_uses_existing_authorization_environment_option(self):
        args = build_parser().parse_args(
            (
                "crawl",
                "https://example.test/",
                "--scope",
                "example.test",
                "--browser-discovery",
                "--authorization-env",
                "RED_AUTH",
            )
        )

        self.assertTrue(args.browser_discovery)
        self.assertEqual(args.authorization_env, "RED_AUTH")


if __name__ == "__main__":
    unittest.main()
