import unittest

from nightrecon.security_headers import analyze_security_headers


class SecurityHeaderAnalysisTests(unittest.TestCase):

    def test_security_header_names_are_case_insensitive(self):
        headers = {
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Strict-Transport-Security": "max-age=31536000",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "camera=()",
        }

        result = analyze_security_headers(headers)

        self.assertEqual(
            result.present,
            (
                "content-security-policy",
                "strict-transport-security",
                "x-content-type-options",
                "x-frame-options",
                "referrer-policy",
                "permissions-policy",
            ),
       )
        self.assertEqual(result.missing, ())

    def test_hsts_can_be_excluded_when_not_applicable(self):
        headers = {
            "strict-transport-security": "max-age=31536000",
            "x-content-type-options": "nosniff",
        }

        result = analyze_security_headers(
            headers,
            require_hsts=False,
        )

        self.assertNotIn(
            "strict-transport-security",
            result.present,
        )
        self.assertNotIn(
            "strict-transport-security",
            result.missing,
        )

    def test_present_and_missing_security_headers_are_identified(self):
        headers = {
            "content-security-policy": "default-src 'self'",
            "x-content-type-options": "nosniff",
            "x-frame-options": "DENY",
        }

        result = analyze_security_headers(headers)

        self.assertEqual(
            result.present,
            (
                "content-security-policy",
                "x-content-type-options",
                "x-frame-options",
            ),
        )
        self.assertEqual(
            result.missing,
            (
                "strict-transport-security",
                "referrer-policy",
                "permissions-policy",
            ),
        )


if __name__ == "__main__":
    unittest.main()