"""Tests for scoped HTTPS interception primitives."""

import ssl
import tempfile
import unittest
from pathlib import Path

from nightrecon_red_engine.https_intercept import (
    AssessmentCertificateAuthority,
    authorize_connect_target,
    summarize_decrypted_request,
)
from nightrecon_shared_core.authorization import Scope


class HttpsInterceptTests(unittest.TestCase):
    def test_ephemeral_ca_issues_host_cert_and_server_context(self):
        with tempfile.TemporaryDirectory() as directory:
            with AssessmentCertificateAuthority(directory=directory) as ca:
                material = ca.issue_host_certificate("example.test")
                self.assertTrue(Path(material.certificate_path).is_file())
                self.assertTrue(Path(material.private_key_path).is_file())
                self.assertEqual(len(material.certificate_sha256), 64)
                context = ca.server_context("example.test")
                self.assertIsInstance(context, ssl.SSLContext)

    def test_connect_target_requires_explicit_scope(self):
        scope = Scope.from_values(["example.test"])
        authorize_connect_target("example.test", 443, scope)
        with self.assertRaises(PermissionError):
            authorize_connect_target("other.test", 443, scope)

    def test_decrypted_request_metadata_suppresses_secret_values_and_query(self):
        metadata = summarize_decrypted_request(
            method="POST",
            path="/login?token=secret",
            host="example.test",
            headers=(
                ("Authorization", "Bearer secret-value"),
                ("Cookie", "sid=secret-cookie"),
                ("Content-Type", "application/json"),
            ),
            body=b'{"password":"secret"}',
        )
        text = str(metadata)
        self.assertEqual(metadata.path, "/login")
        self.assertIn("authorization", metadata.secret_header_names)
        self.assertIn("cookie", metadata.secret_header_names)
        self.assertNotIn("secret-value", text)
        self.assertNotIn("secret-cookie", text)
        self.assertNotIn('"password"', text)
        self.assertEqual(len(metadata.body_sha256), 64)


if __name__ == "__main__":
    unittest.main()
