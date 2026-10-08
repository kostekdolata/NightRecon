"""Tests for Red Night protocol metadata dissectors."""

import unittest

from nightrecon_red_engine.protocol_dissectors import (
    dissect_http,
    dissect_payload,
    dissect_smb,
    dissect_ssh,
)


class ProtocolDissectorTests(unittest.TestCase):
    def test_http_request_metadata_omits_query_values(self):
        result = dissect_http(b"GET /search?q=secret HTTP/1.1\r\nHost: x\r\n\r\n")
        self.assertIsNotNone(result)
        self.assertEqual(result.get("method"), "GET")
        self.assertEqual(result.get("path"), "/search")
        self.assertNotIn("secret", str(result))

    def test_ssh_banner_is_identified_and_fingerprinted(self):
        result = dissect_ssh(b"SSH-2.0-OpenSSH_9.6\r\n")
        self.assertIsNotNone(result)
        self.assertEqual(result.protocol, "ssh")
        self.assertEqual(result.get("protocol_version"), "2.0")
        self.assertTrue(result.get("banner_sha256"))

    def test_smb2_header_is_identified(self):
        payload = b"\xfeSMB" + (b"\x00" * 8) + b"\x05\x00" + (b"\x00" * 10)
        result = dissect_smb(payload)
        self.assertIsNotNone(result)
        self.assertEqual(result.protocol, "smb2")
        self.assertEqual(result.get("command"), "5")

    def test_generic_payload_dispatch(self):
        result = dissect_payload(
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
            src_port=80,
            dst_port=51000,
        )
        self.assertIsNotNone(result)
        self.assertEqual(result.protocol, "http")
        self.assertEqual(result.get("status"), "200")


if __name__ == "__main__":
    unittest.main()
