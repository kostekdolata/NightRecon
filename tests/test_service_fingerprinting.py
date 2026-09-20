"""Tests for NightRecon passive service fingerprinting."""

import unittest

from nightrecon.service_detection import identify_service_from_banner


class ServiceFingerprintingTests(unittest.TestCase):
    def test_ssh_banner_is_identified(self):
        service = identify_service_from_banner(
            "SSH-2.0-OpenSSH_9.6"
        )

        self.assertEqual(service, "ssh")

    def test_ftp_banner_is_identified(self):
        service = identify_service_from_banner(
            "220 ProFTPD 1.3.7 Server"
        )

        self.assertEqual(service, "ftp")

    def test_smtp_banner_is_identified(self):
        service = identify_service_from_banner(
            "220 mail.example.com ESMTP Postfix"
        )

        self.assertEqual(service, "smtp")


if __name__ == "__main__":
    unittest.main()