"""Tests for the NightRecon CISA KEV provider."""

import io
import json
import unittest
from unittest.mock import patch

from nightrecon.cisa_kev_provider import CisaKevProvider


class CisaKevProviderTests(unittest.TestCase):
    def test_requested_kev_records_are_parsed(self):
        payload = {
            "catalogVersion": "2026.09.24",
            "dateReleased": "2026-09-24T12:00:00Z",
            "vulnerabilities": [
                {
                    "cveID": "CVE-2026-1234",
                    "dateAdded": "2026-09-01",
                    "dueDate": "2026-09-22",
                    "knownRansomwareCampaignUse": "Known",
                    "requiredAction": "Apply vendor mitigations.",
                },
                {
                    "cveID": "CVE-2026-9999",
                    "dateAdded": "2026-09-02",
                    "dueDate": "2026-09-23",
                    "knownRansomwareCampaignUse": "Unknown",
                    "requiredAction": "Apply updates.",
                },
            ],
        }

        response = io.BytesIO(
            json.dumps(payload).encode("utf-8")
        )

        with patch(
            "nightrecon.cisa_kev_provider.urlopen",
            return_value=response,
        ) as urlopen:
            provider = CisaKevProvider(timeout=3.0)
            result = provider.lookup(
                ("CVE-2026-1234",)
            )

        self.assertEqual(
            tuple(result),
            ("CVE-2026-1234",),
        )
        record = result["CVE-2026-1234"]
        self.assertEqual(record.date_added, "2026-09-01")
        self.assertEqual(record.due_date, "2026-09-22")
        self.assertEqual(
            record.known_ransomware_campaign_use,
            "Known",
        )
        self.assertEqual(
            record.required_action,
            "Apply vendor mitigations.",
        )
        self.assertEqual(
            urlopen.call_args.kwargs["timeout"],
            3.0,
        )

    def test_empty_request_skips_network(self):
        with patch(
            "nightrecon.cisa_kev_provider.urlopen"
        ) as urlopen:
            provider = CisaKevProvider()
            result = provider.lookup(())

        self.assertEqual(result, {})
        urlopen.assert_not_called()


if __name__ == "__main__":
    unittest.main()
