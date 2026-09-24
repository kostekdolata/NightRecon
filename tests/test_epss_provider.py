"""Tests for the NightRecon FIRST EPSS provider."""

import io
import json
import unittest
from unittest.mock import patch

from nightrecon.epss_provider import FirstEpssProvider


class FirstEpssProviderTests(unittest.TestCase):
    def test_epss_records_are_parsed(self):
        payload = {
            "status": "OK",
            "data": [
                {
                    "cve": "CVE-2026-1234",
                    "epss": "0.420000000",
                    "percentile": "0.970000000",
                    "date": "2026-09-24",
                }
            ],
        }

        response = io.BytesIO(
            json.dumps(payload).encode("utf-8")
        )

        with patch(
            "nightrecon.epss_provider.urlopen",
            return_value=response,
        ) as urlopen:
            provider = FirstEpssProvider(timeout=4.0)
            result = provider.lookup(
                ("CVE-2026-1234",)
            )

        record = result["CVE-2026-1234"]
        self.assertEqual(record.probability, 0.42)
        self.assertEqual(record.percentile, 0.97)
        self.assertEqual(record.date, "2026-09-24")
        request = urlopen.call_args.args[0]
        self.assertIn(
            "cve=CVE-2026-1234",
            request.full_url,
        )
        self.assertEqual(
            urlopen.call_args.kwargs["timeout"],
            4.0,
        )

    def test_empty_request_skips_network(self):
        with patch(
            "nightrecon.epss_provider.urlopen"
        ) as urlopen:
            provider = FirstEpssProvider()
            result = provider.lookup(())

        self.assertEqual(result, {})
        urlopen.assert_not_called()

    def test_large_requests_are_batched(self):
        ids = tuple(
            f"CVE-2026-{index:04d}"
            for index in range(300)
        )

        response = io.BytesIO(
            json.dumps(
                {
                    "status": "OK",
                    "data": [],
                }
            ).encode("utf-8")
        )

        with patch(
            "nightrecon.epss_provider.urlopen",
            side_effect=lambda *args, **kwargs: io.BytesIO(
                response.getvalue()
            ),
        ) as urlopen:
            provider = FirstEpssProvider()
            provider.lookup(ids)

        self.assertGreater(
            urlopen.call_count,
            1,
        )


if __name__ == "__main__":
    unittest.main()
