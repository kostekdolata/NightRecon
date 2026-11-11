"""Synthetic cross-tool correlation tests; never access the network."""
import json
import unittest

from nightrecon_red_engine.amass_httpx_offline_correlation import (
    OfflineWebCorrelationError, correlate_amass_httpx,
)


def dns(name):
    return json.dumps({"name": name, "secret": "do-not-copy"}).encode()


def web(url, status=200):
    return json.dumps({"url": url, "status_code": status,
                       "body": "do-not-copy"}).encode()


class OfflineWebCorrelationTests(unittest.TestCase):
    def test_exact_host_association_and_provenance(self):
        result = correlate_amass_httpx(
            dns("example.org"), web("https://example.org/", 200),
            allowed_hosts=("example.org",),
            allowed_urls=("https://example.org/",),
        )
        self.assertEqual(result["link_count"], 1)
        self.assertEqual(result["links"][0]["classification"],
                         "unverified_cross_tool_association")
        self.assertEqual(result["links"][0]["source_amass_sha256"],
                         result["sources"]["amass"]["sha256"])
        self.assertNotIn("do-not-copy", str(result))
        self.assertEqual(result["authority"], "untrusted_offline_import")

    def test_no_inferred_subdomains_or_scope_expansion(self):
        result = correlate_amass_httpx(
            dns("example.org"), web("https://other.example.org/"),
            allowed_hosts=("example.org",),
            allowed_urls=("https://other.example.org/",),
        )
        self.assertEqual(result["links"], [])
        with self.assertRaises(OfflineWebCorrelationError):
            correlate_amass_httpx(
                dns("example.org"), web("https://evil.example.org/"),
                allowed_hosts=("example.org",),
                allowed_urls=("https://example.org/",),
            )

    def test_deduplicates_and_fails_closed_on_budget(self):
        payload = web("https://example.org/") + b"\\n" + web("https://example.org/")
        kwargs = dict(allowed_hosts=("example.org",),
                      allowed_urls=("https://example.org/",))
        result = correlate_amass_httpx(dns("example.org"), payload, **kwargs)
        self.assertEqual(result["link_count"], 1)
        with self.assertRaises(OfflineWebCorrelationError):
            correlate_amass_httpx(
                dns("example.org"),
                web("https://example.org/") + b"\\n" + web("https://example.org/", 404),
                **kwargs, max_links=1,
            )
        with self.assertRaises(OfflineWebCorrelationError):
            correlate_amass_httpx(dns("example.org"), payload, **kwargs, max_links=0)

    def test_malformed_source_rejected(self):
        with self.assertRaises(OfflineWebCorrelationError):
            correlate_amass_httpx(
                b"{", web("https://example.org/"),
                allowed_hosts=("example.org",),
                allowed_urls=("https://example.org/",),
            )


if __name__ == "__main__":
    unittest.main()
