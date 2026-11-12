"""Offline benchmark regression: scope, provenance and unknown labels."""
import hashlib
import json
import unittest

from nightrecon_red_engine.offline_discovery_benchmark import (
    DiscoveryBenchmarkError, compare_offline_discovery,
)


def payload(**fields):
    return json.dumps(fields).encode()


class OfflineDiscoveryBenchmarkTests(unittest.TestCase):
    def setUp(self):
        self.dns = payload(name="a.example.test")
        self.web = payload(url="https://a.example.test", status_code=200)
        self.dns_id = hashlib.sha256(b"a.example.test").hexdigest()
        self.web_id = hashlib.sha256(b"https://a.example.test|200").hexdigest()
        self.args = dict(amass_payload=self.dns, httpx_payload=self.web,
                         approved_domain="example.test",
                         approved_origins=("https://a.example.test",))

    def test_positive_and_unknown_not_false_positive(self):
        labels = {"amass": {self.dns_id: "expected"}, "httpx": {}}
        result = compare_offline_discovery(**self.args, labels=labels)
        self.assertEqual(result["results"]["amass"]["recall"], 1)
        self.assertEqual(result["results"]["httpx"]["unlabeled"], 1)
        self.assertEqual(result["results"]["httpx"]["false_positive"], 0)
        self.assertIsNone(result["results"]["httpx"]["precision"])
        self.assertEqual(result, compare_offline_discovery(**self.args, labels=labels))
        self.assertNotIn("a.example.test", str(result))

    def test_negative_and_missing_expected(self):
        missing = hashlib.sha256(b"missing.example.test").hexdigest()
        result = compare_offline_discovery(**self.args, labels={
            "amass": {missing: "expected"},
            "httpx": {self.web_id: "known_negative"}})
        self.assertEqual(result["results"]["amass"]["false_negative"], 1)
        self.assertEqual(result["results"]["httpx"]["false_positive"], 1)

    def test_fail_closed_labels_and_scope(self):
        for labels in ({}, {"amass": {}, "httpx": {"invalid": "expected"}},
                       {"amass": {}, "httpx": {self.web_id: "confirmed_exploitable"}}):
            with self.subTest(labels=labels), self.assertRaises(DiscoveryBenchmarkError):
                compare_offline_discovery(**self.args, labels=labels)
        with self.assertRaises(ValueError):
            compare_offline_discovery(**{**self.args, "approved_domain": "other.test"},
                                      labels={"amass": {}, "httpx": {}})
        with self.assertRaises(ValueError):
            compare_offline_discovery(**{**self.args, "approved_origins": ("https://other.test",)},
                                      labels={"amass": {}, "httpx": {}})
