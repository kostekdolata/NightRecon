import json
import unittest

from nightrecon_red_engine.amass_offline_jsonl_import import (
    AmassOfflineImportError, import_amass_jsonl,
)


def entry(name):
    return json.dumps({"name": name, "domain": "example.org",
                       "addresses": [{"ip": "192.0.2.1"}]}).encode()


class AmassOfflineImportTests(unittest.TestCase):
    def test_deterministic_offline_import_and_provenance(self):
        payload = entry("example.org") + b"\n" + entry("api.example.org")
        kwargs = {"allowed_hosts": ("example.org", "api.example.org")}
        result = import_amass_jsonl(payload, **kwargs)
        self.assertEqual(result, import_amass_jsonl(payload, **kwargs))
        self.assertEqual(result["record_count"], 2)
        self.assertEqual([x["record_index"] for x in result["observations"]], [0, 1])
        self.assertEqual(result["authority"], "untrusted_offline_import")
        self.assertEqual(len(result["sha256"]), 64)
        self.assertNotIn("addresses", result["observations"][0])

    def test_exact_scope_does_not_infer_subdomains(self):
        for name in ("api.example.org", "badexample.org",
                     "example.org.evil.test", "EXAMPLE.ORG", "example.org."):
            with self.subTest(name=name), self.assertRaises(AmassOfflineImportError):
                import_amass_jsonl(entry(name), allowed_hosts=("example.org",))

    def test_malformed_records_and_budgets_fail_closed(self):
        for payload in (b"{}", b"{", b"[]", b"", entry("example.org") + b"\n\n" + entry("example.org"),
                        entry("127.0.0.1"), entry("localhost")):
            with self.subTest(payload=payload), self.assertRaises(AmassOfflineImportError):
                import_amass_jsonl(payload, allowed_hosts=("example.org",))
        for opts in ({"allowed_hosts": ()},
                     {"allowed_hosts": ("example.org",), "max_records": 0},
                     {"allowed_hosts": ("example.org",), "max_bytes": 1},
                     {"allowed_hosts": ("example.org", "example.org")}):
            with self.subTest(opts=opts), self.assertRaises(AmassOfflineImportError):
                import_amass_jsonl(entry("example.org"), **opts)
        with self.assertRaises(AmassOfflineImportError):
            import_amass_jsonl(entry("example.org") + b"\n" + entry("example.org"),
                               allowed_hosts=("example.org",), max_records=1)


if __name__ == "__main__":
    unittest.main()
