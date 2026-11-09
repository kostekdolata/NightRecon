import hashlib
import json
import unittest

from nightrecon_red_engine.amass_jsonl_import import (
    AmassEvidenceError, import_amass_jsonl,
)


def payload(*records):
    return b"\n".join(json.dumps(record).encode() for record in records)


def import_records(data, **kwargs):
    return import_amass_jsonl(data, source_name="amass.jsonl",
                             allowed_domains=("example.org",), **kwargs)


class TestAmassEvidenceImport(unittest.TestCase):
    def test_bounded_valid_observations_and_provenance(self):
        data = payload({"name": "WWW.Example.Org.", "addresses": [{"ip": "192.0.2.10"}],
                        "source": "DNS", "tag": "dns"},
                       {"name": "example.org", "addresses": []})
        result = import_records(data)
        self.assertEqual(result["record_count"], 2)
        self.assertEqual(result["sha256"], hashlib.sha256(data).hexdigest())
        self.assertEqual(result["authority"], "untrusted_offline_import")
        self.assertEqual(result["observations"][0]["name"], "www.example.org")
        self.assertEqual(result["observations"][0]["addresses"], ["192.0.2.10"])
        self.assertEqual(result["observations"][0]["classification"], "unverified_tool_observation")

    def test_scope_is_suffix_boundary_not_string_suffix(self):
        for name in ("badexample.org", "example.org.attacker.test", "other.org"):
            with self.subTest(name=name), self.assertRaises(AmassEvidenceError):
                import_records(payload({"name": name}))
        with self.assertRaises(AmassEvidenceError):
            import_amass_jsonl(payload({"name": "example.org"}),
                               source_name="fixture", allowed_domains=())

    def test_fail_closed_malformed_records(self):
        cases = (b"", b"{", b"[]", b"\xff",
                 payload({"name": "example.org", "addresses": "bad"}),
                 payload({"name": "example.org", "addresses": [{"ip": "invalid"}]}),
                 payload({"name": "example.org", "source": 123}),
                 payload({"name": "example.org", "addresses": [{}]}))
        for data in cases:
            with self.subTest(data=data[:50]), self.assertRaises(AmassEvidenceError):
                import_records(data)

    def test_resource_budgets(self):
        data = payload({"name": "example.org"}, {"name": "www.example.org"})
        with self.assertRaises(AmassEvidenceError):
            import_records(data, max_records=1)
        with self.assertRaises(AmassEvidenceError):
            import_records(data, max_bytes=4)
        with self.assertRaises(AmassEvidenceError):
            import_records(payload({"name": "example.org",
                                    "addresses": [{"ip": "192.0.2.1"}] * 101}))


if __name__ == "__main__":
    unittest.main()
