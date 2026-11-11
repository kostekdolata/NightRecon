"""Synthetic offline Greenbone contract tests; no scanner or network."""
import unittest

from nightrecon_red_engine.greenbone_offline_report import (
    GreenboneOfflineImportError, import_greenbone_report,
)


def report(host="127.0.0.1", port="443/tcp", severity="5.0"):
    return (f"<report><results><result><host>{host}</host>"
            f"<port>{port}</port><severity>{severity}</severity>"
            "</result></results></report>").encode()


class GreenboneOfflineReportTests(unittest.TestCase):
    def test_deterministic_unverified_observations(self):
        result = import_greenbone_report(report(), allowed_hosts=("127.0.0.1",))
        self.assertEqual(result, import_greenbone_report(
            report(), allowed_hosts=("127.0.0.1",)))
        self.assertEqual(result["record_count"], 1)
        self.assertEqual(result["observations"][0]["port"], "443/tcp")
        self.assertEqual(result["authority"], "untrusted_offline_import")
        self.assertEqual(len(result["sha256"]), 64)
        self.assertIn("unverified", result["limitations"])

    def test_out_of_scope_and_bad_xml_fail_closed(self):
        bad = (
            report("127.0.0.2"), report("evil.example.org"),
            b"<!DOCTYPE report [<!ENTITY x SYSTEM 'file:///etc/passwd'>]>"
            b"<report><results/></report>",
            b"<report><results><result/></results></report>",
            b"<report><results/></report><report/>",
            report(port="65536/tcp"), report(port="80/other"),
            report(severity="11"), report(severity="-1"),
        )
        for payload in bad:
            with self.subTest(payload=payload), self.assertRaises(GreenboneOfflineImportError):
                import_greenbone_report(payload, allowed_hosts=("127.0.0.1",))

    def test_budgets_and_scope_inputs(self):
        for kwargs in (
            {"allowed_hosts": ()},
            {"allowed_hosts": ("127.0.0.1", "127.0.0.1")},
            {"allowed_hosts": ("127.0.0.1",), "max_bytes": 2},
            {"allowed_hosts": ("127.0.0.1",), "max_results": 0},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(GreenboneOfflineImportError):
                import_greenbone_report(report(), **kwargs)
        with self.assertRaises(GreenboneOfflineImportError):
            import_greenbone_report(
                b"<report><results>" +
                b"<result><host>127.0.0.1</host><port>80/tcp</port><severity>0</severity></result>" * 2 +
                b"</results></report>",
                allowed_hosts=("127.0.0.1",), max_results=1,
            )


if __name__ == "__main__":
    unittest.main()
