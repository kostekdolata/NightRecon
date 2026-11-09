import hashlib
import unittest

from nightrecon_red_engine.greenbone_xml_import import (
    GreenboneEvidenceError, import_greenbone_xml,
)


def report(results):
    return ("<get_reports_response><report><results>" + results
            + "</results></report></get_reports_response>").encode()


def result(host="example.org", severity="7.5"):
    return ("<result><host>" + host + "</host><name>Sample finding</name>"
            "<port>443/tcp</port><severity>" + severity
            + "</severity></result>")


def imported(payload, **kwargs):
    return import_greenbone_xml(
        payload, source_name="report.xml", allowed_hosts=("example.org", "192.0.2.1"),
        **kwargs,
    )


class TestGreenboneXmlImport(unittest.TestCase):
    def test_valid_report_is_unverified_and_provenanced(self):
        data = report(result() + result("192.0.2.1", "0"))
        value = imported(data)
        self.assertEqual(value["sha256"], hashlib.sha256(data).hexdigest())
        self.assertEqual(value["record_count"], 2)
        self.assertEqual(value["authority"], "untrusted_offline_import")
        self.assertEqual(value["observations"][0]["reported_severity"], 7.5)
        self.assertEqual(value["observations"][0]["classification"],
                         "unverified_tool_observation")

    def test_exact_host_scope(self):
        for host in ("sub.example.org", "badexample.org", "example.org.attacker.test"):
            with self.subTest(host=host), self.assertRaises(GreenboneEvidenceError):
                imported(report(result(host)))
        with self.assertRaises(GreenboneEvidenceError):
            import_greenbone_xml(report(result()), source_name="x", allowed_hosts=())

    def test_malformed_xml_and_limits_fail_closed(self):
        for data in (b"", b"<", b"<evil/>", b"<!DOCTYPE x [<!ENTITY a 'b'>]><report/>",
                     report(result(severity="nan")), report(result(severity="11")),
                     report("<result><host>example.org</host></result>")):
            with self.subTest(data=data[:70]), self.assertRaises(GreenboneEvidenceError):
                imported(data)
        data = report(result() + result())
        with self.assertRaises(GreenboneEvidenceError):
            imported(data, max_results=1)
        with self.assertRaises(GreenboneEvidenceError):
            imported(data, max_bytes=10)


if __name__ == "__main__":
    unittest.main()
