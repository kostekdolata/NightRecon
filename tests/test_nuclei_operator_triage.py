"""Offline Nuclei triage contract tests: no tools, sockets or subprocesses."""
import json
import unittest

from nightrecon_red_engine.nuclei_offline_evidence import import_nuclei_jsonl
from nightrecon_red_engine.nuclei_operator_triage import build_nuclei_triage, NucleiTriageError


def imported():
    row = {"template-id": "test-template", "matched-at": "https://example.test/path",
           "info": {"severity": "medium"}, "request": "SECRET"}
    payload = ("\\n".join(json.dumps(row) for _ in range(2))).encode()
    return import_nuclei_jsonl(payload, engagement_id="lab",
                               authorized_hosts=("example.test",))


class NucleiTriageTests(unittest.TestCase):
    def test_deduplication_and_provenance(self):
        report = build_nuclei_triage(imported())
        self.assertEqual(report["observation_count"], 2)
        self.assertEqual(report["unique_observation_count"], 1)
        self.assertEqual(report["observations"][0]["occurrences"], 2)
        self.assertEqual(report["confirmed_findings"], 0)
        self.assertEqual(report["source_sha256"], imported()["source_sha256"])
        self.assertEqual(report, build_nuclei_triage(imported()))
        self.assertNotIn("SECRET", str(report))
        self.assertNotIn("/path", str(report))

    def test_operator_disposition_never_promotes_finding(self):
        first = build_nuclei_triage(imported())
        identifier = first["observations"][0]["observation_id"]
        reviewed = build_nuclei_triage(imported(), decisions={identifier: "follow_up_required"})
        self.assertEqual(reviewed["observations"][0]["operator_disposition"], "follow_up_required")
        self.assertEqual(reviewed["confirmed_findings"], 0)
        self.assertNotEqual(first["report_sha256"], reviewed["report_sha256"])

    def test_fail_closed_tampering_and_unknown_decisions(self):
        evidence = imported()
        for key, value in (("confirmed_findings", 1), ("external_execution", True),
                           ("observation_count", 999), ("source_sha256", "bad")):
            altered = dict(evidence, **{key: value})
            with self.subTest(key=key), self.assertRaises(NucleiTriageError):
                build_nuclei_triage(altered)
        with self.assertRaises(NucleiTriageError):
            build_nuclei_triage(evidence, max_observations=1)
        with self.assertRaises(NucleiTriageError):
            build_nuclei_triage(evidence, decisions={"unknown": "dismissed"})
        with self.assertRaises(NucleiTriageError):
            build_nuclei_triage(evidence, decisions={"unknown": "confirmed"})
        altered = imported()
        altered["observations"][0]["classification"] = "confirmed"
        with self.assertRaises(NucleiTriageError):
            build_nuclei_triage(altered)


if __name__ == "__main__":
    unittest.main()
