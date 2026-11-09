import unittest

from nightrecon_red_engine.nmap_offline_xml_workflow import review_nmap_offline_xml
from nightrecon_red_engine.nmap_offline_xml_import import NmapOfflineImportError
from nightrecon_red_engine.tier1_offline_plan import Tier1PlanError

XML = (b'<nmaprun><host><address addrtype="ipv4" addr="127.0.0.1"/>'
       b'<ports><port protocol="tcp" portid="443"><state state="open"/></port>'
       b'<port protocol="udp" portid="53"><state state="open|filtered"/></port>'
       b'</ports></host></nmaprun>')


class NmapOfflineWorkflowTests(unittest.TestCase):
    def args(self):
        return {"payload": XML, "targets": ("127.0.0.1",),
                "allowed_targets": ("127.0.0.1", "127.0.0.2"),
                "capabilities": {}, "engagement_authorized": True}

    def test_complete_offline_workflow_is_deterministic_and_non_executable(self):
        first = review_nmap_offline_xml(**self.args())
        self.assertEqual(first, review_nmap_offline_xml(**self.args()))
        self.assertFalse(first["plan"]["steps"][0]["executable"])
        self.assertIn("capability_not_registered", first["plan"]["steps"][0]["blockers"])
        self.assertEqual(first["report"]["finding_status"], "not_assessed")
        self.assertEqual(first["report"]["observation_count"], 2)
        self.assertEqual(first["report"]["observations"][0]["observed_state"], "open")
        self.assertEqual(first["report"]["observations"][1]["observed_state"], "open|filtered")
        self.assertEqual(len(first["report"]["artifact_sha256"]), 64)
        self.assertEqual(len(first["report"]["report_sha256"]), 64)

    def test_authorization_scope_and_hostname_fail_closed(self):
        for field, value in (("engagement_authorized", False),
                             ("targets", ("127.0.0.3",)),
                             ("targets", ("localhost",)),
                             ("allowed_targets", ("127.0.0.2",))):
            args = self.args()
            args[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(Tier1PlanError):
                review_nmap_offline_xml(**args)

    def test_untrusted_xml_and_resource_limits_fail_closed(self):
        for field, value in (("payload", XML.replace(b'127.0.0.1', b'127.0.0.2')),
                             ("payload", b'<!DOCTYPE nmaprun><nmaprun/>'),
                             ("max_ports", 1)):
            args = self.args()
            args[field] = value
            with self.subTest(field=field), self.assertRaises(NmapOfflineImportError):
                review_nmap_offline_xml(**args)

    def test_missing_tool_remains_blocked_even_with_report(self):
        args = self.args()
        args["capabilities"] = {"Nmap": {"available": True,
                                        "platform_supported": True,
                                        "prerequisites_met": True}}
        result = review_nmap_offline_xml(**args)
        self.assertFalse(result["plan"]["steps"][0]["executable"])
        self.assertIn("guarded_executor_and_live_policy_required",
                      result["plan"]["steps"][0]["blockers"])


if __name__ == "__main__":
    unittest.main()
