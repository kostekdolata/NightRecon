import unittest

from nightrecon_red_engine.offline_tool_correlation import (
    OfflineCorrelationError, correlate_offline_hosts,
)


def evidence(tool, host, digest="a" * 64):
    observation = {"classification": "unverified_tool_observation"}
    observation["name" if tool == "Amass" else "host"] = host
    return {"source_tool": tool, "source_name": "offline.json",
            "sha256": digest, "authority": "untrusted_offline_import",
            "record_count": 1, "observations": [observation]}


class TestOfflineToolCorrelation(unittest.TestCase):
    def test_exact_host_join_preserves_each_artifact_without_verdict(self):
        imports = (
            evidence("Amass", "example.org"),
            evidence("ProjectDiscovery httpx", "example.org", "b" * 64),
            evidence("Greenbone/OpenVAS", "other.example.org", "c" * 64),
        )
        result = correlate_offline_hosts(imports, allowed_hosts=("example.org", "other.example.org"))
        self.assertEqual(result["observation_count"], 3)
        self.assertEqual(result["host_count"], 2)
        self.assertEqual(result["hosts"][0]["source_tools"], ["Amass", "ProjectDiscovery httpx"])
        self.assertEqual(result["hosts"][0]["verdict"], "not_assessed")
        self.assertEqual([o["sha256"] for o in result["hosts"][0]["observations"]],
                         ["a" * 64, "b" * 64])
        self.assertEqual(result["authority"], "untrusted_offline_correlation")

    def test_scope_does_not_expand_from_amass_domain_or_other_tool(self):
        with self.assertRaises(OfflineCorrelationError):
            correlate_offline_hosts((evidence("Amass", "sub.example.org"),),
                                    allowed_hosts=("example.org",))
        with self.assertRaises(OfflineCorrelationError):
            correlate_offline_hosts((evidence("ProjectDiscovery httpx", "badexample.org"),),
                                    allowed_hosts=("example.org",))

    def test_rejects_untrusted_provenance_and_verdict_promotion(self):
        for field, value in (("sha256", "invalid"), ("authority", "trusted"),
                             ("record_count", 2), ("source_tool", "Metasploit")):
            item = evidence("Amass", "example.org")
            item[field] = value
            with self.subTest(field=field), self.assertRaises(OfflineCorrelationError):
                correlate_offline_hosts((item,), allowed_hosts=("example.org",))
        item = evidence("Amass", "example.org")
        item["observations"][0]["classification"] = "confirmed_exploitable"
        with self.assertRaises(OfflineCorrelationError):
            correlate_offline_hosts((item,), allowed_hosts=("example.org",))

    def test_budgets_and_missing_scope_fail_closed(self):
        item = evidence("Amass", "example.org")
        for kwargs in ({"allowed_hosts": ()},
                       {"allowed_hosts": ("example.org",), "max_imports": 0},
                       {"allowed_hosts": ("example.org",), "max_observations": 0}):
            with self.subTest(kwargs=kwargs), self.assertRaises(OfflineCorrelationError):
                correlate_offline_hosts((item,), **kwargs)
        with self.assertRaises(OfflineCorrelationError):
            correlate_offline_hosts((item, item), allowed_hosts=("example.org",),
                                    max_observations=1)


if __name__ == "__main__":
    unittest.main()
