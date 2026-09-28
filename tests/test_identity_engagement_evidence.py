"""Identity evidence bridge produces portable unified-graph records."""

from __future__ import annotations

import unittest

from nightrecon_red_engine.graph_identity_evidence import IdentityEvidence
from nightrecon_red_engine.identity_engagement_evidence import (
    identity_bundle_to_engagement_records,
)
from nightrecon_red_engine.red_directory_import import import_directory_snapshot
from nightrecon_red_engine.unified_attack_graph import build_unified_attack_graph
from nightrecon_red_engine.graph_identity_evidence import IdentityEvidenceBundle


class IdentityEngagementEvidenceTests(unittest.TestCase):
    def test_directory_bundle_projects_into_unified_graph(self):
        imported = import_directory_snapshot(
            b'{"schema_version":1,"entries":['
            b'{"dn":"CN=Alice,DC=example,DC=test","kind":"user","name":"Alice"},'
            b'{"dn":"CN=Ops,DC=example,DC=test","kind":"group","name":"Ops",'
            b'"members":["CN=Alice,DC=example,DC=test"]}]}',
            source_id="ldap-readonly-1",
        )
        records = identity_bundle_to_engagement_records(
            imported.evidence,
            engagement_id="eng-bridge",
            observed_at="2026-09-28T12:00:00+00:00",
        )
        self.assertEqual(
            sorted(item.evidence_type for item in records),
            ["graph.relationship", "group.observation", "identity.observation"],
        )
        graph = build_unified_attack_graph(records)
        self.assertEqual(graph.unresolved_records, ())
        self.assertEqual(len(graph.graph.nodes), 2)
        self.assertEqual(len(graph.graph.edges), 1)
        self.assertEqual(graph.graph.edges[0].relationship, "member-of")

    def test_bridge_is_deterministic(self):
        imported = import_directory_snapshot(
            b'{"schema_version":1,"entries":[]}',
            source_id="source",
        )
        first = identity_bundle_to_engagement_records(
            imported.evidence,
            engagement_id="eng-bridge",
            observed_at="2026-09-28T12:00:00+00:00",
        )
        second = identity_bundle_to_engagement_records(
            imported.evidence,
            engagement_id="eng-bridge",
            observed_at="2026-09-28T12:00:00+00:00",
        )
        self.assertEqual(first, second)

    def test_secret_like_properties_fail_closed(self):
        bundle = IdentityEvidenceBundle(identities=(
            IdentityEvidence(
                "user:test", "Test", "fixture",
                properties=(("api_token", "not-allowed"),),
            ),
        ))
        with self.assertRaisesRegex(ValueError, "secret-like"):
            identity_bundle_to_engagement_records(
                bundle,
                engagement_id="eng-bridge",
                observed_at="2026-09-28T12:00:00+00:00",
            )


if __name__ == "__main__":
    unittest.main()
