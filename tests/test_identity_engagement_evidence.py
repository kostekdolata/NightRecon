"""Identity evidence bridge produces portable unified-graph records."""

from __future__ import annotations

import unittest

from nightrecon_red_engine.graph_identity_evidence import (
    IdentityEvidence,
    IdentityEvidenceBundle,
    IdentityRelationshipEvidence,
    RoleEvidence,
)
from nightrecon_red_engine.graph_models import GraphNodeKind
from nightrecon_red_engine.identity_engagement_evidence import (
    identity_bundle_to_engagement_records,
)
from nightrecon_red_engine.red_directory_import import import_directory_snapshot
from nightrecon_red_engine.unified_attack_graph import build_unified_attack_graph


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

    def test_role_and_ownership_records_round_trip_into_unified_graph(self):
        bundle = IdentityEvidenceBundle(
            identities=(
                IdentityEvidence(
                    "entra:user:alice",
                    "Alice",
                    "entra-user",
                    identity_type="entra-user",
                ),
                IdentityEvidence(
                    "entra:application:app",
                    "Example App",
                    "entra-app",
                    identity_type="entra-application",
                ),
            ),
            roles=(
                RoleEvidence(
                    "entra:role:reader",
                    "Directory Readers",
                    "entra-role",
                ),
            ),
            relationships=(
                IdentityRelationshipEvidence(
                    source_kind=GraphNodeKind.IDENTITY,
                    source_key="entra:user:alice",
                    target_kind=GraphNodeKind.IDENTITY,
                    target_key="entra:application:app",
                    relationship="owns",
                    source_id="entra-owner",
                ),
                IdentityRelationshipEvidence(
                    source_kind=GraphNodeKind.IDENTITY,
                    source_key="entra:user:alice",
                    target_kind=GraphNodeKind.PERMISSION,
                    target_key="entra:role:reader",
                    relationship="assigned-role",
                    source_id="entra-assignment",
                    properties=(("directory_scope_id", "/"),),
                ),
            ),
        )

        records = identity_bundle_to_engagement_records(
            bundle,
            engagement_id="eng-entra-rel",
            observed_at="2026-09-29T01:00:00+00:00",
        )
        self.assertEqual(
            sorted(item.evidence_type for item in records),
            [
                "graph.relationship",
                "graph.relationship",
                "identity.observation",
                "identity.observation",
                "permission.observation",
            ],
        )
        graph = build_unified_attack_graph(records)
        self.assertEqual(graph.unresolved_records, ())
        self.assertEqual(
            {edge.relationship for edge in graph.graph.edges},
            {"owns", "assigned-role"},
        )
        self.assertTrue(any(
            node.kind is GraphNodeKind.PERMISSION
            and node.natural_key == "entra:role:reader"
            for node in graph.graph.nodes
        ))

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
