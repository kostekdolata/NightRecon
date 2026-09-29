"""Offline directory imports should create only observed, bounded evidence."""

import json
import unittest

from nightrecon.graph_builder import IdentityGraphBuilder
from nightrecon.graph_identity_projection import add_identity_evidence_to_identity_graph
from nightrecon.graph_models import GraphEvidenceState, GraphNodeKind
from nightrecon.red_directory_import import (
    DirectoryImportLimits,
    import_directory_snapshot,
)


USER_DN = "CN=Alice,OU=People,DC=example,DC=test"
COMPUTER_DN = "CN=WS01,OU=Computers,DC=example,DC=test"
SERVICE_DN = "CN=WebSvc,OU=Services,DC=example,DC=test"
GROUP_DN = "CN=Operators,OU=Groups,DC=example,DC=test"
PARENT_DN = "CN=Admins,OU=Groups,DC=example,DC=test"


def snapshot(entries):
    return json.dumps({"schema_version": 1, "entries": entries}).encode()


class DirectoryImportTests(unittest.TestCase):
    def test_observed_users_and_nested_groups_project_with_provenance(self):
        data = snapshot([
            {"dn": USER_DN, "kind": "user", "name": "Alice"},
            {"dn": GROUP_DN, "kind": "group", "name": "Operators",
             "members": [USER_DN]},
            {"dn": PARENT_DN, "kind": "group", "name": "Admins",
             "members": [GROUP_DN]},
        ])
        result = import_directory_snapshot(data, source_id="approved-export-1")
        graph = add_identity_evidence_to_identity_graph(
            IdentityGraphBuilder().build(), result.evidence,
        )
        self.assertEqual(result.unresolved_members, 0)
        self.assertEqual(len(graph.nodes), 3)
        self.assertEqual(len(graph.edges), 2)
        self.assertEqual({edge.relationship for edge in graph.edges}, {"member-of"})
        self.assertTrue(all(edge.evidence_state is GraphEvidenceState.OBSERVED
                            for edge in graph.edges))
        self.assertTrue(all("approved-export-1#entry-" in node.provenance[0].source_id
                            for node in graph.nodes))
        self.assertTrue(all(USER_DN not in node.natural_key for node in graph.nodes))
        self.assertEqual(
            {node.kind for node in graph.nodes},
            {GraphNodeKind.IDENTITY, GraphNodeKind.GROUP},
        )

    def test_computer_and_service_identities_project_as_observed_members(self):
        data = snapshot([
            {"dn": COMPUTER_DN, "kind": "computer", "name": "ws01.example.test",
             "properties": {"dns_hostname": "ws01.example.test"}},
            {"dn": SERVICE_DN, "kind": "service", "name": "Web Service",
             "properties": {"spn_hosts": "web.example.test"}},
            {"dn": GROUP_DN, "kind": "group", "name": "Operators",
             "members": [COMPUTER_DN, SERVICE_DN]},
        ])

        result = import_directory_snapshot(data, source_id="approved-export-2")
        graph = add_identity_evidence_to_identity_graph(
            IdentityGraphBuilder().build(), result.evidence,
        )

        self.assertEqual(
            {item.identity_type for item in result.evidence.identities},
            {"ad-computer", "ad-service"},
        )
        self.assertEqual(len(result.evidence.memberships), 2)
        properties_by_type = {
            item.identity_type: dict(item.properties)
            for item in result.evidence.identities
        }
        self.assertEqual(
            properties_by_type["ad-computer"]["dns_hostname"],
            "ws01.example.test",
        )
        self.assertEqual(
            properties_by_type["ad-service"]["spn_hosts"],
            "web.example.test",
        )
        self.assertTrue(all(
            item.member_kind is GraphNodeKind.IDENTITY
            for item in result.evidence.memberships
        ))
        self.assertEqual(len(graph.nodes), 3)
        self.assertEqual(len(graph.edges), 2)
        self.assertTrue(all(
            edge.evidence_state is GraphEvidenceState.OBSERVED
            for edge in graph.edges
        ))
        identity_type_properties = {
            dict(node.properties).get("identity_type")
            for node in graph.nodes
            if node.kind is GraphNodeKind.IDENTITY
        }
        self.assertEqual(
            identity_type_properties,
            {"ad-computer", "ad-service"},
        )

    def test_entra_namespace_is_distinct_from_active_directory(self):
        object_id = "11111111-1111-1111-1111-111111111111"
        payload = snapshot([
            {"dn": object_id, "kind": "user", "name": "Cloud User"},
        ])

        ad = import_directory_snapshot(
            payload,
            source_id="ad-source",
        )
        entra = import_directory_snapshot(
            payload,
            source_id="entra-source",
            namespace="entra",
        )

        self.assertNotEqual(
            ad.evidence.identities[0].natural_key,
            entra.evidence.identities[0].natural_key,
        )
        self.assertTrue(ad.evidence.identities[0].natural_key.startswith("ad:user:"))
        self.assertTrue(
            entra.evidence.identities[0].natural_key.startswith("entra:user:")
        )
        self.assertEqual(ad.evidence.identities[0].identity_type, "ad-user")
        self.assertEqual(entra.evidence.identities[0].identity_type, "entra-user")

    def test_out_of_snapshot_membership_is_unresolved_not_observed(self):
        result = import_directory_snapshot(snapshot([
            {"dn": GROUP_DN, "kind": "group", "name": "Operators",
             "members": [USER_DN]},
        ]), source_id="partial-export")
        self.assertEqual(result.unresolved_members, 1)
        self.assertEqual(result.evidence.memberships, ())

    def test_order_and_source_are_deterministic(self):
        data = snapshot([
            {"dn": GROUP_DN, "kind": "group", "name": "Operators",
             "members": [USER_DN]},
            {"dn": USER_DN, "kind": "user", "name": "Alice"},
        ])
        self.assertEqual(
            import_directory_snapshot(data, source_id="export"),
            import_directory_snapshot(data, source_id="export"),
        )

    def test_rejects_secrets_unexpected_fields_and_duplicate_json_keys(self):
        for data in (
            snapshot([{"dn": USER_DN, "kind": "user", "name": "Alice",
                       "password": "secret"}]),
            b'{"schema_version":1,"schema_version":1,"entries":[]}',
            snapshot([{"dn": USER_DN, "kind": "user", "name": "Alice",
                       "members": []}]),
            snapshot([{"dn": COMPUTER_DN, "kind": "computer", "name": "WS01",
                       "members": []}]),
            snapshot([{"dn": SERVICE_DN, "kind": "service", "name": "WebSvc",
                       "members": []}]),
            snapshot([{"dn": USER_DN, "kind": "user", "name": "Alice"},
                      {"dn": USER_DN, "kind": "user", "name": "Alice"}]),
            snapshot([{"dn": GROUP_DN, "kind": "group", "name": "Ops",
                       "members": [USER_DN, USER_DN]}]),
            snapshot([{"dn": USER_DN, "kind": "user", "name": "Alice",
                       "properties": []}]),
            snapshot([{"dn": USER_DN, "kind": "user", "name": "Alice",
                       "properties": {"": "value"}}]),
        ):
            with self.subTest(data=data):
                with self.assertRaises(ValueError):
                    import_directory_snapshot(data, source_id="export")

    def test_limits_fail_before_evidence_is_returned(self):
        data = snapshot([{"dn": GROUP_DN, "kind": "group", "name": "Ops",
                          "members": [USER_DN]}])
        with self.assertRaisesRegex(ValueError, "max_bytes"):
            import_directory_snapshot(data, source_id="export",
                                      limits=DirectoryImportLimits(max_bytes=len(data) - 1))
        with self.assertRaisesRegex(ValueError, "max_entries"):
            import_directory_snapshot(
                snapshot([{"dn": USER_DN, "kind": "user", "name": "Alice"},
                          {"dn": GROUP_DN, "kind": "group", "name": "Ops"}]),
                source_id="export", limits=DirectoryImportLimits(max_entries=1),
            )
        with self.assertRaisesRegex(ValueError, "max_memberships"):
            import_directory_snapshot(
                snapshot([{"dn": GROUP_DN, "kind": "group", "name": "Ops",
                           "members": [USER_DN, PARENT_DN]}]),
                source_id="export", limits=DirectoryImportLimits(max_memberships=1),
            )


if __name__ == "__main__":
    unittest.main()
