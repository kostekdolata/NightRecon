"""Tests for generic identity evidence projection."""

import unittest

from nightrecon.asset_inventory import AssetInventory, AssetRecord, AssetServiceRecord
from nightrecon.graph_identity_evidence import (
    GroupEvidence,
    GroupMembershipEvidence,
    IdentityEvidence,
    IdentityEvidenceBundle,
    PermissionEvidence,
    IdentityRelationshipEvidence,
    RoleEvidence,
)
from nightrecon.graph_identity_projection import add_identity_evidence_to_identity_graph
from nightrecon.graph_models import GraphEvidenceState, GraphNodeKind
from nightrecon.graph_projection import build_identity_graph_from_asset_inventory


class GraphIdentityProjectionTests(unittest.TestCase):
    def base_graph(self):
        return build_identity_graph_from_asset_inventory(
            AssetInventory(
                assets=(
                    AssetRecord(
                        address="192.0.2.120",
                        first_seen="2026-09-27T19:00:00+00:00",
                        last_seen="2026-09-27T19:00:00+00:00",
                        last_checked_at="2026-09-27T19:00:00+00:00",
                        services=(AssetServiceRecord(port=443, service="https"),),
                        source_session_ids=("identity-base",),
                    ),
                ),
            )
        )

    def test_projects_identity_nested_group_and_permission_evidence(self):
        graph = add_identity_evidence_to_identity_graph(
            self.base_graph(),
            IdentityEvidenceBundle(
                identities=(
                    IdentityEvidence(
                        natural_key="user:alice",
                        label="Alice",
                        source_id="id-1",
                        identity_type="user",
                    ),
                ),
                groups=(
                    GroupEvidence(
                        natural_key="group:operators",
                        label="Operators",
                        source_id="group-1",
                    ),
                    GroupEvidence(
                        natural_key="group:admins",
                        label="Admins",
                        source_id="group-2",
                    ),
                ),
                memberships=(
                    GroupMembershipEvidence(
                        member_kind=GraphNodeKind.IDENTITY,
                        member_key="user:alice",
                        group_key="group:operators",
                        source_id="membership-1",
                    ),
                    GroupMembershipEvidence(
                        member_kind=GraphNodeKind.GROUP,
                        member_key="group:operators",
                        group_key="group:admins",
                        source_id="membership-2",
                        evidence_state=GraphEvidenceState.INFERRED,
                    ),
                ),
                permissions=(
                    PermissionEvidence(
                        natural_key="permission:admin-on-192.0.2.120",
                        label="Administrative access",
                        subject_kind=GraphNodeKind.GROUP,
                        subject_key="group:admins",
                        target_kind=GraphNodeKind.ASSET,
                        target_key="192.0.2.120",
                        source_id="permission-1",
                        properties=(("access", "administrative"),),
                    ),
                ),
            ),
            observed_at="2026-09-27T19:01:00+00:00",
        )

        kinds = {node.kind for node in graph.nodes}
        self.assertIn(GraphNodeKind.IDENTITY, kinds)
        self.assertIn(GraphNodeKind.GROUP, kinds)
        self.assertIn(GraphNodeKind.PERMISSION, kinds)
        relationships = tuple(edge.relationship for edge in graph.edges)
        self.assertIn("member-of", relationships)
        self.assertIn("has-permission", relationships)
        self.assertIn("applies-to", relationships)
        inferred_memberships = tuple(
            edge
            for edge in graph.edges
            if edge.relationship == "member-of"
            and edge.evidence_state is GraphEvidenceState.INFERRED
        )
        self.assertEqual(len(inferred_memberships), 1)

    def test_projects_ownership_and_directory_role_relationships(self):
        graph = add_identity_evidence_to_identity_graph(
            self.base_graph(),
            IdentityEvidenceBundle(
                identities=(
                    IdentityEvidence(
                        natural_key="entra:user:alice",
                        label="Alice",
                        source_id="entra-user",
                        identity_type="entra-user",
                    ),
                    IdentityEvidence(
                        natural_key="entra:application:app",
                        label="Example App",
                        source_id="entra-app",
                        identity_type="entra-application",
                    ),
                ),
                roles=(
                    RoleEvidence(
                        natural_key="entra:role:reader",
                        label="Directory Readers",
                        source_id="entra-role",
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
            ),
        )

        relationships = {edge.relationship for edge in graph.edges}
        self.assertIn("owns", relationships)
        self.assertIn("assigned-role", relationships)
        role_nodes = [
            node for node in graph.nodes if node.kind is GraphNodeKind.PERMISSION
            and node.natural_key == "entra:role:reader"
        ]
        self.assertEqual(len(role_nodes), 1)

    def test_missing_permission_target_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "permission target is missing"):
            add_identity_evidence_to_identity_graph(
                self.base_graph(),
                IdentityEvidenceBundle(
                    identities=(
                        IdentityEvidence(
                            natural_key="user:bob",
                            label="Bob",
                            source_id="id-2",
                        ),
                    ),
                    permissions=(
                        PermissionEvidence(
                            natural_key="permission:bob-missing",
                            label="Access",
                            subject_kind=GraphNodeKind.IDENTITY,
                            subject_key="user:bob",
                            target_kind=GraphNodeKind.ASSET,
                            target_key="192.0.2.199",
                            source_id="permission-2",
                        ),
                    ),
                ),
            )

    def test_missing_membership_subject_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "group membership member is missing"):
            add_identity_evidence_to_identity_graph(
                self.base_graph(),
                IdentityEvidenceBundle(
                    groups=(
                        GroupEvidence(
                            natural_key="group:admins",
                            label="Admins",
                            source_id="group-3",
                        ),
                    ),
                    memberships=(
                        GroupMembershipEvidence(
                            member_kind=GraphNodeKind.IDENTITY,
                            member_key="user:missing",
                            group_key="group:admins",
                            source_id="membership-3",
                        ),
                    ),
                ),
            )


if __name__ == "__main__":
    unittest.main()
