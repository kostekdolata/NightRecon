"""Tests for deterministic label-free identity benchmark results."""

from __future__ import annotations

import json
import unittest

from nightrecon_red_engine.graph_identity_evidence import (
    IdentityEvidence,
    IdentityEvidenceBundle,
    IdentityRelationshipEvidence,
    RoleEvidence,
)
from nightrecon_red_engine.graph_models import GraphNodeKind
from nightrecon_red_engine.identity_benchmark import benchmark_identity_collection
from nightrecon_red_engine.identity_collection import IdentityCollectionResult
from nightrecon_red_engine.red_directory_import import import_directory_snapshot


def snapshot(payload: bytes):
    return import_directory_snapshot(
        payload,
        source_id="benchmark-fixture",
    )


class IdentityBenchmarkTests(unittest.TestCase):
    def test_exact_fixture_has_full_expected_coverage_and_no_invented_edges(self):
        imported = snapshot(
            b'{"schema_version":1,"entries":['
            b'{"dn":"CN=Alice,DC=example,DC=test","kind":"user","name":"Alice"},'
            b'{"dn":"CN=Ops,DC=example,DC=test","kind":"group","name":"Ops",'
            b'"members":["CN=Alice,DC=example,DC=test"]}]}'
        )
        result = IdentityCollectionResult(
            source_type="active-directory",
            target="dc.example.test",
            entry_count=2,
            unresolved_members=0,
            evidence=imported.evidence,
            provider_requests=2,
            provider_duration_ms=37,
        )

        benchmark = benchmark_identity_collection(result, imported.evidence)

        self.assertTrue(benchmark.expected_coverage_complete)
        self.assertFalse(benchmark.unexpected_evidence_present)
        self.assertEqual(benchmark.missed_identities, 0)
        self.assertEqual(benchmark.missed_groups, 0)
        self.assertEqual(benchmark.missed_memberships, 0)
        self.assertEqual(benchmark.invented_memberships, 0)
        self.assertEqual(benchmark.provider_requests, 2)
        self.assertEqual(benchmark.provider_duration_ms, 37)
        self.assertEqual(len(benchmark.graph_sha256), 64)
        self.assertEqual(len(benchmark.benchmark_sha256), 64)

        serialized = json.dumps(benchmark.to_dict(), sort_keys=True)
        self.assertNotIn("Alice", serialized)
        self.assertNotIn("CN=Alice", serialized)
        self.assertNotIn("Ops", serialized)

    def test_fingerprint_excludes_nondeterministic_runtime(self):
        imported = snapshot(b'{"schema_version":1,"entries":[]}')
        first = IdentityCollectionResult(
            source_type="active-directory",
            target="dc.example.test",
            entry_count=0,
            unresolved_members=0,
            evidence=imported.evidence,
            provider_requests=2,
            provider_duration_ms=12,
        )
        second = IdentityCollectionResult(
            source_type="active-directory",
            target="dc.example.test",
            entry_count=0,
            unresolved_members=0,
            evidence=imported.evidence,
            provider_requests=2,
            provider_duration_ms=987,
        )

        first_benchmark = benchmark_identity_collection(first, imported.evidence)
        second_benchmark = benchmark_identity_collection(second, imported.evidence)

        self.assertNotEqual(
            first_benchmark.provider_duration_ms,
            second_benchmark.provider_duration_ms,
        )
        self.assertEqual(
            first_benchmark.benchmark_sha256,
            second_benchmark.benchmark_sha256,
        )

    def test_missing_and_invented_topology_is_counted_without_risk_claims(self):
        expected = snapshot(
            b'{"schema_version":1,"entries":['
            b'{"dn":"CN=Alice,DC=example,DC=test","kind":"user","name":"Alice"},'
            b'{"dn":"CN=Ops,DC=example,DC=test","kind":"group","name":"Ops",'
            b'"members":["CN=Alice,DC=example,DC=test"]}]}'
        )
        observed = snapshot(
            b'{"schema_version":1,"entries":['
            b'{"dn":"CN=Alice,DC=example,DC=test","kind":"user","name":"Alice"},'
            b'{"dn":"CN=Admins,DC=example,DC=test","kind":"group","name":"Admins",'
            b'"members":["CN=Alice,DC=example,DC=test"]}]}'
        )
        result = IdentityCollectionResult(
            source_type="active-directory",
            target="dc.example.test",
            entry_count=2,
            unresolved_members=0,
            evidence=observed.evidence,
        )

        benchmark = benchmark_identity_collection(result, expected.evidence)

        self.assertFalse(benchmark.expected_coverage_complete)
        self.assertTrue(benchmark.unexpected_evidence_present)
        self.assertEqual(benchmark.missed_identities, 0)
        self.assertEqual(benchmark.missed_groups, 1)
        self.assertEqual(benchmark.invented_groups, 1)
        self.assertEqual(benchmark.missed_memberships, 1)
        self.assertEqual(benchmark.invented_memberships, 1)
        self.assertNotIn("risk", json.dumps(benchmark.to_dict()).lower())
        self.assertNotIn("exploitable", json.dumps(benchmark.to_dict()).lower())

    def test_roles_and_relationships_are_part_of_coverage(self):
        bundle = IdentityEvidenceBundle(
            identities=(
                IdentityEvidence(
                    "entra:user:alice",
                    "Alice",
                    "fixture",
                    identity_type="entra-user",
                ),
                IdentityEvidence(
                    "entra:application:app",
                    "Example App",
                    "fixture",
                    identity_type="entra-application",
                ),
            ),
            roles=(
                RoleEvidence(
                    "entra:role:reader",
                    "Directory Readers",
                    "fixture",
                ),
            ),
            relationships=(
                IdentityRelationshipEvidence(
                    source_kind=GraphNodeKind.IDENTITY,
                    source_key="entra:user:alice",
                    target_kind=GraphNodeKind.IDENTITY,
                    target_key="entra:application:app",
                    relationship="owns",
                    source_id="fixture",
                ),
                IdentityRelationshipEvidence(
                    source_kind=GraphNodeKind.IDENTITY,
                    source_key="entra:user:alice",
                    target_kind=GraphNodeKind.PERMISSION,
                    target_key="entra:role:reader",
                    relationship="assigned-role",
                    source_id="fixture",
                    properties=(("directory_scope_id", "/"),),
                ),
            ),
        )
        result = IdentityCollectionResult(
            source_type="entra-id",
            target="tenant",
            entry_count=2,
            unresolved_members=0,
            evidence=bundle,
        )

        benchmark = benchmark_identity_collection(result, bundle)

        self.assertTrue(benchmark.expected_coverage_complete)
        self.assertFalse(benchmark.unexpected_evidence_present)
        self.assertEqual(benchmark.expected_roles, 1)
        self.assertEqual(benchmark.discovered_expected_roles, 1)
        self.assertEqual(benchmark.expected_relationships, 2)
        self.assertEqual(benchmark.discovered_expected_relationships, 2)
        self.assertEqual(benchmark.missed_relationships, 0)
        self.assertEqual(benchmark.invented_relationships, 0)

    def test_truncation_and_unresolved_references_explain_missing_evidence(self):
        expected = snapshot(
            b'{"schema_version":1,"entries":['
            b'{"dn":"CN=Alice,DC=example,DC=test","kind":"user","name":"Alice"},'
            b'{"dn":"CN=Ops,DC=example,DC=test","kind":"group","name":"Ops",'
            b'"members":["CN=Alice,DC=example,DC=test"]}]}'
        )
        observed = snapshot(
            b'{"schema_version":1,"entries":['
            b'{"dn":"CN=Ops,DC=example,DC=test","kind":"group","name":"Ops",'
            b'"members":["CN=Alice,DC=example,DC=test"]}]}'
        )
        result = IdentityCollectionResult(
            source_type="active-directory",
            target="dc.example.test",
            entry_count=1,
            unresolved_members=observed.unresolved_members,
            evidence=observed.evidence,
            truncated=True,
            provider_requests=1,
            limitations=("Active Directory page ceiling reached.",),
        )

        benchmark = benchmark_identity_collection(result, expected.evidence)

        self.assertTrue(benchmark.truncated)
        self.assertEqual(benchmark.missed_identities, 1)
        self.assertEqual(benchmark.missed_memberships, 1)
        self.assertEqual(benchmark.unresolved_members, 1)
        self.assertTrue(
            any("page ceiling" in item.lower() for item in benchmark.missed_reasons)
        )
        self.assertTrue(
            any("unresolved" in item.lower() for item in benchmark.missed_reasons)
        )

    def test_duplicate_expected_keys_fail_closed(self):
        expected = IdentityEvidenceBundle(identities=(
            IdentityEvidence("same", "A", "fixture"),
            IdentityEvidence("same", "B", "fixture"),
        ))
        result = IdentityCollectionResult(
            source_type="active-directory",
            target="dc.example.test",
            entry_count=0,
            unresolved_members=0,
            evidence=IdentityEvidenceBundle.empty(),
        )

        with self.assertRaisesRegex(ValueError, "duplicates"):
            benchmark_identity_collection(result, expected)


if __name__ == "__main__":
    unittest.main()
