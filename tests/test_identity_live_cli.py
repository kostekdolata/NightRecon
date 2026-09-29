"""Operator-surface tests for authorization-first live identity collection."""

from __future__ import annotations

import contextlib
from datetime import datetime, timezone
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from nightrecon_red_engine.active_directory_provider import (
    ActiveDirectoryIdentityProvider,
)
from nightrecon_red_engine.entra_provider import EntraIdentityProvider
from nightrecon_red_engine.graph_identity_evidence import (
    IdentityEvidenceBundle,
    IdentityRelationshipEvidence,
    RoleEvidence,
)
from nightrecon_red_engine.graph_models import GraphNodeKind
from nightrecon_red_engine.identity_collection import (
    DirectoryEntry,
    IdentityProviderCollection,
)
from nightrecon_red_engine.red_cli import main as red_main
from nightrecon_red_engine.red_directory_import import directory_natural_key
from nightrecon_shared_core.contracts import EngagementMetadata
from nightrecon_shared_core.engagement_policy import EngagementExecutionPolicy
from nightrecon_shared_core.workspace import LocalWorkspace


AD_TARGET = "dc.example.test"
USER_DN = "CN=Alice,DC=example,DC=test"
GROUP_DN = "CN=Operators,DC=example,DC=test"
TENANT = "11111111-2222-3333-4444-555555555555"
ENTRA_USER = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
ENTRA_APP = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
ENTRA_ROLE = "cccccccc-cccc-cccc-cccc-cccccccccccc"


def make_workspace(root: str, *, scope=(AD_TARGET,), max_actions=4) -> LocalWorkspace:
    workspace = LocalWorkspace(root)
    workspace.create_engagement(EngagementMetadata(
        engagement_id="eng-live",
        name="Identity live collection",
        created_at="2026-09-29T00:00:00+00:00",
        authorization_reference="approval://eng-live",
        status="active",
    ))
    workspace.set_execution_policy(EngagementExecutionPolicy(
        engagement_id="eng-live",
        scope=scope,
        valid_from="2026-01-01T00:00:00+00:00",
        valid_until="2027-01-01T00:00:00+00:00",
        max_actions=max_actions,
        permitted_capabilities=("identity.collect",),
    ))
    return workspace


class LiveIdentityCliTests(unittest.TestCase):
    def test_authorized_ad_collection_is_identity_safe_and_records_evidence(self):
        with tempfile.TemporaryDirectory() as root:
            workspace = make_workspace(root)
            report_path = Path(root) / "safe-report.json"
            output = io.StringIO()
            error = io.StringIO()
            result = IdentityProviderCollection(
                entries=(
                    DirectoryEntry(USER_DN, "user", "Alice"),
                    DirectoryEntry(
                        GROUP_DN,
                        "group",
                        "Operators",
                        (USER_DN,),
                    ),
                ),
                request_count=2,
                duration_ms=17,
            )

            with patch.dict(os.environ, {"AD_BIND_SECRET": "super-secret-value"}):
                with patch.object(
                    ActiveDirectoryIdentityProvider,
                    "collect",
                    return_value=result,
                ) as collect:
                    with contextlib.redirect_stdout(output), contextlib.redirect_stderr(error):
                        red_main((
                            "identity",
                            "collect",
                            "ad",
                            "--workspace", root,
                            "--engagement-id", "eng-live",
                            "--source-id", "ad-cli-1",
                            "--target", AD_TARGET,
                            "--base-dn", "DC=example,DC=test",
                            "--bind-username", "EXAMPLE\\reader",
                            "--password-env", "AD_BIND_SECRET",
                            "--report-output", str(report_path),
                        ))

            collect.assert_called_once()
            request = collect.call_args.args[0]
            self.assertEqual(request.source_type, "active-directory")
            self.assertEqual(request.target, AD_TARGET)

            rendered = output.getvalue()
            self.assertEqual(error.getvalue(), "")
            payload = json.loads(rendered)
            self.assertEqual(payload["provider"], "active-directory")
            self.assertEqual(payload["identities"], 1)
            self.assertEqual(payload["groups"], 1)
            self.assertEqual(payload["observed_memberships"], 1)
            self.assertEqual(payload["provider_requests"], 2)
            self.assertFalse(payload["graph_exported"])
            self.assertEqual(len(payload["graph_sha256"]), 64)

            for sensitive in (
                "Alice",
                "Operators",
                USER_DN,
                GROUP_DN,
                "super-secret-value",
                "AD_BIND_SECRET",
            ):
                self.assertNotIn(sensitive, rendered)
                self.assertNotIn(sensitive, report_path.read_text(encoding="utf-8"))

            reopened = LocalWorkspace(root)
            self.assertEqual(
                reopened.execution_policy("eng-live").actions_used,
                1,
            )
            evidence_types = {
                item.evidence_type
                for item in reopened.envelope("eng-live").records
            }
            self.assertIn("identity.collection-summary", evidence_types)
            self.assertIn("identity.observation", evidence_types)
            self.assertIn("group.observation", evidence_types)
            self.assertIn("graph.relationship", evidence_types)

    def test_explicit_graph_export_is_the_only_cli_surface_with_labels(self):
        with tempfile.TemporaryDirectory() as root:
            make_workspace(root)
            graph_path = Path(root) / "detailed-graph.json"
            output = io.StringIO()
            result = IdentityProviderCollection(entries=(
                DirectoryEntry(USER_DN, "user", "Alice"),
            ))

            with patch.dict(os.environ, {"AD_BIND_SECRET": "secret-value"}):
                with patch.object(
                    ActiveDirectoryIdentityProvider,
                    "collect",
                    return_value=result,
                ):
                    with contextlib.redirect_stdout(output):
                        red_main((
                            "identity",
                            "collect",
                            "ad",
                            "--workspace", root,
                            "--engagement-id", "eng-live",
                            "--source-id", "ad-cli-export",
                            "--target", AD_TARGET,
                            "--base-dn", "DC=example,DC=test",
                            "--bind-username", "EXAMPLE\\reader",
                            "--password-env", "AD_BIND_SECRET",
                            "--export-graph", str(graph_path),
                        ))

            rendered = output.getvalue()
            self.assertNotIn("Alice", rendered)
            self.assertNotIn(USER_DN, rendered)
            self.assertNotIn("secret-value", rendered)
            self.assertTrue(json.loads(rendered)["graph_exported"])

            detailed = graph_path.read_text(encoding="utf-8")
            self.assertIn("Alice", detailed)
            self.assertNotIn(USER_DN, detailed)
            self.assertNotIn("secret-value", detailed)

    def test_denied_ad_collection_never_calls_provider_or_resolves_secret(self):
        with tempfile.TemporaryDirectory() as root:
            make_workspace(root, scope=("approved.example.test",))
            output = io.StringIO()
            error = io.StringIO()

            with patch.dict(os.environ, {"AD_BIND_SECRET": "do-not-touch"}):
                with patch.object(
                    ActiveDirectoryIdentityProvider,
                    "collect",
                ) as collect:
                    with contextlib.redirect_stdout(output), contextlib.redirect_stderr(error):
                        with self.assertRaises(SystemExit) as exit_status:
                            red_main((
                                "identity",
                                "collect",
                                "ad",
                                "--workspace", root,
                                "--engagement-id", "eng-live",
                                "--source-id", "ad-denied",
                                "--target", AD_TARGET,
                                "--base-dn", "DC=example,DC=test",
                                "--bind-username", "EXAMPLE\\reader",
                                "--password-env", "AD_BIND_SECRET",
                            ))

            self.assertEqual(exit_status.exception.code, 2)
            collect.assert_not_called()
            self.assertEqual(output.getvalue(), "")
            self.assertIn("target_out_of_scope", error.getvalue())
            self.assertNotIn("do-not-touch", error.getvalue())
            self.assertNotIn("AD_BIND_SECRET", error.getvalue())
            self.assertEqual(
                LocalWorkspace(root).execution_policy("eng-live").actions_used,
                0,
            )

    def test_entra_collection_reports_applications_roles_and_relationships_safely(self):
        with tempfile.TemporaryDirectory() as root:
            make_workspace(root, scope=(TENANT,))
            user_key = directory_natural_key(
                "user", ENTRA_USER, namespace="entra"
            )
            app_key = directory_natural_key(
                "application", ENTRA_APP, namespace="entra"
            )
            role_key = directory_natural_key(
                "role", f"{ENTRA_ROLE}|/", namespace="entra"
            )
            result = IdentityProviderCollection(
                entries=(
                    DirectoryEntry(ENTRA_USER, "user", "Cloud User"),
                    DirectoryEntry(ENTRA_APP, "application", "Example Application"),
                ),
                request_count=5,
                supplemental_evidence=IdentityEvidenceBundle(
                    roles=(
                        RoleEvidence(
                            role_key,
                            "Directory Readers",
                            "entra-role",
                            properties=(("directory_scope_id", "/"),),
                        ),
                    ),
                    relationships=(
                        IdentityRelationshipEvidence(
                            source_kind=GraphNodeKind.IDENTITY,
                            source_key=user_key,
                            target_kind=GraphNodeKind.IDENTITY,
                            target_key=app_key,
                            relationship="owns",
                            source_id="entra-owner",
                            properties=(("target_type", "application"),),
                        ),
                        IdentityRelationshipEvidence(
                            source_kind=GraphNodeKind.IDENTITY,
                            source_key=user_key,
                            target_kind=GraphNodeKind.PERMISSION,
                            target_key=role_key,
                            relationship="assigned-role",
                            source_id="entra-role-assignment",
                            properties=(("directory_scope_id", "/"),),
                        ),
                    ),
                ),
            )
            output = io.StringIO()
            error = io.StringIO()

            with patch.dict(os.environ, {"GRAPH_TOKEN": "graph-secret-token"}):
                with patch.object(
                    EntraIdentityProvider,
                    "collect",
                    return_value=result,
                ) as collect:
                    with contextlib.redirect_stdout(output), contextlib.redirect_stderr(error):
                        red_main((
                            "identity",
                            "collect",
                            "entra",
                            "--workspace", root,
                            "--engagement-id", "eng-live",
                            "--source-id", "entra-cli-1",
                            "--target", TENANT,
                            "--token-env", "GRAPH_TOKEN",
                        ))

            collect.assert_called_once()
            payload = json.loads(output.getvalue())
            self.assertEqual(payload["provider"], "entra-id")
            self.assertEqual(payload["identities"], 2)
            self.assertEqual(payload["roles"], 1)
            self.assertEqual(payload["observed_relationships"], 2)
            self.assertEqual(payload["provider_requests"], 5)
            self.assertEqual(error.getvalue(), "")

            for sensitive in (
                "Cloud User",
                "Example Application",
                "Directory Readers",
                ENTRA_USER,
                ENTRA_APP,
                "graph-secret-token",
                "GRAPH_TOKEN",
            ):
                self.assertNotIn(sensitive, output.getvalue())

    def test_graph_fingerprint_is_stable_for_identical_evidence(self):
        hashes = []
        for _ in range(2):
            with tempfile.TemporaryDirectory() as root:
                make_workspace(root)
                output = io.StringIO()
                result = IdentityProviderCollection(entries=(
                    DirectoryEntry(USER_DN, "user", "Alice"),
                ))
                with patch.dict(os.environ, {"AD_BIND_SECRET": "secret"}):
                    with patch.object(
                        ActiveDirectoryIdentityProvider,
                        "collect",
                        return_value=result,
                    ):
                        with contextlib.redirect_stdout(output):
                            red_main((
                                "identity",
                                "collect",
                                "ad",
                                "--workspace", root,
                                "--engagement-id", "eng-live",
                                "--source-id", "stable-source",
                                "--target", AD_TARGET,
                                "--base-dn", "DC=example,DC=test",
                                "--bind-username", "EXAMPLE\\reader",
                                "--password-env", "AD_BIND_SECRET",
                            ))
                hashes.append(json.loads(output.getvalue())["graph_sha256"])

        self.assertEqual(hashes[0], hashes[1])


if __name__ == "__main__":
    unittest.main()
