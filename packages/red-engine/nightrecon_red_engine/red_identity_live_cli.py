"""Authorization-first live identity collection CLI for Red Night."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
from collections.abc import Callable, Sequence

from nightrecon_red_engine.active_directory_provider import (
    ActiveDirectoryIdentityProvider,
    Ldap3ActiveDirectoryTransport,
)
from nightrecon_red_engine.entra_provider import (
    EntraIdentityProvider,
    MicrosoftGraphTransport,
)
from nightrecon_red_engine.graph_builder import IdentityGraphBuilder
from nightrecon_red_engine.graph_identity_projection import (
    add_identity_evidence_to_identity_graph,
)
from nightrecon_red_engine.graph_report import IdentityGraphReport
from nightrecon_red_engine.graph_snapshot import create_identity_graph_snapshot_manifest
from nightrecon_red_engine.identity_collection import (
    IdentityCollectionDenied,
    IdentityCollectionLimits,
    IdentityCollectionRequest,
    collect_authorized_identity_intelligence,
)
from nightrecon_red_engine.identity_engagement_evidence import (
    identity_bundle_to_engagement_records,
)
from nightrecon_shared_core.contracts import EngagementEnvelope, EvidenceRecord
from nightrecon_shared_core.workspace import LocalWorkspace


REPORT_SCHEMA_VERSION = 1


def _error(message: str) -> None:
    print(f"red-night identity collect: {message}", file=sys.stderr)
    raise SystemExit(2) from None


def _secret_resolver(variable_name: str) -> Callable[[], str]:
    if (
        not isinstance(variable_name, str)
        or not variable_name
        or variable_name != variable_name.strip()
    ):
        raise ValueError("credential environment variable name must be nonblank")

    def resolve() -> str:
        value = os.environ.get(variable_name)
        if value is None or not value:
            raise LookupError("identity credential source is missing or empty")
        return value

    return resolve


def _collection_record(
    *,
    engagement_id: str,
    source_id: str,
    observed_at: str,
    provider: str,
    target: str,
    graph_sha256: str,
    graph_schema_version: int,
    counts: dict[str, int],
    truncated: bool,
    provider_requests: int,
    limitations: tuple[str, ...],
) -> EvidenceRecord:
    evidence_id = "red-identity-collection-" + sha256(
        (
            f"{engagement_id}:{source_id}:{provider}:{target}:"
            f"{graph_sha256}:{observed_at}"
        ).encode("utf-8")
    ).hexdigest()
    return EvidenceRecord(
        engagement_id=engagement_id,
        evidence_id=evidence_id,
        source_night="red",
        evidence_type="identity.collection-summary",
        observed_at=observed_at,
        provenance=source_id,
        data={
            "provider": provider,
            "target": target,
            "graph_sha256": graph_sha256,
            "graph_schema_version": graph_schema_version,
            "identity_count": counts["identities"],
            "group_count": counts["groups"],
            "role_count": counts["roles"],
            "membership_count": counts["memberships"],
            "relationship_count": counts["relationships"],
            "unresolved_member_count": counts["unresolved_members"],
            "provider_requests": provider_requests,
            "truncated": truncated,
        },
        limitations=tuple(dict.fromkeys(
            limitations + (
                "Read-only observed identity evidence.",
                "No privilege or exploitability verdict.",
            )
        )),
    )


def _safe_report(
    *,
    provider: str,
    target: str,
    engagement_id: str,
    result,
    graph_report: IdentityGraphReport,
    graph_sha256: str,
    workspace_records_added: int,
    graph_exported: bool,
) -> dict[str, object]:
    graph_summary = graph_report.to_dict()["summary"]
    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "provider": provider,
        "target": target,
        "engagement_id": engagement_id,
        "identities": len(result.evidence.identities),
        "groups": len(result.evidence.groups),
        "roles": len(result.evidence.roles),
        "observed_memberships": len(result.evidence.memberships),
        "observed_relationships": len(result.evidence.relationships),
        "unresolved_members": result.unresolved_members,
        "truncated": result.truncated,
        "provider_requests": result.provider_requests,
        "provider_duration_ms": result.provider_duration_ms,
        "limitations": list(result.limitations),
        "graph_sha256": graph_sha256,
        "graph_nodes": graph_summary["nodes"],
        "graph_edges": graph_summary["edges"],
        "observed_edges": graph_summary["observed_edges"],
        "inferred_edges": graph_summary["inferred_edges"],
        "workspace_records_added": workspace_records_added,
        "graph_exported": graph_exported,
        "interpretation": (
            "Read-only observed identity evidence; no privilege or "
            "exploitability verdict."
        ),
    }


def _add_common_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--workspace",
        required=True,
        help="Existing Red Night workspace root.",
    )
    parser.add_argument("--engagement-id", required=True)
    parser.add_argument(
        "--source-id",
        required=True,
        help="Non-secret provenance identifier for this collection.",
    )
    parser.add_argument(
        "--target",
        required=True,
        help=(
            "Authorized directory-controller target for AD or configured tenant "
            "identifier for Entra."
        ),
    )
    parser.add_argument(
        "--approved",
        action="store_true",
        help="Supply explicit operator approval when the engagement policy requires it.",
    )
    parser.add_argument(
        "--report-output",
        help="Optional path for the identity-safe JSON collection summary.",
    )
    parser.add_argument(
        "--export-graph",
        help=(
            "Explicitly export the detailed graph, including identity labels, "
            "to this JSON file. Labels are never printed by default."
        ),
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="red-night identity collect")
    providers = parser.add_subparsers(dest="provider", required=True)

    ad = providers.add_parser(
        "ad",
        help="Collect bounded read-only Active Directory identity evidence.",
    )
    _add_common_arguments(ad)
    ad.add_argument("--base-dn", required=True)
    ad.add_argument("--bind-username", required=True)
    ad.add_argument(
        "--password-env",
        required=True,
        help="Environment variable containing the AD bind password.",
    )
    ad.add_argument(
        "--mode",
        choices=("ldaps", "starttls"),
        default="ldaps",
    )
    ad.add_argument("--port", type=int)
    ad.add_argument("--ca-certs-file")

    entra = providers.add_parser(
        "entra",
        help="Collect bounded read-only Microsoft Entra identity evidence.",
    )
    _add_common_arguments(entra)
    entra.add_argument(
        "--token-env",
        required=True,
        help="Environment variable containing a Microsoft Graph access token.",
    )

    return parser


def _provider(args):
    if args.provider == "ad":
        transport = Ldap3ActiveDirectoryTransport(
            host=args.target,
            bind_username=args.bind_username,
            secret_resolver=_secret_resolver(args.password_env),
            mode=args.mode,
            port=args.port,
            ca_certs_file=args.ca_certs_file,
        )
        return (
            "active-directory",
            ActiveDirectoryIdentityProvider(
                transport=transport,
                base_dn=args.base_dn,
            ),
        )

    transport = MicrosoftGraphTransport(
        access_token_resolver=_secret_resolver(args.token_env),
    )
    return (
        "entra-id",
        EntraIdentityProvider(
            transport=transport,
            tenant_id=args.target,
        ),
    )


def _write_json(path: str, payload: dict[str, object]) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )


def main(argv: Sequence[str]) -> None:
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        source_type, provider = _provider(args)
        workspace = LocalWorkspace(args.workspace)
        request = IdentityCollectionRequest(
            engagement_id=args.engagement_id,
            source_id=args.source_id,
            source_type=source_type,
            target=args.target,
            limits=IdentityCollectionLimits(),
            approval_present=args.approved,
        )
        result = collect_authorized_identity_intelligence(
            workspace,
            provider,
            request,
        )

        observed_at = datetime.now(timezone.utc).isoformat()
        graph = add_identity_evidence_to_identity_graph(
            IdentityGraphBuilder().build(),
            result.evidence,
        )
        graph_report = IdentityGraphReport.create(graph)
        manifest = create_identity_graph_snapshot_manifest(graph)

        records = identity_bundle_to_engagement_records(
            result.evidence,
            engagement_id=args.engagement_id,
            observed_at=observed_at,
        )
        counts = {
            "identities": len(result.evidence.identities),
            "groups": len(result.evidence.groups),
            "roles": len(result.evidence.roles),
            "memberships": len(result.evidence.memberships),
            "relationships": len(result.evidence.relationships),
            "unresolved_members": result.unresolved_members,
        }
        collection_record = _collection_record(
            engagement_id=args.engagement_id,
            source_id=args.source_id,
            observed_at=observed_at,
            provider=source_type,
            target=args.target,
            graph_sha256=manifest.graph_sha256,
            graph_schema_version=manifest.schema_version,
            counts=counts,
            truncated=result.truncated,
            provider_requests=result.provider_requests,
            limitations=result.limitations,
        )
        merge = workspace.merge_envelope(EngagementEnvelope(
            engagement_id=args.engagement_id,
            records=records + (collection_record,),
        ))
        if not merge.applied:
            raise ValueError("identity evidence could not be merged into the workspace")

        if args.export_graph:
            _write_json(args.export_graph, graph_report.to_dict())

        report = _safe_report(
            provider=source_type,
            target=args.target,
            engagement_id=args.engagement_id,
            result=result,
            graph_report=graph_report,
            graph_sha256=manifest.graph_sha256,
            workspace_records_added=merge.added_records,
            graph_exported=bool(args.export_graph),
        )
        if args.report_output:
            _write_json(args.report_output, report)
        print(json.dumps(report, sort_keys=True))
    except IdentityCollectionDenied as exc:
        _error(str(exc))
    except LookupError:
        _error("identity credential source is missing or empty")
    except (OSError, UnicodeDecodeError, ValueError, RuntimeError) as exc:
        _error(str(exc))
    except Exception:
        _error("live identity collection failed")
