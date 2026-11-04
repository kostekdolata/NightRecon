"""Operator CLI for advanced Red Night network and traffic capabilities."""

from __future__ import annotations

import argparse
import json
import time

from nightrecon_red_engine.cyber_range_simulation import (
    CyberRange,
    RangeAction,
    VirtualHost,
    build_simulation_payload,
)
from nightrecon_red_engine.deep_packet_analysis import analyze_pcap_deep
from nightrecon_red_engine.http2_repeater import replay_http2_request
from nightrecon_red_engine.network_environment import collect_network_environment
from nightrecon_red_engine.packet_intelligence import (
    analyze_packets,
    capture_live,
    filter_packets,
    import_pcap,
)
from nightrecon_red_engine.ports import parse_ports
from nightrecon_red_engine.scan_profiles import get_scan_timing_profile
from nightrecon_red_engine.syn_scanner import scan_syn_ports
from nightrecon_red_engine.validation_module_registry import (
    BUILTIN_VALIDATION_MODULES,
)
from nightrecon_red_engine.web_proxy_repeater import (
    BoundedInterceptProxy,
    build_exchange_record,
    replay_request,
)
from nightrecon_shared_core.authorization import Scope


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="red-night advanced")
    sub = parser.add_subparsers(dest="command", required=True)

    nmap = sub.add_parser(
        "nmap-governed",
        help="Run an explicitly authorised Nmap TCP-connect assessment.",
    )
    nmap.add_argument("target", help="Single exact IPv4/IPv6 address in engagement scope.")
    nmap.add_argument("--authority-db", required=True)
    nmap.add_argument("--engagement-id", required=True)
    nmap.add_argument("--action-id", required=True)
    nmap.add_argument("--audit-path", required=True)
    nmap.add_argument("--result-audit-path", required=True)
    nmap.add_argument("--nmap-executable", required=True)
    nmap.add_argument("--trusted-sha256", required=True)
    nmap.add_argument(
        "--execute", action="store_true",
        help="Opt in to the bounded scan after existing policy/approval checks.",
    )

    tshark = sub.add_parser(
        "tshark-inspect",
        help="Read a bounded local packet capture with a verified TShark binary.",
    )
    tshark.add_argument("target", help="Exact authorised engagement target for attribution.")
    tshark.add_argument("--authority-db", required=True)
    tshark.add_argument("--engagement-id", required=True)
    tshark.add_argument("--action-id", required=True)
    tshark.add_argument("--audit-path", required=True)
    tshark.add_argument("--result-audit-path", required=True)
    tshark.add_argument("--tshark-executable", required=True)
    tshark.add_argument("--trusted-sha256", required=True)
    tshark.add_argument("--capture-root", required=True)
    tshark.add_argument("--capture", required=True)
    tshark.add_argument("--execute", action="store_true")

    zap = sub.add_parser(
        "zap-local-status", help="Read-only status from an operator-running local OWASP ZAP."
    )
    zap.add_argument("--port", type=int, default=8080)
    zap.add_argument("--connect", action="store_true", help="Explicit opt-in to local API connection.")

    msf = sub.add_parser(
        "metasploit-status",
        help="Read-only, TLS-verified status of local Metasploit RPC.",
    )
    msf.add_argument("--port", type=int, default=55553)
    msf.add_argument("--ca-file", help="CA certificate for verified local msfrpcd TLS.")
    msf.add_argument("--connect", action="store_true", help="Explicit RPC connection opt-in.")

    nuclei = sub.add_parser(
        "nuclei-fingerprint",
        help="Run a single approved low-impact Nuclei HTTP fingerprint.",
    )
    nuclei.add_argument("target_url", help="Exact HTTP(S) IPv4 origin in engagement scope.")
    nuclei.add_argument("--authority-db", required=True)
    nuclei.add_argument("--engagement-id", required=True)
    nuclei.add_argument("--action-id", required=True)
    nuclei.add_argument("--audit-path", required=True)
    nuclei.add_argument("--result-audit-path", required=True)
    nuclei.add_argument("--nuclei-executable", required=True)
    nuclei.add_argument("--trusted-sha256", required=True)
    nuclei.add_argument("--execute", action="store_true")

    batch = sub.add_parser(
        "governed-batch",
        help="Run a bounded plan of approved Nmap/TShark/Nuclei tasks with per-task progress.",
    )
    batch.add_argument("--authority-db", required=True)
    batch.add_argument("--plan", required=True, help="Trusted local JSON task plan.")
    batch.add_argument("--audit-dir", required=True, help="Existing protected audit directory.")
    batch.add_argument("--max-workers", type=int, default=2)
    batch.add_argument("--execute", action="store_true")

    report = sub.add_parser(
        "tool-report", help="Summarize actual governed execution events across tools.",
    )
    report.add_argument("--result-audit-path", required=True)
    report.add_argument("--engagement-id")

    env = sub.add_parser("network-env")
    env.add_argument("--json", action="store_true")

    syn = sub.add_parser("syn-scan")
    syn.add_argument("target")
    syn.add_argument("--scope", action="append", required=True)
    syn.add_argument("--ports", default="1-1024")
    syn.add_argument(
        "--profile",
        choices=("polite", "normal", "fast"),
        default="normal",
    )

    packet = sub.add_parser("packet")
    packet_sub = packet.add_subparsers(dest="packet_command", required=True)

    pcap = packet_sub.add_parser("analyze")
    pcap.add_argument("pcap")
    pcap.add_argument("--host", default="")
    pcap.add_argument("--protocol", default="")
    pcap.add_argument("--port", type=int)
    pcap.add_argument(
        "--deep",
        action="store_true",
        help="Perform bounded TCP byte-stream reassembly and protocol dissection.",
    )

    capture = packet_sub.add_parser("capture")
    capture.add_argument("--interface")
    capture.add_argument("--count", type=int, default=500)
    capture.add_argument("--timeout", type=float, default=10.0)
    capture.add_argument("--filter", default="")

    replay = sub.add_parser("web-replay")
    replay.add_argument("method")
    replay.add_argument("url")
    replay.add_argument("--scope", action="append", required=True)
    replay.add_argument("--header", action="append", default=[])
    replay.add_argument("--body", default="")
    replay.add_argument("--timeout", type=float, default=5.0)
    replay.add_argument(
        "--http2",
        action="store_true",
        help="Use the optional HTTP/2 repeater runtime for HTTPS requests.",
    )

    proxy = sub.add_parser("web-proxy")
    proxy.add_argument("--scope", action="append", required=True)
    proxy.add_argument("--port", type=int, default=8081)
    proxy.add_argument(
        "--https-intercept",
        action="store_true",
        help=(
            "Enable scoped HTTPS CONNECT interception using a local assessment "
            "CA. The CA is never trusted automatically."
        ),
    )
    proxy.add_argument(
        "--ca-directory",
        help=(
            "Optional directory for generated assessment CA material. "
            "Use only a protected operator-controlled path."
        ),
    )
    proxy.add_argument(
        "--duration",
        type=float,
        default=60.0,
        help="Run duration in seconds; maximum 300.",
    )

    validation = sub.add_parser("validation-modules")
    validation.add_argument("--json", action="store_true")

    range_parser = sub.add_parser("range-sim")
    range_parser.add_argument(
        "--host",
        action="append",
        required=True,
        help=(
            "Virtual host specification HOST_ID[:compromised][:privileged]. "
            "This creates only in-memory range state."
        ),
    )
    range_parser.add_argument(
        "--step",
        action="append",
        required=True,
        help="Simulation step ACTION:SOURCE:TARGET.",
    )
    range_parser.add_argument(
        "--scenario-id",
        default="manual-range-scenario",
    )
    range_parser.add_argument(
        "--no-rollback",
        action="store_true",
        help="Retain only in-memory simulated state after the run.",
    )

    return parser


def _headers(values: list[str]) -> tuple[tuple[str, str], ...]:
    result = []
    for value in values:
        if ":" not in value:
            raise ValueError("--header values must use Name: Value")
        name, header_value = value.split(":", 1)
        name = name.strip()
        if not name:
            raise ValueError("header name must not be empty")
        result.append((name, header_value.strip()))
    return tuple(result)


def _packet_payload(report) -> dict[str, object]:
    return {
        "packets": len(report.packets),
        "conversations": [
            {
                "endpoint_a": item.endpoint_a,
                "endpoint_b": item.endpoint_b,
                "transport": item.transport,
                "packets": item.packets,
                "bytes": item.bytes,
            }
            for item in report.conversations
        ],
        "streams": [
            {
                "stream_id": item.stream_id,
                "client": item.client,
                "server": item.server,
                "transport": item.transport,
                "packets": item.packets,
                "bytes": item.bytes,
                "protocol_hints": list(item.protocol_hints),
            }
            for item in report.streams
        ],
        "findings": [
            {
                "finding_id": item.finding_id,
                "kind": item.kind,
                "severity": item.severity,
                "summary": item.summary,
                "packet_ids": list(item.packet_ids),
                "evidence": list(item.evidence),
            }
            for item in report.findings
        ],
        "artifacts": [
            {
                "type": item.artifact_type,
                "value": item.value,
                "packet_ids": list(item.packet_ids),
            }
            for item in report.artifacts
        ],
    }


def main(argv: tuple[str, ...]) -> object | None:
    args = build_parser().parse_args(argv)

    if args.command == "nmap-governed":
        from pathlib import Path
        from nightrecon_red_engine.governed_nmap_coordinator import (
            execute_governed_nmap_discovery,
        )
        from nightrecon_red_engine.transactional_policy_authority import (
            TransactionalPolicyAuthority,
        )
        if not args.execute:
            raise PermissionError(
                "Nmap execution disabled; explicitly supply --execute after operator approval"
            )
        if not Path(args.authority_db).is_file():
            raise FileNotFoundError("Registered engagement authority database required")
        authority = TransactionalPolicyAuthority(args.authority_db)
        result = execute_governed_nmap_discovery(
            authority=authority,
            engagement_id=args.engagement_id,
            action_id=args.action_id,
            target=args.target,
            executable=args.nmap_executable,
            trusted_sha256=args.trusted_sha256,
            audit_path=args.audit_path,
            result_audit_path=args.result_audit_path,
            enabled=True,
        )
        print(json.dumps(result.operator_report(), indent=2))
        return result

    if args.command == "tshark-inspect":
        from pathlib import Path
        from nightrecon_red_engine.governed_tshark_coordinator import (
            execute_governed_tshark_inspection,
        )
        from nightrecon_red_engine.transactional_policy_authority import (
            TransactionalPolicyAuthority,
        )
        if not args.execute:
            raise PermissionError("Offline TShark requires explicit --execute opt-in")
        if not Path(args.authority_db).is_file():
            raise FileNotFoundError("Registered engagement authority database required")
        result = execute_governed_tshark_inspection(
            authority=TransactionalPolicyAuthority(args.authority_db),
            engagement_id=args.engagement_id,
            action_id=args.action_id,
            target=args.target,
            executable=args.tshark_executable,
            trusted_sha256=args.trusted_sha256,
            capture_path=args.capture,
            capture_root=args.capture_root,
            audit_path=args.audit_path,
            result_audit_path=args.result_audit_path,
            enabled=True,
        )
        print(json.dumps(result.operator_report(), indent=2))
        return result

    if args.command == "zap-local-status":
        import os
        from nightrecon_red_engine.zap_local_observer import inspect_local_zap
        if not args.connect:
            raise PermissionError("Local ZAP connection requires explicit --connect opt-in")
        key = os.environ.get("RED_NIGHT_ZAP_API_KEY", "")
        if not key:
            raise PermissionError("RED_NIGHT_ZAP_API_KEY is required")
        result = inspect_local_zap(port=args.port, api_key=key)
        print(json.dumps(result.operator_report(), indent=2))
        return result

    if args.command == "metasploit-status":
        import os
        from nightrecon_red_engine.metasploit_local_rpc import inspect_local_metasploit
        if not args.connect:
            raise PermissionError("Metasploit RPC requires explicit --connect opt-in")
        token = os.environ.get("RED_NIGHT_METASPLOIT_RPC_TOKEN", "")
        if not token:
            raise PermissionError("RED_NIGHT_METASPLOIT_RPC_TOKEN is required")
        result = inspect_local_metasploit(
            port=args.port, token=token, ca_file=args.ca_file,
        )
        print(json.dumps(result.operator_report(), indent=2))
        return result

    if args.command == "nuclei-fingerprint":
        from pathlib import Path
        from nightrecon_red_engine.governed_nuclei_fingerprint import (
            execute_governed_nuclei_fingerprint,
        )
        from nightrecon_red_engine.transactional_policy_authority import (
            TransactionalPolicyAuthority,
        )
        if not args.execute:
            raise PermissionError("Nuclei fingerprint requires explicit --execute opt-in")
        if not Path(args.authority_db).is_file():
            raise FileNotFoundError("Registered engagement authority database required")
        result = execute_governed_nuclei_fingerprint(
            authority=TransactionalPolicyAuthority(args.authority_db),
            engagement_id=args.engagement_id,
            action_id=args.action_id,
            target_url=args.target_url,
            executable=args.nuclei_executable,
            trusted_sha256=args.trusted_sha256,
            audit_path=args.audit_path,
            result_audit_path=args.result_audit_path,
            enabled=True,
        )
        print(json.dumps(result.operator_report(), indent=2))
        return result

    if args.command == "governed-batch":
        from pathlib import Path
        from nightrecon_red_engine.governed_assessment_batch import (
            GovernedAssessmentTask, run_governed_assessment_batch,
        )
        from nightrecon_red_engine.transactional_policy_authority import (
            TransactionalPolicyAuthority,
        )
        if not args.execute:
            raise PermissionError("Governed batch requires explicit --execute opt-in")
        if not Path(args.authority_db).is_file():
            raise FileNotFoundError("Registered engagement authority database required")
        root = Path(args.audit_dir).resolve(strict=True)
        if not root.is_dir():
            raise ValueError("Audit directory must exist")
        plan_path = Path(args.plan)
        if not plan_path.is_file() or plan_path.stat().st_size > 65536:
            raise ValueError("Plan is unavailable or too large")
        plan = json.loads(plan_path.read_text(encoding="utf-8"))
        if (not isinstance(plan, dict) or set(plan) != {"schema", "tasks"}
            or plan["schema"] != 1 or not isinstance(plan["tasks"], list)
            or not 1 <= len(plan["tasks"]) <= 8):
            raise ValueError("Invalid bounded assessment plan")
        tasks = []
        common_keys = {
            "kind", "engagement_id", "action_id", "target",
            "executable", "trusted_sha256",
        }
        for entry in plan["tasks"]:
            if not isinstance(entry, dict):
                raise ValueError("Invalid batch task")
            kind = entry.get("kind")
            required = common_keys | ({"capture_path", "capture_root"} if kind == "tshark" else set())
            if kind not in ("nmap", "tshark", "nuclei") or set(entry) != required:
                raise ValueError("Unapproved batch task fields or kind")
            if not all(isinstance(entry[key], str) for key in required):
                raise ValueError("Batch task fields must be strings")
            tasks.append(GovernedAssessmentTask(
                kind=kind, engagement_id=entry["engagement_id"],
                action_id=entry["action_id"], target=entry["target"],
                executable=entry["executable"],
                trusted_sha256=entry["trusted_sha256"],
                audit_path=root / "authorization.jsonl",
                result_audit_path=root / "execution.jsonl",
                capture_path=entry.get("capture_path"),
                capture_root=entry.get("capture_root"),
            ))
        def progress(event):
            print(json.dumps({
                "type": "task-event", "action_id": event.action_id,
                "tool": event.kind, "status": event.status,
                "recorded_at": event.recorded_at,
            }), flush=True)
        report = run_governed_assessment_batch(
            authority=TransactionalPolicyAuthority(args.authority_db),
            tasks=tuple(tasks), enabled=True, max_workers=args.max_workers,
            on_event=progress,
        )
        from nightrecon_red_engine.governed_execution_report import (
            summarize_governed_execution_ledger,
        )
        final = {"type": "batch-report", **report.operator_report()}
        # Match only actions from the current operator plan. Never expose
        # unrelated actions, even if they share the same engagement ledger.
        expected = {(t.engagement_id, t.action_id) for t in tasks}
        ledger_path = root / "execution.jsonl"
        if ledger_path.is_file():
            try:
                recorded = summarize_governed_execution_ledger(ledger_path)
                observed = [
                    item for item in recorded["actions"]
                    if (item["engagement_id"], item["action_id"]) in expected
                ]
                final["execution_audit"] = {
                    "status": "available" if len(observed) == len(expected)
                    else "incomplete",
                    "actions": observed,
                    "missing_actions": [
                        {"engagement_id": engagement, "action_id": action}
                        for engagement, action in sorted(expected - {
                            (item["engagement_id"], item["action_id"]) for item in observed
                        })
                    ],
                }
            except (OSError, ValueError):
                final["execution_audit"] = {
                    "status": "unavailable-or-invalid",
                    "actions": [],
                }
        else:
            final["execution_audit"] = {
                "status": "not-recorded", "actions": [],
            }
        print(json.dumps(final), flush=True)
        return report

    if args.command == "tool-report":
        from nightrecon_red_engine.governed_execution_report import (
            summarize_governed_execution_ledger,
        )
        result = summarize_governed_execution_ledger(
            args.result_audit_path, engagement_id=args.engagement_id,
        )
        print(json.dumps(result, indent=2))
        return result

    if args.command == "network-env":
        snapshot = collect_network_environment()
        payload = {
            "interfaces": [
                {"name": item.name, "index": item.index}
                for item in snapshot.interfaces
            ],
            "routes": [
                {
                    "destination": item.destination,
                    "gateway": item.gateway,
                    "interface": item.interface,
                    "metric": item.metric,
                    "family": item.family,
                }
                for item in snapshot.routes
            ],
            "errors": list(snapshot.collection_errors),
        }
        print(json.dumps(payload, indent=2))
        return snapshot

    if args.command == "syn-scan":
        profile = get_scan_timing_profile(args.profile)
        results = scan_syn_ports(
            address=args.target,
            ports=parse_ports(args.ports),
            scope=Scope.from_values(args.scope),
            timeout=profile.timeout_seconds,
            retries=min(profile.retries, 2),
            max_probes_per_second=profile.max_probes_per_second,
        )
        print(json.dumps([
            {
                "address": item.address,
                "port": item.port,
                "state": item.state,
                "confidence": item.confidence,
                "evidence": item.evidence,
                "attempts": item.attempts,
            }
            for item in results
        ], indent=2))
        return results

    if args.command == "packet":
        if args.packet_command == "analyze" and args.deep:
            deep = analyze_pcap_deep(args.pcap)
            report = deep.packet_report
            if args.host or args.protocol or args.port is not None:
                packets = filter_packets(
                    report.packets,
                    host=args.host,
                    protocol=args.protocol,
                    port=args.port,
                )
                report = analyze_packets(packets)
            payload = _packet_payload(report)
            payload["reassembled_tcp_streams"] = [
                {
                    "packet_ids": list(item.packet_ids),
                    "bytes_reassembled": item.bytes_reassembled,
                    "sha256": item.sha256,
                    "truncated": item.truncated,
                    "gaps_detected": item.gaps_detected,
                    "protocol": (
                        {
                            "name": item.protocol.protocol,
                            "fields": dict(item.protocol.fields),
                            "confidence": item.protocol.confidence,
                        }
                        if item.protocol is not None
                        else None
                    ),
                }
                for item in deep.reassembled_tcp_streams
            ]
            print(json.dumps(payload, indent=2))
            return deep

        if args.packet_command == "analyze":
            packets = import_pcap(args.pcap)
            packets = filter_packets(
                packets,
                host=args.host,
                protocol=args.protocol,
                port=args.port,
            )
        else:
            packets = capture_live(
                interface=args.interface,
                packet_count=args.count,
                timeout_seconds=args.timeout,
                bpf_filter=args.filter,
            )
        report = analyze_packets(packets)
        print(json.dumps(_packet_payload(report), indent=2))
        return report

    if args.command == "web-replay":
        scope = Scope.from_values(args.scope)
        headers = _headers(args.header)
        body = args.body.encode("utf-8")
        if args.http2:
            http2_response = replay_http2_request(
                method=args.method,
                url=args.url,
                scope=scope,
                headers=headers,
                body=body,
                timeout=args.timeout,
            )
            from nightrecon_red_engine.web_proxy_repeater import RepeaterResponse
            response = RepeaterResponse(
                status=http2_response.status,
                reason=http2_response.http_version,
                headers=http2_response.headers,
                body=http2_response.body,
                truncated=http2_response.truncated,
            )
        else:
            response = replay_request(
                method=args.method,
                url=args.url,
                scope=scope,
                headers=headers,
                body=body,
                timeout=args.timeout,
            )
        record = build_exchange_record(
            method=args.method,
            url=args.url,
            request_headers=headers,
            request_body=body,
            response=response,
        )
        print(json.dumps({
            "exchange_id": record.exchange_id,
            "status": record.response_status,
            "transport": "http2" if args.http2 else "http1",
            "request_body_bytes": record.request_body_bytes,
            "response_body_bytes": record.response_body_bytes,
            "parameters": [
                {"location": item.location, "name": item.name}
                for item in record.parameters
            ],
            "cookies": [
                {
                    "name": item.name,
                    "secure": item.secure,
                    "http_only": item.http_only,
                    "same_site": item.same_site,
                    "issue": item.issue,
                }
                for item in record.cookies
            ],
        }, indent=2))
        return record

    if args.command == "web-proxy":
        if args.duration <= 0 or args.duration > 300:
            raise ValueError("--duration must be between 0 and 300 seconds")
        scope = Scope.from_values(args.scope)
        with BoundedInterceptProxy(
            scope=scope,
            port=args.port,
            https_intercept=args.https_intercept,
            ca_directory=args.ca_directory,
        ) as proxy:
            host, port = proxy.address
            scheme = "HTTP/HTTPS" if args.https_intercept else "HTTP"
            print(
                f"Red Night {scheme} intercept proxy listening on {host}:{port}"
            )
            if args.https_intercept:
                print(
                    "Assessment CA certificate: "
                    f"{proxy.ca_certificate_path}"
                )
                print(
                    "Assessment CA SHA-256: "
                    f"{proxy.ca_fingerprint_sha256}"
                )
            time.sleep(args.duration)
            records = tuple(proxy.records)
        print(json.dumps({
            "exchanges": len(records),
            "exchange_ids": [item.exchange_id for item in records],
        }, indent=2))
        return records

    if args.command == "validation-modules":
        payload = [
            {
                "module_id": item.module_id,
                "title": item.title,
                "family": item.family,
                "proof_mode": item.proof_mode,
                "required_service": item.required_service,
                "preconditions": [
                    condition.name
                    for condition in item.preconditions
                ],
                "cleanup_required": item.cleanup_required,
                "impact": item.impact,
            }
            for item in BUILTIN_VALIDATION_MODULES
        ]
        print(json.dumps(payload, indent=2))
        return BUILTIN_VALIDATION_MODULES

    if args.command == "range-sim":
        hosts = []
        for value in args.host:
            parts = value.split(":")
            if not parts[0].strip():
                raise ValueError("virtual host id must not be empty")
            flags = {
                item.strip().lower()
                for item in parts[1:]
            }
            hosts.append(VirtualHost(
                host_id=parts[0].strip(),
                compromised="compromised" in flags,
                privileged="privileged" in flags,
            ))

        steps = []
        actions = []
        for value in args.step:
            parts = value.split(":", 2)
            if len(parts) != 3:
                raise ValueError(
                    "--step must use ACTION:SOURCE:TARGET"
                )
            try:
                action = RangeAction(parts[0].strip())
            except ValueError as exc:
                raise ValueError(
                    f"unsupported range action: {parts[0]}"
                ) from exc
            actions.append(action)
            steps.append((
                parts[1].strip(),
                parts[2].strip(),
                action,
            ))

        payload = build_simulation_payload(
            scenario_id=args.scenario_id,
            allowed_actions=tuple(dict.fromkeys(actions)),
            max_steps=max(1, len(steps)),
        )
        range_ = CyberRange(tuple(hosts))
        report = range_.run_scenario(
            payload=payload,
            steps=tuple(steps),
            rollback=not args.no_rollback,
        )
        print(json.dumps({
            "scenario_id": report.scenario_id,
            "simulation_only": True,
            "cleaned": report.cleaned,
            "rollback_snapshot_id": report.rollback_snapshot_id,
            "events": [
                {
                    "sequence": item.sequence,
                    "action": item.action.value,
                    "source_host": item.source_host,
                    "target_host": item.target_host,
                    "outcome": item.outcome,
                    "evidence_id": item.evidence_id,
                }
                for item in report.events
            ],
        }, indent=2))
        return report

    return None
