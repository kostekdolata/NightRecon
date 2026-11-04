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
