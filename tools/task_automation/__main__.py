"""Offline queue administration only; no run/agent/push/merge command."""

import argparse
import base64
import json
from pathlib import Path
import sys
import time

from .controller import Rejected, _json, _keys, _require, load_policy
from .objectives import TrustKey, verify_approval
from .queue import ObjectiveQueue


def read_trust(raw: bytes) -> dict[str, TrustKey]:
    data = _json(raw, 65536)
    _require(0 < len(data) <= 20, "owner trust registry is empty or too large")
    result = {}
    for key_id, value in data.items():
        _keys(value, {"owner", "role", "public_key_base64"})
        _require(type(value["owner"]) is str and value["role"] == "owner"
                 and type(value["public_key_base64"]) is str, "invalid owner trust entry")
        try:
            public = base64.b64decode(value["public_key_base64"], validate=True)
        except ValueError as exc:
            raise Rejected("invalid owner public key") from exc
        _require(len(public) == 32, "Ed25519 public key must be 32 bytes")
        result[key_id] = TrustKey(value["owner"], value["role"], public)
    return result


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--policy-sha256", required=True)
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--integrity-key-file", type=Path, required=True)
    sub = parser.add_subparsers(dest="command", required=True)
    enqueue = sub.add_parser("enqueue", help="Verify and persist one owner-signed objective")
    enqueue.add_argument("--approval", type=Path, required=True)
    enqueue.add_argument("--owner-trust", type=Path, required=True)
    report = sub.add_parser("report", help="Read authenticated durable state; never execute it")
    report.add_argument("objective_id")
    args = parser.parse_args(argv)
    queue = None
    try:
        policy = load_policy(args.policy.read_bytes(), expected_digest=args.policy_sha256)
        if args.command == "enqueue":
            owners = read_trust(args.owner_trust.read_bytes())
            envelope = args.approval.read_bytes()
            verify_approval(envelope, policy, owners, now=int(time.time()))
        key = args.integrity_key_file.read_bytes()
        queue = ObjectiveQueue(args.database, integrity_key=key)
        if args.command == "enqueue":
            result = queue.enqueue(envelope, policy, owners, now=int(time.time()))
        else:
            result = queue.read(args.objective_id)
        print(json.dumps({"schema_version": 1, "operational": False, "result": result}, sort_keys=True))
        return 0
    except (Rejected, OSError, ValueError) as exc:
        # Never print raw files, signatures, environment variables or test output.
        reason = str(exc) if isinstance(exc, Rejected) else "local configuration unavailable or invalid"
        print(json.dumps({"schema_version": 1, "operational": False, "state": "blocked", "reason": reason}))
        return 1
    finally:
        if queue is not None:
            queue.close()


if __name__ == "__main__":
    sys.exit(main())
