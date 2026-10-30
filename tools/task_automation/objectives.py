"""Authenticated objective approvals and independent validation receipts.

Signing keys never belong in repository files or coding/validation workspaces.
This module verifies signatures only. It cannot approve an objective itself.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .controller import (
    Candidate, Check, Policy, Rejected, Task, _canonical, _digest, _integer,
    _json, _keys, _require, _sha, _strings, _text, parse_task,
)


APPROVAL_DOMAIN = b"nightrecon-objective-approval-v1\x00"
VALIDATION_DOMAIN = b"nightrecon-independent-validation-v1\x00"
RELEASE_DOMAIN = b"nightrecon-release-manifest-v1\x00"
PLATFORMS = frozenset({"ubuntu-py311", "ubuntu-py314", "windows-py311", "windows-py314"})


class ValidationFailed(Rejected):
    """A genuine, independently signed executed-check failure permits repair."""


@dataclass(frozen=True)
class TrustKey:
    owner: str
    role: str
    public_key: bytes


def verify_envelope(raw: bytes, domain: bytes, keys: dict[str, TrustKey],
                    required_role: str) -> tuple[dict, TrustKey, str]:
    envelope = _json(raw, 1048576)
    _keys(envelope, {"key_id", "payload", "signature"})
    key_id = _text(envelope["key_id"], 128)
    _require(key_id in keys, "untrusted signing key")
    key = keys[key_id]
    _require(key.role == required_role, "incorrect signing role")
    _require(type(envelope["payload"]) is dict, "signed object required")
    _require(type(envelope["signature"]) is str, "invalid signature type")
    body = _canonical(envelope["payload"])
    try:
        signature = base64.b64decode(envelope["signature"], validate=True)
        Ed25519PublicKey.from_public_bytes(key.public_key).verify(signature, domain + body)
    except (ValueError, InvalidSignature) as exc:
        raise Rejected("signature verification failed") from exc
    return envelope["payload"], key, key_id


@dataclass(frozen=True)
class Limits:
    max_batches: int
    max_repairs_per_batch: int
    max_attempts: int
    max_wall_seconds: int
    max_tokens: int
    max_cost_microusd: int


@dataclass(frozen=True)
class Approval:
    objective_id: str
    owner: str
    digest: str
    task: Task
    approved_at: int
    expires_at: int
    limits: Limits
    release_authorized: bool
    release_tag: str | None
    artifact_names: tuple[str, ...]
    signing_key_ids: tuple[str, ...]


def verify_approval(raw: bytes, policy: Policy, trusted_owners: dict[str, TrustKey],
                    *, now: int) -> Approval:
    data, key, _ = verify_envelope(raw, APPROVAL_DOMAIN, trusted_owners, "owner")
    _keys(data, {"schema_version", "objective_id", "owner", "repository", "task",
                 "policy_digest", "approved_at", "expires_at", "limits", "release",
                 "allow_safety_control_changes"})
    _require(type(data["schema_version"]) is int and data["schema_version"] == 1,
             "unsupported approval version")
    _require(data["owner"] == key.owner and key.owner in policy.allowed_submitters,
             "approval owner mismatch")
    _require(data["repository"] == "kostekdolata/NightRecon", "approval repository mismatch")
    _require(data["policy_digest"] == policy.digest, "approval policy mismatch")
    _require(data["allow_safety_control_changes"] is False,
             "safety/control-plane changes require a separate reviewed infrastructure path")
    task = parse_task(_canonical(data["task"]), policy)
    expected_id = f"issue-{task.issue_number}-r{task.revision}"
    _require(data["objective_id"] == expected_id, "objective identity mismatch")
    approved = _integer(data["approved_at"], 0, 2**53 - 1)
    expires = _integer(data["expires_at"], 1, 2**53 - 1)
    _integer(now, 0, 2**53 - 1)
    _require(approved <= now < expires and expires - approved <= 604800,
             "approval not active or exceeds seven-day lifetime")
    values = _keys(data["limits"], set(Limits.__dataclass_fields__))
    maxima = {"max_batches": 20, "max_repairs_per_batch": policy.max_repair_attempts,
              "max_attempts": 60, "max_wall_seconds": policy.max_runtime_minutes * 60,
              "max_tokens": 2000000, "max_cost_microusd": 100000000}
    for name, maximum in maxima.items():
        _integer(values[name], 0 if name == "max_repairs_per_batch" else 1, maximum)
    release = _keys(data["release"], {"authorized", "tag", "artifact_names", "signing_key_ids"})
    _require(type(release["authorized"]) is bool, "invalid release authorization")
    if release["authorized"]:
        import re
        _require(type(release["tag"]) is str
                 and re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", release["tag"]) is not None,
                 "invalid release tag")
        names = _strings(release["artifact_names"], 20)
        from .controller import path_name
        for name in names:
            path_name(name)
            _require("/" not in name, "release artifact must be a basename")
        signing = _strings(release["signing_key_ids"], 20)
    else:
        _require(release["tag"] is None and release["artifact_names"] == []
                 and release["signing_key_ids"] == [], "unauthorized release fields")
        names, signing = (), ()
    return Approval(expected_id, key.owner, _digest(_canonical(data)), task, approved,
                    expires, Limits(**values), release["authorized"], release["tag"],
                    names, signing)


@dataclass(frozen=True)
class Receipt:
    digest: str
    candidate_digest: str
    parent_sha: str
    batch: int
    validator: str
    checks: tuple[Check, ...]
    run_urls: tuple[str, ...]
    envelope: bytes


def verify_receipt(raw: bytes, approval: Approval, candidate: Candidate, policy: Policy,
                   validator_keys: dict[str, TrustKey], *, parent_sha: str,
                   batch: int, now: int) -> Receipt:
    data, key, _ = verify_envelope(raw, VALIDATION_DOMAIN, validator_keys, "validator")
    _keys(data, {"schema_version", "approval_digest", "policy_digest", "candidate_digest",
                 "parent_sha", "batch", "validator", "worker", "issued_at", "expires_at",
                 "platforms", "checks", "run_urls"})
    _require(type(data["schema_version"]) is int and data["schema_version"] == 1,
             "invalid receipt version")
    _require(data["approval_digest"] == approval.digest and data["policy_digest"] == policy.digest,
             "receipt approval/policy mismatch")
    _require(candidate.task_id == approval.task.task_id and candidate.scope_valid,
             "non-passing candidate")
    _require(data["candidate_digest"] == candidate.digest, "receipt candidate mismatch")
    _require(_sha(data["parent_sha"]) == parent_sha, "receipt parent mismatch")
    _require(type(data["batch"]) is int and data["batch"] == batch, "receipt batch mismatch")
    _require(data["validator"] == key.owner and data["worker"] != key.owner,
             "validation is not independently signed")
    issued = _integer(data["issued_at"], 0, 2**53 - 1)
    expires = _integer(data["expires_at"], 1, 2**53 - 1)
    _require(approval.approved_at <= issued <= now < expires <= approval.expires_at,
             "receipt expired or outside approval")
    _require(set(_strings(data["platforms"], 4)) == PLATFORMS,
             "required cross-platform validation missing")
    _require(type(data["checks"]) is list and len(data["checks"]) <= 128,
             "invalid validation checks")
    checks = []
    for item in data["checks"]:
        _keys(item, set(Check.__dataclass_fields__))
        check = Check(**item)
        check.validate()
        _require(set(check.skip_ids) <= set(policy.allowed_skip_ids), "unexpected validation skips")
        _require(check.candidate_digest == candidate.digest, "stale check")
        if check.status == "failed":
            raise ValidationFailed("executed validation failed: " + check.name)
        _require(check.status == "passed", "required validation unavailable: " + check.name)
        if check.name in {"python-suite", "controller-tests", "red-package-boundary"}:
            _require(check.tests_run is not None, "missing test counts")
        checks.append(check)
    _require(len({c.name for c in checks}) == len(checks), "duplicate receipt checks")
    _require(set(policy.required_checks) <= {c.name for c in checks}, "missing required checks")
    urls = _strings(data["run_urls"], 128)
    import re
    for url in urls:
        _require(re.fullmatch(r"https://github\.com/kostekdolata/NightRecon/actions/runs/[1-9][0-9]*", url)
                 is not None, "untrusted validation run URL")
    return Receipt(_digest(_canonical(data)), candidate.digest, parent_sha, batch,
                   key.owner, tuple(checks), urls, raw)


def verify_release(raw: bytes, approval: Approval, signing_keys: dict[str, TrustKey],
                   artifacts: dict[str, bytes], *, merge_sha: str,
                   allowlisted_commit: str, existing_tag_commit: str,
                   now: int) -> dict:
    """Integrity gate only: never creates tags, releases or uploads."""
    _require(approval.release_authorized and now < approval.expires_at, "release not authorized")
    data, _, key_id = verify_envelope(raw, RELEASE_DOMAIN, signing_keys, "release-signer")
    _keys(data, {"schema_version", "approval_digest", "tag", "source_sha", "artifacts",
                 "sbom_sha256", "integrity_checks_passed"})
    _require(data["schema_version"] == 1 and type(data["schema_version"]) is int,
             "invalid release version")
    _require(key_id in approval.signing_key_ids and data["approval_digest"] == approval.digest,
             "release signing authority mismatch")
    _require(data["tag"] == approval.release_tag and data["source_sha"] == _sha(merge_sha)
             and allowlisted_commit == existing_tag_commit == merge_sha,
             "release tag/allowlist/source gate")
    _require(data["integrity_checks_passed"] is True, "release integrity checks failed")
    _sha(data["sbom_sha256"], 64)
    _require(type(data["artifacts"]) is dict and set(data["artifacts"]) == set(artifacts)
             == set(approval.artifact_names), "release artifact set mismatch")
    for name, content in artifacts.items():
        _require(type(content) is bytes and data["artifacts"][name] == _digest(content),
                 "release artifact digest mismatch")
    _require(data["sbom_sha256"] in data["artifacts"].values(), "SBOM not among verified artifacts")
    return data
