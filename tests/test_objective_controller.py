"""Objective/queue/broker tests use generated keys and simulated CI only.

No Codex process, GitHub request, credential provisioning or external target.
Signed platform claims below are fixtures, NOT evidence of real Windows runs.
"""

import base64
import contextlib
from dataclasses import replace
import hashlib
import json
import io
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.task_automation.controller import Check, FileEntry, Rejected, _canonical, inspect_candidate, load_policy
from tools.task_automation.github_gateway import GateBlocked, GatePending, GitHubGateway, REPO
from tools.task_automation.objectives import (
    APPROVAL_DOMAIN, PLATFORMS, RELEASE_DOMAIN, VALIDATION_DOMAIN, TrustKey,
    verify_approval, verify_envelope, verify_receipt, verify_release,
)
from tools.task_automation.queue import ObjectiveQueue
from tools.task_automation.service import (
    DEPLOYMENT_DOMAIN, Deployment, ObjectiveService, validate_plan, verify_deployment,
)
from tools.task_automation.__main__ import main as queue_cli


BASE = "09707e49116b6021fa7bb695c1979aeb240b4fca"


def sign(payload, key, domain, key_id="owner"):
    signature = key.sign(domain + _canonical(payload))
    return _canonical({"key_id": key_id, "payload": payload,
                       "signature": base64.b64encode(signature).decode("ascii")})


def trust(key, owner, role):
    return TrustKey(owner, role, key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))


class WorkerFixture:
    live = False

    def __init__(self, snapshots):
        self.snapshots = list(snapshots)
        self.calls = []

    def plan(self, approval, tokens, cost_microusd):
        return [{"number": 1, "goal": "Add regression", "acceptance_criteria": list(approval.task.acceptance_criteria)}]

    def implement(self, approval, batch, current, failure, tokens, cost_microusd):
        self.calls.append((batch.number, failure, tokens, cost_microusd))
        return self.snapshots.pop(0)


class ValidatorFixture:
    live = False

    def __init__(self, fixture):
        self.fixture = fixture
        self.calls = []
        self.failures = 0
        self.tamper = False
        self.accept = True

    def validate(self, approval, candidate, parent_sha, batch):
        self.calls.append(candidate.digest)
        payload = self.fixture.receipt_payload(candidate, approval=approval, parent=parent_sha, batch=batch)
        if self.failures:
            self.failures -= 1
            payload["checks"][0].update(status="failed", exit_code=1, passed=0, failed=1)
        if self.tamper:
            payload["candidate_digest"] = "f" * 64
        return sign(payload, self.fixture.validator_key, VALIDATION_DOMAIN, "validator")

    def acceptance(self, approval, candidate, parent_sha):
        return sign({"approval_digest": approval.digest, "candidate_digest": candidate.digest,
                     "head_sha": parent_sha, "criteria": list(approval.task.acceptance_criteria),
                     "passed": self.accept}, self.fixture.validator_key,
                    b"nightrecon-objective-acceptance-v1\x00", "validator")


class PublisherFixture:
    live = False

    def __init__(self):
        self.commits = []
        self.merges = []
        self.timeout = False
        self.merge_blocked = False

    def commit_push(self, approval, candidate, snapshot, receipt, parent_sha, batch, operation, deployment):
        if self.timeout:
            raise TimeoutError("publisher acknowledgement unknown")
        result = {"branch": approval.task.branch, "commit_sha": f"{batch:040x}",
                  "candidate_digest": candidate.digest, "pull_request": 201}
        self.commits.append((parent_sha, result))
        return result

    def reconcile(self, approval, record, snapshot):
        return bool(self.commits and self.commits[-1][1]["commit_sha"] == record["parent_sha"])

    def merge(self, approval, publication, deployment):
        self.merges.append(publication)
        if self.merge_blocked:
            raise GateBlocked("required_review: one independent approval missing")
        return {"merged": True, "merge_sha": "9" * 40}


class GitHubFixture:
    """Minimal GitHub API emulator; never performs HTTP."""

    def __init__(self, base=None):
        self.calls = []
        self.base = dict(base or {})
        self.current_tree = dict(self.base)
        self.blobs = {}
        self.head = None
        self.branch = None
        self.pull = None
        self.allow_merge = True
        self.check_failure = None
        self.check_names = tuple(sorted(PLATFORMS))

    def mutations(self):
        return [call for call in self.calls if call[0] != "GET"]

    def tree(self, entries):
        return {"truncated": False, "tree": [{"path": path, "mode": entry.mode, "type": "blob",
            "sha": hashlib.sha1(b"blob " + str(len(entry.content)).encode() + b"\x00" + entry.content).hexdigest()}
            for path, entry in entries.items()]}

    def request(self, method, path, body=None):
        self.calls.append((method, path, body))
        route = path.removeprefix(REPO)
        if method == "GET" and route.startswith("/git/ref/heads/"):
            return None if self.head is None else {"object": {"type": "commit", "sha": self.head}}
        if method == "GET" and route.startswith("/git/commits/"):
            return {"tree": {"sha": "a" * 40}}
        if method == "GET" and route.startswith("/git/trees/"):
            return self.tree(self.base if route.startswith("/git/trees/" + "a" * 40) else self.current_tree)
        if method == "POST" and route == "/git/blobs":
            content = base64.b64decode(body["content"])
            oid = hashlib.sha1(b"blob " + str(len(content)).encode() + b"\x00" + content).hexdigest()
            self.blobs[oid] = content
            return {"sha": oid}
        if method == "POST" and route == "/git/trees":
            self.current_tree = dict(self.base)
            for entry in body["tree"]:
                if entry["sha"] is None:
                    self.current_tree.pop(entry["path"])
                else:
                    self.current_tree[entry["path"]] = FileEntry(entry["mode"], self.blobs[entry["sha"]])
            return {"sha": "b" * 40}
        if method == "POST" and route == "/git/commits":
            return {"sha": "c" * 40}
        if route == "/git/refs" and method == "POST":
            self.head, self.branch = body["sha"], body["ref"].removeprefix("refs/heads/")
            return {"ref": body["ref"]}
        if route.startswith("/git/refs/heads/") and method == "PATCH":
            self.head = body["sha"]
            return {}
        if route.startswith("/pulls?"):
            return [] if self.pull is None else [self.pull]
        if route == "/pulls" and method == "POST":
            self.pull = {"number": 201, "head": {"ref": body["head"], "sha": self.head},
                         "base": {"ref": "master"}, "state": "open", "draft": False}
            return self.pull
        if route == "/pulls/201" and method == "GET":
            return self.pull
        if route == "/rules/branches/master":
            return [{"type": "pull_request"}, {"type": "required_status_checks", "parameters": {
                "required_status_checks": [{"context": name} for name in self.check_names]}}]
        if route.startswith("/commits/") and "/check-runs" in route:
            return {"total_count": 4, "check_runs": [{"name": name, "head_sha": self.head,
                "status": "completed", "conclusion": "failure" if name == self.check_failure else "success",
                "app": {"id": 42}} for name in self.check_names]}
        if route == "/pulls/201/merge":
            if not self.allow_merge:
                raise GateBlocked("GitHub required review gate")
            return {"merged": True, "sha": "9" * 40}
        raise AssertionError((method, path))


class ReleaseGitHubFixture(GitHubFixture):
    def request(self, method, path, body=None):
        route = path.removeprefix(REPO)
        self.calls.append((method, path, body))
        if route.startswith("/contents/.github/release-tag-allowlist.tsv"):
            text = "v0.99.0\t" + "9" * 40 + "\tReviewed fixture tag\n"
            return {"content": base64.b64encode(text.encode()).decode()}
        if route == "/git/ref/tags/v0.99.0":
            return {"object": {"type": "commit", "sha": "9" * 40}}
        if route == "/releases/tags/v0.99.0":
            return None
        if method == "POST" and route == "/releases":
            return {"id": 201, **body}
        if method == "PATCH" and route == "/releases/201":
            return {"id": 201, "tag_name": "v0.99.0", **body}
        raise AssertionError((method, path))

    def upload(self, release_id, name, content):
        self.calls.append(("UPLOAD", str(release_id), {"name": name}))
        return {"digest": "sha256:" + hashlib.sha256(content).hexdigest()}


class ObjectiveControllerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.raw_policy = (ROOT / ".github/codex/task-policy.json").read_bytes()
        self.policy = load_policy(self.raw_policy, expected_digest=hashlib.sha256(self.raw_policy).hexdigest())
        self.owner_key = Ed25519PrivateKey.generate()
        self.validator_key = Ed25519PrivateKey.generate()
        self.signer_key = Ed25519PrivateKey.generate()
        self.owners = {"owner": trust(self.owner_key, "kostekdolata", "owner")}
        self.validators = {"validator": trust(self.validator_key, "ci-validator", "validator")}
        self.signers = {"release": trust(self.signer_key, "release-service", "release-signer")}
        self.now = 1000
        self.payload = {
            "schema_version": 1, "objective_id": "issue-200-r1", "owner": "kostekdolata",
            "repository": "kostekdolata/NightRecon", "policy_digest": self.policy.digest,
            "approved_at": 900, "expires_at": 2000, "allow_safety_control_changes": False,
            "task": {"schema_version": 1, "issue_number": 200, "revision": 1, "base_sha": BASE,
                     "objective": "Fix a bounded offline regression", "acceptance_criteria": ["Regression tests pass"],
                     "permitted_paths": ["tests/example/"], "permitted_operations": ["add", "modify"]},
            "limits": {"max_batches": 3, "max_repairs_per_batch": 2, "max_attempts": 10,
                       "max_wall_seconds": 600, "max_tokens": 1000, "max_cost_microusd": 1000},
            "release": {"authorized": False, "tag": None, "artifact_names": [], "signing_key_ids": []},
        }
        self.envelope = sign(self.payload, self.owner_key, APPROVAL_DOMAIN)
        self.approval = verify_approval(self.envelope, self.policy, self.owners, now=self.now)
        self.queue_path = Path(self.temp.name) / "queue.sqlite"
        self.integrity_key = b"test-only-private-queue-key" * 2
        self.queue = ObjectiveQueue(self.queue_path, integrity_key=self.integrity_key)
        self.addCleanup(self.queue.close)
        self.queue.enqueue(self.envelope, self.policy, self.owners, now=self.now)
        self.snapshot = {"tests/example/regression.py": FileEntry("100644", b"regression")}

    def approval_for(self, fields):
        raw = sign(self.payload | fields, self.owner_key, APPROVAL_DOMAIN)
        return verify_approval(raw, self.policy, self.owners, now=self.now)

    def receipt_payload(self, candidate, *, approval=None, parent=BASE, batch=1):
        approval = approval or self.approval
        return {"schema_version": 1, "approval_digest": approval.digest, "policy_digest": self.policy.digest,
                "candidate_digest": candidate.digest, "parent_sha": parent, "batch": batch,
                "validator": "ci-validator", "worker": "coding-worker", "issued_at": 1000,
                "expires_at": 1900, "platforms": sorted(PLATFORMS),
                "checks": [Check(name, "passed", 0, candidate.digest, 1, 1, 0, 0, 0).__dict__
                           for name in self.policy.required_checks],
                "run_urls": ["https://github.com/kostekdolata/NightRecon/actions/runs/999"]}

    def service(self, worker=None, validator=None, publisher=None):
        return ObjectiveService(self.queue, self.policy, owner_keys=self.owners,
            validator_keys=self.validators, worker=worker or WorkerFixture([self.snapshot]),
            validator=validator or ValidatorFixture(self), publisher=publisher or PublisherFixture(),
            clock=lambda: self.now, attempt_tokens=100, attempt_cost_microusd=100)

    def test_owner_signature_and_policy_bound_snapshot(self):
        self.assertEqual(self.approval.owner, "kostekdolata")
        self.assertEqual(self.approval.task.branch, self.queue.read(self.approval.objective_id)["branch"])
        changed = self.payload | {"owner": "attacker"}
        with self.assertRaises(Rejected):
            verify_approval(sign(changed, self.owner_key, APPROVAL_DOMAIN), self.policy, self.owners, now=self.now)

    def test_unsigned_tampered_unknown_key_and_wrong_role_approvals_fail(self):
        envelope = json.loads(self.envelope)
        cases = [envelope | {"signature": "invalid"}, envelope | {"key_id": "attacker"},
                 envelope | {"payload": self.payload | {"expires_at": 3000}}]
        for case in cases:
            with self.subTest(case=case), self.assertRaises(Rejected):
                verify_approval(_canonical(case), self.policy, self.owners, now=self.now)
        with self.assertRaises(Rejected):
            verify_approval(self.envelope, self.policy,
                {"owner": trust(self.owner_key, "kostekdolata", "worker")}, now=self.now)

    def test_expired_future_scope_expanding_and_unbounded_approvals_fail(self):
        for fields in ({"expires_at": 999}, {"approved_at": 1001},
                       {"policy_digest": "f" * 64}, {"allow_safety_control_changes": True},
                       {"limits": self.payload["limits"] | {"max_repairs_per_batch": 3}},
                       {"task": self.payload["task"] | {"permitted_paths": [".github/"]}},
                       {"repository": "other/repository"}):
            with self.subTest(fields=fields), self.assertRaises(Rejected):
                self.approval_for(fields)

    def test_release_requires_explicit_signed_fields(self):
        with self.assertRaises(Rejected):
            self.approval_for({"release": self.payload["release"] | {"tag": "v1.0.0"}})
        with self.assertRaises(Rejected):
            self.approval_for({"release": {"authorized": True, "tag": "latest",
                "artifact_names": ["x"], "signing_key_ids": ["release"]}})

    def test_approval_replay_is_idempotent_but_edits_conflict(self):
        self.queue.enqueue(self.envelope, self.policy, self.owners, now=self.now)
        self.assertEqual(len(self.queue.events(self.approval.objective_id)), 1)
        changed = self.payload | {"task": self.payload["task"] | {"objective": "Different goal"}}
        with self.assertRaises(Rejected):
            self.queue.enqueue(sign(changed, self.owner_key, APPROVAL_DOMAIN), self.policy, self.owners, now=self.now)

    def test_approval_rows_cannot_be_mutated(self):
        with self.assertRaises(sqlite3.IntegrityError):
            self.queue.db.execute("UPDATE approvals SET digest=?", ("f" * 64,))

    def test_queue_reopen_retains_authenticated_state(self):
        reopened = ObjectiveQueue(self.queue_path, integrity_key=self.integrity_key)
        self.addCleanup(reopened.close)
        self.assertEqual(reopened.read(self.approval.objective_id)["state"], "pending")
        wrong = ObjectiveQueue(self.queue_path, integrity_key=b"x" * 32)
        self.addCleanup(wrong.close)
        with self.assertRaises(Rejected):
            wrong.read(self.approval.objective_id)

    def test_queue_state_tampering_is_detected(self):
        self.queue.db.execute("UPDATE objectives SET record=?", (_canonical({"state": "completed"}),))
        with self.assertRaises(Rejected):
            self.queue.read(self.approval.objective_id)

    def test_lease_conflict_fencing_and_version_conflict(self):
        first = self.queue.claim(self.approval.objective_id, worker="one", now=1000, lease_seconds=10)
        with self.assertRaises(Rejected):
            self.queue.claim(self.approval.objective_id, worker="two", now=1001)
        second = self.queue.claim(self.approval.objective_id, worker="two", now=1011)
        with self.assertRaises(Rejected):
            self.queue.update(self.approval.objective_id, worker="one", generation=first["lease_generation"],
                version=first["version"], now=1012, event="stale", changes={"state": "running"})
        with self.assertRaises(Rejected):
            self.queue.update(self.approval.objective_id, worker="two", generation=second["lease_generation"],
                version=0, now=1012, event="stale-version", changes={"state": "running"})

    def test_resource_reservation_blocks_before_exceeding_limit(self):
        record = self.queue.claim(self.approval.objective_id, worker="one", now=1000)
        record = self.queue.update(self.approval.objective_id, worker="one", generation=1,
            version=record["version"], now=1000, event="running", changes={"state": "running"})
        record = self.queue.reserve_attempt(self.approval, worker="one", generation=1,
            version=record["version"], now=1000, tokens=1000, cost_microusd=1000)
        with self.assertRaises(Rejected):
            self.queue.reserve_attempt(self.approval, worker="one", generation=1,
                version=record["version"], now=1000, tokens=1, cost_microusd=1)
        self.assertEqual(self.queue.read(self.approval.objective_id)["attempts"], 1)

    def test_deadline_persists_blocked_state(self):
        record = self.queue.expire(self.approval.objective_id, now=1600)
        self.assertEqual(record["state"], "blocked")
        self.assertIn("deadline", record["reason"])

    def test_artifact_content_addressing_and_tamper_detection(self):
        digest = self.queue.store_artifact(b"candidate")
        self.assertEqual(self.queue.store_artifact(b"candidate"), digest)
        self.assertEqual(self.queue.artifact(digest), b"candidate")
        self.queue.db.execute("UPDATE artifacts SET payload=?", (b"tampered",))
        with self.assertRaises(Rejected):
            self.queue.artifact(digest)

    def test_plan_covers_acceptance_without_scope_expansion(self):
        plan = [{"number": 1, "goal": "Fix regression", "acceptance_criteria": ["Regression tests pass"]}]
        self.assertEqual(validate_plan(plan, self.approval)[0].number, 1)
        for bad in ([], [plan[0] | {"number": 2}], [plan[0] | {"acceptance_criteria": ["Unrelated feature"]}],
                    [plan[0] | {"command": "untrusted shell"}]):
            with self.subTest(bad=bad), self.assertRaises(Rejected):
                validate_plan(bad, self.approval)

    def test_signed_receipt_requires_all_platforms_and_checks(self):
        candidate = inspect_candidate(self.approval.task, self.policy, {}, self.snapshot)
        payload = self.receipt_payload(candidate)
        for changes in ({"platforms": ["ubuntu-py311"]}, {"checks": []}, {"parent_sha": "f" * 40},
                        {"candidate_digest": "f" * 64}, {"validator": "coding-worker"},
                        {"worker": "ci-validator"}, {"expires_at": 999}, {"batch": 2}):
            with self.subTest(changes=changes), self.assertRaises(Rejected):
                verify_receipt(sign(payload | changes, self.validator_key, VALIDATION_DOMAIN, "validator"),
                    self.approval, candidate, self.policy, self.validators, parent_sha=BASE, batch=1, now=self.now)

    def test_worker_key_cannot_sign_independent_receipt(self):
        candidate = inspect_candidate(self.approval.task, self.policy, {}, self.snapshot)
        raw = sign(self.receipt_payload(candidate), self.owner_key, VALIDATION_DOMAIN, "validator")
        with self.assertRaises(Rejected):
            verify_receipt(raw, self.approval, candidate, self.policy, self.validators,
                           parent_sha=BASE, batch=1, now=self.now)

    def test_simulated_harmless_objective_commits_and_merges_once(self):
        publisher = PublisherFixture()
        report = self.service(publisher=publisher).run(self.approval.objective_id, worker_id="worker", base={})
        self.assertEqual(report["state"], "completed")
        self.assertEqual(len(publisher.commits), 1)
        self.assertEqual(len(publisher.merges), 1)
        self.assertFalse(report["operational"])
        self.assertEqual(len(report["tests"]), len(self.policy.required_checks))
        self.assertTrue(report["ci_results"])
        self.assertIsNotNone(self.queue.artifact(report["commits"][0]["artifact"]))
        with self.assertRaises(Rejected):
            self.service().run(self.approval.objective_id, worker_id="other", base={})

    def test_dependent_batches_share_one_branch_and_verified_parent_chain(self):
        later = self.snapshot | {"tests/example/second.py": FileEntry("100644", b"second")}
        publisher = PublisherFixture()
        worker = WorkerFixture([self.snapshot, later])
        plan = [{"number": n, "goal": f"Increment {n}", "acceptance_criteria": ["Regression tests pass"]}
                for n in (1, 2)]
        report = self.service(worker=worker, publisher=publisher).run(
            self.approval.objective_id, worker_id="worker", base={}, plan=plan)
        self.assertEqual(report["state"], "completed")
        self.assertEqual(publisher.commits[1][0], publisher.commits[0][1]["commit_sha"])
        self.assertEqual({commit[1]["branch"] for commit in publisher.commits}, {self.approval.task.branch})

    def test_failed_validation_repairs_then_fully_revalidates_before_one_commit(self):
        fixed = {"tests/example/regression.py": FileEntry("100644", b"fixed")}
        validator, publisher = ValidatorFixture(self), PublisherFixture()
        validator.failures = 1
        worker = WorkerFixture([self.snapshot, fixed])
        report = self.service(worker, validator, publisher).run(self.approval.objective_id, worker_id="worker", base={})
        self.assertEqual(report["state"], "completed")
        self.assertEqual(len(validator.calls), 2)
        self.assertEqual(len(publisher.commits), 1)
        self.assertIsNotNone(worker.calls[1][1])

    def test_failed_validation_never_commits_or_publishes(self):
        validator, publisher = ValidatorFixture(self), PublisherFixture()
        validator.failures = 10
        worker = WorkerFixture([self.snapshot] * 3)
        report = self.service(worker, validator, publisher).run(self.approval.objective_id, worker_id="worker", base={})
        self.assertEqual(report["state"], "blocked")
        self.assertIn("repair limit", report["reason"])
        self.assertEqual(publisher.commits, [])
        self.assertEqual(publisher.merges, [])

    def test_out_of_scope_candidate_never_reaches_validator_or_publisher(self):
        bad = {"nightrecon/unrelated.py": FileEntry("100644", b"unrelated")}
        validator, publisher = ValidatorFixture(self), PublisherFixture()
        report = self.service(WorkerFixture([bad] * 3), validator, publisher).run(
            self.approval.objective_id, worker_id="worker", base={})
        self.assertEqual(report["state"], "blocked")
        self.assertEqual(validator.calls, [])
        self.assertEqual(publisher.commits, [])

    def test_repair_cannot_touch_other_approved_but_unrelated_file(self):
        validator, publisher = ValidatorFixture(self), PublisherFixture()
        validator.failures = 1
        unrelated = self.snapshot | {"tests/example/unrelated.py": FileEntry("100644", b"new")}
        report = self.service(WorkerFixture([self.snapshot, unrelated]), validator, publisher).run(
            self.approval.objective_id, worker_id="worker", base={})
        self.assertEqual(report["state"], "blocked")
        self.assertIn("unrelated", report["reason"])
        self.assertEqual(publisher.commits, [])

    def test_tampered_validation_artifact_never_commits(self):
        validator, publisher = ValidatorFixture(self), PublisherFixture()
        validator.tamper = True
        report = self.service(WorkerFixture([self.snapshot] * 3), validator, publisher).run(
            self.approval.objective_id, worker_id="worker", base={})
        self.assertEqual(report["state"], "blocked")
        self.assertEqual(publisher.commits, [])

    def test_uncertain_publication_is_durable_and_never_retried(self):
        publisher = PublisherFixture()
        publisher.timeout = True
        report = self.service(publisher=publisher).run(self.approval.objective_id, worker_id="worker", base={})
        self.assertEqual(report["state"], "blocked")
        self.assertEqual(report["intent"]["kind"], "commit_push")
        with self.assertRaises(Rejected):
            self.queue.claim(self.approval.objective_id, worker="other", now=1400)

    def test_required_review_gate_blocks_merge_without_bypass(self):
        publisher = PublisherFixture()
        publisher.merge_blocked = True
        report = self.service(publisher=publisher).run(self.approval.objective_id, worker_id="worker", base={})
        self.assertEqual(report["state"], "blocked")
        self.assertIn("required_review", report["reason"])
        self.assertEqual(len(publisher.commits), 1)

    def test_objective_acceptance_failure_prevents_merge(self):
        validator, publisher = ValidatorFixture(self), PublisherFixture()
        validator.accept = False
        report = self.service(validator=validator, publisher=publisher).run(
            self.approval.objective_id, worker_id="worker", base={})
        self.assertEqual(report["state"], "blocked")
        self.assertEqual(publisher.merges, [])

    def test_live_execution_disabled_without_separate_deployment_acceptance(self):
        worker, publisher = WorkerFixture([self.snapshot]), PublisherFixture()
        worker.live = True
        report = self.service(worker=worker, publisher=publisher).run(
            self.approval.objective_id, worker_id="worker", base={})
        self.assertEqual(report["state"], "blocked")
        self.assertEqual(worker.calls, [])
        self.assertEqual(publisher.commits, [])

    def test_deployment_requires_authenticated_harmless_e2e_and_security_signoff(self):
        keys = {"owner": trust(self.owner_key, "kostekdolata", "deployment-owner")}
        data = {"expires_at": 2000, "capabilities": ["execute", "push", "merge"],
                "security_acceptance": True,
                "harmless_e2e_run_url": "https://github.com/kostekdolata/NightRecon/actions/runs/999",
                "harmless_e2e_artifact_sha256": "a" * 64}
        self.assertIn("push", verify_deployment(sign(data, self.owner_key, DEPLOYMENT_DOMAIN), keys, now=1000).capabilities)
        for changes in ({"security_acceptance": False}, {"harmless_e2e_run_url": "https://attacker.test/"},
                        {"expires_at": 999}, {"capabilities": ["bypass"]}):
            with self.subTest(changes=changes), self.assertRaises(Rejected):
                verify_deployment(sign(data | changes, self.owner_key, DEPLOYMENT_DOMAIN), keys, now=1000)

    def gateway(self, api):
        return GitHubGateway(api, self.policy, base_snapshot={}, validator_keys=self.validators,
                             required_ci_names=tuple(sorted(PLATFORMS)), actions_app_id=42, clock=lambda: 1000,
                             deployment_keys={"owner": trust(self.owner_key, "kostekdolata", "deployment-owner")})

    def deployment(self, capabilities=("push", "merge")):
        data = {"expires_at": 2000, "capabilities": list(capabilities), "security_acceptance": True,
            "harmless_e2e_run_url": "https://github.com/kostekdolata/NightRecon/actions/runs/999",
            "harmless_e2e_artifact_sha256": "a" * 64}
        raw = sign(data, self.owner_key, DEPLOYMENT_DOMAIN)
        return verify_deployment(raw, {"owner": trust(self.owner_key, "kostekdolata", "deployment-owner")}, now=1000)

    def gateway_inputs(self):
        candidate = inspect_candidate(self.approval.task, self.policy, {}, self.snapshot)
        raw = sign(self.receipt_payload(candidate), self.validator_key, VALIDATION_DOMAIN, "validator")
        receipt = verify_receipt(raw, self.approval, candidate, self.policy, self.validators,
                                 parent_sha=BASE, batch=1, now=1000)
        return candidate, receipt

    def test_gateway_reverifies_artifact_before_any_mutation(self):
        api = GitHubFixture()
        gateway = self.gateway(api)
        candidate, receipt = self.gateway_inputs()
        with self.assertRaises(Rejected):
            gateway.commit_push(self.approval, candidate, {}, receipt, BASE, 1, "f" * 64,
                                 self.deployment(("push",)))
        self.assertEqual(api.mutations(), [])

    def test_gateway_push_and_merge_use_verified_tree_and_normal_protected_api(self):
        api = GitHubFixture()
        gateway = self.gateway(api)
        candidate, receipt = self.gateway_inputs()
        deployment = self.deployment()
        publication = gateway.commit_push(self.approval, candidate, self.snapshot, receipt,
                                          BASE, 1, "f" * 64, deployment)
        merged = gateway.merge(self.approval, publication, deployment)
        self.assertTrue(merged["merged"])
        for method, path, body in api.mutations():
            self.assertNotIn("/pulls/160", path)
            self.assertNotIn("/git/refs/heads/master", path)
            self.assertFalse((body or {}).get("force", False))
            self.assertNotIn("protection", path)

    def test_gateway_failed_ci_context_never_calls_merge(self):
        api = GitHubFixture()
        gateway = self.gateway(api)
        candidate, receipt = self.gateway_inputs()
        deployment = self.deployment()
        publication = gateway.commit_push(self.approval, candidate, self.snapshot, receipt,
                                          BASE, 1, "f" * 64, deployment)
        api.check_failure = api.check_names[0]
        with self.assertRaises(GateBlocked):
            gateway.merge(self.approval, publication, deployment)
        self.assertFalse(any(path.endswith("/merge") for _, path, _ in api.calls))

    def test_gateway_missing_live_gate_never_mutates(self):
        api = GitHubFixture()
        candidate, receipt = self.gateway_inputs()
        with self.assertRaises(Rejected):
            self.gateway(api).commit_push(self.approval, candidate, self.snapshot, receipt,
                                          BASE, 1, "f" * 64, Deployment())
        self.assertEqual(api.mutations(), [])

    def test_release_signing_hash_sbom_and_allowlist_gates(self):
        approval = self.approval_for({"release": {"authorized": True, "tag": "v0.99.0",
            "artifact_names": ["app.zip", "SBOM.json"], "signing_key_ids": ["release"]}})
        artifacts = {"app.zip": b"application", "SBOM.json": b"sbom"}
        hashes = {name: hashlib.sha256(value).hexdigest() for name, value in artifacts.items()}
        payload = {"schema_version": 1, "approval_digest": approval.digest, "tag": "v0.99.0",
                   "source_sha": "9" * 40, "artifacts": hashes, "sbom_sha256": hashes["SBOM.json"],
                   "integrity_checks_passed": True}
        raw = sign(payload, self.signer_key, RELEASE_DOMAIN, "release")
        result = verify_release(raw, approval, self.signers, artifacts, merge_sha="9" * 40,
            allowlisted_commit="9" * 40, existing_tag_commit="9" * 40, now=1000)
        self.assertEqual(result["tag"], "v0.99.0")
        for modified, allowlisted in ((artifacts | {"app.zip": b"tampered"}, "9" * 40),
                                      (artifacts, "f" * 40)):
            with self.subTest(allowlisted=allowlisted), self.assertRaises(Rejected):
                verify_release(raw, approval, self.signers, modified, merge_sha="9" * 40,
                    allowlisted_commit=allowlisted, existing_tag_commit="9" * 40, now=1000)
        with self.assertRaises(Rejected):
            verify_release(raw, self.approval, self.signers, artifacts, merge_sha="9" * 40,
                allowlisted_commit="9" * 40, existing_tag_commit="9" * 40, now=1000)

    def test_offline_cli_enqueues_signed_snapshot_and_reports_without_execution(self):
        directory = Path(self.temp.name)
        approval_path, trust_path, key_path = (directory / name for name in ("approval.json", "trust.json", "queue.key"))
        approval_path.write_bytes(self.envelope)
        trust_path.write_bytes(_canonical({"owner": {"owner": "kostekdolata", "role": "owner",
            "public_key_base64": base64.b64encode(self.owners["owner"].public_key).decode()}}))
        key_path.write_bytes(self.integrity_key)
        arguments = ["--policy", str(ROOT / ".github/codex/task-policy.json"),
            "--policy-sha256", self.policy.digest, "--database", str(directory / "cli.sqlite"),
            "--integrity-key-file", str(key_path)]
        output = io.StringIO()
        with contextlib.redirect_stdout(output), patch("tools.task_automation.__main__.time.time", return_value=1000):
            result = queue_cli(arguments + ["enqueue", "--approval", str(approval_path), "--owner-trust", str(trust_path)])
        self.assertEqual(result, 0)
        self.assertEqual(json.loads(output.getvalue())["result"]["state"], "pending")
        self.assertNotIn(self.integrity_key.decode(), output.getvalue())
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = queue_cli(arguments + ["report", self.approval.objective_id])
        self.assertEqual(result, 0)
        self.assertFalse(json.loads(output.getvalue())["operational"])

    def test_cli_invalid_policy_reports_blocked_without_creating_queue(self):
        output = io.StringIO()
        database = Path(self.temp.name) / "not-created.sqlite"
        with contextlib.redirect_stdout(output):
            result = queue_cli(["--policy", str(ROOT / ".github/codex/task-policy.json"),
                "--policy-sha256", "f" * 64, "--database", str(database),
                "--integrity-key-file", "unread.key", "report", self.approval.objective_id])
        self.assertEqual(result, 1)
        self.assertEqual(json.loads(output.getvalue())["state"], "blocked")
        self.assertFalse(database.exists())

    def test_existing_first_objective_branch_is_not_adopted(self):
        api = GitHubFixture()
        api.head = BASE
        candidate, receipt = self.gateway_inputs()
        with self.assertRaises(Rejected):
            self.gateway(api).commit_push(self.approval, candidate, self.snapshot, receipt,
                BASE, 1, "f" * 64, self.deployment())
        self.assertEqual(api.mutations(), [])

    def test_remote_tree_mismatch_never_creates_commit(self):
        api = GitHubFixture()
        original = api.tree
        api.tree = lambda entries: {"truncated": True, "tree": original(entries)["tree"]}
        candidate, receipt = self.gateway_inputs()
        with self.assertRaises(Rejected):
            self.gateway(api).commit_push(self.approval, candidate, self.snapshot, receipt,
                BASE, 1, "f" * 64, self.deployment())
        self.assertFalse(any(path.endswith("/git/commits") for _, path, _ in api.mutations()))

    def test_pending_ci_is_polled_without_duplicate_commit(self):
        class WaitingPublisher(PublisherFixture):
            pending = 1

            def merge(self, *args):
                if self.pending:
                    self.pending -= 1
                    raise GatePending("CI pending")
                return super().merge(*args)

        publisher = WaitingPublisher()
        service = self.service(publisher=publisher)
        service.sleeper = lambda seconds: setattr(self, "now", self.now + seconds)
        report = service.run(self.approval.objective_id, worker_id="worker", base={})
        self.assertEqual(report["state"], "completed")
        self.assertEqual(len(publisher.commits), 1)
        self.assertIn("waiting_for_required_ci", [e["event"] for e in self.queue.events(self.approval.objective_id)])

    def test_unknown_adapter_exception_is_blocked_without_echoing_output(self):
        worker = WorkerFixture([])
        worker.implement = lambda *args: (_ for _ in ()).throw(RuntimeError("sensitive-untrusted-output"))
        publisher = PublisherFixture()
        report = self.service(worker=worker, publisher=publisher).run(
            self.approval.objective_id, worker_id="worker", base={})
        self.assertEqual(report["state"], "blocked")
        self.assertNotIn("sensitive-untrusted-output", report["reason"])
        self.assertEqual(publisher.commits, [])

    def test_release_objective_without_signer_is_blocked_before_coding(self):
        payload = self.payload | {"objective_id": "issue-201-r1", "task": self.payload["task"] | {"issue_number": 201},
            "release": {"authorized": True, "tag": "v0.99.0", "artifact_names": ["app.zip"], "signing_key_ids": ["release"]}}
        envelope = sign(payload, self.owner_key, APPROVAL_DOMAIN)
        approval = verify_approval(envelope, self.policy, self.owners, now=1000)
        self.queue.enqueue(envelope, self.policy, self.owners, now=1000)
        worker, publisher = WorkerFixture([]), PublisherFixture()
        report = self.service(worker=worker, publisher=publisher).run(approval.objective_id, worker_id="worker", base={})
        self.assertEqual(report["state"], "blocked")
        self.assertEqual(worker.calls, [])
        self.assertEqual(publisher.commits, [])

    def test_resource_counters_cannot_be_reset(self):
        record = self.queue.claim(self.approval.objective_id, worker="worker", now=1000)
        record = self.queue.update(self.approval.objective_id, worker="worker", generation=1,
            version=record["version"], now=1000, event="started", changes={"state": "running", "attempts": 1})
        with self.assertRaises(Rejected):
            self.queue.update(self.approval.objective_id, worker="worker", generation=1,
                version=record["version"], now=1000, event="reset", changes={"attempts": 0})

    def test_expired_uncertain_implementation_requires_reconciliation(self):
        record = self.queue.claim(self.approval.objective_id, worker="worker", now=1000, lease_seconds=10)
        record = self.queue.update(self.approval.objective_id, worker="worker", generation=1,
            version=record["version"], now=1000, event="implementation_intent",
            changes={"state": "running", "intent": {"kind": "implementation"}})
        expired = self.queue.expire(self.approval.objective_id, now=1011)
        self.assertEqual(expired["state"], "blocked")
        self.assertIsNotNone(expired["intent"])

    def test_gateway_tampered_signed_receipt_never_mutates(self):
        api = GitHubFixture()
        candidate, receipt = self.gateway_inputs()
        forged = replace(receipt, envelope=receipt.envelope.replace(b'"signature":"', b'"signature":"bad'))
        with self.assertRaises(Rejected):
            self.gateway(api).commit_push(self.approval, candidate, self.snapshot, forged,
                BASE, 1, "f" * 64, self.deployment())
        self.assertEqual(api.mutations(), [])

    def release_fixture(self):
        approval = self.approval_for({"release": {"authorized": True, "tag": "v0.99.0",
            "artifact_names": ["app.zip", "SBOM.json"], "signing_key_ids": ["release"]}})
        artifacts = {"app.zip": b"app", "SBOM.json": b"sbom"}
        hashes = {name: hashlib.sha256(content).hexdigest() for name, content in artifacts.items()}
        data = {"schema_version": 1, "approval_digest": approval.digest, "tag": "v0.99.0",
            "source_sha": "9" * 40, "artifacts": hashes, "sbom_sha256": hashes["SBOM.json"],
            "integrity_checks_passed": True}
        return approval, artifacts, sign(data, self.signer_key, RELEASE_DOMAIN, "release")

    def test_gateway_release_requires_explicit_objective_permission(self):
        api = ReleaseGitHubFixture()
        approval, artifacts, manifest = self.release_fixture()
        with self.assertRaises(Rejected):
            self.gateway(api).release(self.approval, manifest=manifest, signing_keys=self.signers,
                artifacts=artifacts, merge_sha="9" * 40, deployment=self.deployment(("release",)))
        self.assertEqual(api.mutations(), [])

    def test_gateway_tampered_release_artifact_never_creates_release(self):
        api = ReleaseGitHubFixture()
        approval, artifacts, manifest = self.release_fixture()
        with self.assertRaises(Rejected):
            self.gateway(api).release(approval, manifest=manifest, signing_keys=self.signers,
                artifacts=artifacts | {"app.zip": b"tampered"}, merge_sha="9" * 40,
                deployment=self.deployment(("release",)))
        self.assertEqual(api.mutations(), [])

    def test_gateway_verified_release_is_drafted_uploaded_and_published_in_order(self):
        api = ReleaseGitHubFixture()
        approval, artifacts, manifest = self.release_fixture()
        result = self.gateway(api).release(approval, manifest=manifest, signing_keys=self.signers,
            artifacts=artifacts, merge_sha="9" * 40, deployment=self.deployment(("release",)))
        self.assertFalse(result["draft"])
        self.assertEqual([method for method, _, _ in api.mutations()], ["POST", "UPLOAD", "UPLOAD", "PATCH"])

    def test_crash_after_verified_batch_resumes_without_repeating_commit(self):
        plan = [{"number": n, "goal": f"Increment {n}", "acceptance_criteria": ["Regression tests pass"]}
                for n in (1, 2)]
        publisher = PublisherFixture()
        original = self.queue.update

        def crash_after_publication(*args, **kwargs):
            result = original(*args, **kwargs)
            if kwargs["event"] == "batch_published":
                raise SystemExit("simulated controller host crash")
            return result

        self.queue.update = crash_after_publication
        with self.assertRaises(SystemExit):
            self.service(WorkerFixture([self.snapshot]), publisher=publisher).run(
                self.approval.objective_id, worker_id="first", base={}, plan=plan)
        self.queue.update = original
        self.now = 1301
        later = self.snapshot | {"tests/example/second.py": FileEntry("100644", b"second")}
        worker = WorkerFixture([later])
        report = self.service(worker=worker, publisher=publisher).run(
            self.approval.objective_id, worker_id="recovery", base={})
        self.assertEqual(report["state"], "completed")
        self.assertEqual(len(publisher.commits), 2)
        self.assertEqual([call[0] for call in worker.calls], [2])


if __name__ == "__main__":
    unittest.main()
