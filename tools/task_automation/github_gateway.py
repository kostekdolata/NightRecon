"""Credential-broker integration: verified GitHub Git/PR API operations only.

The transport runs in a separate publisher service and owns the short-lived App
token. No transport/credential is passed to a coding or validation runner. There
is deliberately no default network transport or automatic credential discovery.
"""

from __future__ import annotations

import base64
from typing import Protocol

from .controller import Rejected, _require, _sha, inspect_candidate
from .objectives import verify_receipt, verify_release


REPO = "/repos/kostekdolata/NightRecon"


class GateBlocked(Rejected):
    pass


class GatePending(GateBlocked):
    """An ordinary CI wait, not permission to bypass a failed/review gate."""


class GitHubTransport(Protocol):
    def request(self, method: str, path: str, body: dict | None = None) -> object:
        """Authenticated HTTPS in the broker; raise GateBlocked with sanitized gate details."""

    def upload(self, release_id: int, name: str, content: bytes) -> dict:
        """Upload only to uploads.github.com for this repository/release ID."""


class GitHubGateway:
    live = True

    def __init__(self, transport: GitHubTransport, policy, *, base_snapshot,
                 validator_keys, required_ci_names: tuple[str, ...],
                 actions_app_id: int, clock, deployment_keys):
        self.transport, self.policy = transport, policy
        self.base = dict(base_snapshot)
        self.validator_keys, self.required_ci = validator_keys, required_ci_names
        self.actions_app_id, self.clock = actions_app_id, clock
        self.deployment_keys = deployment_keys
        _require(len(required_ci_names) >= 4 and len(set(required_ci_names)) == len(required_ci_names),
                 "complete cross-platform CI name registry required")
        _require(type(actions_app_id) is int and actions_app_id > 0, "trusted CI App ID required")

    def _capability(self, deployment, capability):
        from .service import verify_deployment
        _require(deployment.envelope is not None, "signed deployment acceptance required")
        verified = verify_deployment(deployment.envelope, self.deployment_keys, now=self.clock())
        _require(verified == deployment and capability in verified.capabilities,
                 f"deployment gate missing: {capability}")

    def _verify_tree(self, tree_sha, snapshot):
        import hashlib
        remote = self.transport.request("GET", REPO + "/git/trees/" + tree_sha + "?recursive=1")
        _require(remote.get("truncated") is False, "truncated tree cannot establish source integrity")
        actual = {entry["path"]: (entry["mode"], entry["sha"])
                  for entry in remote["tree"] if entry["type"] != "tree"}
        expected = {}
        for path, entry in snapshot.items():
            oid = (entry.content.decode("ascii") if entry.mode == "160000" else
                   hashlib.sha1(b"blob " + str(len(entry.content)).encode("ascii")
                                + b"\x00" + entry.content).hexdigest())
            expected[path] = (entry.mode, oid)
        _require(actual == expected, "Git tree differs from independently validated inventory")

    def reconcile(self, approval, record, snapshot):
        """Read-only acknowledgement of an already verified completed batch."""
        reference = self.transport.request("GET", REPO + "/git/ref/heads/" + approval.task.branch)
        _require(reference is not None and reference["object"]["sha"] == record["parent_sha"],
                 "objective branch changed while controller was offline")
        commit = self.transport.request("GET", REPO + "/git/commits/" + record["parent_sha"])
        self._verify_tree(commit["tree"]["sha"], snapshot)
        return True

    def commit_push(self, approval, candidate, snapshot, receipt, parent_sha,
                    batch, idempotency_key, deployment):
        self._capability(deployment, "push")
        _require(self.clock() < approval.expires_at, "objective approval expired")
        _sha(idempotency_key, 64)
        recomputed = inspect_candidate(approval.task, self.policy, self.base, snapshot)
        _require(recomputed.scope_valid and recomputed.digest == candidate.digest,
                 "publisher candidate/artifact mismatch")
        # Reverify independently at the credential boundary before any mutation.
        verify_receipt(receipt.envelope, approval, recomputed, self.policy, self.validator_keys,
                       parent_sha=parent_sha, batch=batch, now=self.clock())
        branch = approval.task.branch
        reference = REPO + "/git/ref/heads/" + branch
        current = self.transport.request("GET", reference)
        if current is None:
            _require(batch == 1 and parent_sha == approval.task.base_sha, "missing objective branch")
        else:
            _require(batch > 1, "objective branch already exists at first publication")
            _require(current["object"]["sha"] == parent_sha, "objective branch head conflict")
        base_commit = self.transport.request("GET", REPO + "/git/commits/" + approval.task.base_sha)
        self._verify_tree(base_commit["tree"]["sha"], self.base)
        tree = []
        for change in recomputed.changes:
            if change.operation == "delete":
                tree.append({"path": change.path, "mode": "100644", "type": "blob", "sha": None})
            else:
                blob = self.transport.request("POST", REPO + "/git/blobs", {
                    "encoding": "base64", "content": base64.b64encode(snapshot[change.path].content).decode("ascii")})
                _sha(blob["sha"])
                tree.append({"path": change.path, "mode": "100644", "type": "blob", "sha": blob["sha"]})
        created_tree = self.transport.request("POST", REPO + "/git/trees", {
            "base_tree": base_commit["tree"]["sha"], "tree": tree})
        _sha(created_tree["sha"])
        self._verify_tree(created_tree["sha"], snapshot)
        commit = self.transport.request("POST", REPO + "/git/commits", {
            "message": f"{approval.objective_id}: verified batch {batch}\n\nOperation: {idempotency_key}",
            "tree": created_tree["sha"], "parents": [_sha(parent_sha)]})
        sha = _sha(commit["sha"])
        # Re-read before mutation, then use GitHub's non-fast-forward protection.
        observed = self.transport.request("GET", reference)
        _require(observed == current, "branch changed during publication")
        if current is None:
            self.transport.request("POST", REPO + "/git/refs", {"ref": "refs/heads/" + branch, "sha": sha})
        else:
            self.transport.request("PATCH", REPO + "/git/refs/heads/" + branch, {"sha": sha, "force": False})
        verified = self.transport.request("GET", reference)
        _require(verified["object"]["sha"] == sha, "push acknowledgement uncertain")
        pulls = self.transport.request("GET", REPO + "/pulls?state=open&base=master&head=kostekdolata:" + branch)
        if pulls:
            _require(len(pulls) == 1 and pulls[0]["head"]["ref"] == branch,
                     "objective pull request conflict")
            pull = pulls[0]
        else:
            pull = self.transport.request("POST", REPO + "/pulls", {
                "title": approval.task.objective[:200], "head": branch, "base": "master", "draft": False,
                "body": f"Approved objective {approval.objective_id}. Approval digest: {approval.digest}.\n"
                        "Validated batch commits only. Required reviews and branch rules still apply."})
        _require(type(pull["number"]) is int and pull["number"] != 160, "reserved PR may not be modified")
        return {"branch": branch, "commit_sha": sha, "candidate_digest": candidate.digest,
                "pull_request": pull["number"]}

    def merge(self, approval, publication, deployment):
        self._capability(deployment, "merge")
        _require(self.clock() < approval.expires_at, "objective approval expired")
        number = publication["pull_request"]
        _require(type(number) is int and number > 0 and number != 160, "invalid objective PR")
        pr = self.transport.request("GET", REPO + f"/pulls/{number}")
        _require(pr["head"]["ref"] == approval.task.branch and pr["base"]["ref"] == "master"
                 and pr["head"]["sha"] == publication["commit_sha"] and not pr["draft"]
                 and pr["state"] == "open", "objective PR/head gate")
        rules = self.transport.request("GET", REPO + "/rules/branches/master")
        _require(type(rules) is list and any(rule["type"] == "required_status_checks" for rule in rules)
                 and any(rule["type"] == "pull_request" for rule in rules),
                 "effective protected-branch rules could not be verified")
        required = set(self.required_ci)
        for rule in rules:
            if rule["type"] == "required_status_checks":
                required.update(item["context"] for item in rule["parameters"]["required_status_checks"])
        checks = []
        for page in range(1, 21):
            result = self.transport.request("GET", REPO + "/commits/" + publication["commit_sha"]
                                            + f"/check-runs?per_page=100&page={page}&filter=latest")
            checks.extend(result["check_runs"])
            if len(checks) >= result["total_count"]:
                break
        else:
            raise GateBlocked("CI check pagination limit")
        by_name = {}
        for check in checks:
            if check["name"] in required:
                _require(check["name"] not in by_name, "ambiguous duplicate CI context")
                by_name[check["name"]] = check
        for name in sorted(required):
            check = by_name.get(name)
            if not check or check["status"] in {"queued", "in_progress", "waiting", "pending"}:
                raise GatePending("required CI context pending: " + name)
            if check["head_sha"] != publication["commit_sha"] or check["status"] != "completed" \
                    or check["conclusion"] != "success" or check["app"]["id"] != self.actions_app_id:
                raise GateBlocked("required CI context not successful/verified: " + name)
        # GitHub evaluates review rules, merge queues, signatures and branch
        # freshness again on this normal merge request. No bypass/admin flag,
        # approval API, forced ref update, or branch-rule modification is used.
        self._capability(deployment, "merge")
        _require(self.clock() < approval.expires_at, "objective approval expired before merge")
        result = self.transport.request("PUT", REPO + f"/pulls/{number}/merge", {
            "sha": publication["commit_sha"], "merge_method": "merge"})
        if result.get("merged") is not True:
            raise GateBlocked("GitHub protected merge refused: " + str(result.get("message", "unknown gate"))[:200])
        return {"merged": True, "merge_sha": _sha(result["sha"])}

    def release(self, approval, *, manifest, signing_keys, artifacts, merge_sha, deployment):
        self._capability(deployment, "release")
        tag = approval.release_tag
        _require(approval.release_authorized, "objective does not authorize a release")
        allowlist = self.transport.request("GET", REPO + "/contents/.github/release-tag-allowlist.tsv?ref=master")
        raw = base64.b64decode(allowlist["content"], validate=False).decode("utf-8")
        rows = [line.split("\t", 2) for line in raw.splitlines() if line and not line.startswith("#")]
        approved = [row[1] for row in rows if len(row) == 3 and row[0] == tag]
        _require(approved == [merge_sha], "release tag is not uniquely allowlisted for the merge commit")
        ref = self.transport.request("GET", REPO + "/git/ref/tags/" + tag)
        _require(ref is not None, "approved release tag must already exist; use existing tag guard")
        obj = ref["object"]
        for _ in range(4):
            if obj["type"] == "commit":
                break
            _require(obj["type"] == "tag", "unsupported release ref")
            obj = self.transport.request("GET", REPO + "/git/tags/" + obj["sha"])["object"]
        verify_release(manifest, approval, signing_keys, artifacts, merge_sha=merge_sha,
                       allowlisted_commit=approved[0], existing_tag_commit=obj["sha"], now=self.clock())
        _require(obj["type"] == "commit", "tag peel limit")
        existing = self.transport.request("GET", REPO + "/releases/tags/" + tag)
        _require(existing is None, "existing release requires reconciliation; never overwrite artifacts")
        release = self.transport.request("POST", REPO + "/releases", {
            "tag_name": tag, "target_commitish": merge_sha, "name": tag, "draft": True,
            "body": f"Approved objective {approval.objective_id}; signed integrity manifest verified."})
        for name, content in artifacts.items():
            uploaded = self.transport.upload(release["id"], name, content)
            from .controller import _digest
            _require(uploaded.get("digest") == "sha256:" + _digest(content), "uploaded artifact hash mismatch")
        return self.transport.request("PATCH", REPO + f"/releases/{release['id']}", {"draft": False})
