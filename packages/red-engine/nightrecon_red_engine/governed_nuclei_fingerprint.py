"""Single-template, low-impact governed Nuclei HTTP fingerprint.

This is NOT arbitrary template execution, fuzzing, OAST or exploitation.
The only template is generated here, uses one HTTP GET, and has no user
input beyond a literal authorised IPv4 target and an optional port.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import ipaddress
from pathlib import Path
import tempfile
import threading
from urllib.parse import urlsplit

from .atomic_command_executor import execute_atomically_governed
from .governed_command_runner import FixedCommand
from .nuclei_import import parse_nuclei_jsonl
from .transactional_policy_authority import TransactionalPolicyAuthority

_HTTP_TEMPLATE = """id: rednight-safe-http-fingerprint
info:
  name: Red Night bounded HTTP response fingerprint
  author: rednight
  severity: info
  description: Single GET to authorised URL root; no vulnerability claim
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: status
        status:
          - 200
          - 201
          - 204
          - 301
          - 302
          - 401
          - 403
          - 404
"""

@dataclass(frozen=True)
class GovernedNucleiResult:
    action_id: str
    target_url: str
    returncode: int
    matches: tuple[tuple[str, str], ...]

    def operator_report(self) -> dict:
        return {
            "tool": "nuclei",
            "operation": "bounded-http-fingerprint",
            "action_id": self.action_id,
            "target": self.target_url,
            "execution_status": "succeeded" if self.returncode == 0 else "failed",
            "command_exit_code": self.returncode,
            "template_id": "rednight-safe-http-fingerprint",
            "templates_executed": 1,
            "requests_per_second_limit": 1,
            "observations": [
                {"template_id": template, "matched_origin": origin}
                for template, origin in self.matches
            ],
            "evidence_status": "unverified-http-observation",
            "limitations": (
                "Only a single HTTP GET fingerprint was attempted.",
                "Response observations are not confirmed vulnerabilities.",
                "No community templates, OAST, fuzzing or exploit checks were executed.",
            ),
        }


def execute_governed_nuclei_fingerprint(
    *,
    authority: TransactionalPolicyAuthority,
    engagement_id: str,
    action_id: str,
    target_url: str,
    executable: str | Path,
    trusted_sha256: str,
    audit_path: str | Path,
    result_audit_path: str | Path,
    enabled: bool = False,
    cancel_event: threading.Event | None = None,
) -> GovernedNucleiResult:
    """Run only the built-in GET fingerprint against an authorised literal IP."""
    if not enabled:
        raise PermissionError("Nuclei network execution requires explicit opt-in")
    url = urlsplit(target_url)
    if url.scheme not in ("http", "https") or not url.hostname:
        raise ValueError("Nuclei fingerprint target must be HTTP(S)")
    try:
        target = ipaddress.IPv4Address(url.hostname)
        port = url.port
    except ValueError as exc:
        raise ValueError("Nuclei target must be a literal IPv4 address and valid port") from exc
    if (
        target.is_multicast or target.is_unspecified
        or url.username is not None or url.password is not None
        or url.path not in ("", "/") or url.query or url.fragment
        or (port is not None and port == 0)
    ):
        raise ValueError("Nuclei target must be an exact HTTP(S) IPv4 origin")
    origin = f"{url.scheme}://{target}" + (f":{port}" if port is not None else "")
    program = Path(executable)
    if not program.is_absolute() or program.name.lower() not in ("nuclei", "nuclei.exe"):
        raise ValueError("Nuclei executable must be an approved absolute path")
    if not program.is_file():
        raise FileNotFoundError("Trusted Nuclei executable unavailable")
    with program.open("rb") as handle:
        actual = hashlib.file_digest(handle, "sha256").hexdigest()
    if actual != trusted_sha256.lower():
        raise PermissionError("Nuclei executable digest mismatch")

    with tempfile.TemporaryDirectory(prefix="rednight-nuclei-") as directory:
        root = Path(directory)
        template = root / "rednight-safe-http.yaml"
        config = root / "empty-config.yaml"
        template.write_text(_HTTP_TEMPLATE, encoding="utf-8")
        config.write_text("{}\n", encoding="utf-8")
        template.chmod(0o600)
        config.chmod(0o600)
        command = FixedCommand(
            name="nuclei-bounded-http-fingerprint",
            executable=program,
            arguments=(
                "-u", origin, "-t", str(template),
                "-config", str(config),
                "-duc", "-ni", "-no-stdin", "-nh",
                "-rl", "1", "-bs", "1", "-c", "1",
                "-timeout", "5", "-retries", "0",
                "-jsonl", "-or", "-silent", "-nc",
            ),
            capability="external.nuclei.http-fingerprint",
            impact="low", timeout_seconds=30,
            executable_sha256=trusted_sha256.lower(),
        )
        outcome = execute_atomically_governed(
            command=command,
            action_id=action_id, engagement_id=engagement_id,
            engagement_status="active", target=str(target),
            policy_store=None, ledger=None, authority=authority,
            audit_path=audit_path, result_audit_path=result_audit_path,
            cancel_event=cancel_event,
        )
    if outcome.returncode != 0:
        raise RuntimeError(f"Governed Nuclei failed with exit code {outcome.returncode}")
    evidence = parse_nuclei_jsonl(outcome.stdout.encode("utf-8"))
    for finding in evidence.findings:
        if finding.matched_origin != origin:
            raise PermissionError("Nuclei reported a result outside the authorised origin")
        if finding.template_id != "rednight-safe-http-fingerprint":
            raise PermissionError("Nuclei returned an unexpected template result")
    matches = tuple((finding.template_id, finding.matched_origin) for finding in evidence.findings)
    return GovernedNucleiResult(action_id, origin, outcome.returncode, matches)
