"""Pure, read-only assessment planning. Not an authorisation decision."""
from __future__ import annotations

from dataclasses import dataclass
import ipaddress

ENGINE_NAMES = ("Nmap", "Nuclei", "OWASP ZAP", "TShark", "Metasploit")
ENGINE_CAPABILITIES = {
    "Nmap": "governed bounded TCP discovery requires registered engagement",
    "Nuclei": "passive evidence import only",
    "OWASP ZAP": "passive evidence import only",
    "TShark": "passive evidence import only",
    "Metasploit": "module catalogue only",
}

@dataclass(frozen=True)
class AssessmentPreview:
    engagement_id: str
    targets: tuple[str, ...]
    engines: tuple[str, ...]
    issues: tuple[str, ...]
    def as_text(self) -> str:
        lines = ["READ-ONLY ASSESSMENT PREVIEW", "",
                 f"Engagement: {self.engagement_id or '(missing)'}",
                 f"Targets: {', '.join(self.targets) or '(none)'}",
                 f"Selected engines: {', '.join(self.engines) or '(none)'}", ""]
        lines.extend(f"{name}: {ENGINE_CAPABILITIES[name]}" for name in self.engines)
        lines.extend(["", "Preflight issues:"])
        lines.extend(f"- {issue}" for issue in self.issues)
        lines.extend(["", "NOT AUTHORISED. NO SCANS WILL RUN.",
                      "Operational permissions must come from the verified policy authority."])
        return "\n".join(lines)


def plan_assessment(*, engagement_id: str, targets_text: str,
                    mode: str, selected_engines: tuple[str, ...]) -> AssessmentPreview:
    issues = []
    engagement_id = engagement_id.strip()
    if not engagement_id or len(engagement_id) > 128:
        issues.append("Valid engagement identifier is required")
    if mode not in ("all", "custom"):
        raise ValueError("Invalid assessment mode")
    if len(targets_text) > 8192:
        raise ValueError("Target list too large")
    addresses = []
    for candidate in targets_text.replace(",", "\n").splitlines():
        candidate = candidate.strip()
        if not candidate:
            continue
        try:
            parsed = ipaddress.ip_address(candidate)
            if parsed.is_multicast or parsed.is_unspecified:
                raise ValueError()
            value = str(parsed)
            if value not in addresses:
                addresses.append(value)
        except ValueError:
            issues.append(f"Unsupported target (single IP only): {candidate[:80]}")
        if len(addresses) > 32:
            raise ValueError("Target count limit exceeded")
    if not addresses:
        issues.append("At least one valid single-IP target is required")
    if mode == "all":
        engines = ENGINE_NAMES
    else:
        if any(name not in ENGINE_NAMES for name in selected_engines):
            raise ValueError("Unknown engine")
        engines = tuple(name for name in ENGINE_NAMES if name in selected_engines)
    if not engines:
        issues.append("Select at least one engine")
    issues.append("Engagement authorisation and permitted capability not verified")
    for name in engines:
        if name != "Nmap":
            issues.append(f"{name} execution is not integrated")
    return AssessmentPreview(engagement_id, tuple(addresses), engines, tuple(issues))
