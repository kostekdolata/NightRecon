# Red Night specialist competitiveness — measurable acceptance gates

Status: development priorities, **not** a claim of market leadership or parity.
Source of truth: [ROADMAP.md](../ROADMAP.md),
[RED_ACCEPTANCE.md](../RED_ACCEPTANCE.md), and
[NIGHT_PRODUCT_STANDARD.md](../NIGHT_PRODUCT_STANDARD.md).

## Product direction

Red Night should win professional preference through **reproducible evidence,
safe scope control, useful end-to-end assessment workflows, reliable deployment,
and measurable discovery/validation quality**. Additional tool integrations are
useful only if they improve these operator outcomes.

Do not mark any gate completed solely because an integration or unit-test
fixture exists. Record the tested version, fixture/image, authorized target,
comparator version, ground truth, date, limitations and review evidence.

## Priority P0 — close quality and deployment release gates

1. Complete the active beta7, beta8 and beta9 verification sequence on their
   exact branch heads: full Windows/Linux CI, packaging, UEFI smoke, promotion
   in dependency order and post-merge checks.
2. Preserve the known Red v0.43 release baseline and v0.44 deployment
   qualification boundaries. CI boot evidence **does not** prove Secure Boot,
   real hardware compatibility, or removable-media endurance.
3. Ship no third-party Nmap, Npcap, TShark or Nuclei binary until version-specific
   redistribution, provenance and installer security requirements are documented.
   A checksum manifest stored alongside an executable is **not** an independent
   trust anchor. Validate protected, independently pinned release metadata and
   installation ACLs before promoting the managed-tool packaging feature.
4. Prove that normal installation, upgrade, rollback, removal and recovery
   preserve the same shared-core authorization and evidence boundaries.

## Priority P1 — benchmark specialist detection quality

Create one reproducible, controlled, explicitly authorized lab suite with
independent ground truth for:

| Area | Ground truth and comparators | Acceptance evidence |
| --- | --- | --- |
| TCP/UDP + service discovery | Known open/closed/filtered ports and services on IPv4/IPv6 hosts; compare matching Nmap scan profiles | TP/FP/FN, precision and recall where defined, UDP ambiguous states, latency, probe count, scope-denial results |
| Browser/web/API | Local authenticated and unauthenticated intentionally vulnerable services, OpenAPI/GraphQL fixtures; compare Burp and ZAP in matching authorized modes | Reachable assets, missed endpoints, false findings, confidence, login/session state preservation, forbidden mutations, operator steps |
| AD/Entra attack-path intelligence | Disposable identity tenants/domains with independently reviewed rights/trust relationships; compare specialist identity graph evidence | Correct/missed/invented edges and paths, inferred-vs-observed separation, collector permission footprint |
| Controlled validation | Reviewed non-destructive evidence fixtures and explicitly permitted lab targets; compare verified preconditions and postconditions | Confirmed/potential/inconclusive rates, timeouts, revocation and operator-stop latency, cleanup, retest reproducibility |
| Reporting and retesting | Known finding/evidence corpus and repeated engagements | Verified provenance, complete remediation steps, reproducible retest, secret redaction, technical/executive exports |

**Metric honesty:** For a category with no predicted positives, precision is
undefined; with no expected positives, recall is undefined. Never represent
undefined as 100%. UDP open|filtered is ambiguous evidence, not a confirmed
open-port true positive. A deterministic fixture comparison does not establish
independent specialist-product parity.

For comparative runs, match authorization, target scope, bandwidth/worker
ceilings, timeouts, credentials, selected check families and lab state. Record
per-tool configuration, versions, resource use and the complete result
distribution. No invented benchmark values or unsupported superiority claims.

## Priority P2 — operator workflow and differentiators

- Deliver an end-to-end engagement flow: authorization and scope review,
  selected evidence collection, validation proposal, explicit approval,
  bounded execution, defensible finding, remediation, retest and export.
- Improve a reviewable evidence timeline, conflicting-evidence handling,
  operator progress visibility, safe cancellation and deterministic exports.
- Support local/offline operation with secure workspace recovery and compatible
  stack composition; prove that adding/removing another Night does not weaken
  Red's independent execution boundary.
- Evaluate time-to-first-finding, time-to-validated-report, missed findings,
  false positives, steps per engagement and re-test time with real testers.

## Promotion rule

A capability is **implemented** when code and tests exist, **CI verified**
when exact-head automated checks pass, **field qualified** when representative
authorized lab/hardware evidence is reviewed, and **competitive evidence
supported** only after controlled, independently reviewable comparisons.
These statuses must never be conflated. The release train remains incremental;
no automatic exploitation, implicit scanning or authority derived from a
discovered tool, network address or imported evidence.
