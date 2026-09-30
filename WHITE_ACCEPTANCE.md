# White Night Completion Standard

White Night is intended to be a separately installable, authorization-first
engagement and exercise-control application for authorized security work. It is
the second standalone NightRecon product track after Red Night.

White Night is not an assessment scanner, adversary engine, SIEM, EDR, or attack
executor. Its product responsibility is to define and manage the engagement
control plane: authorization, scope, rules of engagement, approvals, safety
limits, evidence custody, audit, exercise control, emergency stop, and
after-action reporting.

The mandatory NightRecon shared core remains authoritative for enforcement even
when White Night is not installed. White Night adds management, orchestration,
review, and operator workflows; it must never become an optional safety bypass
or a mandatory runtime dependency of another Night.

## Benchmark categories

White Night should be measured against the strongest relevant capabilities from
multiple product categories rather than against one claimed all-in-one
competitor.

| Reference category | Representative products/frameworks | Capability to measure | White Night acceptance target |
| --- | --- | --- | --- |
| Cyber-range and exercise control | Immersive, Cyberbit, RangeForce | Exercise lifecycle, roles, scenarios, injects, live control, performance evidence, after-action review | Reproducible technical and tabletop exercises with facilitator control, objectives, injects, timeline evidence, pause/resume/abort, and structured AAR output |
| SOAR and human-in-the-loop workflows | Splunk SOAR, Cortex XSOAR, Tines | Approval steps, escalation, operator prompts, decision history, workflow audit | Policy-driven single/dual/quorum approvals, expiry, delegation, rejection, revocation, escalation, and immutable decision evidence |
| Pentest/engagement management | Dradis, PlexTrac, Faraday | Engagement workspaces, imported evidence, collaboration, findings, reporting | One engagement workspace with scope, approvals, evidence, review state, comments/assignments where appropriate, imports, exports, and professional reports |
| Breach-and-attack/security validation | SafeBreach, Picus, AttackIQ, SCYTHE | Repeatable validation plans, ATT&CK context, retest history, outcome evidence | White orchestrates and records approved validation requests/outcomes without absorbing Red/Blue execution engines; validation state and retests remain traceable |
| Exercise planning guidance | NIST SP 800-115, NIST SP 800-84, NCSC Exercise in a Box, CISA exercise guidance | Rules of engagement, exercise planning, facilitator roles, deviations, evaluation and improvement plans | Human-readable and machine-readable ROE, explicit deviation approval, role assignment, exercise objectives, communications, evaluation, lessons learned, and improvement tracking |

These references define evaluation categories, not a plan to copy proprietary
implementations or to claim parity from feature names alone. White Night must
have repeatable acceptance evidence for each category before claiming that it
matches or exceeds a specialist product.

## Locked architectural acceptance rules

1. **Shared-core authority:** scope enforcement, target validation, action
   budgets, stop enforcement, secret-handling primitives, and cross-Night
   evidence/engagement contracts remain in the shared core.
2. **No Night-to-Night runtime dependency:** White may coordinate Red, Blue,
   Purple, and Black through versioned contracts, but no Night imports White as
   a mandatory runtime dependency.
3. **Evidence is not authorization:** imported findings, discovered assets,
   correlations, or workspace records never expand scope or grant permission.
4. **One product, multiple deployments:** the White application code and domain
   contracts remain the same across standalone installation, composed full-stack
   installation, and White Night Live USB.
5. **Fail closed:** missing, expired, ambiguous, unverifiable, revoked, or
   inconsistent authorization state cannot silently become permission.
6. **No hidden cloud dependency:** core engagement, approval, evidence, audit,
   reporting, and Live USB workflows must remain usable offline and air-gapped.
7. **Secret-free ordinary evidence:** credentials, session material, private keys,
   and raw secrets do not enter normal reports, audit records, or cross-Night
   evidence contracts.

## Release gates

1. **Independent installation**
   - `nightrecon-white-night` installs and runs with the mandatory
     `nightrecon-shared-core` without Red, Blue, Purple, or Black applications.
   - Removing White does not break another Night.
   - Installing White alongside another Night does not change that Night's
     default authorization or execution behavior.

2. **Deployment parity**
   - The same core engagement, ROE, approval, audit, evidence, exercise, and
     reporting semantics work in:
     - standalone White installation;
     - White installed in a composed NightRecon stack;
     - White Night Live USB.
   - Deployment-specific storage and OS services may differ, but versioned
     engagement/evidence contracts and resulting semantics remain compatible.

3. **Engagement domain**
   - immutable engagement identity and versioned metadata;
   - named owners and operational roles;
   - explicit start/end windows and status;
   - target allowlists and exclusions;
   - technique/action-class constraints;
   - maximum intrusiveness and action budgets;
   - communication/escalation contacts;
   - data-handling and retention policy.

4. **Rules of engagement and policy compilation**
   - one source of truth produces both human-readable ROE and a deterministic
     machine-enforceable policy bundle;
   - every approved policy version has a stable fingerprint;
   - approved versions cannot be edited in place;
   - changes create a new version and require the configured approval path;
   - policy bundles support authenticity/integrity verification and expiry;
   - compiler tests prove policy output cannot silently broaden source scope.

5. **Approval workflows**
   - support for single, dual-control, and quorum approvals;
   - named authority and role-based eligibility;
   - separation-of-duties rules where configured;
   - explicit approve/reject decisions;
   - expiry and stale-approval rejection;
   - delegation with bounded scope and lifetime;
   - revocation and escalation;
   - immutable reason, actor, time, policy version, and decision evidence.

6. **Safety and emergency stop**
   - shared-core stop enforcement is available without White;
   - White provides engagement-, Night-, and operation-level stop controls;
   - approval revocation and freeze-new-actions are distinct operations;
   - active workers acknowledge stop state at bounded checkpoints;
   - user interfaces distinguish stop requested from stop acknowledged;
   - offline/disconnected workers are bounded by policy expiry, execution limits,
     and mandatory authorization checkpoints.

7. **Evidence custody**
   - stable evidence IDs;
   - source Night/tool and operation provenance;
   - observed/created/ingested timestamps where relevant;
   - cryptographic content fingerprint;
   - schema and producer version;
   - authorization context reference;
   - classification and limitations;
   - parent/derivation references;
   - custody history;
   - modification creates new evidence rather than silently replacing history;
   - portable integrity manifests and signed export support.

8. **Audit**
   - append-only logical audit history;
   - deterministic event ordering rules;
   - actor, action, engagement, policy/approval reference, and timestamp;
   - tamper-evidence suitable for offline verification;
   - import/export and administrative actions are audited;
   - ordinary audit output remains secret-free.

9. **Exercise Director**
   - technical and tabletop exercise modes;
   - objectives, phases, scenario events, injects, and expected outcomes;
   - facilitator, participant, observer, reviewer, and other bounded roles;
   - manual and scheduled inject release;
   - pause, resume, terminate, and time-control semantics;
   - evidence-linked observations and decisions;
   - lessons learned and improvement actions.

10. **Mission Control**
    - one live engagement timeline;
    - current authorization and policy version;
    - pending/approved/rejected/revoked approvals;
    - budget and time-window state;
    - connected Night capability/state visibility without importing their
      runtimes;
    - emergency-stop state and acknowledgements;
    - evidence/event ingestion with clear source attribution.

11. **Cross-Night interoperability**
    - versioned, secret-free engagement and event envelopes;
    - source Night, engagement ID, event ID, operation ID, authorization
      reference, timestamp, evidence references, confidence, and limitations;
    - export/import works when Nights are not co-installed;
    - composed installs may use a shared backend without changing contracts;
    - Red is the first integration acceptance target.

12. **Professional output**
    - ROE and scope report;
    - approval/decision history;
    - activity timeline;
    - evidence manifest;
    - audit report;
    - exercise after-action report;
    - lessons/improvement plan;
    - machine-readable JSON export;
    - sensitive material excluded or explicitly protected.

13. **Quality gate**
    - deterministic unit and contract tests;
    - negative authorization and stale-policy tests;
    - package-isolation smoke tests;
    - standalone/composed deployment tests;
    - Live USB VM boot tests;
    - encrypted-persistence and ephemeral-mode tests;
    - power-loss/removal recovery tests where practical;
    - performance baselines for large engagements/evidence sets;
    - migration/version compatibility tests;
    - full supported CI matrix green before release tagging.

## White Night Live USB acceptance

White Night Live is a first-class deployment target, not a fork.

Production acceptance requires:

- reproducibly built x86-64 UEFI Live image;
- immutable/read-only base system image;
- encrypted LUKS2 persistent workspace for engagement state;
- explicit ephemeral mode with no engagement persistence;
- recovery/integrity-check boot mode;
- automatic White Night application start after secure workspace unlock;
- no requirement for a preinstalled host OS application;
- no attempt to bypass Windows removable-media AutoRun protections;
- offline operation with no required telemetry or SaaS service;
- verified image/package manifest;
- controlled update and rollback process;
- documented Secure Boot support target and compatibility testing;
- lost-drive confidentiality through mandatory encrypted persistence;
- full-stack Live composition using the same Night packages and contracts as
  normal installation.

## Initial completion sequence

White Night development should proceed in small verified batches:

1. foundation documentation and package/live architecture;
2. package namespaces and isolation tests;
3. engagement/scope/ROE domain;
4. deterministic policy compiler;
5. approval engine;
6. evidence vault and tamper-evident audit;
7. first bootable Live USB alpha with encrypted persistence;
8. Exercise Director;
9. Mission Control and emergency-stop management;
10. Red Night interoperability;
11. professional workspace and reporting;
12. hardened Live USB/full-stack composition and comparison labs.

A White Night release must remain independently useful at every tagged stable
milestone and must not weaken the shared authorization boundary.
