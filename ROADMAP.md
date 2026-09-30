# NightRecon Development Roadmap

NightRecon is being developed as an authorization-first adversarial security validation platform for reconnaissance, penetration testing, attack-path analysis, defensive-control validation, and controlled cyber-range operations.

This roadmap is directional. Release scope may be split into smaller verified increments when that reduces risk. Every release must preserve the authorization boundary, avoid unrelated refactors, pass the full automated test matrix, and leave `master` at a stable checkpoint before the next development branch begins.

## Night product standard

All Night product tracks are governed by
[NIGHT_PRODUCT_STANDARD.md](NIGHT_PRODUCT_STANDARD.md).

Every Night must be developed against three equal product pillars:

1. **NightRecon stack capability** — first-class composition through shared,
   versioned contracts without peer-engine runtime coupling.
2. **Standalone capability** — a complete independently useful product, with
   direct-device installation and Live/offline deployment where applicable,
   using the same application/engine packages as the stack.
3. **Domain-leading specialist capability** — complete professional workflows,
   evidence/data quality, analysis, reporting, exports, integrations, and
   measurable acceptance for that Night's assigned role.

A Night is not considered mature if only one or two pillars are complete.
The standard maturity gates are also the template for developing future Nights.

## Product delivery order

Red Night v0.43.0 is the verified stable standalone baseline, with v0.44.0
Standalone & Live Deployment Foundation continuing as a separate verified Red
development track under [RED_ACCEPTANCE.md](RED_ACCEPTANCE.md).

White Night is the second standalone product track. Its development may proceed
in parallel from verified Red checkpoints provided White work does not refactor,
weaken, or silently change Red execution behavior. White is governed by
[WHITE_ACCEPTANCE.md](WHITE_ACCEPTANCE.md),
[WHITE_OWNERSHIP.md](WHITE_OWNERSHIP.md),
[WHITE_PACKAGE_PLAN.md](WHITE_PACKAGE_PLAN.md), and
[WHITE_LIVE_ARCHITECTURE.md](WHITE_LIVE_ARCHITECTURE.md).

White must remain one product across standalone installation, composed
full-stack installation, and bootable White Night Live USB.

Blue Night, Purple Night, and Black Night remain distinct later standalone
applications. Shared authorization/safety enforcement remains Night-neutral and
must work without White installed.

## Operating Modes

NightRecon will converge on five independently installable applications:
White Night, Blue Night, Red Night, Purple Night, and Black Night. Users will be
able to install one, any combination, or the full suite. They share one mandatory
authorization-first core, so installing one Night alone never removes the safety boundary. The
edition architecture and honest availability status are in [EDITIONS.md](EDITIONS.md).

- **Red Night** — reconnaissance, exposure discovery, vulnerability validation, attack-path validation, and controlled adversary emulation.
- **Blue Night** — defensive-control testing, telemetry validation, detection engineering, exposure reduction, and remediation verification.
- **White Night** — authorization, scope, rules of engagement, approvals, safety controls, audit, evidence, exercise control, and emergency stop.
- **Black Night** — deliberately knowledge-limited external assessment beginning from an explicitly authorized starting scope.
- **Purple Night** — correlation of approved Red Night actions with Blue Night prevention, telemetry, alerts, and detection coverage, usable on its own with exported evidence or alongside Red Night and Blue Night.

White Night additionally has a locked deployment requirement: the same White
application/engine code and versioned contracts must support standalone install,
full-stack composition, and a bootable encrypted Live USB. No Night may become
a mandatory runtime dependency of another.

## Locked Safety Principles

1. Network and application activity must pass explicit target validation and authorization before execution.
2. Passive is the default. Safe-active behavior must be explicit, bounded, and non-destructive.
3. Intrusive or higher-impact validation belongs behind separate approval-gated workflows rather than ordinary scan flags.
4. Destructive behavior is never part of routine scanning. Future destructive training must remain isolated to explicit cyber-range or simulation contexts.
5. Secrets and live session material remain ephemeral wherever possible and must not enter reports, normal audit output, or CLI output.
6. Findings remain evidence-based. Vulnerability or threat-intelligence matches do not automatically become exploitability claims.
7. Every release must be testable, reviewable, reversible, and independently useful.

## Generation 1 — Complete the Assessment Foundation

### v0.24.0 — Ephemeral Authenticated Session Continuity

Status: released and verified stable.

- opt-in in-memory session cookie continuity
- same session context reused across authorized same-origin crawl requests
- safe-active OPTIONS probes reuse the same transient session
- session state excluded from persisted crawl results, reports, audit records, and CLI output
- raw cookie-header mode remains mutually exclusive with session-cookie mode
- existing scope, redirect, request-count, and intrusiveness controls remain unchanged

Release gate: completed; merged to `master` with post-merge cross-platform CI verified.

### v0.25.0 — Stateful Web Workflow Engine

Status: released and verified stable.

Delivered capabilities:

- immutable workflow model, navigation state, and explicit transition policy
- passive same-origin workflow planning from captured crawl evidence
- field-name/type classification for ordinary, hidden, credential, anti-CSRF, and session-token inputs without retaining values
- deterministic workflow action budgets and same-origin revalidation
- bounded GET-only workflow execution with hard timeout/response ceilings
- ephemeral Authorization and in-memory cookie continuity across approved GET steps
- explicit form-submission policy that defaults to disabled
- same-origin POST-only internal form executor with exact field allowlists, sensitive-field gates, submission budgets, stale-approval rejection, body/response ceilings, and redirect refusal
- destructive-looking actions blocked by default
- v0.25 CLI exposes planning and explicit GET execution only; form POST execution remains internal
- separate non-secret workflow reports and reproducible execution evidence
- real loopback integration coverage proving GET/POST boundaries without external network access

Release gate: version/docs complete, exact-head cross-platform CI green, merge to `master`, then post-merge CI verification.

### v0.26.0 — Browser-Powered Application Discovery

Status: released and verified stable.

Delivered capabilities:

- optional Playwright/Chromium browser runtime behind the `browser` extra
- backend-neutral browser worker controller and immutable accounting state
- exact-origin interception policy with GET/HEAD-only defaults
- request/page/runtime/response/DOM/DOM-item ceilings
- request-budget reservation before network continuation
- service workers blocked in Chromium contexts
- dynamic DOM and JavaScript/SPA link discovery
- bounded form metadata observation without form submission
- only same-origin discovered links/form actions retained
- cross-origin resource requests blocked before reaching outside servers
- mutating browser methods blocked by default
- redirects blocked at the response boundary
- structured non-secret browser reports with query/fragment redaction
- explicit opt-in `--browser-discovery` CLI surface
- dedicated real Chromium loopback CI validation
- authenticated browser context intentionally deferred beyond v0.26
- no clicks, file uploads, arbitrary methods, or automatic high-impact actions

Release gate: version/docs complete, exact-head standard + Chromium CI green, merge to `master`, then post-merge verification.

### v0.27.0 — API Intelligence

Status: released and verified stable.

Delivered capabilities:

- normalized OpenAPI 3.x and Swagger 2.0 inventory models
- bounded local JSON description loading and optional YAML support through the `api` extra
- operation, parameter, server, security-scheme, request-content, and response-status modelling
- server URL and external `$ref` redaction with no automatic remote-reference fetching
- passive `nightrecon api inspect` command with explicit scope validation
- structured machine-readable API inventory reports
- explicit operation selectors and schema-derived URL planning
- GET/HEAD-only safe-active API executor with exact-origin request policy
- no invented required parameter values and no unresolved path templates
- mutation operations blocked from the safe probe path
- independent request, timeout, and response-byte ceilings
- transient Authorization context through named environment variables only
- response bodies excluded from validation result/report models
- explicit `nightrecon api probe` command and separate validation reports
- offline saved GraphQL introspection inspection
- one fixed explicit GraphQL live introspection operation
- GraphQL type, field, argument, query-root, mutation-root, and subscription-root metadata
- no arbitrary GraphQL query text, variables, mutations, subscriptions, or arbitrary headers
- redirect refusal and response ceilings for GraphQL introspection
- real loopback API and GraphQL integration tests
- dedicated API YAML runtime CI job alongside the existing Chromium integration job

Release gate: version/docs complete, exact-head six-job push + PR CI green, merge to `master`, then post-merge six-job verification.

### v0.28.0 — Expanded Safe-Active DAST

Status: released, tagged, and verified stable.

Delivered capabilities:

- reusable safe-active DAST check definitions restricted to GET/HEAD/OPTIONS
- independent global, family, and per-check request ceilings
- immutable request accounting with stale-decision and inconsistent-state rejection
- bounded non-secret response fingerprints using SHA-256 samples instead of body retention
- conservative response-difference analysis with strong and weak signals
- hash-only body changes treated as weak evidence to reduce dynamic-content false positives
- URL credential/query/fragment redaction before DAST persistence
- stable retest identifiers and deterministic retest descriptors
- generic exact-origin safe-active HTTP transport with redirect refusal and hard timeout/response ceilings
- budget reservation before every attempted request, including failed attempts
- transient Authorization and in-memory CookieJar reuse without report persistence
- raw Cookie-header mode excluded from the v0.28 DAST path
- strict synthetic-request-header allowlist limited to CORS preflight metadata
- first deterministic check family for credentialed CORS origin reflection
- fixed synthetic origin `https://nightrecon.invalid` with no external callback dependency
- baseline + synthetic-origin OPTIONS comparison per same-origin target
- finding requires explicit synthetic-origin reflection plus credential allowance
- wildcard origin, reflection without credentials, cross-origin targets, duplicate targets, and incomplete pairs do not generate the credentialed-reflection finding
- conservative finding language that does not equate configuration evidence with exploitability
- explicit `--dast-cors` integration into the existing authorized crawl flow
- DAST requires explicit safe-active assessment mode and rejects raw cookie-header mode
- configured target counts must fit total/family budgets before network activity begins
- separate structured `<session>-dast.json` reports with findings, fingerprints, differences, budgets, and retest IDs
- real loopback coverage for transport limits, CORS positive/negative cases, secret non-retention, and cross-platform behavior

Release gate: version/docs complete, exact-head six-job push + PR CI green, merge to `master`, verify post-merge six-job CI, then add the verified merge commit to the guarded release-tag allowlist.

### v0.29.0 — Read-Only SSH Credentialed Assessment

Status: released, tagged, and verified stable.

Delivered capabilities:

- protocol-neutral credentialed infrastructure action/state/policy models
- explicit scope enforcement and transport allowlists
- symbolic action IDs instead of arbitrary command text
- immutable per-run action budgets
- mutating actions blocked by default
- opaque credential references with no secret-value fields
- ephemeral in-memory secret handles with TTL, byte ceilings, zeroization, redacted representations, and serialization refusal
- credential-provider boundary registry with environment-backed resolution built in
- one-shot infrastructure execution contract that clears credential material after every attempt
- bounded typed fact model for secret-free transport evidence
- optional Paramiko SSH runtime through the `ssh` extra
- strict `known_hosts` verification and reject policy for unknown/changed host keys
- password-authenticated SSH with agent and local-key discovery disabled
- fixed internal read-only actions only: `ssh.system_identity` and `ssh.os_inventory`
- no shell, PTY, SFTP, arbitrary command text, file transfer, or mutation action surface
- connect/command timeout, output-byte, and total-action ceilings
- allowlisted typed parsing of system identity and OS-release metadata
- sanitized authentication/host-key/SSH/connection/command/parse/output-limit failure reasons
- separate secret-free infrastructure assessment reports
- explicit `nightrecon infra ssh` CLI surface
- dedicated Paramiko runtime compatibility CI job

Release gate: version/docs complete, exact-head seven-job PR CI green, merge to `master`, verify post-merge seven-job CI, then add the verified merge commit to the guarded release-tag allowlist.

### v0.30.0 — Broader Credentialed Infrastructure Assessment

Status: released, tagged, and verified stable.

Delivered capabilities:

- authorization-first credentialed assessment extended beyond SSH
- SMB server identity and bounded share inventory
- Impacket SMB runtime with NTLMv1 disabled and no file/remote-execution surface
- WinRM system identity and bounded patch inventory
- pywinrm HTTPS/NTLM runtime with mandatory certificate validation
- PostgreSQL server identity and bounded schema inventory through psycopg
- MySQL server identity and bounded schema inventory through mysql-connector
- database TLS and server-identity verification required with no CLI bypass
- selected network-device evidence contract for NETCONF-over-SSH metadata
- fixed network-device identity and interface-inventory actions
- mandatory network-device host-identity verification represented in policy
- exact symbolic read-only action allowlists for every protocol
- immutable per-run action budgets and pre-resolution budget validation
- fresh one-action ephemeral credential leases
- secret-free typed evidence and separate infrastructure reports
- deterministic bounded inventory normalization and duplicate rejection
- sanitized failure reasons with no credential or exception-detail leakage
- explicit single-host scope enforcement and CIDR rejection
- no arbitrary shell, PowerShell, SQL, device command, RPC payload, file access, configuration mutation, remote execution, or general-purpose query surface
- dedicated Paramiko, Impacket, pywinrm, psycopg, and MySQL connector compatibility CI jobs
- cross-platform Python 3.11/3.14 verification on Ubuntu and Windows

Release gate: completed; exact-head eleven-job push + PR CI passed, release merged to `master`, post-merge verification completed, the release merge commit was added to the guarded release-tag allowlist, and annotated tag `v0.30.0` points to release commit `3f909117193c6394462df31472890d2405d5f01e`.

## Generation 2 — Identity and Attack-Path Intelligence

Goal: move from isolated findings to graph-based exposure reasoning.

### v0.31.0 — Identity Graph Foundation

Status: released, tagged, and verified stable.

Delivered foundation:

- immutable graph node and edge models with stable identifiers
- explicit provenance on graph nodes and relationships
- clear separation of observed facts from inferred hypotheses
- asset, service, identity, group, permission, vulnerability, assessment-finding, and critical-asset node types
- deterministic graph normalization, duplicate rejection, and bounded in-memory construction
- deterministic graph assembly from existing asset, service, vulnerability, threat-context, assessment, identity, permission, and critical-asset evidence
- graph consistency validation with fail-closed pipeline enforcement
- canonical structured graph export and reproducible SHA-256 snapshot manifests
- deterministic read-only graph indexing, structural querying, descriptive summaries, and bounded traversal
- generic offline identity/group/permission evidence contracts with nested-group relationships
- critical-asset classification evidence
- bounded directed evidence-backed path discovery with depth/path ceilings and no ranking or exploitability claim
- comprehensive cross-platform unit/integration coverage across the existing CI matrix
- no new credential collection, network identity collectors, or intrusive execution in the foundation release

The foundation remains intentionally data-model-first so later Active Directory, Entra ID, cloud, repository, certificate/trust, and privilege collectors can plug into one evidence contract without weakening the existing authorization boundary.

Deferred to subsequent Generation 2 releases:

- Active Directory and Entra ID collection
- local-admin and delegated privilege collectors
- service-account and machine-identity collectors
- certificate and trust relationships
- cloud and repository identities
- choke-point and blast-radius analysis
- higher-level attack-path ranking or validation

NightRecon continues to distinguish observed relationships from inferred hypotheses and keeps path reasoning reproducible and evidence-backed.

### v0.32.0 — Red Product Readiness

Status: integrated into the v0.40.0 Red release train; not separately tagged.

The v0.32 work established the Red product boundary, dedicated launcher,
package-isolation path, offline identity evidence bridge, and evidence-only
path review used by the later Red release train.

### v0.33.0-v0.40.0 — Red Night Product Integration Release Train

Status: v0.40.0 release finalization.

Delivered in the integrated Red train:

- v0.33 engagement lifecycle workspace and fail-closed execution policy
- v0.34 authorization-first read-only identity collection boundary
- v0.35 approval-gated controlled validation runtime
- v0.36 unified evidence-backed attack graph
- v0.37 policy-constrained plan-only Red operator
- v0.38 persistent remediation and controlled retest lifecycle
- v0.39 signed Red Checks ecosystem policy and catalog
- v0.40 authorization-first cloud/hybrid evidence boundary
- deterministic stack-wide v0.40 release acceptance across policy, persistence,
  identity, cloud, validation, graph, planning, checks, remediation, and retest

The dedicated `nightrecon-red-night`, `nightrecon-red-engine`, and
`nightrecon-shared-core` packages are versioned together at 0.40.0. The
legacy `nightrecon` compatibility distribution remains 0.31.0 while the
migration window is open.

The measurable specialist comparison and broader product-completion gates remain
in [RED_ACCEPTANCE.md](RED_ACCEPTANCE.md); a stable v0.40 milestone does not
claim universal parity with specialist tools.

### v0.41.0 — Live Identity Intelligence

Status: released, tagged, and verified stable.

Delivered capabilities:

- concrete authorization-first read-only Active Directory provider over
  certificate-validating LDAPS/StartTLS
- concrete authorization-first read-only Microsoft Entra provider over a fixed
  Microsoft Graph v1.0 collection plan
- identity-safe live operator commands under the existing engagement policy
- dedicated AD and Entra evidence namespaces
- user, service, computer, application, group, role, and domain identities
- direct/nested and primary-group membership evidence
- bounded membership-path review
- Entra application/service-principal ownership and scoped directory roles
- selected well-known AD privileged-group semantics
- AD `managedBy`, constrained-delegation, and domain-trust relationships
- explicit incomplete-evidence handling and provider request/runtime limits
- deterministic label-free AD/Entra benchmark fixtures
- reproducible graph fingerprints and explicit graph-label export boundary
- full package/migration ownership registration for the v0.41 identity modules

The v0.41 release closes the concrete AD/Entra identity-provider foundation and
selected relationship-modeling milestone. It does not claim universal parity
with BloodHound or another specialist identity product; live authorized
comparison labs and broader ACL/security-descriptor coverage remain measured
acceptance work.

Release gate: coordinated 0.41.0 package metadata, exact-head 19-job CI,
standalone/combined distribution smoke, merge to `master`, post-merge 19-job
verification, then guarded annotated tag creation.

### v0.42.0 — Cross-Domain Exposure Intelligence

Status: released, tagged, and verified stable.

Product goal:

Make Red Night operate as one evidence-backed engagement system across network,
web/API, identity, cloud/hybrid, vulnerability, validation, remediation, and
critical-asset evidence rather than as disconnected specialist surfaces.

Batch 1 — Cross-Domain Attack Path Atlas:

- bounded directed paths from selected identity/group/asset/service starts to
  critical assets
- one global exploration budget across the atlas
- deterministic path IDs and ordering
- observed/inferred hop counts retained explicitly
- supporting engagement-evidence IDs retained per path
- structural node/edge participation counts with no risk or exploitability
  score
- explicit truncation reasons for start, target, depth, path, and global
  expansion ceilings
- deterministic no-network cross-domain runtime benchmark on Python 3.11/3.14

Batch 2 — Exact AD Identity/Network Correlation:

- bounded identity correlation properties carried through provider,
  normalization, engagement evidence, and graph projection
- exact Active Directory computer/service to network-asset correlation using
  observed DNS/SPN host evidence
- inferred `correlates-to` edges only for one-to-one exact hostname matches
- no fuzzy/display-name joins, DNS resolution, or exploitability inference
- explicit no-match and ambiguous-correlation results
- deterministic duplicate-proof aggregation and hard correlation ceilings
- correlated direct and portable unified graph builders

Batch 3 — Exact Web/API Origin Correlation:

- web crawl, OpenAPI base, and GraphQL endpoint origins represented as explicit
  observation-scoped service evidence
- normalized HTTP(S) scheme, host, and explicit/default port retained as
  bounded correlation properties
- hostname origins require exactly one observed network asset hostname match
- IP-literal origins require an exact observed asset address
- the selected asset must expose an observed TCP service on the exact origin port
- inferred `correlates-to` edges run from observed network service to web/API
  surface so the attack-path atlas can traverse into application evidence
- missing/ambiguous asset or service evidence remains unresolved with opaque
  correlation metadata
- dedicated deterministic runtime benchmark on Python 3.11/3.14

Batch 4 — Exact Cloud Correlation:

- provider-specific allowlisted AWS/Azure/Entra/Kubernetes correlation evidence
  retained through portable graph projection
- exact canonical cloud IP/DNS evidence joined only to observed network assets
- exact Azure/Entra tenant + object-ID evidence joined only to observed Entra identities
- ambiguous or conflicting exact evidence fails closed without a correlation edge
- no DNS resolution, fuzzy/display-name matching, IP adjacency inference, or
  provider identity guessing

Batch 5 — Proposal-Only Validation Candidates:

- deterministic bounded candidates compiled from exact atlas paths
- exact node, edge, evidence and observed/inferred-hop context retained
- validation capability, approval review and scope review declared explicitly
- no adapter execution, credential resolution, action consumption or mutation

Batch 6 — Exposure Review and Structural Concentration:

- path evidence-gap review including inferred hops and unresolved correlations
- remediation/retest status summary and before/after path-set comparison
- descriptive node/edge path, start and critical-target participation counts
- no risk score, exploitability ranking, probability or automatic prioritization

Batch 7 — Reproducible Comparison/Runtime Lab:

- deterministic expected/matched/missed/invented path and edge measurements
- evidence completeness, runtime, operator-step count and truncation reporting
- explicit non-parity interpretation; live specialist comparison remains a
  broader Red acceptance activity

The v0.42 atlas and correlation layers remain evidence-review surfaces. Graph
reachability or a `correlates-to` edge does not establish exploitability,
likelihood, impact, authentication access, compromise, or risk.

See [V042_ATTACK_PATH_ATLAS.md](V042_ATTACK_PATH_ATLAS.md) and
[V042_UNIFIED_EXPOSURE_INTELLIGENCE.md](V042_UNIFIED_EXPOSURE_INTELLIGENCE.md).
### v0.43.0 — Controlled Validation Intelligence

Status: released, tagged, and verified stable.

Product goal:

Turn v0.42 proposal-only validation candidates into reviewed, bounded,
explicitly selected controlled-validation plans while preserving independent
authorization, approval, action-budget, revocation, evidence, and cleanup
boundaries.

Batch 1 — Reviewed Technique Registry:

- metadata-only canonical technique definitions
- explicit target kinds, expected non-secret evidence keys, impact and approval
  metadata
- optional strict ATT&CK-ID field without claiming unreviewed mappings
- fixed `read-only-proof` adapter classification
- deterministic bridge into the existing `ValidationDefinition` runtime object
- no commands, payloads, scripts, credentials, automatic selection, or execution
- high-impact metadata must declare approval
- unknown techniques, target kinds, secret-like evidence fields, and invalid
  mappings fail closed

Batch 2 — Exact Candidate-to-Technique Eligibility:

- separate expected output evidence from graph eligibility prerequisites
- exact canonical target-kind classification from graph evidence
- candidate path/evidence/hop/safety metadata revalidated before planning
- deterministic all-matches planning with no ranking or automatic selection
- explicit no-target and missing-prerequisite rejection reasons
- hard candidate/technique/target/option/rejection ceilings

Batch 3 — Explicit Adapter + Precondition/Postcondition Contracts:

- immutable metadata-only adapter contracts derived from reviewed techniques
- exact graph-property preconditions and reviewed evidence postconditions
- deterministic explicit eligibility-to-contract bindings
- stale target/provenance/eligibility metadata and contract drift fail closed
- confirmed observations require all reviewed evidence keys
- unexpected top-level evidence is rejected
- no callable adapters, network activity, credentials, payloads, or execution

Batch 4 — Isolated Revocable Worker Execution Boundary:

- explicit operator-selected binding required before authorization
- one canonical `validation.run` action consumed before worker start
- fresh spawned process receives only a minimal typed reviewed request
- fixed TCP, TLS fingerprint, and HTTP HEAD read-only proof adapters only
- live policy rechecks reload revocation/status/window/capability/scope/approval
  state while the worker runs
- authorization change or lease failure terminates the child fail closed
- hard runtime, adapter-I/O, polling, and serialized-result ceilings
- Batch 3 postconditions validate all returned evidence before acceptance
- no arbitrary commands, scripts, credentials, payloads, request templates,
  high-impact techniques, or automatic technique selection

Batch 5 — Cleanup / Evidence Lifecycle + Deterministic Retest:

- deterministic portable validation worker-result evidence
- deterministic explicit cleanup evidence paired to every persisted result
- current no-side-effect techniques record cleanup as not-required with zero actions
- side-effecting/cleanup-required bindings fail closed until reviewed support exists
- idempotent shared-workspace persistence with conflict rejection
- retest state changes derive only from exact persisted lifecycle records
- exact validation/cleanup evidence IDs retained on remediation findings
- confirmed -> regressed, not-confirmed -> verified, other worker states inconclusive
- no new active technique, mutation, credential, or network capability

Batch 6 — Reviewed ATT&CK Mappings + Controlled Comparison Labs:

- every current validation technique has an explicit ATT&CK review disposition
- TCP selected-service proof is related to T1046 Network Service Discovery,
  without claiming complete T1046 implementation
- TLS and HTTP policy proofs are explicitly reviewed-unmapped
- mapping records retain official ATT&CK source/version/last-modified metadata
- deterministic lifecycle comparison measures matched/missed/invented scenarios,
  evidence keys, cleanup state, ATT&CK review disposition and operator steps
- runtime is reported separately from the deterministic comparison fingerprint
- fixture results explicitly do not claim parity with specialist products
- no new worker technique, credential, payload, cleanup mutation or execution power

Release acceptance:

- all six Controlled Validation Intelligence batches are integrated
- coordinated Red Night, Red engine, and shared-core distributions are 0.43.0
- the legacy compatibility distribution remains 0.31.0 with matching Red pins
- the integrated v0.43 release-acceptance test and complete cross-platform
  release matrix pass before the guarded tag is created
- live authorized specialist-product comparisons remain broader Red acceptance
  work and are not implied by the v0.43 fixture comparison lab

The v0.43 registry and planning layers do not grant permission to execute.
Every live validation action independently passes the existing `validation.run`
authorization boundary and explicit operator-selection rules.

See [V043_CONTROLLED_VALIDATION_INTELLIGENCE.md](V043_CONTROLLED_VALIDATION_INTELLIGENCE.md).

### v0.44.0 — Standalone & Live Deployment Foundation

Status: active development.

Goal: make Red Night deployable as the same independently versioned product in
normal standalone installs, composed NightRecon stacks, and a future bootable
Red Night Live USB environment.

Locked rules:

- stable v0.43.0 remains the functional baseline;
- Live USB is a deployment layer, not a Red-engine fork;
- Red depends only on Red engine + shared core, never another Night runtime;
- composed installs gain interoperability through shared contracts/services;
- peer Nights remain independently installable/removable;
- no deployment profile weakens scope, authorization, approval, budget,
  revocation, evidence, cleanup, or worker-isolation controls.

Batch 1 — Deployment Architecture Contracts:

- immutable Red deployment-profile metadata for standalone, composed, and
  Live USB modes;
- identical mandatory Red/shared-core package set across all profiles;
- explicit optional peer-Night composition contract;
- offline-capable/no-auto-host-disk-mount deployment invariants;
- Red-specific Live architecture document and acceptance gates;
- unit + installed-wheel regression coverage proving no cross-Night runtime
  dependency.

Planned follow-on v0.44 batches:

- Batch 2: Debian `live-build` skeleton + x86-64 UEFI VM boot smoke;
- Batch 3: appliance session + explicit Secure/Ephemeral/Recovery modes;
- Batch 4: LUKS2 persistent workspace + reboot/ephemeral-state verification;
- Batch 5: Red+White and selected/full-stack package composition profiles;
- Batch 6: integrity manifests, signed/offline updates, recovery, SBOM,
  Secure Boot target, hardware compatibility and endurance testing.

See [RED_LIVE_ARCHITECTURE.md](RED_LIVE_ARCHITECTURE.md).

## Generation 3 — Red Validation Engine

Goal: controlled validation of authorized attack paths.

Execution model:

`observation -> hypothesis -> authorization/approval -> isolated validation -> evidence -> cleanup`

Planned capabilities:

- ATT&CK-mapped playbooks
- bounded exploitability validation
- controlled privilege-escalation validation
- controlled lateral-movement validation
- credential-access simulations
- persistence simulations in explicit training/range contexts
- precondition/postcondition reasoning
- automatic cleanup where supported
- action budgets and rate limits
- approval gates and kill switch
- isolated workers with revocable execution capability

High-impact actions must never be exposed as ordinary scan options.

## Generation 4 — White Night Command and Exercise Control

Goal: make authorization, engagement governance, evidence custody, exercise
control, and emergency-stop management a first-class standalone product while
preserving shared-core enforcement when White is absent.

Locked architecture:

- one White product across standalone install, full-stack install, and Live USB;
- `White application -> White engine -> shared core`;
- no White-to-Red/Blue/Purple/Black runtime imports;
- no Red/Blue/Purple/Black dependency on White;
- shared-core scope, budget, impact, stop, and secret-handling enforcement
  remains authoritative;
- imported evidence never grants authorization.

### White Batch 1 — Foundation and acceptance

Status: completed documentation foundation.

### White Batch 2 — Package skeleton

Status: implemented and PR-CI verified.

### White Batch 3 — Engagement, scope and ROE domain

Status: implemented and PR-CI verified.

### White Batch 4 — Deterministic policy compiler

Status: implemented and PR-CI verified on the earlier shared-core baseline.

### White Batch 5 — Approval workflow engine

Status: implemented and PR-CI verified.

Delivered single/dual/quorum approval, role eligibility, separation of duties,
bounded delegation without authority multiplication, expiry, rejection,
escalation, revocation, action-bound grants, replay protection, and hash-linked
decision evidence.

### White Batch 6 — Evidence custody and tamper-evident audit

Status: completed and merged to `master` as White `0.1.0a6`.
The replayed current-baseline tree passed the full 39-job pull-request matrix,
all four isolated White distribution combinations, and post-merge master CI.

Current scope:

- govern the existing shared-core `EvidenceRecord` contract instead of creating
  a White-only evidence schema;
- classification and retention inherited from engagement data-handling policy;
- evidence-record SHA-256 fingerprints and integrity-bound custody wrappers;
- derived-evidence parent lineage with parents required to already be in custody;
- current and historical custodian projection;
- append-only hash-linked custody events for intake, derivation, transfer, and
  governed export;
- metadata-only evidence manifests that omit evidence payload data;
- portable export bundles binding manifest, custody case, and shared-core records;
- explicit `authorization_effect: none` in custody/export contracts;
- export refusal when engagement policy forbids export or retention has expired;
- backend-neutral custody/audit store protocols plus atomic local file stores;
- append-only logical audit trails with actor, subject, outcome, reason code,
  timestamp, secret-safe details, event fingerprints, and trail fingerprints;
- semantic and cryptographic verification on import/reopen;
- secret-safe custody/audit summaries;
- local `evidence` and `audit` CLI operations only;
- no target execution, network activity, or cross-Night runtime dependency.

Digital signatures/authenticity remain a later hardening layer. Batch 6 provides
tamper evidence and deterministic integrity verification, not signer identity.

### White Batch 7 — White Night Live USB alpha

Status: active development.

Live Batch 1 is completed and CI-verified: source-controlled Debian trixie
`live-build` inputs, an x86-64 UEFI image, exact shared-core/White wheel
artifacts staged into the immutable filesystem, checksum verification, retained
ISO artifact, and an offline QEMU/OVMF userspace boot marker all pass while the
complete NightRecon CI remains green.

Live Batch 2 is now active on `v0.1.0-white-live-batch2-dev`: install those exact built White
artifacts inside the immutable image and prove the booted system can execute the
packaged White application boundary before adding appliance-style auto-start.
Persistence, Secure Workspace/Ephemeral/Recovery behavior, LUKS2, host-storage
workflows, Red composition, Secure Boot acceptance, and production hardening
remain later verified slices.

### White Batches 8-12

Exercise Director, Mission Control/emergency stop management, Red composition,
professional workspace/reporting, then hardened standalone/composed/Live
deployment acceptance.

White remains independently useful for its own control-plane responsibility.
Full-stack capability comes from composition, not duplicated engines.

## Generation 5 — Blue Defensive Validation

Goal: test whether defensive controls actually prevent or detect approved activity.

Planned integrations and capabilities:

- SIEM
- EDR/XDR
- NDR
- WAF
- firewall
- IDS/IPS
- cloud security telemetry
- ATT&CK coverage maps
- Sigma rule validation
- detection regression tests
- expected-telemetry definitions
- prevention vs detection classification
- detection-latency measurement
- false-negative tracking
- remediation and re-test loops

Purple Night workflows will correlate approved Red Night activity with Blue Night telemetry and detections.

## Generation 6 — Black-Box / External Attack Surface

Goal: assess an organization from an explicitly authorized low-knowledge external starting point.

Planned capabilities:

- domains and subdomains
- DNS and certificates
- external IPs and ASNs
- exposed cloud services
- web applications and APIs
- exposed repositories and public artifacts
- service fingerprinting
- shadow infrastructure
- externally visible vulnerabilities
- change tracking
- provenance showing why each discovered asset is associated with the authorized organization

## Platform and Product Layer

The engine will eventually require a production platform around it:

- REST API
- web UI
- projects and engagements
- RBAC
- encrypted secrets
- distributed workers and job queues
- scheduler
- webhooks and integrations
- evidence viewer
- remediation workflows
- HTML, PDF, CSV, SARIF, and JSON exports
- signed update feeds
- health monitoring
- containerized deployment
- offline/self-hosted operation
- backup/restore
- performance and regression benchmarking
- multi-tenant architecture only after the single-tenant security model is proven

## Immediate Sequence

The current execution order is:

1. Keep Red Night v0.43.0 as the verified stable Controlled Validation Intelligence baseline.
2. Develop v0.44.0 Standalone & Live Deployment Foundation in isolated,
   CI-verified Red batches.
3. Complete Batch 1 deployment architecture contracts before introducing any
   boot-image build machinery.
4. Then build the Red Live skeleton from the same versioned Red/shared-core
   artifacts used by normal installation.
5. Continue broader Red acceptance work without weakening authorization,
   evidence-honesty, approval, revocation, isolated-worker, action-budget,
   cleanup, or bounded-execution rules.

White Night proceeds as a separate non-breaking product track:

1. Verify Batch 6 custody, manifest, export, audit, retention, and tamper-detection
   semantics against the current Red v0.44 master baseline.
2. Require the full current Red/general matrix plus all four isolated White
   distribution combinations before marking Batch 6 complete.
3. Keep evidence explicitly non-authoritative: imports, manifests, and exports
   never expand scope or satisfy an approval by themselves.
4. Keep Batch 6 integrity-only; signer authenticity and key-management remain a
   later explicit hardening step rather than being implied by SHA-256 hashes.
5. Begin White Batch 7 only after Batch 6 is green on the current baseline.
