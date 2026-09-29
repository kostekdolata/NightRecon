# NightRecon Development Roadmap

NightRecon is being developed as an authorization-first adversarial security validation platform for reconnaissance, penetration testing, attack-path analysis, defensive-control validation, and controlled cyber-range operations.

This roadmap is directional. Release scope may be split into smaller verified increments when that reduces risk. Every release must preserve the authorization boundary, avoid unrelated refactors, pass the full automated test matrix, and leave `master` at a stable checkpoint before the next development branch begins.

## Product delivery order

Red Night remains the currently available standalone Night and continues its
evidence-backed completion work under
[RED_ACCEPTANCE.md](RED_ACCEPTANCE.md). For each relevant specialist category,
measure coverage, false positives, safety, repeatability, usability, and
operational evidence. Never claim universal superiority from a feature checklist
or a passing unit-test count.

White Night is the second standalone product track. Its development may proceed
while Red Night remains stable, provided White work does not refactor or change
Red execution behavior. White implementation is governed by
[WHITE_ACCEPTANCE.md](WHITE_ACCEPTANCE.md),
[WHITE_OWNERSHIP.md](WHITE_OWNERSHIP.md),
[WHITE_PACKAGE_PLAN.md](WHITE_PACKAGE_PLAN.md), and
[WHITE_LIVE_ARCHITECTURE.md](WHITE_LIVE_ARCHITECTURE.md).

White Night must be designed from the start for three equivalent deployment
profiles: standalone installation, composed full-stack installation, and
bootable White Night Live USB. These are deployments of one White product, not
separate forks.

Blue Night, Purple Night, and Black Night remain distinct later standalone
applications. Maintenance of the shared authorization/safety core continues
throughout and never waits for White Night; another Night must remain safe and
usable without White installed.

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
full-stack composition, and a bootable encrypted Live USB. A future full-stack
Live image may include the other Night packages, but no Night may become a
mandatory runtime dependency of another.

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

Status: active development.

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

Planned follow-on v0.42 batches:

- concrete AWS/Azure/Kubernetes correlation keys and cloud-to-network/identity joins
- bounded validation-candidate compilation from evidence-backed paths
- cross-domain engagement/path reporting with evidence gaps and retest state
- choke-point and blast-radius analysis that remains descriptive rather than
  an exploitability or risk score
- reproducible specialist comparison labs measuring path coverage,
  false/invented edges, runtime, evidence completeness, and operator effort

The v0.42 atlas and correlation layers remain evidence-review surfaces. Graph
reachability or a `correlates-to` edge does not establish exploitability,
likelihood, impact, authentication access, compromise, or risk.

See [V042_ATTACK_PATH_ATLAS.md](V042_ATTACK_PATH_ATLAS.md) and
[V042_UNIFIED_EXPOSURE_INTELLIGENCE.md](V042_UNIFIED_EXPOSURE_INTELLIGENCE.md).
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

White Night is the second standalone product track after Red Night.

Locked architecture:

- one White product across standalone install, full-stack install, and Live USB;
- `White application -> White engine -> shared core`;
- no White-to-Red/Blue/Purple/Black runtime imports;
- no Red/Blue/Purple/Black dependency on White;
- shared-core scope, budget, stop, and secret-handling enforcement remains
  authoritative;
- imported evidence never grants authorization.

### White Batch 1 — Foundation and acceptance

Status: completed documentation foundation.

- `WHITE_ACCEPTANCE.md`
- `WHITE_OWNERSHIP.md`
- `WHITE_PACKAGE_PLAN.md`
- `WHITE_LIVE_ARCHITECTURE.md`
- edition/roadmap composition contract

### White Batch 2 — Package skeleton

Status: implemented and PR-CI verified.

Delivered:

- independent White engine/application package boundary
- `white-night-app` launcher
- informational `editions` surface only
- explicit zero-active-command manifest
- package isolation tests
- standalone wheel/install/uninstall smoke
- Ubuntu/Windows, Python 3.11/3.14 White distribution CI
- no dependency on another Night runtime or legacy `nightrecon`

### White Batch 3 — Engagement, scope and ROE domain

Status: implemented and PR-CI verified.

Delivered:

- immutable/versioned engagement definitions
- named engagement contacts and roles
- deterministic target allowlists and exclusions validated by shared-core syntax
- timezone-aware testing/exercise windows
- allowed/prohibited technique declarations
- maximum intrusiveness and total-action budget declarations
- data classification, retention, and export policy
- deterministic canonical JSON and SHA-256 fingerprints
- stable human-readable ROE and engagement summary rendering
- deterministic normalization for unordered scope/technique/contact inputs
- explicit non-authorization semantics: authoring models cannot execute,
  approve, or authorize operations
- isolated built-package smoke coverage
- current-master compatibility verification with Red v0.42 web/API correlation

Release evidence: the clean current-master PR matrix completed 27/27 jobs
successfully, including all four White distribution combinations and every
current Red/general integration job.

Deferred to Batch 4:

- compilation into shared-core executable policy
- authorization decisions
- policy signing/publication/revocation

### White Batch 4 — Deterministic policy compiler

Planned:

- ROE to machine-enforceable policy bundle
- stable policy fingerprint
- approval/version binding
- expiry/revocation
- authenticity/integrity verification
- negative tests proving policy compilation cannot broaden source scope

### White Batch 5 — Approval workflow engine

Planned:

- single approval
- dual control
- quorum approval
- separation of duties
- expiry
- delegation
- rejection
- revocation
- escalation
- immutable decision evidence

### White Batch 6 — Evidence custody and tamper-evident audit

Planned:

- provenance-backed evidence intake
- custody events
- cryptographic evidence fingerprints
- classification and limitations
- derivation/parent references
- append-only logical audit
- portable integrity manifest
- signed export support
- secret-free ordinary audit/report output

### White Batch 7 — White Night Live USB alpha

Planned:

- reproducible Debian-based `live-build` configuration
- x86-64 UEFI first target
- immutable/read-only base system image
- White packages installed from versioned artifacts
- Secure Workspace, Ephemeral Session, and Recovery/Integrity modes
- LUKS2 encrypted persistent workspace
- automatic White application start after workspace unlock
- VM boot/reboot persistence tests
- no removable-media AutoRun bypass

### White Batch 8 — Exercise Director

Planned:

- technical and tabletop exercise modes
- objectives/phases/scenarios
- facilitator/participant/observer/reviewer roles
- injects
- exercise clock
- pause/resume/terminate
- observations
- lessons learned
- improvement actions

### White Batch 9 — Mission Control and emergency-stop management

Planned:

- one engagement timeline
- authorization/policy visibility
- approval state
- budget/time-window state
- Night capability/status visibility through shared contracts
- stop engagement/Night/operation
- freeze new actions
- revoke approval
- stop requested versus stop acknowledged
- bounded offline authorization checkpoints

### White Batch 10 — Red Night composition

Planned:

- Red publishes versioned action/evidence events to the shared engagement layer
- White consumes Red evidence without importing Red engine code
- Red consumes shared-core-enforceable White-approved policy without importing
  White runtime code
- standalone export/import path
- composed shared-workspace path
- prove imported Red evidence never expands authorization

### White Batch 11 — Professional workspace and reporting

Planned:

- engagement dashboard
- scope/ROE review
- approval inbox
- evidence browser
- audit viewer
- facilitator console
- after-action report
- evidence manifest
- policy/decision history
- machine-readable exports

### White Batch 12 — Hardened deployment and acceptance

Planned:

- standalone/composed/Live deployment parity tests
- signed/offline Live update bundles
- recovery and rollback
- Secure Boot production target
- SBOM/build manifest
- hardware compatibility matrix
- large-engagement/evidence performance tests
- migration/version tests
- benchmark labs against relevant cyber-range, SOAR, engagement-management,
  BAS, and exercise-planning categories

White Night must remain independently useful even when no other Night is
installed. Full-stack capability comes from composition, not duplicated engines.

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

1. Complete and verify v0.42 Batch 3 — Exact Web/API Origin Correlation.
2. Extend exact correlation into concrete AWS/Azure/Kubernetes resources.
3. Compile bounded controlled-validation candidates from evidence-backed paths;
   never auto-execute them.
4. Add cross-domain operator reporting, evidence-gap review, and remediation
   impact on exposure paths.
5. Run reproducible comparison labs and keep Red Night as the active product
   track until the full [RED_ACCEPTANCE.md](RED_ACCEPTANCE.md) standard is
   evidence-backed.

White Night proceeds as a separate non-breaking product track:

1. Verify Batch 3 immutable engagement/scope/ROE models against the current Red
   master and full CI matrix.
2. Keep White command execution informational until Batch 4 policy compilation
   is explicitly implemented and tested.
3. Begin the reproducible Live USB build skeleton early, but do not fork White
   domain/storage semantics for Live deployment.
4. Preserve current Red execution behavior and shared-core authorization
   semantics throughout White development.
