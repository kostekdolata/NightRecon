# NightRecon Development Roadmap

NightRecon is being developed as an authorization-first adversarial security validation platform for reconnaissance, penetration testing, attack-path analysis, defensive-control validation, and controlled cyber-range operations.

This roadmap is directional. Release scope may be split into smaller verified increments when that reduces risk. Every release must preserve the authorization boundary, avoid unrelated refactors, pass the full automated test matrix, and leave `master` at a stable checkpoint before the next development branch begins.

## Product delivery order

Red Night is the only active Night product track until it passes the complete
[Red Night acceptance standard](RED_ACCEPTANCE.md) and documented, repeatable
comparison labs. For each relevant specialist category, measure coverage,
false positives, safety, repeatability, usability, and operational evidence.
The goal is to exceed leading tools where Red Night can demonstrate a material
advantage and meet their essential capability baseline elsewhere. Never claim
universal superiority from a feature checklist or a passing unit-test count.

After Red Night reaches that evidence-backed gate, choose the next Night using
its own acceptance and comparison plan. Blue Night, White Night, Purple Night,
and Black Night remain distinct future applications, not parallel delivery
tracks. Maintenance of the shared authorization core continues throughout;
it cannot wait for the separate White Night application.

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

Status: development in verified batches; no release tag yet.

The measurable Red completion gates and specialist comparison are maintained
in [RED_ACCEPTANCE.md](RED_ACCEPTANCE.md). The evidence-only path-review
primitive and shared-distribution launcher are implemented. An offline
normalized directory-export importer now bridges observed user/group
membership evidence into the graph without live queries. Red remains an
integrated CLI capability until
its independent installation, command isolation, and acceptance tests pass.

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

## Generation 4 — Blue Defensive Validation

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

## Generation 5 — White Team Command Layer

Goal: make authorization and exercise control a first-class product capability.

Planned capabilities:

- engagements and projects
- authorization records
- target allowlists and exclusions
- testing windows
- allowed techniques
- maximum intrusiveness
- approval chains
- request/action budgets
- worker permissions
- encrypted credential/secrets handling
- immutable audit evidence
- exercise control and scoring
- emergency stop and worker revocation
- data-retention policy
- evidence custody and export

The separate White Night application will provide engagement administration
and exercise control. Mandatory shared-core authorization and safety remain
available to Red Night before White Night exists as an application.

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

1. Keep the five-Night catalog, separation contract, and v0.31 CLI version
   correction merged and verified.
2. Verify the internal fail-closed edition command gateway without changing
   the existing single-package CLI defaults.
3. Complete the Red Night acceptance gates in [RED_ACCEPTANCE.md](RED_ACCEPTANCE.md).
   Evidence-only path review, a shared-distribution `red-night` launcher, and a
   separately built `red-night-app` preview now exist. Split shared safety
   core and Red-only engines, and verify isolation before production release.
4. Build authorization-first live Active Directory and Entra ID collectors on
   the stable graph evidence contract; the offline normalized directory export
   bridge is an intermediate step, not a live collector.
5. Finish Red Night's remaining controlled validation, engagement safety,
   reporting, and repeatable specialist-comparison gates before beginning
   product development of another Night.
