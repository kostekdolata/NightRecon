# NightRecon Development Roadmap

NightRecon is being developed as an authorization-first adversarial security validation platform for reconnaissance, penetration testing, attack-path analysis, defensive-control validation, and controlled cyber-range operations.

This roadmap is directional. Release scope may be split into smaller verified increments when that reduces risk. Every release must preserve the authorization boundary, avoid unrelated refactors, pass the full automated test matrix, and leave `master` at a stable checkpoint before the next development branch begins.

## Operating Modes

NightRecon will converge on four controlled operational modes, with Purple workflows linking offensive actions to defensive detections.

- **Red** — reconnaissance, exposure discovery, vulnerability validation, attack-path validation, and controlled adversary emulation.
- **Blue** — defensive-control testing, telemetry validation, detection engineering, exposure reduction, and remediation verification.
- **White** — authorization, scope, rules of engagement, approvals, safety controls, audit, evidence, exercise control, and emergency stop.
- **Black** — deliberately knowledge-limited external assessment beginning from an explicitly authorized starting scope.
- **Purple workflow** — correlation of Red actions with Blue prevention, telemetry, alerts, and detection coverage.

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

Status: release candidate.

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

Status: release candidate.

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

Release gate: version/docs complete, exact-head eleven-job push + PR CI green, merge to `master`, verify post-merge eleven-job CI, add the verified release merge commit to the guarded release-tag allowlist, then create the annotated `v0.30.0` tag pointing to that release merge commit.

## Generation 2 — Identity and Attack-Path Intelligence

Goal: move from isolated findings to graph-based exposure reasoning.

Planned capabilities:

- unified asset/service/identity/permission/vulnerability graph
- Active Directory and Entra ID collection
- group and nested-group relationships
- local-admin and delegated privilege relationships
- service accounts and machine identities
- certificate and trust relationships
- cloud and repository identities
- critical-asset classification
- choke-point and blast-radius analysis
- evidence-backed attack-path search

NightRecon must distinguish observed relationships from inferred hypotheses and keep path reasoning reproducible.

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

Purple workflows will correlate approved Red activity with Blue telemetry and detections.

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

The White layer becomes the authority that decides what NightRecon is permitted to execute.

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

The current locked execution order is:

1. Finish and release v0.29.0 Read-Only SSH Credentialed Assessment.
2. Verify the merged `master` commit with the full seven-job matrix and create the guarded `v0.29.0` annotated tag.
3. Start v0.30.x Broader Credentialed Infrastructure Assessment in a fresh development branch.
4. Extend the same secret-handling, allowlist, identity-verification, typed-evidence, and action-budget model to SMB, WinRM, supported databases, and selected network devices before beginning identity/attack-path intelligence.
