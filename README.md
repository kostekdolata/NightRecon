# NightRecon

NightRecon is a modular reconnaissance and penetration-testing platform designed for authorized security assessments.

> Use NightRecon only against systems you own or have explicit permission to test.

## Current Version

**v0.22.0**

NightRecon now includes scope-enforced concurrent TCP scanning, authorized bounded CIDR host discovery, persistent asset inventory and historical exposure tracking, concurrent service detection, evidence-backed deep service fingerprinting, evidence-based host operating-system fingerprinting, opt-in bounded active service probes, bounded banner detection, HTTP and HTTPS service intelligence, TLS certificate inspection, HTTP security-header analysis, structured software identity, opt-in NVD vulnerability intelligence with match evidence and descriptive summaries, opt-in CISA KEV and FIRST EPSS threat context, an extensible assessment-check engine with built-in, Python-plugin, and signed declarative check-pack support, a managed signed check-feed lifecycle with verified install, sync, inventory, rollback, replay protection, dry-run update planning, and active installed-pack execution, plus a scope-enforced bounded same-origin web crawler with passive content discovery, secret-safe authenticated crawling, passive DAST, and explicitly gated bounded safe-active web assessment.

## Features

- TCP connect scanning for authorized single-host targets
- Port lists and port ranges
- Concurrent scanning with configurable worker limits
- IPv4 and IPv6 TCP scanning
- Open-port detection
- Service identification for common TCP services
- Concurrent service detection across confirmed open ports
- Configurable service-detection worker limits
- Passive banner fingerprinting for SSH, FTP, and SMTP
- Structured deep service fingerprints with protocol, protocol version, product, version, platform, source evidence, and confidence
- Passive high-confidence fingerprint extraction from OpenSSH, ProFTPD, FileZilla, Postfix, Exim, and HTTP Server observations
- Explicit platform hints preserved only when present in observed banners or HTTP Server metadata
- Opt-in bounded active service-probe engine with intensity levels 0 through 9
- Active HTTP HEAD, SMTP EHLO, Redis PING, memcached version, IMAP CAPABILITY, and POP3 CAPA probes
- Active service probing disabled by default with `--service-probe-intensity 0`
- Raw-print port 9100 excluded from active service probes
- Bounded per-probe response reads and fail-soft timeout/OSError handling
- Active probe fingerprints can identify services on non-standard ports without speculative fallback
- Explicit active product/version evidence can feed existing software identity and downstream CPE/vulnerability intelligence
- Deep fingerprints displayed in CLI output and persisted in scan reports
- Persistent asset inventory tracks protocol version, platform, fingerprint source, and confidence
- Fingerprint changes are journaled separately from software-version changes
- Existing v0.18 schema-version-1 asset inventories remain backward-compatible with empty defaults for new fingerprint fields
- Evidence-based host operating-system fingerprints aggregated from explicit service platform observations
- Deterministic normalization for Ubuntu, Debian, Red Hat Enterprise Linux, CentOS, Alpine Linux, FreeBSD, OpenBSD, Windows, and Unix evidence
- Single explicit OS observation produces medium confidence; agreeing independent service evidence raises confidence to high
- Conflicting platform evidence is preserved as explicit conflict candidates instead of forcing an OS guess
- One OS fingerprint produced per resolved host address with deterministic address ordering
- Host OS fingerprints persisted in scan reports and displayed in CLI output
- Persistent asset inventory tracks OS platform, family, confidence, conflict candidates, and evidence count
- OS fingerprint changes are journaled as dedicated `os-fingerprint-changed` events
- Scans without new OS evidence preserve prior asset OS evidence rather than erasing it
- Existing schema-version-1 inventories remain backward-compatible with empty OS defaults
- Banner-based service identification on non-standard ports
- Bounded passive banner detection on confirmed open ports
- Graceful banner timeout handling
- Structured service-detection results
- Bounded HTTP HEAD probing for confirmed HTTP services
- HTTP status-line and Server-header extraction
- HTTP metadata displayed in the CLI and persisted in scan reports
- Bounded HTTP response-header capture with normalized header names
- Security-header presence/missing analysis for Content-Security-Policy, Strict-Transport-Security, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, and Permissions-Policy
- Transport-aware HSTS analysis: required only for HTTPS hostname targets, not plaintext HTTP or direct-IP scans
- Security-header analysis skipped when no HTTP response is observed
- Security-header analysis displayed in the CLI and persisted in structured scan reports
- Bounded HTTPS HEAD probing through established TLS connections
- TLS version and cipher detection
- TLS Server Name Indication (SNI) support for hostname targets
- X.509 certificate subject and issuer extraction
- X.509 certificate validity-date extraction
- X.509 DNS Subject Alternative Name extraction
- X.509 SHA-256 certificate fingerprinting
- HTTPS status-line, Server-header, and bounded response-header extraction
- TLS and HTTPS metadata displayed in the CLI and persisted in scan reports
- TLS, certificate, and HTTPS probe failures handled without aborting the scan
- Structured software identity from explicit HTTP Server metadata and OpenSSH banners
- Deterministic CPE 2.3 mapping for supported nginx, Apache HTTP Server, and OpenSSH identities
- Provider-neutral vulnerability intelligence models with fail-soft provider errors
- Opt-in NVD CVE 2.0 lookup using exact deterministic CPE identities
- NVD pagination, deduplication, CVSS severity/score, summary, and reference extraction
- Optional NVD API key via `NIGHTRECON_NVD_API_KEY`
- Vulnerability lookup disabled by default and enabled with `--vuln-lookup`
- Service-bound vulnerability intelligence persisted in structured scan reports
- CLI vulnerability-intelligence match counts and CVE metadata without claiming exploitability
- Exact vulnerability match evidence persisted as provider match basis plus matched identifier
- NVD findings record the exact deterministic CPE used for each lookup
- Reports explicitly distinguish vulnerability lookup disabled from enabled-with-zero-matches
- Descriptive vulnerability summaries include services queried, provider successes/failures, total matches, severity counts, and maximum observed CVSS
- CLI CVE output includes provider match evidence when available
- CLI vulnerability summaries remain descriptive and do not generate exploitability or risk verdicts
- Optional threat-context enrichment with `--threat-context` after `--vuln-lookup`
- CISA Known Exploited Vulnerabilities (KEV) catalog enrichment for confirmed CVE identifiers
- KEV date-added, due-date, ransomware-campaign-use, and required-action evidence
- FIRST EPSS probability and percentile enrichment for CVE findings
- EPSS CVE requests automatically batched within the provider query-length limit
- KEV and EPSS provider failures handled fail-soft without aborting scans
- Threat-context results deduplicated by CVE across multiple affected services
- Threat-context reports and CLI summaries include CVEs enriched, KEV count, EPSS coverage, maximum EPSS probability/percentile, and distinct provider-error count
- Extensible assessment-check engine with structured metadata, findings, execution results, and service-bound context
- Explicit check intrusiveness levels: passive, safe-active, intrusive, and destructive
- Safe default assessment ceiling of safe-active
- Ordinary scan CLI can enable only passive, safe-active, or intrusive checks; destructive checks are structurally excluded from the standard scan path
- Authorization is revalidated at the assessment-engine boundary before any check runs
- Check prerequisites for authentication and runtime capabilities with deterministic skip reasons
- Deterministic check registry and filtering by exact check ID, family, or tag
- Installed third-party check discovery through the `nightrecon.checks` Python entry-point group
- Plugin factories may provide a single check or multiple checks; broken plugins fail soft and are reported without hiding healthy checks
- Built-in passive check pack for observed missing HTTP security headers and legacy TLS protocol evidence
- `nightrecon checks list` catalog with ID/family/tag filtering and declared intrusiveness/service visibility
- Explicit `--assessment` scan mode with `--check`, `--check-family`, `--check-tag`, and `--max-check-intrusiveness`
- Service-bound assessment findings persisted in structured scan reports
- Assessment summaries include services assessed, checks completed/skipped/errored, and finding totals
- Declarative JSON assessment check packs with schema validation and no arbitrary code execution
- Whitelisted declarative observation fields and fixed safe condition operators
- Ed25519-signed check-pack envelopes with explicit trusted signer keys
- Fail-closed signature verification for explicitly requested check packs
- Signed declarative pack loading through `--check-pack` and `--check-pack-key`
- Declarative pack checks participate in the normal registry, duplicate-ID protection, filters, safety ceilings, and reporting path
- Pack provenance persisted through assessment execution as source pack ID and pack version
- Signed check-feed manifests with Ed25519 verification
- HTTPS-only feed-advertised pack URLs, bounded downloads, SHA-256 pinning, and signer-key pinning
- `nightrecon checks feed` command for verified feed inspection
- Managed signed check-pack store with immutable cached versions and atomic activation state
- Verified feed install and full-feed synchronization into the local check-pack store
- Offline installed-pack inventory with active-version visibility
- Verified rollback to previously cached signed versions
- Active installed packs can be reverified and loaded into assessment catalogs and scans
- Signed-feed replay protection using persisted generation timestamps and signed-manifest digests
- Same-generation signed payload mutation is rejected
- Feed-advertised mutation of an immutable installed pack version is rejected
- Non-mutating `--plan` update inspection classifies install/change/cache-activation/unchanged/conflict states without downloads or activation
- Dry-run update planning performs replay validation without advancing persisted feed state
- CLI display of detected services and observed banners
- Service connection-failure reporting without aborting the scan
- Structured completed scan reports
- Scope-enforced bounded same-origin HTTP(S) crawling through the dedicated `nightrecon crawl` command
- Crawl URL hosts must independently satisfy existing hostname/IP/CIDR authorization rules before any request is sent
- Cross-origin redirects are blocked and only normalized same-origin links are eligible for traversal
- Explicit page-count, per-page byte, and per-request timeout bounds with fail-soft request errors
- IPv4 and bracketed IPv6 web-origin support with deterministic URL normalization
- Passive HTML content discovery for page titles, same-origin links, form actions/methods, input names/types, and script source URLs
- Form field values are never collected; form actions and script sources are observation-only and are not automatically requested
- Structured web-crawl reports persisted as JSON with page, form, script, link, and failure summaries
- Opt-in passive web DAST mode with `nightrecon crawl ... --assessment`
- Passive DAST checks for password forms on plaintext HTTP pages, password fields submitted with GET, and HTTPS pages referencing HTTP scripts
- Web assessment is disabled by default and uses only captured crawl metadata; it does not submit forms or send additional assessment probes
- Authenticated crawling can read complete Authorization and Cookie header values from user-selected environment variables via `--authorization-env` and `--cookie-env`
- Authentication secret values remain ephemeral request context and are excluded from crawl reports, audit events, and CLI output
- Authenticated context is reused by safe-active probes without persisting credentials
- Web assessment intrusiveness is independently gated with `--max-web-assessment-intrusiveness passive|safe-active`, defaulting to passive
- Safe-active web assessment currently sends only bounded non-mutating OPTIONS requests and never sends PUT, DELETE, TRACE, CONNECT, PATCH, or form submissions
- Safe-active OPTIONS probes never follow redirects, revalidate authorization at the assessment boundary, and enforce a hard `--max-web-assessment-requests` ceiling
- Advertised PUT, DELETE, TRACE, or CONNECT methods are reported only as low-severity observed evidence; NightRecon does not claim those methods are exploitable
- Per-port result storage
- Ordinary `scan` CIDR port-scanning remains blocked; network discovery is isolated behind the explicit `discover` command
- Authorized CIDR host discovery with full scope-containment validation before any probe activity
- Hard per-run `--max-hosts` guard enforced before discovery probes are submitted
- Bounded concurrent TCP reachability discovery using configurable evidence ports
- TCP-open and TCP-refused observations treated as explicit host responsiveness evidence
- IPv4 and IPv6 discovery support using standard TCP sockets without raw-packet privileges
- Deterministic host-result ordering and structured per-host evidence
- Optional fail-soft reverse-DNS enrichment for responsive hosts only
- Structured discovery reports with responsive/unresponsive/named-host summaries
- Network inventory metadata including normalized CIDR, address family, prefix length, total address capacity, and first/last addresses
- Dedicated discovery audit events and JSON result persistence
- Persistent schema-versioned asset inventory keyed by IP address
- Explicit `--update-inventory` support for both discovery and single-host scan workflows
- Asset evidence tracks first seen, last seen, last checked, hostnames, discovery methods, observed services, software versions, TLS certificate fingerprints, and contributing session IDs
- Unresponsive discovery observations update the latest check state without erasing prior positive `last_seen` evidence
- Scan reconciliation detects new assets, hostname additions, opened ports, closed ports, service identity changes, software changes, and host responsiveness transitions
- Atomic `assets.json` persistence with fail-closed schema and corruption validation
- Append-only `changes.jsonl` asset-change journal with source session, source type, timestamp, port, and before/after evidence
- Offline `nightrecon assets list` current-inventory inspection
- Offline `nightrecon assets history` with address and recent-count filters

- Structured JSON Lines audit logging
- Runtime timeout and worker configuration
- Configurable results and log directories
- Authorized hostname resolution
- IPv4 and IPv6 DNS result handling
- Resolution failure reporting
- Dedicated NightRecon test runner with pass/fail summary

- Installed `nightrecon` command-line interface
- IPv4 target validation
- IPv6 target validation
- CIDR target validation
- Hostname validation
- Explicit authorization scope rules
- CIDR containment checking
- Out-of-scope target blocking
- Scan session generation
- Unique scan-session IDs
- UTC timestamps
- Structured JSON result storage
- Automated test coverage

## Example

nightrecon scan 127.0.0.1 --scope 127.0.0.1

Crawl an explicitly authorized web origin with bounded same-origin traversal:

`nightrecon crawl https://example.test --scope example.test --max-pages 50`

Add passive content-based DAST checks without form submission or extra probe requests:

`nightrecon crawl https://example.test --scope example.test --assessment`

Use authenticated crawl context from environment variables without putting secret values in the command line:

`nightrecon crawl https://example.test --scope example.test --authorization-env NIGHTRECON_WEB_AUTH --cookie-env NIGHTRECON_WEB_COOKIE`

Enable the bounded safe-active OPTIONS layer explicitly:

`nightrecon crawl https://example.test --scope example.test --assessment --max-web-assessment-intrusiveness safe-active --max-web-assessment-requests 10`

Enable bounded active service fingerprint probes at a conservative intensity:

`nightrecon scan 127.0.0.1 --scope 127.0.0.1 --ports 22,80,443,6379,9000 --service-probe-intensity 1`

Discover responsive hosts in an explicitly authorized CIDR:

`nightrecon discover 192.0.2.0/24 --scope 192.0.2.0/24 --max-hosts 1024`

Add reverse-DNS enrichment for responsive hosts:

`nightrecon discover 192.0.2.0/24 --scope 192.0.2.0/24 --ports 22,80,443,445 --reverse-dns`

Persist discovered assets and changes:

`nightrecon discover 192.0.2.0/24 --scope 192.0.2.0/24 --reverse-dns --update-inventory --inventory-dir inventory`

Merge a single-host scan into the same inventory:

`nightrecon scan 192.0.2.10 --scope 192.0.2.0/24 --ports 22,80,443 --update-inventory --inventory-dir inventory`

Inspect current assets offline:

`nightrecon assets list --inventory-dir inventory`

Inspect recent asset changes offline:

`nightrecon assets history --inventory-dir inventory --address 192.0.2.10 --limit 20`

Enable vulnerability intelligence explicitly:

`nightrecon scan 127.0.0.1 --scope 127.0.0.1 --vuln-lookup`

Add external exploitation context to the resulting CVE findings:

`nightrecon scan 127.0.0.1 --scope 127.0.0.1 --vuln-lookup --threat-context`

Inspect available built-in and installed assessment checks:

`nightrecon checks list`

List only web-family checks:

`nightrecon checks list --family web`

Inspect a verified signed check feed:

`nightrecon checks feed --url https://updates.example.test/feed.json --feed-key official=<base64-ed25519-public-key>`

Preview feed changes without downloading or activating packs:

`nightrecon checks feed --url https://updates.example.test/feed.json --feed-key official=<base64-ed25519-public-key> --plan`

Synchronize all verified feed packs into the local store:

`nightrecon checks feed --url https://updates.example.test/feed.json --feed-key official=<base64-ed25519-public-key> --sync --pack-key official=<base64-ed25519-public-key>`

Inspect installed cached versions offline:

`nightrecon checks feed --list-installed`

Run an assessment using all active installed signed packs:

`nightrecon scan 127.0.0.1 --scope 127.0.0.1 --assessment --installed-check-packs --check-pack-key official=<base64-ed25519-public-key>`

Load a signed declarative check pack into an assessment:

`nightrecon scan 127.0.0.1 --scope 127.0.0.1 --assessment --check-pack ./check-packs/web-baseline.json --check-pack-key official=<base64-ed25519-public-key>`

Run the safe-by-default assessment engine after service detection:

`nightrecon scan 127.0.0.1 --scope 127.0.0.1 --assessment`

Run only passive web checks:

`nightrecon scan 127.0.0.1 --scope 127.0.0.1 --assessment --check-family web --max-check-intrusiveness passive`

Optionally set an NVD API key in the environment before the scan:

`NIGHTRECON_NVD_API_KEY=<your-key>`

A target outside the explicitly supplied scope is rejected:

nightrecon scan 192.168.2.25 --scope 192.168.1.0/24

## Development Setup

Create and activate a virtual environment:

py -m venv .venv
.\.venv\Scripts\Activate.ps1

Install NightRecon in editable mode:

python -m pip install -e .

Run the test suite:

python tests\run_tests.py

### Assessment Check Plugins

Third-party Python packages can register NightRecon checks through the `nightrecon.checks` entry-point group. For example:

```toml
[project.entry-points."nightrecon.checks"]
acme_checks = "acme_nightrecon:checks"
```

The loaded object may be one check, a tuple/list of checks, or a factory returning either form. Each check exposes `metadata` using `AssessmentCheckMetadata` and a `run(context)` method returning structured `AssessmentFinding` objects. NightRecon validates check IDs, applies service/authentication/capability prerequisites, enforces the configured intrusiveness ceiling, and isolates plugin exceptions into structured execution errors.

### Declarative Check Packs

Signed declarative packs provide a lower-trust alternative to Python plugins. Pack conditions can inspect only a fixed whitelist of NightRecon observations such as service identity, HTTP/TLS metadata, security-header results, and structured software identity. Supported operators are fixed by NightRecon; declarative packs cannot import modules, evaluate Python expressions, execute commands, or open their own network connections. External pack files are accepted only after Ed25519 signature verification against user-supplied trusted public keys.

Signed feed manifests can advertise pack versions and HTTPS locations. NightRecon verifies the feed signature, requires HTTPS pack URLs, checks a pinned SHA-256 of the downloaded signed-pack document, pins the expected pack signer, and then verifies the pack's own Ed25519 signature before loading it.


## Security Model

NightRecon is designed around explicit authorization and scope enforcement.

Future scanning components should not operate directly on arbitrary input. Targets must first pass through NightRecon's validation and scope authorization layers.

CIDR discovery is intentionally separated from ordinary port scanning. The entire requested CIDR must be contained by an explicit scope rule, and NightRecon enforces the configured host ceiling before submitting any active discovery probe. Reverse-DNS enrichment runs only after reachability evidence is collected and never changes host responsiveness classification.

Persistent asset state remains evidence-based. A later discovery timeout or filtered response does not delete an asset or rewrite its prior `last_seen`; it records only the latest check outcome. Explicit scan results can close previously observed ports only when those ports were actually requested in the new scan.

Deep service fingerprints remain evidence-backed. Active service probing is disabled by default, uses a bounded probe catalog and response size, skips raw-print port 9100, fails soft on probe errors, and does not infer product/version/platform values that are absent from observed responses.

Operating-system fingerprints are evidence aggregations, not blind stack guesses. NightRecon only promotes explicit platform evidence already observed from services, raises confidence when independent services agree, and reports conflicting candidates rather than selecting an unsupported winner.

Vulnerability intelligence is evidence enrichment, not exploitation. An NVD/CPE match does not prove that a detected service is exploitable in its deployed context. CVSS values are reported as severity metadata and should not be treated as a complete risk assessment.

NightRecon preserves the provider match basis and exact identifier used to obtain each vulnerability record. Summary counts and maximum observed CVSS are descriptive evidence only; they are not a NightRecon risk score.

Threat context is kept separate from CVE matching: CISA KEV indicates known exploitation evidence, while FIRST EPSS reports a probability/percentile signal. Neither is treated as proof that a particular NightRecon target is exploitable.

Assessment checks are gated by explicit scope authorization and declared intrusiveness. Passive and safe-active checks are the default ceiling. The ordinary scan CLI intentionally does not expose destructive checks; higher-impact validation belongs behind a separate approval-gated workflow rather than an ordinary scan flag.

Declarative check packs are intentionally non-executable data. NightRecon does not trust a remote feed or downloaded pack merely because it came over HTTPS: feed signatures, pack hashes, signer IDs, and pack signatures are independently validated before a pack is accepted.

Managed feed state adds replay protection and immutable local version storage. Installed packs are reverified before activation, rollback, and assessment use. Dry-run planning validates signed feed freshness without persisting the newer generation or downloading artifacts.

Web crawling reuses NightRecon's existing scope authorization boundary. The URL host is validated before requests begin, cross-origin redirects are blocked, and traversal is limited to normalized same-origin links. Passive content discovery records structure rather than secrets: form values are not retained, form actions are not submitted, and script sources are not fetched merely because they were observed. Authentication header values may be supplied only through named environment variables in the crawl CLI and remain ephemeral request context; they are not stored in NightRecon reports or audit records. Web assessment remains passive by default. Safe-active mode requires an explicit intrusiveness setting, revalidates authorization at the assessment boundary, enforces a separate request ceiling, sends only OPTIONS requests, refuses redirects, and treats advertised risky methods as descriptive evidence rather than proof of exploitability.

## Roadmap

- session-aware authenticated web workflows, form-aware navigation, and broader bounded safe-active DAST
- authenticated SSH, SMB, WinRM, database, and network-device assessment
- Active Directory and identity-security assessment
- cloud posture assessment for AWS, Azure, and GCP
- container, image, Kubernetes, and infrastructure-as-code assessment
- secrets, sensitive-data, and exposed-credential discovery
- SBOM, VEX, package, and software-supply-chain intelligence
- compliance and configuration-audit packs
- HTML, PDF, SARIF, CSV, and machine-to-machine export formats
- scheduled and distributed scan workers with APIs and webhooks
- sandboxed, approval-gated exploit validation for explicitly authorized environments

## License

NightRecon is licensed under the MIT License.


