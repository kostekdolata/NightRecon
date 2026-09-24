# NightRecon

NightRecon is a modular reconnaissance and penetration-testing platform designed for authorized security assessments.

> Use NightRecon only against systems you own or have explicit permission to test.

## Current Version

**v0.14.0**

NightRecon now includes scope-enforced concurrent TCP scanning, concurrent service detection, passive service fingerprinting, bounded banner detection, HTTP and HTTPS service intelligence, TLS certificate inspection, HTTP security-header analysis, structured software identity, opt-in NVD vulnerability intelligence with match evidence and descriptive summaries, opt-in CISA KEV and FIRST EPSS threat context, an extensible assessment-check engine with built-in and third-party plugins, structured scan reports, target resolution, audit logging, and runtime configuration.

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
- CLI display of detected services and observed banners
- Service connection-failure reporting without aborting the scan
- Structured completed scan reports
- Per-port result storage
- CIDR active scanning blocked until explicitly implemented

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

Enable vulnerability intelligence explicitly:

`nightrecon scan 127.0.0.1 --scope 127.0.0.1 --vuln-lookup`

Add external exploitation context to the resulting CVE findings:

`nightrecon scan 127.0.0.1 --scope 127.0.0.1 --vuln-lookup --threat-context`

Inspect available built-in and installed assessment checks:

`nightrecon checks list`

List only web-family checks:

`nightrecon checks list --family web`

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


## Security Model

NightRecon is designed around explicit authorization and scope enforcement.

Future scanning components should not operate directly on arbitrary input. Targets must first pass through NightRecon's validation and scope authorization layers.

Vulnerability intelligence is evidence enrichment, not exploitation. An NVD/CPE match does not prove that a detected service is exploitable in its deployed context. CVSS values are reported as severity metadata and should not be treated as a complete risk assessment.

NightRecon preserves the provider match basis and exact identifier used to obtain each vulnerability record. Summary counts and maximum observed CVSS are descriptive evidence only; they are not a NightRecon risk score.

Threat context is kept separate from CVE matching: CISA KEV indicates known exploitation evidence, while FIRST EPSS reports a probability/percentile signal. Neither is treated as proof that a particular NightRecon target is exploitable.

Assessment checks are gated by explicit scope authorization and declared intrusiveness. Passive and safe-active checks are the default ceiling. The ordinary scan CLI intentionally does not expose destructive checks; higher-impact validation belongs behind a separate approval-gated workflow rather than an ordinary scan flag.

## Roadmap

- host discovery and network topology mapping
- deeper service and operating-system fingerprinting
- declarative check-pack format and signed/updateable check feeds
- web crawling, content discovery, and DAST assessment
- authenticated SSH, SMB, WinRM, database, and network-device assessment
- Active Directory and identity-security assessment
- cloud posture assessment for AWS, Azure, and GCP
- container, image, Kubernetes, and infrastructure-as-code assessment
- secrets, sensitive-data, and exposed-credential discovery
- SBOM, VEX, package, and software-supply-chain intelligence
- compliance and configuration-audit packs
- asset inventory, historical comparison, and regression detection
- HTML, PDF, SARIF, CSV, and machine-to-machine export formats
- scheduled and distributed scan workers with APIs and webhooks
- sandboxed, approval-gated exploit validation for explicitly authorized environments

## License

NightRecon is licensed under the MIT License.


