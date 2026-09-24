# NightRecon

NightRecon is a modular reconnaissance and penetration-testing platform designed for authorized security assessments.

> Use NightRecon only against systems you own or have explicit permission to test.

## Current Version

**v0.11.0**

NightRecon now includes scope-enforced concurrent TCP scanning, concurrent service detection, passive service fingerprinting, bounded banner detection, HTTP and HTTPS service intelligence, TLS certificate inspection, HTTP security-header analysis, structured software identity, opt-in NVD vulnerability intelligence, structured scan reports, target resolution, audit logging, and runtime configuration.

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

## Security Model

NightRecon is designed around explicit authorization and scope enforcement.

Future scanning components should not operate directly on arbitrary input. Targets must first pass through NightRecon's validation and scope authorization layers.

Vulnerability intelligence is evidence enrichment, not exploitation. An NVD/CPE match does not prove that a detected service is exploitable in its deployed context. CVSS values are reported as severity metadata and should not be treated as a complete risk assessment.

## Roadmap

- structured logging
- configuration management
- host discovery
- TCP port scanning
- service identification
- reporting

## License

NightRecon is licensed under the MIT License.


