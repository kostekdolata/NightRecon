# NightRecon

NightRecon is a modular reconnaissance and penetration-testing platform designed for authorized security assessments.

> Use NightRecon only against systems you own or have explicit permission to test.

## Current Version

**v0.5.1**

NightRecon now includes scope-enforced concurrent TCP scanning, service identification, bounded passive banner detection, structured scan reports, target resolution, audit logging, and runtime configuration.

## Features

- TCP connect scanning for authorized single-host targets
- Port lists and port ranges
- Concurrent scanning with configurable worker limits
- IPv4 and IPv6 TCP scanning
- Open-port detection
- Service identification for common TCP services
- Bounded passive banner detection on confirmed open ports
- Graceful banner timeout handling
- Structured service-detection results
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

A target outside the explicitly supplied scope is rejected:

nightrecon scan 192.168.2.25 --scope 192.168.1.0/24

## Development Setup

Create and activate a virtual environment:

py -m venv .venv
.\.venv\Scripts\Activate.ps1

Install NightRecon in editable mode:

python -m pip install -e .

Run the test suite:

python -m unittest discover -s tests -v

## Security Model

NightRecon is designed around explicit authorization and scope enforcement.

Future scanning components should not operate directly on arbitrary input. Targets must first pass through NightRecon's validation and scope authorization layers.

## Roadmap

- structured logging
- configuration management
- host discovery
- TCP port scanning
- service identification
- HTTP and HTTPS reconnaissance
- TLS inspection
- security-header analysis
- vulnerability intelligence
- reporting

## License

NightRecon is licensed under the MIT License.


