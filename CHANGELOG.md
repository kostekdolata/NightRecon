# Changelog

All notable NightRecon/Red Night release milestones are recorded here.

## [0.40.0] - 2026-09-28

### Red Night

- Stabilized the dedicated Red Night application, Red engine, and shared core at
  version 0.40.0.
- Added engagement lifecycle/workspace policy and persistent authorization audit.
- Added authorization-first read-only identity intelligence.
- Added approval-gated controlled validation.
- Added the unified evidence-backed attack graph.
- Added the policy-constrained plan-only Red operator.
- Added remediation and controlled retest lifecycle.
- Added signed Red Checks ecosystem policy and catalog.
- Added authorization-first normalized cloud/hybrid intelligence boundary.
- Added deterministic stack-wide release acceptance across the v0.33-v0.40
  integration path.

### Compatibility

- Kept the legacy `nightrecon` compatibility distribution at 0.31.0 while
  pinning stable Red engine/shared-core 0.40.0 dependencies.
- Preserved standalone Red installation and combined legacy/Red installation
  smoke coverage.

### Safety

- No exploit payloads, credential harvesting, arbitrary command execution,
  cloud write operations, persistence mechanisms, privilege changes, or
  autonomous execution were added by this release.

Detailed release notes: [V040_RELEASE_NOTES.md](V040_RELEASE_NOTES.md)

Earlier release history remains documented in [ROADMAP.md](ROADMAP.md) and the
guarded annotated tags.
