# NightRecon Shared Core

Development-preview package for capabilities that must remain common across
independently installable NightRecon applications.

Current exported surface:

- edition identity and fail-closed command ownership policy
- explicit target parsing and scope authorization
- versioned, secret-free cross-Night evidence and engagement metadata contracts
- backend-neutral engagement-store protocol
- in-memory reference store
- portable deterministic JSON file store for standalone Nights
- backend-neutral workspace coordination, summaries, evidence breakdowns,
  conflict-safe merges, and portable exchange

The dependency direction is always:

`Night application -> nightrecon-shared-core`

The shared core must never depend on Red, Blue, White, Purple, Black, or the
legacy application runtime. It is intentionally network-free and contains no
scanners, protocol clients, browser automation, credential providers,
exploit/validation engines, or Night-specific graph logic.

Standalone Nights can use `FileEngagementStore` directly or `LocalWorkspace`
for a shared workspace root. Composed installations can provide another backend
implementing the same `EngagementStore` / `WorkspaceStore` semantics so
multiple Nights share evidence without direct Night-to-Night imports.

The portable store uses strict schema validation, immutable evidence IDs,
metadata conflict rejection, deterministic ordering, and atomic file replacement.
Engagements can be exported/imported while retaining source Night, provenance,
limitations, and metadata. Metadata carries only an authorization reference; it
never grants authorization to perform an active operation. Legacy
schema-version-1 envelopes without metadata remain readable.

The current file-backed local workspace assumes serialized writers. It is not a
concurrent multi-process database. Future full-stack workspace backends must add
locking/transactions while preserving the same conflict and authorization
semantics.
