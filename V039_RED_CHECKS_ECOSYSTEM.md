# v0.39.0 Red Checks Ecosystem

The Red Checks ecosystem builds on the existing cryptographic pack/feed stack:
Ed25519-signed declarative packs, signed feeds, SHA-256 pinning, immutable local
versions, bounded HTTPS downloads, and no arbitrary code execution.

v0.39 adds a local ecosystem policy and searchable catalog. An already-verified
pack is eligible only when its signer is trusted, check count is bounded,
declared intrusiveness is within policy, and every required capability is
explicitly allowed. Catalog entries retain signer, feed, digest, families,
services, tags, capabilities, and eligibility reasons.

The ecosystem layer does not weaken or replace signature verification. It adds a
second local-policy gate after cryptographic verification and before operators
choose packs for assessment.
