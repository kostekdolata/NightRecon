# NightRecon Shared Core

Development-preview package for policy that must remain common across independently installable NightRecon applications.

Current exported surface:

- edition identity and fail-closed command ownership policy
- explicit target parsing
- explicit scope authorization

This package is intentionally network-free and does not contain scanners, protocol clients, browser automation, credential providers, exploit/validation engines, or Red-only graph logic.

During the migration it imports the canonical implementations from the legacy `nightrecon` source tree. The next package-isolation step will move those implementations into this distribution so Red Night no longer needs the complete legacy runtime for policy.
