# v0.38.0 Remediation & Retest

Red Night v0.38 adds a persistent finding-remediation lifecycle:

open -> in-progress -> ready-for-retest -> verified/regressed

A finding can be closed as verified only when a controlled validation retest
returns NOT_CONFIRMED. A CONFIRMED retest marks the finding regressed/still
present. DENIED or ERROR validation results are inconclusive and leave the
finding ready for another retest.

The store records the last validation ID and retest state, rejects invalid
lifecycle transitions, and never silently converts an inconclusive test into a
successful remediation outcome.
