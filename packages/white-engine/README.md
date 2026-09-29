# White Night engine distribution

`nightrecon-white-engine` is the independently packaged White Night control-plane
engine.

The `0.1.0a4` development package adds the immutable White Night approval workflow engine on top of the deterministic engagement/ROE and policy-compiler foundation. Approval requests are bound to one engagement, compiled-policy fingerprint, capability, target, impact, requester, and expiry window. Single, dual, and quorum approval, separation of duties, bounded delegation, rejection, escalation, revocation, replay-resistant grants, and hash-linked decision evidence remain local and network-free.

The engine depends only on the mandatory `nightrecon-shared-core==0.41.0`
package. It does not depend on Red, Blue, Purple, Black, or the legacy
`nightrecon` distribution.

Future White batches will add engagement, ROE, approval, evidence-custody,
audit, exercise-control, and reporting behavior behind this package boundary.
The same engine package is intended for standalone, composed full-stack, and
White Night Live USB deployments.
