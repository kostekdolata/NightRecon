# NightRecon Privilege Model

## Locked product rule

Every Night instance must run with the operating-system privilege required to
perform its specialist role completely.

This rule applies to every current and future Night, including:

- Red Night;
- White Night;
- Blue Night;
- Purple Night;
- Black Night;
- any future NightRecon specialist Night.

It applies equally to:

- a Night installed and launched on its own;
- the same Night running inside a composed/full-stack NightRecon installation;
- a Night running from its Live/bootable appliance profile;
- service-hosted or interactive Night execution.

The deployment shape must not reduce the Night's capability by forcing it into
an artificially unprivileged OS account, restricted sandbox, or capability set
that blocks legitimate authorized work required by that Night.

## Platform interpretation

- Linux and Live environments: root-equivalent execution when the Night is active.
- Windows: elevated Administrator or appropriately privileged service execution.
- Future supported platforms: the platform-equivalent privileged execution model
  required for complete Night capability.

## Privilege is not authorization

Operating-system privilege and NightRecon authorization are separate layers.

OS privilege answers:

> Can the Night technically perform the operation on this platform?

NightRecon authorization answers:

> Is this Night allowed to perform this operation in this engagement now?

Running a Night with privileged OS access must never imply target authorization,
engagement approval, destructive-operation approval, or permission to exceed
scope.

The following controls remain authoritative regardless of OS privilege:

- engagement and target scope;
- authorization state;
- approval requirements;
- action and impact budgets;
- revocation and emergency stop;
- destructive/high-impact operation gates;
- evidence and audit requirements;
- cleanup requirements;
- data-handling and retention policy;
- explicit operator confirmation where required.

## Deployment parity rule

A Night must have the same required privilege model across its supported
deployment profiles.

For example, Red Night must not run privileged in Live mode but unprivileged in
standalone or full-stack mode if that would reduce its assessment capability.

Likewise, White, Blue, Purple, Black, and future Nights must not lose required
capabilities merely because they are launched from a different NightRecon
deployment shape.

## Engineering rule

Future Night development must treat required OS privilege as a capability
requirement, not as the primary safety boundary.

Safety boundaries belong in NightRecon's authorization, policy, approval,
budget, revocation, evidence, cleanup, and explicit destructive-action controls.

Privilege reduction may still be used for helper processes that do not require
full Night capability, but the primary Night runtime must not be restricted in a
way that prevents the Night from delivering its intended specialist outcome.
