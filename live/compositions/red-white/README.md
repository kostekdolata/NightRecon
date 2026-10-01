# Red + White Night composition profile

This directory is the source-controlled Batch 5 composition contract for running
Red Night and White Night in one NightRecon stack.

This slice is a composition profile, not yet a combined boot image.

The profile requires exactly these independently versioned distributions:

- nightrecon-shared-core
- nightrecon-red-engine
- nightrecon-red-night
- nightrecon-white-engine
- nightrecon-white-night

Composition rules:

- both Nights retain the OS privilege required for their full specialist role;
- Red and White remain independently installable and removable;
- neither Night imports or depends on the other Night's runtime;
- cross-Night state and cooperation use shared-core contracts only;
- installing both Nights has authorization effect `none`;
- active operations still pass shared-core scope, approval, budget, revocation,
  evidence, cleanup, and stop controls;
- host disks are never automatically mounted;
- the composition remains offline-capable.

A combined install smoke and combined Live image are subsequent Batch 5 slices.
