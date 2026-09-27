# Red Night application distribution (development preview)

This separately built package supplies the `red-night-app` command. It depends
on the NightRecon shared distribution, which contains the authorization core
and existing Red assessment engines. It does not install the future White,
Blue, Purple, or Black Night applications. Run `red-night-app --help` to see the
commands supported by the existing fail-closed Red gateway.

The shared NightRecon package also supplies the older `red-night` command.
These distinct script names keep installation and removal of either package
from changing the other command. Dedicated core/engine separation, optional
extras, and arbitrary combinations of all five Nights remain future work.
This development preview is not a completed Red Night release.
