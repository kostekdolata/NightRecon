"""Separate Red Night application distribution, backed by shared NightRecon."""


def main() -> None:
    from nightrecon.red_night import main as run_red_night

    run_red_night()
