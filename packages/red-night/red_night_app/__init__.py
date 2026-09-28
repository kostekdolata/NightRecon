"""Separate Red Night application distribution backed directly by the Red engine."""


def main() -> None:
    from nightrecon_red_engine.red_cli import main as run_red_night

    run_red_night()
