"""Separate Red Night application distribution backed directly by the Red engine."""


def main() -> None:
    import os

    from .privilege import require_platform_privilege
    from nightrecon_red_engine.red_cli import main as run_red_night

    require_platform_privilege()
    os.environ["REDNIGHT_PRIVILEGED_OPERATOR_MODE"] = "1"
    run_red_night()
