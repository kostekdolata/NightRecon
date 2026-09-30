"""Behavioral tests for the White Night Live boot-mode contract."""

from __future__ import annotations

from importlib.machinery import SourceFileLoader
from importlib.util import module_from_spec, spec_from_loader
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SELECTOR = (
    ROOT
    / "live"
    / "white-night"
    / "config"
    / "includes.chroot"
    / "usr"
    / "local"
    / "sbin"
    / "white-night-live-mode-select"
)


def load_selector():
    loader = SourceFileLoader("white_live_mode_select", str(SELECTOR))
    spec = spec_from_loader(loader.name, loader)
    if spec is None:
        raise RuntimeError("unable to load White Night Live mode selector")
    module = module_from_spec(spec)
    loader.exec_module(module)
    return module


MODE = load_selector()


class WhiteLiveModeTests(unittest.TestCase):
    def test_default_is_ephemeral(self) -> None:
        self.assertEqual(MODE.select_mode("boot=live components"), "ephemeral")

    def test_all_explicit_modes_are_recognized(self) -> None:
        for mode in (
            "secure-workspace",
            "ephemeral",
            "recovery",
        ):
            with self.subTest(mode=mode):
                self.assertEqual(
                    MODE.select_mode(
                        f"boot=live nightrecon.live_mode={mode} components"
                    ),
                    mode,
                )

    def test_unknown_mode_fails_closed(self) -> None:
        with self.assertRaises(ValueError):
            MODE.select_mode(
                "boot=live nightrecon.live_mode=unknown components"
            )

    def test_duplicate_mode_parameter_fails_closed(self) -> None:
        with self.assertRaises(ValueError):
            MODE.select_mode(
                "nightrecon.live_mode=ephemeral "
                "nightrecon.live_mode=recovery"
            )

    def test_ephemeral_is_nonpersistent_and_auto_launches(self) -> None:
        state = MODE.mode_state("ephemeral")
        self.assertTrue(state["ready"])
        self.assertFalse(state["persistence_required"])
        self.assertTrue(state["application_auto_launch"])
        self.assertFalse(state["maintenance_only"])
        self.assertEqual(state["authorization_effect"], "none")

    def test_recovery_is_maintenance_only_and_does_not_auto_launch(self) -> None:
        state = MODE.mode_state("recovery")
        self.assertTrue(state["ready"])
        self.assertFalse(state["persistence_required"])
        self.assertFalse(state["application_auto_launch"])
        self.assertTrue(state["maintenance_only"])
        self.assertEqual(state["authorization_effect"], "none")

    def test_secure_workspace_is_blocked_until_persistence_exists(self) -> None:
        state = MODE.mode_state("secure-workspace")
        self.assertFalse(state["ready"])
        self.assertTrue(state["persistence_required"])
        self.assertFalse(state["application_auto_launch"])
        self.assertEqual(
            state["blocked_reason"],
            "encrypted-persistence-not-configured",
        )
        self.assertEqual(state["authorization_effect"], "none")


if __name__ == "__main__":
    unittest.main()
