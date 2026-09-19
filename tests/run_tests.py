"""NightRecon test runner with final result summary."""

from __future__ import annotations

import sys
import unittest


def main() -> int:
    loader = unittest.TestLoader()
    suite = loader.discover(
        start_dir="tests",
        pattern="test_*.py",
    )

    runner = unittest.TextTestRunner(
        verbosity=2,
    )

    result = runner.run(suite)

    tests_done = result.testsRun
    skipped = len(result.skipped)
    failed = len(result.failures) + len(result.errors)
    passed = tests_done - skipped - failed

    print()
    print("=" * 40)
    print("NightRecon Test Run Finished")
    print("=" * 40)
    print(f"Tests done : {tests_done}")
    print(f"Passed     : {passed}")
    print(f"Skipped    : {skipped}")
    print(f"Failed     : {failed}")

    if result.wasSuccessful():
        print("Result     : PASSED")
        exit_code = 0
    else:
        print("Result     : FAILED")
        exit_code = 1

    print("=" * 40)

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
