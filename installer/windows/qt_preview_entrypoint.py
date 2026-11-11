"""Qt desktop entrypoint with explicit read-only engagement selection.

Without arguments, the overview remains disconnected and non-operational.
"""
import sys

from red_night_app.qt_explicit_snapshot import load_explicit_snapshot


def main() -> None:
    snapshot = load_explicit_snapshot(sys.argv[1:])
    # Import Qt only after argument and evidence validation.
    from PySide6.QtWidgets import QApplication
    from red_night_app.qt_operations_shell import build_window

    app = QApplication.instance() or QApplication(sys.argv[:1])
    window = build_window(operations_snapshot=snapshot)
    window.show()
    app.exec()


if __name__ == "__main__":
    main()
