"""Application entry point.

Enables SeDebugPrivilege (best effort), then launches the Qt app. The process
list is complete either way; running elevated is what allows opening system
and other users' processes for memory maps and reads. Pass --elevate to
relaunch through UAC.
"""

from __future__ import annotations

import sys

from PySide6.QtWidgets import QApplication

from .ui import MainWindow
from .ui.theme import APP_QSS
from .win32 import privileges


def should_relaunch_elevated(argv: list[str]) -> bool:
    """True if the user asked to elevate and we aren't already elevated."""
    return "--elevate" in argv and not privileges.is_elevated()


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv if argv is None else argv

    # Best-effort: enable SeDebugPrivilege if we already have the rights.
    privileges.enable_se_debug_privilege()

    if should_relaunch_elevated(argv) and privileges.relaunch_as_admin():
        return 0  # elevated instance launched; this one exits

    app = QApplication(argv)
    app.setApplicationName("MemDo")
    app.setStyleSheet(APP_QSS)

    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
