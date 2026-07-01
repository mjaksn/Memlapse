"""Application entry point.

Enables SeDebugPrivilege (best effort), then launches the Qt app. Running
elevated is optional for the live monitor but unlocks the full process list;
pass --elevate to relaunch through UAC.
"""

from __future__ import annotations

import sys

from PySide6.QtWidgets import QApplication

from .ui import MainWindow
from .win32 import privileges


def main() -> int:
    # Best-effort: enable SeDebugPrivilege if we already have the rights.
    privileges.enable_se_debug_privilege()

    if "--elevate" in sys.argv and not privileges.is_elevated():
        if privileges.relaunch_as_admin():
            return 0  # elevated instance launched; this one exits

    app = QApplication(sys.argv)
    app.setApplicationName("MemDo")

    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
