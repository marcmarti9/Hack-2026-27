"""Punto de entrada del ejecutable de Vigía."""
import os
import sys
from pathlib import Path

from PySide6.QtCore import QStandardPaths
from PySide6.QtWidgets import QApplication


def main() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName("Vigia")
    app.setApplicationDisplayName("Vigía")
    home = Path(QStandardPaths.writableLocation(QStandardPaths.StandardLocation.AppLocalDataLocation))
    os.environ.setdefault("VIGIA_OUT_DIR", str(home / "index"))

    from apps.desktop.window import Window
    window = Window(home)
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
