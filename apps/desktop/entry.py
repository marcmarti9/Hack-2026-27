"""Punto de entrada del ejecutable de Vigía."""
import os
import sys
from contextlib import ExitStack
from pathlib import Path
from tempfile import TemporaryDirectory

from PySide6.QtCore import QStandardPaths, QTimer
from PySide6.QtWidgets import QApplication


def main() -> int:
    demo, present = "--demo" in sys.argv, "--present" in sys.argv
    if present and not demo:
        raise SystemExit("--present requiere --demo")
    app = QApplication([arg for arg in sys.argv if arg not in {"--demo", "--present"}])
    app.setApplicationName("Vigia")
    app.setApplicationDisplayName("Vigía")
    home = Path(QStandardPaths.writableLocation(QStandardPaths.StandardLocation.AppLocalDataLocation))
    with ExitStack() as stack:
        if demo:
            os.environ["VIGIA_OUT_DIR"] = str(home / "demo-index")
            os.environ["OPENAI_API_KEY"] = ""
            home = Path(stack.enter_context(TemporaryDirectory(prefix="vigia-demo-")))
        else:
            os.environ.setdefault("VIGIA_OUT_DIR", str(home / "index"))

        from apps.desktop.window import Window
        window = Window(home, demo=demo, present=present)
        window.show()
        if present:
            QTimer.singleShot(0, window.enter_demo)
        return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
