"""Ejercita la interfaz con el dataset oficial en un perfil temporal."""
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from time import monotonic

from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication


def wait_for(condition, label: str, timeout: float = 60) -> None:
    deadline = monotonic() + timeout
    while not condition():
        if monotonic() > deadline:
            raise AssertionError(f"Tiempo agotado: {label}")
        QTest.qWait(30)


def main() -> None:
    app = QApplication([])
    with TemporaryDirectory() as path:
        home = Path(path)
        os.environ["VIGIA_OUT_DIR"] = str(home / "index")

        from apps.desktop.window import Window

        window = Window(home)
        window.show()
        window.username.setText("Analista local")
        password = "contraseña de prueba"
        window.password.setText(password)
        window.confirm.setText(password)
        window.login_button.click()

        wait_for(lambda: hasattr(window, "table") and window.job is None, "importación y mesa")
        assert window.total == 11061
        assert window.table.rowCount() == 100
        window.next.click()
        wait_for(lambda: window.offset == 100, "página siguiente")
        window.query.setText("ALR-20261010-011795")
        window.search.click()
        wait_for(lambda: window.total == 1, "búsqueda de alerta")
        assert "ALR-20261010-011795" in window.detail.toPlainText()
        window.question.setText("¿Qué pasó en EDR-0123412?")
        window.send.click()
        wait_for(lambda: window.job is None, "consulta en chat")
        assert "EDR-0123412 (edr_events)" in window.chat.toPlainText()
        window.logout.click()
        window.password.setText("contraseña incorrecta")
        window.login_button.click()
        assert window.login_notice.text() == "Contraseña incorrecta."
        wait_for(window.login_button.isEnabled, "límite de reintento")
        window.password.setText(password)
        window.login_button.click()
        wait_for(lambda: window.job is None and window.total == 11061, "segundo inicio de sesión")
        assert window.account.name() == "Analista local"
        assert password.encode() not in window.account.path.read_bytes()
        if output := os.getenv("VIGIA_DESKTOP_SCREENSHOT"):
            window.grab().save(output)
        window.close()
    app.quit()
    print("Escritorio: alta, sesión, importación, 11.061 alertas, paginación, búsqueda, chat local y bloqueo de contraseña incorrecta.")


if __name__ == "__main__":
    main()
