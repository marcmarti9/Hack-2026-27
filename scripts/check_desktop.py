"""Ejercita la interfaz con el dataset oficial en un perfil temporal."""
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from time import monotonic
from unittest.mock import patch

from PySide6.QtCore import QTimer
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QComboBox, QDialog, QPlainTextEdit, QPushButton


def wait_for(condition, description: str, timeout: float = 60) -> None:
    deadline = monotonic() + timeout
    while not condition():
        if monotonic() > deadline:
            raise AssertionError(f"Tiempo agotado: {description}")
        QTest.qWait(30)


def check(app, window, home, password, output):
    from apps.backend.tools import db
    from apps.desktop.reports import read_report
    from apps.desktop.review import investigate

    window.show()
    if output:
        app.processEvents()
        window.grab().save(str(output.with_name("vigia-acceso.png")))
    assert window.login_button.text() == "Iniciar sesión"
    window.username.setText("Analista local")
    window.password.setText(password)
    window.confirm.setText(password)
    window.login_button.click()
    assert 0 < window.loading_mark.opening < 1
    if output:
        QTest.qWait(180)
        window.grab().save(str(output.with_name("vigia-carga.png")))
    wait_for(lambda: hasattr(window, "workbench"), "importación y mesa")
    work = window.workbench
    assert work.dataset_total == 11061
    assert work.table.rowCount() == 50
    work.next.click()
    wait_for(lambda: work.offset == 50, "página siguiente")
    work.query.setText("ALR-20261010-011795")
    work.search.click()
    wait_for(lambda: work.total == 1, "búsqueda de alerta")
    assert work.selected["alert_id"] == "ALR-20261010-011795"
    work.question.setText("¿Qué pasó en EDR-0123412?")
    work.send.click()
    wait_for(lambda: window.job is None, "consulta en chat")
    assert "EDR-0123412 (edr_events)" in work.chat.toPlainText()

    response = {"verdict": "true_positive", "confidence": 91, "summary": "Propuesta simulada.",
                "citations": ["EDR-0123412"]}
    challenge = {**response, "summary": "Contraste simulado.", "confidence": 77}
    with patch("apps.desktop.review.claude_message", side_effect=[json.dumps(response), json.dumps(challenge)]):
        failures = []

        def drive_detail():
            dialog = app.activeModalWidget()
            try:
                assert isinstance(dialog, QDialog)
                controls = {button.text(): button for button in dialog.findChildren(QPushButton)}
                controls["Analizar y contrastar con Claude"].click()
                wait_for(lambda: window.job is None, "segunda pasada")
                text = dialog.findChild(QPlainTextEdit, "reviewProcess").toPlainText()
                assert "Confianza estimada por test-model: 77%" in text
                assert "Contraste simulado." in text and "EDR-0123412" in text
                if output:
                    dialog.grab().save(str(output.with_name("vigia-detalle.png")))
                assert controls["Aceptar"].isEnabled()
            except BaseException as error:
                failures.append(error)
            finally:
                dialog.close()

        QTimer.singleShot(100, drive_detail)
        work.table.cellWidget(0, 6).findChildren(QPushButton)[0].click()
        if failures:
            raise failures[0]

    with patch("apps.desktop.review.claude_message", side_effect=[
        json.dumps(response), json.dumps({**challenge, "verdict": "false_positive"})
    ]):
        disputed = investigate(work.selected, True)
        assert disputed["verdict"] == "needs_more_info" and disputed["confidence"] is None
    with patch("apps.desktop.review.claude_message", side_effect=[
        json.dumps(response), json.dumps({**challenge, "citations": ["EDR-9999999"]})
    ]):
        invalid = investigate(work.selected, True)
        assert invalid["verdict"] == "needs_more_info" and invalid["review_error"]

    intelligence_id = "ALR-20261009-011792"
    intelligence = investigate(db.get_alert(intelligence_id))
    assert any(record["tip"] for record in intelligence["context"]["inteligencia"])
    window.reviews.save_analysis(intelligence_id, intelligence)
    stored_intel = window.reviews.all()[intelligence_id]["analysis"]["context"]["inteligencia"]
    assert any(isinstance(record["tip"]["first_seen"], str) for record in stored_intel if record["tip"])

    work.table.cellWidget(0, 6).findChildren(QPushButton)[1].click()
    assert work.table.item(0, 3).text() == "Validada"
    assert work.table.item(0, 4).text() == "Verdadero positivo"
    assert not window.reviews.decide(work.selected["alert_id"], "false_negative", "corrected", "Otro")
    work.query.clear()
    work.search.click()
    wait_for(lambda: work.total == 11061, "restaurar cola")
    if output:
        window.grab().save(str(output))
    work.verdict.setCurrentIndex(work.verdict.findData("done"))
    wait_for(lambda: work.total == 1, "filtro de revisadas")
    work.day_filter.setChecked(True)
    wait_for(lambda: window.job is None, "filtro de fecha")
    assert work.total == 0
    work._navigate(1)
    wait_for(lambda: work.stats_loaded, "estadísticas")
    assert "1 decisión registrada" in work.stats_total.text()
    if output:
        window.grab().save(str(output.with_name("vigia-estadisticas.png")))
    work._navigate(2)
    wait_for(lambda: work.report_loaded, "informe diario")
    assert work.hour_totals
    work.hour.setValue(23)
    work.play.click()
    wait_for(lambda: work.hour.value() > 0, "reproducción")
    work.play.click()
    report = home / "ejemplo.jsonl"
    report.write_text(json.dumps({"alert_id": "test", "created_at": "2026-11-01T15:32:00Z",
                                  "severity": "critical", "source_product": "EDR"}) + "\n")
    work.report_rows = read_report(report)
    work._refresh_report()
    wait_for(lambda: window.job is None, "informe importado")
    assert work.hour_totals == {15: 1}
    work.hour.setValue(15)
    assert "EDR · test" in work.replay_signals.text()
    if output:
        window.grab().save(str(output.with_name("vigia-informe.png")))

    work._logout()
    window.password.setText("contraseña incorrecta")
    window.login_button.click()
    assert window.login_notice.text() == "Contraseña incorrecta."
    wait_for(window.login_button.isEnabled, "límite de reintento")
    window.password.setText(password)
    window.login_button.click()
    wait_for(lambda: window.job is None and not window.transitioning, "segundo inicio de sesión")
    assert window.workbench.reviews["ALR-20261010-011795"]["decision"] == "accepted"
    assert window.account.name() == "Analista local"
    assert password.encode() not in window.account.path.read_bytes()
    work = window.workbench
    work.query.setText("ALR-20261005-000172")
    work.search.click()
    wait_for(lambda: work.total == 1, "lote filtrado")
    proposal = {**response, "citations": ["WAF-0001840"]}
    with patch("apps.desktop.review.claude_message", side_effect=[json.dumps(proposal)] * 2) as transport:
        work.prepare.click()
        wait_for(lambda: window.job is None, "preparar lote")
        assert transport.call_count == 2
    assert work.table.item(0, 3).text() == "Por decidir"

    def correct():
        dialog = app.activeModalWidget()
        choice = dialog.findChild(QComboBox)
        choice.setCurrentIndex(choice.findData("false_positive"))
        next(control for control in dialog.findChildren(QPushButton)
             if control.text() == "Registrar decisión").click()

    QTimer.singleShot(100, correct)
    work.table.cellWidget(0, 6).findChildren(QPushButton)[2].click()
    assert work.table.item(0, 3).text() == "Corregida"
    assert work.table.item(0, 4).text() == "Falso positivo"
    window.close()


def main() -> None:
    app = QApplication([])
    with TemporaryDirectory() as path:
        home = Path(path)
        os.environ["VIGIA_OUT_DIR"] = str(home / "index")
        output = Path(value) if (value := os.getenv("VIGIA_DESKTOP_SCREENSHOT")) else None
        from apps.desktop.window import Window
        with patch.dict(os.environ, {"ANTHROPIC_MODEL": "test-model", "ANTHROPIC_API_KEY": "test-key"}):
            check(app, Window(home), home, "contraseña de prueba", output)
    app.quit()
    print("Vigía: sesión, ojo durante carga, 11.061 alertas, búsqueda, fecha y veredicto, chat local, "
          "contraste adversarial simulado, decisiones persistentes, estadísticas y reproducción diaria.")


if __name__ == "__main__":
    main()
