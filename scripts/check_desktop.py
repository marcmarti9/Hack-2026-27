"""Ejercita la interfaz con el dataset oficial en un perfil temporal."""
import io
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from time import monotonic
from unittest.mock import patch

from PySide6.QtCore import QTimer
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QComboBox, QDialog, QPlainTextEdit, QPushButton, QTabWidget


def wait_for(condition, description: str, timeout: float = 60) -> None:
    deadline = monotonic() + timeout
    while not condition():
        if monotonic() > deadline:
            raise AssertionError(f"Tiempo agotado: {description}")
        QTest.qWait(30)


def check(app, window, home, password, output):
    from apps.backend.tools import db
    from apps.desktop.assistant import openai_message
    from apps.desktop.case_data import case_sections, demo_process, soc_status
    from apps.desktop.demo import archive, for_alert
    from apps.desktop.reports import read_report
    from apps.desktop.review import REVIEW_SCHEMA, investigate

    fake_response = {"status": "completed", "output": [
        {"type": "reasoning"},
        {"type": "message", "content": [{"type": "output_text", "text": "respuesta"}]},
    ]}
    with patch("apps.desktop.assistant.build_opener") as opener:
        opener.return_value.open.return_value = io.BytesIO(json.dumps(fake_response).encode())
        assert openai_message("instrucciones", {"dato": "prueba"}, schema=REVIEW_SCHEMA) == "respuesta"
        request = opener.return_value.open.call_args.args[0]
        assert request.full_url == "https://api.openai.com/v1/responses"
        assert request.get_header("Authorization") == "Bearer test-key"
        body = json.loads(request.data)
        assert body["store"] is False and body["text"]["format"]["strict"]
    assert soc_status("2026-10-23T05:59:59Z") == "SOC cerrado"
    assert soc_status("2026-10-23T06:00:00Z") == "SOC abierto"
    assert soc_status("2026-10-26T07:00:00Z") == "SOC abierto"
    assert soc_status("2026-10-26T19:00:00Z") == "SOC cerrado"

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
    assert work.dataset_total == 11061 and work.schedule == (11061, 3503)
    data = archive()
    assert len(data["tickets"]) == 17 and len(data["incidents"]) == 13 and len(data["closed"]) == 10974
    assert db.alert_schedule(ids=list(data["ticket_by_alert"])) == (87, 54)
    for entry in data["tickets"]:
        key = entry["alert_ids"][0]
        ticket, incident, closed = for_alert(key)
        assert ticket["ticket_id"] == entry["ticket_id"] and not closed
        assert any(entry["ticket_id"] in line for line in demo_process(ticket, closed))
        sections = case_sections({"alert_id": key}, {}, [])
        assert entry["alert_ids"][-1] in sections["Entidades"]
        if incident:
            assert incident["incident_id"] in sections["Línea de tiempo"]
    work._navigate(3)
    assert work.sections.ticket_table.rowCount() == 17
    work._navigate(5)
    assert work.sections.document.count() == 11
    work.sections.editor.insertPlainText("Añadido de prueba para la skill.")
    assert work.sections.save.isEnabled()
    work.sections.save.click()
    assert window.reviews.document("SKILL")[0] == 1
    work._navigate(4)
    assert work.sections.history_table.item(0, 1).text() == "Documento guardado"
    work._navigate(0)
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
                "citations": ["EDR-0123412"], "questions": ["¿Se confirmó el acceso inicial?"],
                "actions": ["Verificar el equipo con N2."]}
    challenge = {**response, "summary": "Contraste simulado.", "confidence": 77}
    with patch("apps.desktop.review.openai_message", side_effect=[json.dumps(response), json.dumps(challenge)]) as transport:
        failures = []

        def drive_detail():
            dialog = app.activeModalWidget()
            try:
                assert isinstance(dialog, QDialog)
                controls = {button.text(): button for button in dialog.findChildren(QPushButton)}
                wait_for(lambda: window.job is None, "precarga de datos")
                controls["Analizar y contrastar con OpenAI"].click()
                wait_for(lambda: window.job is None, "segunda pasada")
                text = dialog.findChild(QPlainTextEdit, "reviewProcess").toPlainText()
                assert "Confianza estimada por test-model: 77%" in text
                assert "Contraste simulado." in text and "EDR-0123412" in text
                assert "Fiscal de la demo" in text and "TKT-20261009-011790" in text
                assert "¿Se confirmó el acceso inicial?" in text and "Total " in text
                tabs = dialog.findChild(QTabWidget)
                assert [tabs.tabText(i) for i in range(tabs.count())] == [
                    "Proceso de revisión", "Datos consultados", "Entidades", "Línea de tiempo", "Acciones", "Historial"
                ]
                assert "INC-20261009-011790" in tabs.widget(3).toPlainText()
                assert "Verificar el equipo con N2." in tabs.widget(4).toPlainText()
                proposal, adversary = [call.args[1] for call in transport.call_args_list]
                assert proposal["guía_editable"]["SKILL"]["revision"] == 1
                assert "Añadido de prueba" in proposal["guía_editable"]["SKILL"]["text"]
                assert adversary["propuesta"]["summary"] == "Propuesta simulada."
                analysis = window.reviews.history(work.selected["alert_id"])[0]["data"]
                assert analysis["challenge"]["summary"] == "Contraste simulado."
                assert analysis["sent_events"] == proposal["eventos"]
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

    with patch("apps.desktop.review.openai_message", side_effect=[
        json.dumps(response), json.dumps({**challenge, "verdict": "false_positive"})
    ]):
        disputed = investigate(work.selected, True)
        assert disputed["verdict"] == "needs_more_info" and disputed["confidence"] is None
    with patch("apps.desktop.review.openai_message", side_effect=[
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
    assert "31,7% (3503/11061)" in work.stats_schedule.text()
    assert "62,1% (54/87)" in work.stats_schedule.text()
    if output:
        window.grab().save(str(output.with_name("vigia-estadisticas.png")))
    work._navigate(2)
    wait_for(lambda: work.report_loaded, "informe diario")
    assert work.hour_totals
    work.presentation.click()
    assert window.isFullScreen()
    work.presentation.click()
    assert not window.isFullScreen()
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
    assert "100,0% (1/1)" in work.report_schedule.text()
    assert "SOC cerrado" in work.hour_notice.text()
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
    assert window.reviews.document("SKILL")[0] == 1
    assert [entry["kind"] for entry in window.reviews.history("ALR-20261010-011795")] == ["Aceptada", "Análisis"]
    assert password.encode() not in window.account.path.read_bytes()
    work = window.workbench
    work.query.setText("ALR-20261005-000172")
    work.search.click()
    wait_for(lambda: work.total == 1, "lote filtrado")
    proposal = {**response, "citations": ["WAF-0001840"]}
    with patch("apps.desktop.review.openai_message", side_effect=[json.dumps(proposal)] * 2) as transport:
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
        with patch.dict(os.environ, {"OPENAI_MODEL": "test-model", "OPENAI_API_KEY": "test-key"}):
            check(app, Window(home), home, "contraseña de prueba", output)
    app.quit()
    print("Vigía: sesión, ojo durante carga, 11.061 alertas, búsqueda, fecha y veredicto, chat local, "
          "contraste adversarial simulado, decisiones persistentes, estadísticas y reproducción diaria.")


if __name__ == "__main__":
    main()
