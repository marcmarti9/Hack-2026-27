"""Ejercita la interfaz con el dataset oficial en un perfil temporal."""
import io
import json
import os
import sqlite3
from contextlib import closing
from pathlib import Path
from tempfile import TemporaryDirectory
from time import monotonic
from unittest.mock import patch

from PySide6.QtCore import QTimer, Qt
from PySide6.QtTest import QTest
from PySide6.QtWidgets import (
    QApplication, QComboBox, QDialog, QFileDialog, QLabel, QLineEdit, QMessageBox, QPlainTextEdit,
    QPushButton, QTableWidget, QTabWidget, QTextBrowser,
)


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
    from apps.desktop.defense import load_alerts
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
    assert window.dark
    window.username.setText("Analista local")
    login_theme = window.findChild(QPushButton, "themeToggle")
    login_theme.click()
    assert not window.dark and window.username.text() == "Analista local"
    login_theme.click()
    assert window.dark and window.settings.value("theme", type=str) == "dark"
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
    work.findChild(QPushButton, "themeToggle").click()
    assert not window.dark
    if output:
        app.processEvents()
        window.grab().save(str(output.with_name("vigia-claro.png")))
    work.findChild(QPushButton, "themeToggle").click()
    assert window.dark
    window.resize(990, 690)
    app.processEvents()
    assert not work.chat_panel.isVisible() and not work.chat_toggle.isChecked()
    if output:
        window.grab().save(str(output.with_name("vigia-cola-compacta.png")))
    window.resize(1440, 850)
    app.processEvents()
    assert work.chat_panel.isVisible() and work.chat_toggle.isChecked()
    assert work.rail_logo.isVisible() and not work.rail_eye.isVisible()
    work.menu_toggle.click()
    app.processEvents()
    assert work.rail.width() == 57 and work.rail_eye.isVisible() and not work.rail_logo.isVisible()
    assert work.nav.button(0).accessibleName() == "Inicio" and not work.nav.button(0).text()
    assert window.settings.value("menu_expanded", type=bool) is False
    if output:
        window.grab().save(str(output.with_name("vigia-menu-plegado.png")))
    work.nav.button(0).click()
    assert work.pages.currentIndex() == 0
    work.menu_toggle.click()
    assert work.rail_logo.isVisible() and work.nav.button(0).text() == "Inicio"
    with TemporaryDirectory(prefix="vigia-qa-copias-") as target:
        from apps.desktop.widgets import fade_in
        window.settings.setValue("reduced_motion", True)
        work._navigate(6)
        backup = work.backup_page
        fade_in(backup)
        assert backup.graphicsEffect() is None
        window.settings.setValue("reduced_motion", False)
        backup.local.addItem(target)
        backup.save.click()
        assert "guardados" in backup.status.text()
        backup.start.click()
        wait_for(lambda: window.job is None, "copia local")
        assert "1 de 1 destinos verificados" in backup.status.text()
        assert len(list(Path(target).glob("Vigia/*/*.zip"))) == 1
        if output:
            window.grab().save(str(output.with_name("vigia-copias.png")))
        work._navigate(0)
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
    work.triage_mode.setCurrentIndex(work.triage_mode.findData("guardia"))
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
                assert controls["Triar con datos locales"].isEnabled()
                with patch.object(QMessageBox, "question", return_value=QMessageBox.StandardButton.No) as decline:
                    controls["Analizar y contrastar con OpenAI"].click()
                    assert decline.call_args.args[-1] == QMessageBox.StandardButton.No
                transport.assert_not_called()
                with patch.object(QMessageBox, "question", return_value=QMessageBox.StandardButton.Yes):
                    controls["Analizar y contrastar con OpenAI"].click()
                wait_for(lambda: window.job is None, "segunda pasada")
                text = dialog.findChild(QTextBrowser, "reviewProcess").toPlainText()
                assert "Confianza estimada por test-model: 77%" in text
                assert "Contraste simulado." in text and "EDR-0123412" in text
                assert "Contraste archivado" in text and "TKT-20261009-011790" in text
                assert "¿Se confirmó el acceso inicial?" in text and "Total " in text
                tabs = dialog.findChild(QTabWidget)
                assert [tabs.tabText(i) for i in range(tabs.count())] == [
                    "Resumen", "Evidencias", "Entidades", "Línea de tiempo", "Acciones", "Historial"
                ]
                assert not tabs.findChildren(QPlainTextEdit)
                evidence = tabs.widget(1).findChild(QTextBrowser).toPlainText()
                assert "Cobertura de las evidencias" in evidence and "EDR-0123412" in evidence
                assert "Citas de la propuesta" in evidence and "Citas del contraste" in evidence
                event_choice = tabs.widget(1).findChild(QComboBox)
                event_choice.setCurrentText("EDR-0123412")
                displayed_event = []

                def capture_event(viewer):
                    assert viewer.windowTitle() == "EDR-0123412"
                    displayed_event.append(viewer.findChild(QPlainTextEdit).toPlainText())
                    return QDialog.DialogCode.Rejected

                with patch.object(QDialog, "exec", capture_event):
                    controls["Ver evento original"].click()
                    wait_for(lambda: displayed_event, "lectura del evento original")
                assert "EDR-0123412" in displayed_event[0] and not displayed_event[0].lstrip().startswith("{")
                assert "INC-20261009-011790" in tabs.widget(3).toPlainText()
                assert "Verificar el equipo con N2." in tabs.widget(4).toPlainText()
                guidance_failures = []

                def verify_guidance():
                    viewer = app.activeModalWidget()
                    try:
                        guide_tabs = viewer.findChild(QTabWidget)
                        assert guide_tabs.count() == 2
                        assert guide_tabs.tabText(0) == "RB-02 · v0"
                        assert guide_tabs.tabText(1) == "SKILL · v1"
                    except BaseException as error:
                        guidance_failures.append(error)
                    finally:
                        viewer.close()

                QTimer.singleShot(60, verify_guidance)
                controls["Ver guías"].click()
                if guidance_failures:
                    raise guidance_failures[0]
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
        work.table.setFocus()
        QTest.keyClick(work.table, Qt.Key.Key_Return)
        if failures:
            raise failures[0]
        assert transport.call_count == 2

    with patch("apps.desktop.review.openai_message", side_effect=[
        json.dumps(response), json.dumps({**challenge, "verdict": "false_positive"})
    ]):
        disputed = investigate(work.selected, True)
        assert disputed["verdict"] == "true_positive" and disputed["confidence"] is None
        assert disputed["review_error"] and not disputed["routing"]["automatic"]
    with patch("apps.desktop.review.openai_message", side_effect=[
        json.dumps(response), json.dumps({**challenge, "citations": ["EDR-9999999"]})
    ]):
        invalid = investigate(work.selected, True)
        assert invalid["verdict"] == "true_positive" and invalid["review_error"]

    intelligence_id = "ALR-20261009-011792"
    intelligence = investigate(db.get_alert(intelligence_id))
    assert any(record["tip"] for record in intelligence["context"]["inteligencia"])
    window.reviews.save_analysis(intelligence_id, intelligence)
    stored_intel = window.reviews.all()[intelligence_id]["analysis"]["context"]["inteligencia"]
    assert any(isinstance(record["tip"]["first_seen"], str) for record in stored_intel if record["tip"])

    work.queue_accept.click()
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
    assert work.empty_queue.isVisible() and work.reset_filters.isVisible()
    assert not work.queue_accept.isEnabled() and not work.queue_correct.isEnabled()
    work.reset_filters.click()
    wait_for(lambda: work.total == 11061, "limpiar filtros")
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
    accepted_alert = db.get_alert("ALR-20261010-011795")
    recent = investigate(accepted_alert, triage=True, mode="diurno")
    accepted_path = home / "expediente-aceptado.json"

    def export_accepted(dialog):
        summary = dialog.findChild(QTextBrowser, "reviewProcess").toPlainText()
        assert "Decisión humana vigente" in summary and "Ensayo del lote · histórico" in summary
        next(control for control in dialog.findChildren(QPushButton) if control.text() == "Exportar expediente").click()
        return QDialog.DialogCode.Rejected

    with patch.object(QFileDialog, "getSaveFileName", return_value=(str(accepted_path), "")), patch.object(
            QDialog, "exec", export_accepted):
        work._detail(accepted_alert, defense_result=recent)
    accepted_export = json.loads(accepted_path.read_text())
    accepted_result = accepted_export["resultado_lote"]
    assert accepted_result["persisted_decision"] == accepted_result["report"]["decision_actual"]["decision"] == "accepted"
    assert accepted_result["routing"] == accepted_result["report"]["routing"]
    assert accepted_result["routing"]["mode"] == "guardia"
    assert accepted_export["ensayo_lote_original"]["routing"]["mode"] == "diurno"
    sibling_id = "ALR-20261010-011794"
    sibling = investigate(db.get_alert(sibling_id), triage=True)
    assert window.reviews.save_analysis(sibling_id, sibling)
    work.reviews = window.reviews.all()
    work.sections.refresh_tickets()
    incident_ticket = sibling["report"]["ticket_id"]
    grouped = [row for row in work.sections.ticket_rows if row[0][0] == incident_ticket]
    assert len(grouped) == 1 and grouped[0][1] == "ALR-20261010-011795"
    assert window.reviews.history(sibling_id)[0]["kind"] == "Análisis"

    history_before = window.reviews.history(accepted_alert["alert_id"])
    recovery = db.get_alert("ALR-20261010-011798")
    new_members = ("ALR-20261010-991502", "ALR-20261010-991503")
    batch_path = home / "miembro-incidente.jsonl"
    for identifier, event in zip(new_members, ("EDR-0123415", "EDR-0123416")):
        batch_path.write_text(json.dumps({**recovery, "alert_id": identifier, "related_events": [event]}) + "\n")
        with patch.object(work, "_batch_results") as results:
            work._triage_batch(load_alerts(batch_path), present=True)
            wait_for(lambda: results.called, "incorporar una alerta corroborada")
            (batch_alert, batch_analysis, error), = results.call_args.args[0]
            assert not error and batch_analysis["report"]["ticket_id"] == incident_ticket
    assert new_members[0] not in batch_analysis["report"]["alert_ids"]
    work.sections.refresh_tickets()
    group, = [row for row, _ in work.sections.ticket_rows if row[0] == incident_ticket]
    assert group[2].startswith("11 alertas")

    def export_group(dialog):
        tabs = dialog.findChild(QTabWidget)
        timeline = next(tabs.widget(i) for i in range(tabs.count()) if tabs.tabText(i) == "Línea de tiempo")
        assert all(identifier in timeline.toPlainText() for identifier in new_members)
        next(control for control in dialog.findChildren(QPushButton) if control.text() == "Exportar expediente").click()
        return QDialog.DialogCode.Rejected

    with patch.object(QFileDialog, "getSaveFileName", return_value=(str(accepted_path), "")), patch.object(
            QDialog, "exec", export_group):
        work._detail(accepted_alert)
        current_group = json.loads(accepted_path.read_text())["informe"]
        work._detail(batch_alert, defense_result=batch_analysis)
        current_batch = json.loads(accepted_path.read_text())["resultado_lote"]["report"]
        work._detail(accepted_alert, defense_result=recent)
        accepted_group = json.loads(accepted_path.read_text())
    for report in (current_group, current_batch, accepted_group["resultado_lote"]["report"]):
        assert report["ticket_id"] == incident_ticket
        assert report["alert_ids"] == report["incident"]["alert_ids"] == current_group["alert_ids"]
        assert set(new_members) <= set(report["alert_ids"])
    assert current_group["decision_actual"]["decision"] == "accepted"
    assert set(new_members).isdisjoint(accepted_group["ensayo_lote_original"]["report"]["alert_ids"])
    assert window.reviews.history(accepted_alert["alert_id"]) == history_before

    work.query.setText("ALR-20261005-000173")
    work.search.click()
    wait_for(lambda: work.total == 1, "lote filtrado")
    with patch("apps.desktop.review.openai_message") as transport:
        work.prepare.click()
        wait_for(lambda: window.job is None, "preparar lote")
        transport.assert_not_called()
    assert work.reviews["ALR-20261005-000173"]["decision"] == "automatic"
    assert work.queue_correct.isEnabled()

    def correct():
        dialog = app.activeModalWidget()
        choice = dialog.findChild(QComboBox)
        choice.setCurrentIndex(choice.findData("false_positive"))
        dialog.findChild(QLineEdit, "decisionReason").setText("Decisión de ensayo tras revisar el evento WAF-0001841.")
        next(control for control in dialog.findChildren(QPushButton)
             if control.text() == "Registrar decisión").click()

    QTimer.singleShot(100, correct)
    work.queue_correct.click()
    assert work.table.item(0, 3).text() == "Corregida"
    assert work.table.item(0, 4).text() == "Falso positivo"
    assert "WAF-0001841" in window.reviews.history("ALR-20261005-000173")[0]["data"]["reason"]
    exported_case = home / "expediente-corregido.json"

    def export_corrected(dialog):
        summary = dialog.findChild(QTextBrowser, "reviewProcess").toPlainText()
        assert "Decisión humana vigente" in summary and "Se recomendó cerrar" in summary
        assert "Automatizable según política" not in summary
        next(control for control in dialog.findChildren(QPushButton) if control.text() == "Exportar expediente").click()
        return QDialog.DialogCode.Rejected

    with patch.object(QFileDialog, "getSaveFileName", return_value=(str(exported_case), "")), patch.object(
            QDialog, "exec", export_corrected):
        work._detail(work.selected)
        corrected_report = json.loads(exported_case.read_text())["informe"]
        original_analysis = work.reviews[work.selected["alert_id"]]["analysis"]
        work._detail(work.selected, defense_result={**original_analysis, "persisted_decision": "automatic"})
        corrected_export = json.loads(exported_case.read_text())
        corrected_result = corrected_export["resultado_lote"]
        assert corrected_result["report"] == corrected_report
        assert corrected_result["verdict"] == corrected_report["verdict"]
        assert corrected_result["routing"] == corrected_report["routing"]
        assert corrected_result["persisted_decision"] == "corrected"
        assert corrected_export["ensayo_lote_original"]["routing"]["automatic"]
    assert corrected_report["decision_actual"]["verdict"] == corrected_report["verdict"] == "false_positive"
    assert corrected_report["routing"]["recommendation"] == "review" and not corrected_report["routing"]["automatic"]
    assert corrected_report["triaje_original"]["routing"]["automatic"]
    assert "WAF-0001841" in corrected_report["decision_actual"]["reason"]

    work._toggle_monitor()
    work._toggle_monitor()
    wait_for(lambda: window.job is None, "vigilancia priorizada")
    assert not work.monitor.isActive()
    escalations = [row["analysis"] for row in work.reviews.values() if row["analysis"] and
                   row["analysis"].get("routing", {}).get("recommendation") == "escalate"]
    assert len(escalations) > 1

    inputs = ["ALR-20261005-000301", "ALR-20261010-011795", "ALR-20261021-011900"]
    failures = []
    finished = False

    def verify_batch():
        nonlocal finished
        dialog = app.activeModalWidget()
        if not isinstance(dialog, QDialog):
            QTimer.singleShot(25, verify_batch)
            return
        try:
            assert dialog.windowTitle() == "Lote de defensa"
            grid = dialog.findChild(QTableWidget)
            assert [grid.item(row, 0).text() for row in range(grid.rowCount())] == inputs
            assert "Cierre automático" in grid.item(0, 3).text()
            assert grid.item(1, 3).text() == "Escalar · Aceptada por el analista"
            if output:
                dialog.grab().save(str(output.with_name("vigia-lote-guardia.png")))
        except BaseException as error:
            failures.append(error)
        finally:
            finished = True
            dialog.close()

    work.triage_mode.setCurrentIndex(work.triage_mode.findData("guardia"))
    work._triage_batch([db.get_alert(key) for key in inputs], present=True)
    QTimer.singleShot(80, verify_batch)
    wait_for(lambda: finished, "lote de defensa en la mesa")
    if failures:
        raise failures[0]

    def verify_handover():
        dialog = app.activeModalWidget()
        try:
            assert dialog.windowTitle() == "Relevo de guardia"
            assert dialog.findChild(QTableWidget).rowCount() > 0
            if output:
                dialog.grab().save(str(output.with_name("vigia-relevo-guardia.png")))
        except BaseException as error:
            failures.append(error)
        finally:
            dialog.close()

    QTimer.singleShot(70, verify_handover)
    work._guard_handover()
    if failures:
        raise failures[0]
    with TemporaryDirectory(prefix="vigia-inbox-qa-") as directory:
        work._start_monitor(Path(directory))
        external_id = "ALR-20991231-999998"
        incoming = {**db.get_alert("ALR-20261005-000301"), "alert_id": external_id}
        pending_file = Path(directory) / "nueva.tmp"
        pending_file.write_text(json.dumps(incoming), encoding="utf-8")
        pending_file.rename(pending_file.with_suffix(".jsonl"))
        wait_for(lambda: external_id in work.reviews, "nueva alerta de la carpeta")
        previous = work.reviews[external_id]
        assert previous["analysis"]["input_alert"]["external"]
        previous_history = window.reviews.history(external_id)
        duplicate = pending_file.with_name("repetida.jsonl")
        duplicate.write_text(json.dumps(incoming, sort_keys=True), encoding="utf-8")
        wait_for(lambda: window.job is None, "fin del primer lote de carpeta")
        work._monitor_tick()
        wait_for(lambda: window.job is None, "reenvío idéntico")
        assert window.reviews.history(external_id) == previous_history
        assert "Conflicto de identidad" not in work.status.text()
        collision = {**db.get_alert("ALR-20261010-011795"), "alert_id": external_id}
        pending_file.write_text(json.dumps(collision), encoding="utf-8")
        pending_file.replace(pending_file.with_suffix(".jsonl"))
        work._monitor_tick()
        wait_for(lambda: "Conflicto de identidad" in work.status.text(), "conflicto de identidad en carpeta")
        assert work.reviews[external_id] == previous
        assert window.reviews.history(external_id) == previous_history
        work._stop_monitor("Vigilancia detenida.")
    window.close()


def check_demo(app, window, normal_profile, output):
    from apps.desktop.demo import DEMO_ALERT, DEMO_PASSWORD, DEMO_USER
    from apps.desktop.session import Account

    assert window.username.text() == DEMO_USER
    assert not Account(normal_profile).verify(DEMO_PASSWORD)
    failures = []
    completed = False

    def replay():
        nonlocal completed
        dialog = app.activeModalWidget()
        if not isinstance(dialog, QDialog):
            QTimer.singleShot(50, replay)
            return
        try:
            assert DEMO_ALERT in dialog.windowTitle()
            wait_for(lambda: window.job is None, "evidencias de la demo")
            controls = {control.text(): control for control in dialog.findChildren(QPushButton)}
            assert "Analizar y contrastar con OpenAI" not in controls
            assert controls["Triar con datos locales"].isEnabled()
            assert window.workbench.model.findData(True) == -1
            assert not controls["Aceptar"].isEnabled()
            controls["Cargar análisis de referencia"].click()
            wait_for(lambda: window.job is None, "reproducción del expediente")
            text = dialog.findChild(QTextBrowser, "reviewProcess").toPlainText()
            tabs = dialog.findChild(QTabWidget)
            evidence = tabs.widget(1).findChild(QTextBrowser).toPlainText()
            assert "85%" in text and "EDR-0123412" in evidence
            assert any("Análisis de referencia" in node.text() for node in dialog.findChildren(QLabel))
            if output:
                dialog.grab().save(str(output.with_name("vigia-demo-lsass.png")))
            assert controls["Aceptar"].isEnabled()
            controls["Aceptar"].click()
            rows = window.reviews.history(DEMO_ALERT)
            assert [item["kind"] for item in rows] == ["Aceptada", "Análisis"]
            assert rows[1]["data"]["origin"] == "demo"
            from apps.desktop.review import Reviews
            assert all((row["analysis"] or {}).get("origin") != "demo"
                       for row in Reviews(normal_profile).all().values())
        except BaseException as error:
            failures.append(error)
        finally:
            completed = True
            dialog.close()

    window.show()
    with patch("apps.desktop.review.openai_message") as transport:
        QTimer.singleShot(100, replay)
        window.enter_demo()
        wait_for(lambda: completed, "reproducción y decisión de la demo")
        transport.assert_not_called()
    if failures:
        raise failures[0]
    window.close()


def check_recorded_isolation(window, home):
    from apps.backend.tools import db
    from apps.desktop import sim_response
    from apps.desktop.demo import DEMO_PASSWORD
    from apps.desktop.review import investigate
    from apps.desktop.workbench import Workbench

    alerts = [db.get_alert(key) for key in ("ALR-20261010-011795", "ALR-20261010-011794")]
    analyses = [investigate(alert, triage=True) for alert in alerts]
    for alert, analysis in zip(alerts, analyses):
        assert window.reviews.save_analysis(alert["alert_id"], analysis)
    work = Workbench(window, alerts, 2, "2026-10-10", (2, 2))
    alert_id = alerts[0]["alert_id"]
    replies = iter((
        {"info": {"title": "Tarvia SOC (simulado)", "version": "1.0"},
         "paths": {"/approvals": {"post": {}}, "/containment/{action}": {"post": {}}}},
        {"approval_token": "APR-0000000001"}, {"action": "isolate_host", "result": "ok (simulado)"},
    ))
    with patch.dict(os.environ, {"VIGIA_SIM_PORT": "8765"}), patch.object(
            sim_response, "_request", side_effect=lambda _port, _method, _path, payload=None: {
                **(payload or {}), **next(replies)
            }):
        proposal = sim_response.isolation_proposal(alert_id, practice=True)
        saved = sim_response.execute_isolation(
            window.reviews, window.account, alert_id, practice=True, target=proposal["target"],
            confirmed=True, password=DEMO_PASSWORD, justification="Prueba aislada del expediente agrupado.",
        )
    assert saved["status"] == "executed"

    path = home / "expediente.json"

    def click_export(dialog):
        tabs = dialog.findChild(QTabWidget)
        assert "Ejecutado en el simulador" in tabs.widget(4).toPlainText()
        controls = {control.text(): control for control in dialog.findChildren(QPushButton)}
        assert controls["Aprobar aislamiento simulado"].isHidden()
        controls["Exportar expediente"].click()
        return QDialog.DialogCode.Rejected

    with patch.dict(os.environ, {"VIGIA_SIM_PORT": ""}), patch.object(
            QFileDialog, "getSaveFileName", return_value=(str(path), "")
    ), patch.object(QDialog, "exec", click_export):
        for alert in alerts:
            work._detail(alert)
            assert json.loads(path.read_text())["informe"]["executed_actions"] == [saved]
        work._detail(alerts[1], defense_result=analyses[1])
        report = json.loads(path.read_text())["resultado_lote"]["report"]
        assert report["executed_actions"] == [saved]

        with closing(sqlite3.connect(window.reviews.path)) as connection, connection:
            connection.execute("UPDATE simulated_isolations SET ticket_id = NULL WHERE alert_id = ?", (alert_id,))
        legacy = {**saved, "ticket_id": f"VIG-{alert_id}"}
        work._detail(alerts[1])
        assert json.loads(path.read_text())["informe"]["executed_actions"] == [legacy]
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
            with TemporaryDirectory(prefix="vigia-demo-") as demo_profile:
                check_demo(app, Window(Path(demo_profile), demo=True, present=True), home, output)
            with TemporaryDirectory(prefix="vigia-isolation-") as isolation_profile:
                profile = Path(isolation_profile)
                check_recorded_isolation(Window(profile, demo=True), profile)
    app.quit()
    print("Vigía: sesión, ojo durante carga, 11.061 alertas, búsqueda, fecha y veredicto, chat local, "
          "contraste adversarial simulado, decisiones persistentes, estadísticas, reproducción diaria "
          "y modo de práctica sin OpenAI.")


if __name__ == "__main__":
    main()
