"""Prueba el contrato de la mesa web con el índice oficial y sin llamadas externas."""
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from time import monotonic, sleep
from unittest.mock import patch

from fastapi.testclient import TestClient

from apps.backend.config import DATA, ROOT
from apps.backend.tools import db


def check_incident_projection(client, corroborated, unrelated):
    recovery = db.get_alert("ALR-20261010-011798")
    external = {"ALR-20261010-999991": "EDR-0123415", "ALR-20261010-999992": "EDR-0123416"}
    variants = [{**recovery, "alert_id": aid, "related_events": [event]} for aid, event in external.items()]
    submitted = client.post("/api/analizar", json={"texto": json.dumps([recovery["alert_id"], *variants]),
                                                 "modo": "guardia"})
    assert submitted.status_code == 200, submitted.json()
    until = monotonic() + 25
    while monotonic() < until:
        job = client.get(f"/api/trabajo/{submitted.json()['trabajo']}").json()
        if job["fin"]:
            break
        sleep(0.08)
    assert job["estado"] == "terminado" and len(job["tickets"]) == 3, job["error"]

    group = "VIG-INC-FW-0025321"
    identifiers = {recovery["alert_id"], corroborated["alert_id"], *external}
    queue = {case["alert_id"] for case in client.get("/api/directo").json()["alertas"]}
    assert identifiers | {unrelated["alert_id"]} <= queue
    for cases in (client.get("/api/tickets").json(), client.get("/api/relevo").json()["casos"]):
        matches = [case for case in cases if case["incident_id"] == group]
        assert len(matches) == 1 and identifiers <= set(matches[0]["alert_ids"])
        assert matches[0]["human_review"], "El representante debe conservar la revisión pendiente."
        assert any(case["alert_id"] == unrelated["alert_id"] for case in cases)

    for aid in identifiers:
        matches = client.get("/api/tickets", params={"q": aid}).json()
        assert [case["alert_id"] for case in matches] == [aid]
        detail = client.get(f"/api/tickets/VIG-{aid}").json()
        report = detail["expediente"]
        assert detail["alert_id"] == aid and report["incident"]["incident_id"] == group
        assert identifiers <= set(report["alert_ids"])
        assert unrelated["alert_id"] not in report["alert_ids"]
        assert identifiers <= {step["id"] for step in detail["linea"]["pasos"] if step["hito"]}
        members = {alert["alert_id"]: alert for alert in detail["alertas"]}
        for member, event in external.items():
            assert members[member]["external"] and members[member]["related_events"] == [event]
            if member == aid:
                assert members[member]["entities"] == report["affected"]
        exported = client.get(f"/api/expediente/{aid}").json()
        assert exported["alerta"] == aid and exported["informe"]["alert_ids"] == report["alert_ids"]
        if aid == corroborated["alert_id"]:
            assert detail["decision_actual"]["decision"] == "accepted"
            assert exported["informe"]["decision_actual"]["verdict"] == "true_positive"
        else:
            assert not detail["decision_actual"]


def main():
    with TemporaryDirectory(prefix="vigia-web-test-") as directory, patch.dict(
        os.environ, {"VIGIA_WEB_OUT": directory, "VIGIA_WEB_CORPUS": str(Path(directory) / "no-corpus"),
                     "OPENAI_API_KEY": "sk-vigia-test-local", "VIGIA_WEB_LOCAL_ONLY": "0"}
    ):
        from apps.web.apps.backend import defensa
        from apps.web.apps.backend.live_queue import LiveQueue
        from apps.web.apps.backend.main import app

        sample = DATA / "03_alertas" / "alertas_muestra_desarrollo.jsonl"
        assert len(defensa._input(sample.read_text(encoding="utf-8"))) == 150
        sources = [json.loads(line) for line in (ROOT / "eval" / "lote-presentacion-091.jsonl").read_text().splitlines()]
        corroborated = next(row for row in sources if isinstance(row, dict) and row["alert_id"] == "ALR-20261010-990901")
        unknown = {**corroborated, "alert_id": "ALR-20261201-990981", "created_at": "2026-12-01T00:00:00Z",
                   "severity": "critical", "related_events": ["EDR-0999999"], "entities": {},
                   "evidence": {"action": "detected", "details": {"target": "lsass.exe"}}}
        routine = {**db.get_alert("ALR-20261005-000279"), "alert_id": "ALR-20261005-990982"}
        blocked = {**db.get_alert("ALR-20261005-000173"), "alert_id": "ALR-20261005-990983"}
        missing = {**routine, "alert_id": "ALR-20261005-990984",
                   "related_events": [*routine["related_events"], "EML-0999999"]}
        mismatched = {**routine, "alert_id": "ALR-20261005-990987",
                      "evidence": {**routine["evidence"], "message_id": "<different@retailforum.example>"}}
        body = "\n".join(json.dumps(row) for row in (corroborated, unknown, routine, blocked, missing, mismatched))
        with TestClient(app) as client:
            assert client.get("/api/directo").json() == {"alertas": [], "trabajo": None}
            bad = client.post("/api/analizar", json={"texto": body + "\n{incorrecto}", "modo": "guardia"})
            assert bad.status_code == 400
            assert client.get("/api/directo").json()["alertas"] == []
            valid = client.post("/api/analizar", json={"texto": body, "modo": "guardia", "archivo": "alertas_nuevas.jsonl"})
            assert valid.status_code == 200, valid.json()
            job_id = valid.json()["trabajo"]
            assert len(client.get("/api/directo").json()["alertas"]) == 6
            until = monotonic() + 25
            while monotonic() < until:
                job = client.get(f"/api/trabajo/{job_id}").json()
                if job["fin"]:
                    break
                sleep(0.08)
            assert job["estado"] == "terminado" and len(job["tickets"]) == 6, job["error"]
            rows = {row["alert_id"]: row for row in client.get("/api/directo").json()["alertas"]}
            first, second = rows[corroborated["alert_id"]], rows[unknown["alert_id"]]
            assert first["verdict"] == "true_positive" and first["estado"] == "escalada"
            assert second["verdict"] == "needs_more_info" and second["provisional"] and second["estado"] == "escalada"
            assert second["origin"] == "alertas_nuevas.jsonl"
            report = client.get(f"/api/tickets/{second['ticket_id']}").json()["expediente"]
            assert report["declared_evidence"] == unknown["evidence"] and not report["evidence"]
            assert not report["routing"]["automatic"]
            for alert, verdict in ((routine, "false_positive"), (blocked, "true_positive")):
                closed = rows[alert["alert_id"]]
                assert closed["estado"] == "cerrada" and closed["verdict"] == verdict
                assert not closed["asignado"] and closed["motivo_cierre"]
                report = client.get(f"/api/tickets/{closed['ticket_id']}").json()["expediente"]
                assert report["routing"]["automatic"] and not report["executed_actions"]
                history = defensa.reviews.history(alert["alert_id"])
                assert history[0]["kind"] == "Cierre automático"
                assert history[0]["data"]["citations"] == alert["related_events"]
            assert all(rows[alert["alert_id"]]["estado"] != "cerrada" for alert in (missing, mismatched))
            assign = f"/api/directo/{first['alert_id']}/asignacion"
            assert client.put(assign, json={"rol": "N2", "asignarme": True}).json()["asignado"] == "analista.n2"
            assert client.put(assign, json={"rol": "N1", "asignarme": True}).status_code == 409
            persisted = {row["alert_id"]: row for row in LiveQueue(defensa.reviews.path).rows()}
            assert persisted[first["alert_id"]]["rol"] == "N2"
            assert client.post(f"/api/decision/{first['alert_id']}", json={
                "decision": "accepted", "verdict": "true_positive", "rol": "N2"
            }).status_code == 200
            with patch("apps.web.apps.backend.defensa.investigate") as investigator:
                retry = client.post("/api/analizar", json={"texto": json.dumps(corroborated), "remoto": True})
                assert retry.status_code == 200
                until = monotonic() + 5
                while monotonic() < until:
                    retried = client.get(f"/api/trabajo/{retry.json()['trabajo']}").json()
                    if retried["fin"]:
                        break
                    sleep(0.04)
                assert retried["estado"] == "terminado" and "reutilizó" in retried["pasos"][0]["texto"]
                investigator.assert_not_called()
            changed = {**corroborated, "rule_name": "Otro contenido"}
            assert client.post("/api/analizar", json={"texto": json.dumps(changed)}).status_code == 409
            check_incident_projection(client, corroborated, unknown)

        from apps.desktop.defense import _external
        from apps.desktop.review import investigate
        result = {"verdict": "needs_more_info", "confidence": 90, "summary": "Posible acceso a LSASS sin corroborar.",
                  "citations": [], "questions": ["Recuperar el registro de EDR."], "actions": []}
        with patch("apps.desktop.review.openai_message", return_value=json.dumps(result)) as request:
            analysis = investigate(_external(unknown), remote=True, triage=True, mode="guardia")
            assert request.call_count == 2
            first = request.call_args_list[0]
            assert first.args[1]["alerta"]["declared_evidence"] == unknown["evidence"]
            assert not first.args[1]["alerta"]["related_events"] and first.args[1]["referencias_sin_recuperar"] == 1
            assert first.kwargs["schema"]["properties"]["verdict"]["enum"] == ["needs_more_info"]
            assert analysis["proposal"]["verdict"] == "needs_more_info"
            assert analysis["verdict"] == "needs_more_info" and analysis["confidence"] is None
            assert analysis["routing"]["recommendation"] == "escalate"

        agreement = {**result, "verdict": "false_positive", "summary": "Reporte del ejercicio sin entrega real.",
                     "citations": routine["related_events"]}
        with patch("apps.desktop.review.openai_message", return_value=json.dumps(agreement)) as request:
            analysis = investigate(_external(routine), remote=True, triage=True)
            assert request.call_count == 2 and analysis["routing"]["automatic"]
        with patch("apps.desktop.review.openai_message", side_effect=[json.dumps(agreement), json.dumps(result)]):
            analysis = investigate(_external(routine), remote=True, triage=True)
            assert analysis["review_error"] and not analysis["routing"]["automatic"]

    print("Mesa web: lote nuevo, autocierre auditado, escalado, asignación, incidentes y contraste sin red.")


if __name__ == "__main__":
    main()
