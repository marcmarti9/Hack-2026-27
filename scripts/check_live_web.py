"""Prueba el contrato de la mesa web con el índice oficial y sin llamadas externas."""
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from time import monotonic, sleep
from unittest.mock import patch

from fastapi.testclient import TestClient

from apps.backend.config import DATA, ROOT


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
        body = "\n".join(json.dumps(row) for row in (corroborated, unknown))
        with TestClient(app) as client:
            assert client.get("/api/directo").json() == {"alertas": [], "trabajo": None}
            bad = client.post("/api/analizar", json={"texto": body + "\n{incorrecto}", "modo": "guardia"})
            assert bad.status_code == 400
            assert client.get("/api/directo").json()["alertas"] == []
            valid = client.post("/api/analizar", json={"texto": body, "modo": "guardia", "archivo": "alertas_nuevas.jsonl"})
            assert valid.status_code == 200, valid.json()
            job_id = valid.json()["trabajo"]
            assert len(client.get("/api/directo").json()["alertas"]) == 2
            until = monotonic() + 25
            while monotonic() < until:
                job = client.get(f"/api/trabajo/{job_id}").json()
                if job["fin"]:
                    break
                sleep(0.08)
            assert job["estado"] == "terminado" and len(job["tickets"]) == 2, job["error"]
            rows = {row["alert_id"]: row for row in client.get("/api/directo").json()["alertas"]}
            first, second = rows[corroborated["alert_id"]], rows[unknown["alert_id"]]
            assert first["verdict"] == "true_positive" and first["estado"] == "escalada"
            assert second["verdict"] == "needs_more_info" and second["provisional"] and second["estado"] == "escalada"
            assert second["origin"] == "alertas_nuevas.jsonl"
            report = client.get(f"/api/tickets/{second['ticket_id']}").json()["expediente"]
            assert report["declared_evidence"] == unknown["evidence"] and not report["evidence"]
            assert not report["routing"]["automatic"]
            assign = f"/api/directo/{first['alert_id']}/asignacion"
            assert client.put(assign, json={"rol": "N2", "asignarme": True}).json()["asignado"] == "analista.n2"
            assert client.put(assign, json={"rol": "N1", "asignarme": True}).status_code == 409
            persisted = {row["alert_id"]: row for row in LiveQueue(defensa.reviews.path).rows()}
            assert persisted[first["alert_id"]]["rol"] == "N2"
            changed = {**corroborated, "rule_name": "Otro contenido"}
            assert client.post("/api/analizar", json={"texto": json.dumps(changed)}).status_code == 409

        from apps.desktop.defense import _external
        from apps.desktop.review import investigate
        result = {"verdict": "needs_more_info", "confidence": 90, "summary": "Posible acceso a LSASS sin corroborar.",
                  "citations": [], "questions": ["Recuperar el registro de EDR."], "actions": []}
        with patch("apps.desktop.review.openai_message", return_value=json.dumps(result)) as request:
            analysis = investigate(_external(unknown), remote=True, triage=True, mode="guardia")
            assert request.call_count == 2
            assert request.call_args_list[0].args[1]["alerta"]["declared_evidence"] == unknown["evidence"]
            assert analysis["proposal"]["verdict"] == "needs_more_info"
            assert analysis["verdict"] == "needs_more_info" and analysis["confidence"] is None
            assert analysis["routing"]["recommendation"] == "escalate"

    print("Mesa web: formato oficial, lote nuevo, informe, escalado, asignación, persistencia y contraste sin red.")


if __name__ == "__main__":
    main()
