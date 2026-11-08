"""Verifica el contraste de lotes con el proveedor simulado y el índice de Tarvia."""
import io
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from time import monotonic, sleep
from unittest.mock import patch
from urllib.error import HTTPError

from fastapi.testclient import TestClient

from apps.backend.tools import db


def run_batch(client, alerts):
    response = client.post("/api/analizar", json={
        "texto": "\n".join(json.dumps(alert) for alert in alerts), "modo": "guardia", "remoto": True,
    })
    assert response.status_code == 200, response.json()
    job_id = response.json()["trabajo"]
    limit = monotonic() + 20
    while monotonic() < limit:
        job = client.get(f"/api/trabajo/{job_id}").json()
        if job["fin"] is not None:
            assert job["estado"] == "terminado" and not job["error"], job
            assert [ticket["alert_id"] for ticket in job["tickets"]] == [alert["alert_id"] for alert in alerts]
            return job
        sleep(0.04)
    raise AssertionError("El lote de prueba no terminó.")


def reply(alert, verdict):
    answer = json.dumps({
        "verdict": verdict, "confidence": 95, "summary": "Hipótesis sobre los registros recuperados.",
        "citations": alert["related_events"][:1], "questions": [], "actions": [],
    })
    return io.BytesIO(json.dumps({"status": "completed", "output": [{
        "type": "message", "content": [{"type": "output_text", "text": answer}],
    }]}).encode())


def failure(code, url="https://api.openai.com/v1/responses"):
    return HTTPError(url, code, "Error de prueba", None, None)


def main():
    with TemporaryDirectory(prefix="vigia-provider-batch-") as folder, patch.dict(os.environ, {
        "VIGIA_WEB_OUT": folder, "VIGIA_WEB_CORPUS": str(Path(folder) / "no-corpus"),
        "OPENAI_API_KEY": "sk-vigia-test-batch", "OPENAI_MODEL": "gpt-6-luna", "OPENAI_REVIEW_MODEL": "gpt-6.1-sol",
        "VIGIA_WEB_LOCAL_ONLY": "0",
    }):
        from apps.web.apps.backend import defensa
        from apps.web.apps.backend.main import app

        routine = {**db.get_alert("ALR-20261005-000279"), "alert_id": "ALR-20261005-990975"}
        critical = db.get_alert("ALR-20261010-011795")
        unknown = {**critical, "alert_id": "ALR-20261201-990975", "created_at": "2026-12-01T00:00:00Z",
                   "severity": "critical", "related_events": ["EDR-0999999"], "entities": {},
                   "evidence": {"action": "detected", "details": {"target": "lsass.exe"}}}
        high = db.get_alert("ALR-20261021-011900")

        calls = []

        def unavailable(request, timeout):
            calls.append(json.loads(json.loads(request.data)["input"])["alerta"]["alert_id"])
            sleep(0.2)
            raise failure(429, request.full_url)

        with TestClient(app) as client, patch("apps.desktop.assistant.build_opener") as transport:
            transport.return_value.open.side_effect = unavailable
            start = monotonic()
            job = run_batch(client, [routine, critical, high, unknown])
            print(f"Caída simulada: {len(calls)} petición, 4 expedientes, {monotonic() - start:.2f} s.")
            assert calls == [critical["alert_id"]], calls
            started = [step["texto"].split(" · ", 1)[0] for step in job["pasos"] if step["tipo"] == "caso"]
            assert started == [alert["alert_id"] for alert in (critical, unknown, high, routine)]
            queue = {row["alert_id"]: row for row in client.get("/api/directo").json()["alertas"]}
            assert queue[routine["alert_id"]]["estado"] == "investigada"
            assert all(queue[alert["alert_id"]]["estado"] == "escalada" for alert in (critical, high, unknown))
            for alert in (routine, critical, high, unknown):
                review = defensa.reviews.all()[alert["alert_id"]]
                analysis = review["analysis"]
                assert analysis["provider"] == "gpt-6-luna" and analysis["confidence"] is None
                assert not analysis["routing"]["automatic"] and review["decision"] is None
                skipped = alert is not critical
                assert analysis.get("proposal_skipped", False) == skipped
                assert ("proposal_ms" not in analysis["timing"]) == skipped
                report = client.get(f"/api/expediente/{alert['alert_id']}").json()["informe"]
                assert "HTTP 429" in report["provider_errors"]["proposal"]
                assert ("omitió" in report["provider_errors"]["proposal"]) == skipped
                assert bool(analysis.get("verified_finding")) == (alert is not unknown)

            transport.reset_mock()
            transport.return_value.open.side_effect = failure(404)
            run_batch(client, [routine, unknown])
            assert transport.return_value.open.call_count == 1
            assert defensa.reviews.all()[routine["alert_id"]]["analysis"]["proposal_skipped"]

            transport.reset_mock()
            transport.return_value.open.side_effect = lambda *_args, **_kwargs: reply(routine, "false_positive")
            run_batch(client, [routine])
            assert transport.return_value.open.call_count == 2
            assert defensa.reviews.all()[routine["alert_id"]]["decision"] == "automatic"

            for variant, cause in enumerate(("formato", "cita", "fiscal"), start=1):
                transport.reset_mock()
                new_routine = {**routine, "alert_id": f"ALR-20261005-99097{5 + variant}"}
                new_critical = {**critical, "alert_id": f"ALR-20261010-99097{5 + variant}"}
                replies = {
                    "formato": [failure(400)],
                    "cita": [reply({**new_critical, "related_events": ["EDR-0999999"]}, "true_positive")],
                    "fiscal": [reply(new_critical, "true_positive"), failure(503)],
                }[cause]
                transport.return_value.open.side_effect = [
                    *replies, reply(new_routine, "false_positive"), reply(new_routine, "false_positive"),
                ]
                run_batch(client, [new_critical, new_routine])
                assert transport.return_value.open.call_count == len(replies) + 2
                assert defensa.reviews.all()[new_routine["alert_id"]]["decision"] == "automatic"

    print("Fusible por lote: guardas, nuevo intento, respuesta inválida y fallo aislado del fiscal verificados.")


if __name__ == "__main__":
    main()
