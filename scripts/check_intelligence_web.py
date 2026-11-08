"""Comprueba inteligencia y procedencia con el índice oficial, sin red."""
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

from fastapi.testclient import TestClient

from apps.backend.tools import db
from apps.engine.defense import _external
from apps.engine.review import investigate
from apps.web.apps.backend.timeline import construir


def check_timeline_order():
    events = {
        "VERIFIED": {"source": "edr", "timestamp": "2026-10-10T00:00:00Z"},
        "CONTEXT-A": {"source": "proxy", "timestamp": "2026-10-09T23:58:00Z"},
        "CONTEXT-B": {"source": "dns", "timestamp": "2026-10-10T01:59:00+02:00"},
    }
    alert = {"alert_id": "ALR-TEST", "created_at": "2026-10-10T00:00:00.500Z", "rule_name": "Prueba",
             "rule_id": "TEST", "severity": "high", "related_events": list(events)}
    steps = construir({"criterio_verificado": {"citations": ["VERIFIED"]}}, [alert], None, max_pasos=2,
                      database=SimpleNamespace(get_event=events.get))["pasos"]
    assert [(step["id"], step["fase"]) for step in steps] == [("VERIFIED", "Hallazgo"), ("ALR-TEST", "Alerta SIEM")]


def main():
    check_timeline_order()
    stamp = datetime.now(timezone.utc).isoformat()
    identifier = "CVE-2024-23897"
    with TemporaryDirectory(prefix="vigia-intelligence-test-") as folder:
        snapshot = Path(folder) / "snapshot.json"
        snapshot.write_text(json.dumps({
            "schema": 1, "updated_at": stamp,
            "sources": {"kev": {
                "checked_at": stamp, "fetched_at": stamp, "published_at": stamp,
                "records": {identifier: {"date_added": "2024-08-19", "ransomware": "known"}},
            }},
        }), encoding="utf-8")
        with patch.dict(os.environ, {"VIGIA_THREAT_INTEL_PATH": str(snapshot), "VIGIA_WEB_OUT": folder,
                                     "VIGIA_WEB_LOCAL_ONLY": "0", "OPENAI_API_KEY": "sk-vigia-offline-test"}):
            from apps.web.apps.backend.main import app

            jenkins = db.get_alert("ALR-20261006-011825")
            result = investigate(jenkins, triage=True)
            matches = result["report"]["threat_intel"]
            assert len(matches) == 1 and matches[0]["cve"] == identifier
            assert matches[0]["asset"] == "JENKINS-DEV01" and matches[0]["source"] == "kev"
            assert result["routing"]["recommendation"] == "escalate"

            verified = result["verified_finding"]["citations"]
            assert verified and any(event["verified"] and event["cited_by"] == ["local"]
                                    for event in result["report"]["evidence"] if event["event_id"] in verified)
            answer = {"verdict": "true_positive", "citations": [verified[0]], "summary": "Hallazgo local.",
                      "confidence": 90, "questions": [], "actions": []}
            with patch("apps.engine.review._ask", return_value=answer) as model:
                investigated = investigate(jenkins, remote=True, triage=True)
                assert model.call_count == 2
                assert all(call.args[1]["contexto"]["inteligencia_vulnerabilidades"] ==
                           investigated["report"]["threat_intel"] for call in model.call_args_list)

            unlinked = _external({**jenkins, "alert_id": "ALR-20261006-990911", "related_events": []})
            assert not investigate(unlinked, triage=True)["report"].get("threat_intel")
            unsupported = {**unlinked, "entities": {}, "declared_evidence": {}}
            unknown = investigate(unsupported, triage=True)
            assert unknown["verdict"] == "needs_more_info"
            assert unknown["routing"]["recommendation"] == "escalate"
            assert "N2" in unknown["routing"]["recipients"]
            medium = investigate({**unsupported, "severity": "medium"}, triage=True)
            assert medium["routing"]["recommendation"] == "review"

            with TestClient(app) as client:
                status = client.get("/api/inteligencia").json()["fuentes"]
                assert len(status) == 1 and status[0]["estado"] == "actualizada" and status[0]["registros"] == 1
                assert "records" not in status[0]
                benign = client.get("/api/tickets/VIG-ALR-20261005-000301").json()
                candidates = [event for event in benign["linea"]["pasos"] if event["fuente"] in {"dns", "proxy"}]
                assert benign["verdict"] == "benign_true_positive" and candidates
                assert all(event["fase"] == "Contexto" for event in candidates)
                incident = client.get("/api/tickets/VIG-ALR-20261010-011795").json()
                phases = {event["id"]: event["fase"] for event in incident["linea"]["pasos"]}
                assert phases["EDR-0123412"] == "Robo de credenciales"

    print("Inteligencia y triaje web: fuente trazable, mismo snapshot en ambas pasadas, vínculo de activo, escalado y fases N2.")


if __name__ == "__main__":
    main()
