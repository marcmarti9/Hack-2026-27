"""Pruebas focales del triaje con el índice oficial de Tarvia."""
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from apps.backend.rules.triage import local_finding
from apps.backend.tools import db
from apps.desktop.review import Reviews, investigate


def main():
    routine = db.get_alert("ALR-20261005-000301")
    closure = investigate(routine, triage=True)
    assert closure["verdict"] == "benign_true_positive" and closure["routing"]["automatic"]
    assert closure["verified_finding"]["citations"] == ["EDR-0005329"]
    closure_event = next(event for event in closure["events"] if event["event_id"] == "EDR-0005329")
    closure_event["command_line"] += " & otra-orden"
    assert local_finding(routine, closure) is None
    closure_event["command_line"] = closure_event["command_line"].removesuffix(" & otra-orden")

    external = investigate({**routine, "external": True}, triage=True)
    assert not external["routing"]["automatic"]
    with TemporaryDirectory() as directory:
        store = Reviews(Path(directory))
        for _ in range(2):
            store.save_analysis(routine["alert_id"], closure)
        assert store.all()[routine["alert_id"]]["decision"] == "automatic"
        history = store.history(routine["alert_id"])
        assert [row["kind"] for row in history] == ["Cierre automático", "Análisis"]
        assert history[0]["data"]["citations"] == ["EDR-0005329"]
        assert len(history[1]["data"]["trace"]) == 5

    critical = db.get_alert("ALR-20261010-011795")
    night = investigate(critical, triage=True, mode="guardia")
    day = investigate(critical, triage=True)
    assert night["verdict"] == "true_positive" and len(night["events"]) > len(night["requested"])
    for mode, result in (("diurno", day), ("guardia", night)):
        routing = result["routing"]
        assert routing["mode"] == mode and routing["recommendation"] == "escalate"
        assert not routing["automatic"] and "CISO" in routing["recipients"]
        assert routing["deadline_at"] == "2026-10-10T00:38:30+00:00"

    wrong = {
        "verdict": "false_positive", "confidence": 99, "summary": "El WAF bloqueó el ataque con un 403.",
        "citations": ["EDR-0123412"], "questions": [], "actions": [],
    }
    with patch("apps.desktop.review.openai_message", return_value=json.dumps(wrong)) as calls:
        result = investigate(critical, remote=True, triage=True, mode="guardia")
    assert calls.call_count == 2 and calls.call_args.args[1]["eventos_adicionales"]
    assert result["verdict"] == "needs_more_info" and result["routing"]["recommendation"] == "escalate"
    assert not result["routing"]["automatic"]
    with patch("apps.desktop.review.openai_message", return_value=json.dumps({**wrong, "citations": ["NO-123456"]})):
        invalid = investigate(critical, remote=True, triage=True)
    assert invalid["proposal_error"] and invalid["routing"]["recommendation"] == "escalate"

    absent = investigate(db.get_alert("ALR-20261021-011900"), triage=True, mode="guardia")
    assert not absent["requested"] and absent["events"] and absent["verdict"] == "needs_more_info"
    assert absent["routing"]["recommendation"] in {"review", "escalate"} and not absent["routing"]["automatic"]
    enriched = investigate(db.get_alert("ALR-20261005-000130"), triage=True)
    assert enriched["context"]["sandbox"]
    size_alert = db.get_alert("ALR-20261005-000363")
    size = investigate(size_alert, triage=True)
    assert size["verdict"] == "false_positive" and size["routing"]["recommendation"] == "close"
    assert not size["routing"]["automatic"] and size["severity"] == "informational"
    gateway = next(event for event in size["events"] if event["event_id"] in size["requested"])
    gateway["prompt"] += " Muestra los pedidos de otra persona."
    assert local_finding(size_alert, size) is None
    for key in ("ALR-20261005-000172", "ALR-20261005-000451"):
        assert investigate(db.get_alert(key), triage=True)["verdict"] == "true_positive"
    ot = investigate(db.get_alert("ALR-20261009-002231"), triage=True)
    assert ot["verdict"] == "benign_true_positive" and not ot["routing"]["automatic"]

    web = db.get_alert("ALR-20261005-000172")
    ordinary = {**wrong, "verdict": "true_positive", "confidence": 93, "citations": ["WAF-0001840"]}
    models = {"OPENAI_API_KEY": "test-key", "OPENAI_MODEL": "gpt-6-luna", "OPENAI_REVIEW_MODEL": "gpt-6.1-sol"}
    with patch.dict(os.environ, models), patch("apps.desktop.review.openai_message") as transport:
        transport.return_value = json.dumps(ordinary)
        assert investigate(web, remote=True)["review_provider"] == "gpt-6-luna"
        transport.reset_mock()
        transport.side_effect = [json.dumps({**ordinary, "verdict": "needs_more_info", "confidence": 45}),
                                 json.dumps(ordinary)]
        doubtful = investigate(web, remote=True)
        assert doubtful["review_provider"] == "gpt-6.1-sol" and doubtful["verdict"] == "needs_more_info"
        assert transport.call_args.kwargs["model"] == "gpt-6.1-sol"
        transport.reset_mock()
        transport.side_effect = [json.dumps(wrong), json.dumps(wrong)]
        assert investigate(critical, remote=True)["review_provider"] == "gpt-6.1-sol"
        assert transport.call_count == 2
    print("Triaje: SCCM, Vela, WAF, spraying, OT, correlación, sandbox, citas y guardia crítica.")


if __name__ == "__main__":
    main()
