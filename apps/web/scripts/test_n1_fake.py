"""Prueba el bucle del agente N1 con un cliente falso (no gasta API)."""
import json, jsonschema
from types import SimpleNamespace as NS
from apps.backend.agents import n1
from apps.backend.config import DATA

A = [json.loads(l) for l in open(DATA / "03_alertas/alertas.jsonl", encoding="utf-8")]
al = [a for a in A if a["alert_id"] == "ALR-20261010-011795"]   # volcado de LSASS
paso = {"n": 0}
def fake_create(**kw):
    paso["n"] += 1
    if paso["n"] == 1:
        return NS(content=[NS(type="text", text="Miro el equipo."),
                           NS(type="tool_use", id="t1", name="get_asset", input={"key": "WS-BCN-1770"})])
    return NS(content=[NS(type="tool_use", id="t2", name="submit_ticket", input={
        "title": "Volcado de LSASS en WS-BCN-1770", "verdict": "true_positive", "confidence": 0.9, "summary": "x",
        "severity_adjustments": [{"delta": 1, "reason": "ejecución confirmada"}],
        "affected": {"users": [], "hosts": ["WS-BCN-1770"], "business_services": [], "customers": []},
        "evidence": [{"source": "edr_events", "event_id": "EDR-0123414", "finding": "svchelper"},
                     {"source": "edr_events", "event_id": "EDR-9999999", "finding": "inventada"}],
        "enrichment": [], "mitre": ["T1003.001"], "recommended_actions": [],
        "escalation": {"escalate": True, "to": "N2", "reason": ""},
        "manipulation_detected": {"detected": False, "where": ""}, "open_questions": []})])
n1.client = NS(messages=NS(create=fake_create))
t = n1.investigar(al)
jsonschema.validate(t, json.load(open(DATA / "01_contexto/ticket_salida.schema.json", encoding="utf-8")))
print("OK schema |", t["severity"], "|", t["escalation"]["to"], "|", t["open_questions"])
