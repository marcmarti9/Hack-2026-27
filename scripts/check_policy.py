"""Comprueba la política contra alertas y activos del reto."""
from unittest.mock import patch

from apps.backend.rules.approvals import aprobacion
from apps.backend.rules.engine import fuera_de_horario, madrid, severidad
from apps.backend.tools import db
from apps.engine.review import investigate


def main() -> None:
    alert = db.get_alert("ALR-20261005-000172")
    event = db.get_event(alert["related_events"][0])
    assert event["source"] == "waf" and event["action"] == "blocked" and event["status"] == 403
    severity = severidad(alert, "true_positive", verified_prevention="bloqueo sin efecto (caso de prueba)")
    assert severity.level == "low"
    print("ALR-20261005-000172:", severity.level, "|", severity.rationale)
    assert severidad(alert, "true_positive").level == "medium"
    assert severidad(alert, "true_positive", verified_impact="acceso confirmado",
                     verified_prevention="bloqueo previo").level == "high"

    assert not aprobacion("isolate_host", "PLC-SORT01").permitted
    assert not aprobacion("block_ioc", "10.40.16.100").permitted
    assert not aprobacion("block_ioc", "::ffff:10.40.16.100").permitted
    scan = db.get_alert("ALR-20261007-011850")
    scan_events = db.get_events(scan["related_events"])
    scan_events[0]["dst_ip"] = "10.40.16.21"
    with patch.object(db, "get_events", return_value=scan_events):
        routing = investigate(scan, triage=True, mode="guardia")["routing"]
    assert routing["ot"] and routing["recommendation"] == "escalate" and not routing["automatic"]
    assert "Responsable de Operaciones" in routing["recipients"]
    payroll = db.get_alert("ALR-20261015-011818")
    payroll_events = db.get_events(payroll["related_events"])
    dlp = next(event for event in payroll_events if event["source"] == "dlp")
    ot_flow = db.get_event("FW-0026524")
    ot_flow.update(timestamp=dlp["timestamp"], src_ip=db.asset(dlp["hostname"])["ip"], action="deny")
    payroll["related_events"].append(ot_flow["event_id"])
    with patch.object(db, "get_events", return_value=[*payroll_events, ot_flow]):
        routing = investigate(payroll, triage=True, mode="guardia")["routing"]
    assert {"N2", "DPO", "Responsable de Operaciones"} <= set(routing["recipients"])
    stale_ot = {**scan, "external": True, "created_at": "2026-11-02T12:10:00Z",
                "entities": {"ips": ["192.0.2.90"]}, "related_events": ["FW-0004862"]}
    result = investigate(stale_ot, triage=True, mode="guardia")
    assert not result["routing"]["ot"] and "Responsable de Operaciones" not in result["routing"]["recipients"]
    assert any(row["event_id"] == "FW-0004862" and row["relation"] == "contexto"
               for row in result["report"]["evidence"])
    disclosure = db.get_alert("ALR-20261014-011817")
    assert "DPO" in investigate(disclosure, triage=True)["routing"]["recipients"]
    foreign = {**disclosure, "external": True,
               "entities": {"hosts": [{"hostname": "WMS01"}], "users": [{"upn": "marc.reyes@tarvia.example"}]}}
    result = investigate(foreign, triage=True)
    assert "DPO" not in result["routing"]["recipients"] and not result["report"]["affected"]["hosts"]
    provider = db.get_alert("ALR-20261011-011877")
    assert investigate(provider, triage=True)["verdict"] == "true_positive"
    wrong_ip = {**provider, "external": True, "entities": {**provider["entities"], "ips": ["192.0.2.91"]}}
    assert investigate(wrong_ip, triage=True)["verdict"] == "needs_more_info"
    stop = db.get_alert("ALR-20261018-011896")
    claimed_ot = {**stop, "external": True, "entities": {**stop["entities"],
                  "hosts": [*stop["entities"]["hosts"], {"hostname": "PLC-SORT01"}]}}
    result = investigate(claimed_ot, triage=True, mode="guardia")
    assert result["severity"] == "critical" and not result["routing"]["ot"]
    assert result["report"]["entity_discrepancies"] and result["report"]["recommended_actions"]
    approved = db.get_alert("ALR-20261013-011869")
    for mode in ("diurno", "guardia"):
        result = investigate(approved, triage=True, mode=mode)
        assert result["verdict"] == "benign_true_positive" and result["severity"] == "informational"
        assert result["routing"]["recommendation"] == "close" and result["routing"]["automatic"]
        maintenance = db.get_alert("ALR-20261024-011916")
        assert maintenance["severity"] == "critical"
        result = investigate(maintenance, triage=True, mode=mode)
        assert result["verdict"] == "benign_true_positive" and result["severity"] == "informational"
        assert result["routing"]["recommendation"] == "close" and not result["routing"]["automatic"]
    incomplete = db.get_alert("ALR-20261013-011870")
    incomplete["related_events"].append("EDR-0990017")
    result = investigate(incomplete, triage=True, mode="guardia")
    assert result["routing"]["recommendation"] != "close" and not result["routing"]["automatic"]
    miner = db.get_alert("ALR-20261006-011826")
    original = investigate(miner, triage=True)["verified_finding"]
    printer = db.asset("PRINT01")
    miner["entities"]["hosts"].append({"hostname": printer["hostname"], "ip": printer["ip"]})
    different_host = [{**flow, "src_ip": printer["ip"]} for flow in db.get_events(miner["related_events"])]
    with patch.object(db, "get_events", return_value=different_host):
        result = investigate(miner, triage=True)
    citations = (result.get("verified_finding") or {}).get("citations", [])
    assert not set(original["citations"][1:]) & set(citations)
    fraud = investigate(db.get_alert("ALR-20261011-011800"), triage=True)["report"]
    assert fraud["affected"]["customers"]
    assert any(row["source"] == "ecom_account" and row["cited"] and "Forma de pago" in row["finding"]
               for row in fraud["evidence"])
    web = investigate(alert, triage=True)["report"]
    assert any(row["cited"] and "Frontal" in row["finding"] and "Ruta" in row["finding"]
               for row in web["evidence"])
    assert not aprobacion("block_ioc", "https://mega.nz/file").permitted
    assert not aprobacion("isolate_host", "unknown").permitted
    assert aprobacion("isolate_host", "WEB-ECOM03").roles == ("N2", "Negocio")
    assert aprobacion("isolate_host", "JENKINS-DEV01").roles == ("N2", "Responsable del servicio")
    assert aprobacion("block_ioc", "files.mega.nz.").roles == ("N2",)
    assert aprobacion("block_ioc", "fakemega.nz").roles == ("N1",)
    assert not aprobacion("inventada", "JENKINS-DEV01").permitted
    assert madrid("2026-10-25T00:59:00Z").isoformat() == "2026-10-25T02:59:00+02:00"
    assert madrid("2026-10-25T01:00:00Z").isoformat() == "2026-10-25T02:00:00+01:00"
    assert fuera_de_horario("2026-10-25T01:00:00Z")
    assert not fuera_de_horario("2026-10-26T07:00:00Z")
    print("Política: OT bloqueada, aprobadores por activo, uso dual y cambio horario verificados.")


if __name__ == "__main__":
    main()
