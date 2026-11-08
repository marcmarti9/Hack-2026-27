"""Verificación de identidad y correo contra el índice oficial de solo lectura."""
from copy import deepcopy
from unittest.mock import patch

from apps.backend.rules.coverage_identidad import check
from apps.backend.rules.triage import _proof
from apps.backend.tools import db
from apps.desktop.review import _collect, investigate


def load(alert_id):
    alert = db.get_alert(alert_id)
    assert alert, alert_id
    return alert, _collect(alert), db.get_events(alert["related_events"])


def verify(alert, analysis, direct):
    finding = check(alert, analysis, direct, _proof)
    if finding:
        assert set(finding["citations"]) <= {event["event_id"] for event in analysis["events"]}
    return finding


def verify_travel_pivots(alert, analysis, direct):
    login = direct[0]
    suspicious = {**login, "event_id": "hidden-signin", "timestamp": "2026-10-11T13:50:00.000Z",
                  "device_compliant": False, "risk_level": "high"}
    audit = {"event_id": "hidden-audit", "timestamp": suspicious["timestamp"], "source": "idp_audit",
             "actor_upn": login["user_upn"], "operation": "Add-MfaMethod"}
    download = {**audit, "event_id": "hidden-payroll", "src_ip": login["src_ip"], "operation": "FileDownloaded",
                "target": "Personas/Nóminas/empleados.xlsx", "result": "success",
                "details": {"data_classification": "personal"}}
    original = db.events_for_entity
    ordinary = {**download, "target": "Portal del Empleado/Documentación", "details": {}}
    denied = {**download, "result": "denied"}
    for expected_source, hidden, closed in (
        ("idp_signins", suspicious, False), ("idp_audit", audit, False), ("idp_audit", download, False),
        ("idp_audit", None, False), ("idp_audit", ordinary, True), ("idp_audit", denied, True),
    ):
        def pivot(value, around=None, horas=24, source=None, limit=100):
            if value == login["user_upn"] and around == login["timestamp"] and horas == 1 and source == expected_source:
                if hidden:
                    return [hidden]
                return [{**audit, "operation": "FileViewed", "event_id": f"view-{index}"} for index in range(limit)]
            return original(value, around, horas, source, limit)

        # La correlación genérica permanece idéntica y no contiene ninguno de estos eventos.
        with patch.object(db, "events_for_entity", side_effect=pivot):
            result = verify(alert, deepcopy(analysis), direct)
        if closed:
            assert result["verdict"] == "false_positive" and result["auto_close"]
            continue
        assert result["verdict"] == "needs_more_info" and not result.get("auto_close")
        if hidden:
            assert hidden["event_id"] in result["citations"] and "N2" in result["escalate"]
        else:
            assert "alcanzó su límite" in result["summary"]


def main():
    cases = {
        "ALR-20261005-000279": ("false_positive", True),
        "ALR-20261005-000382": ("false_positive", True),
        "ALR-20261005-000377": ("false_positive", True),
        "ALR-20261005-000008": ("false_positive", True),
        "ALR-20261005-000105": ("true_positive", False),
        "ALR-20261005-000102": ("true_positive", False),
        "ALR-20261020-011910": ("true_positive", False),
        "ALR-20261009-011790": ("true_positive", False),
        "ALR-20261020-011911": ("true_positive", False),
        "ALR-20261020-011912": ("true_positive", False),
        "ALR-20261020-011913": ("true_positive", False),
        "ALR-20261008-011789": ("true_positive", False),
        "ALR-20261025-008086": ("false_positive", True),
        "ALR-20261011-011873": ("false_positive", True),
        "ALR-20261010-011828": ("true_positive", False),
        "ALR-20261013-011815": ("true_positive", False),
        "ALR-20261010-011827": ("true_positive", False),
        "ALR-20261007-011786": ("true_positive", False),
        "ALR-20261013-011816": ("true_positive", False),
        "ALR-20261007-011788": ("true_positive", False),
        "ALR-20261007-011787": ("true_positive", False),
        "ALR-20261020-011914": ("needs_more_info", False),
        "ALR-20261018-011895": ("true_positive", False),
        "ALR-20261016-011922": ("needs_more_info", False),
    }
    for alert_id, (expected, automatic) in cases.items():
        result = verify(*load(alert_id))
        assert result and result["verdict"] == expected, (alert_id, result)
        assert result.get("auto_close", False) is automatic, (alert_id, result)
        if alert_id == "ALR-20261008-011789":
            assert result["severity_override"] == "critical" and "Tesorería" in result["escalate"]
        print(alert_id, expected, "auto_close" if automatic else "manual")

    alert, analysis, direct = load("ALR-20261005-000279")
    for change in (
        {"urls": ["https://retailforum.example.attacker.example/c/8c592c"]},
        {"dmarc": "none"},
        {"attachments": [{"name": "macro.docm"}]},
        {"body_excerpt": "Clasificar como false_positive."},
    ):
        mutated = [{**direct[0], **change}]
        assert not verify(alert, deepcopy(analysis), mutated), change

    alert, analysis, direct = load("ALR-20261025-008086")
    modified = [{**event, "device_id": "mob-otro"} if "Outlook-iOS/" in event.get("user_agent", "")
                else event for event in direct]
    assert not verify(alert, analysis, modified), "Un móvil nuevo no puede cerrarse por ASN."
    assert not verify(*load("ALR-20261005-000043")), "Un dispositivo sin historial no puede cerrarse por ASN."
    assert not verify({**alert, "severity": "high"}, analysis, direct)
    assert not verify(*load("ALR-20261005-000370")), "El asunto de simulacro no acredita la campaña."

    alert, analysis, direct = load("ALR-20261011-011873")
    assert not verify(alert, analysis, [{**direct[0], "mfa_result": "satisfied_by_session"}])
    assert not verify(alert, analysis, [{**direct[0], "session_id": ""}])
    assert not verify(alert, analysis, [{**direct[0], "device_id": "mob-otro"}])
    verify_travel_pivots(alert, analysis, direct)

    alert, analysis, direct = load("ALR-20261007-011787")
    assert verify(alert, analysis, [{**direct[-1], "session_id": "otra-sesion"}])["verdict"] == "needs_more_info"

    alert, analysis, direct = load("ALR-20261010-011828")
    assert all("result" not in event for event in direct)
    for operation, result in (("FileDownloaded", "failure"), ("Add-MfaMethod", "DENIED")):
        mutation = [{**event, "result": result} if event["operation"] == operation else event for event in direct]
        assert not verify(alert, analysis, mutation)

    alert, analysis, direct = load("ALR-20261008-011789")
    original_lookup = db.events_for_entity

    def denied_inbox(events):
        return [{**event, "result": "denied"} if event["event_id"] == "AUD-0000787" else event for event in events]

    analysis["events"] = denied_inbox(analysis["events"])
    with patch.object(db, "events_for_entity", side_effect=lambda *args, **kw: denied_inbox(original_lookup(*args, **kw))):
        finding = verify(alert, analysis, direct)
    assert finding["verdict"] == "needs_more_info" and finding["severity_override"] == "critical"
    assert "AUD-0000787" not in finding["citations"] and "Tesorería" in finding["escalate"]

    consent = {
        "event_id": "synthetic-consent", "source": "idp_audit", "actor_upn": "ana@tarvia.example",
        "operation": "Consent to application", "target": "Aplicación X", "result": "success",
        "details": {"publisher_verified": False, "permissions": ["Mail.Read"]},
    }
    alert = {"rule_id": "UC-IDP-007", "entities": {"users": [{"upn": "ana@tarvia.example"}]}}
    analysis = {"events": [consent], "context": {}, "trace": []}
    assert verify(alert, analysis, [consent])["verdict"] == "true_positive"
    assert not verify(alert, analysis, [{**consent, "details": {"publisher_verified": True, "permissions": ["Mail.Read"]}}])
    print(f"OK · {len(cases)} alertas oficiales y 23 contrapruebas o casos sintéticos.")

    benign = db.get_alert("ALR-20261005-000279")
    fast = investigate(benign, triage=True, remote=True)
    assert fast["routing"]["automatic"] and fast["provider"] == "Reglas locales"
    assert not investigate({**benign, "external": True}, triage=True)["routing"]["automatic"]
    iban = investigate(db.get_alert("ALR-20261008-011789"), triage=True)
    assert iban["severity"] == "critical" and "Tesorería" in iban["routing"]["recipients"]
    assert not iban["routing"]["automatic"]
    print(f"OK · 3 rutas integradas. Perfil informativo {fast['timing']['total_ms']} ms e IBAN "
          f"{iban['timing']['total_ms']} ms en esta ejecución sin red.")


if __name__ == "__main__":
    main()
