"""Verifica clasificación EDR y enlaces del incidente contra un índice oficial de solo lectura."""

from base64 import b64encode
from copy import deepcopy
from datetime import timedelta
from time import perf_counter
from unittest.mock import patch

from apps.backend.rules.coverage_edr import check, link_incident, lsass_attempt, recovery_attempt
from apps.backend.rules.engine import madrid
from apps.backend.rules.triage import _proof
from apps.backend.tools import db
from apps.engine.review import _collect, investigate

INCIDENT_ALERTS = (
    "ALR-20261009-011791",
    "ALR-20261010-011794",
    "ALR-20261010-011795",
    "ALR-20261010-011797",
    "ALR-20261010-011798",
    "ALR-20261018-011896",
)
LINKED_ALERTS = ("ALR-20261009-011790", "ALR-20261009-011792", "ALR-20261018-011895")
INCIDENT_REFS = {
    "EML-0062206", "EDR-0123403", "EDR-0123404", "PRX-0211359", "EDR-0123405",
    "EDR-0123412", "FW-0025321", "EDR-0123413", "EDR-0123414", "EDR-0123415",
    "EDR-0123435", "ADE-0000570", "ADE-0000571", "EDR-0123437",
}


def case(alert_id):
    alert = db.get_alert(alert_id)
    assert alert, alert_id
    analysis = _collect(alert)
    direct = [event for event in analysis["events"] if event["event_id"] in analysis["requested"]]
    return alert, analysis, direct


def verify_incidents():
    timings = []
    for alert_id in INCIDENT_ALERTS:
        start = perf_counter()
        alert, analysis, direct = case(alert_id)
        out = check(alert, analysis, direct, _proof)
        timings.append(round(1000 * (perf_counter() - start)))
        assert out and out["verdict"] == "true_positive" and out["escalate"] == ["N2"], alert_id
        assert out["severity_override"] == "critical", alert_id
        assert not out.get("resolved") and not out.get("auto_close"), alert_id
        incident = out["incident"]
        assert set(incident["affected"]) == {"WS-BCN-1770", "FS01", "PRINT01"}, alert_id
        assert len(incident["timeline"]) == 11, alert_id
        assert incident["timeline"][0]["timestamp"][:10] == "2026-10-09", alert_id
        assert incident["timeline"][-1]["timestamp"][:10] == "2026-10-18", alert_id
        assert INCIDENT_REFS <= set(incident["evidence_ids"]) <= set(out["citations"]), alert_id
        assert set(out["citations"]) <= {event["event_id"] for event in analysis["events"]}, alert_id
        assert any("No se ha observado cifrado" in limit for limit in incident["limits"]), alert_id
        assert any(item["stage"] == "Defensa desactivada" for item in incident["timeline"]), alert_id
        if alert["rule_id"] == "UC-EDR-007":
            assert "reporta bloqueo" in out["summary"]
    return timings


def verify_incident_routing():
    alerts = (*INCIDENT_ALERTS, *LINKED_ALERTS)
    for mode in ("diurno", "guardia"):
        for alert_id in alerts:
            out = investigate(db.get_alert(alert_id), triage=True, mode=mode)
            assert out["report"]["ticket_id"] == "VIG-INC-FW-0025321", alert_id
            assert set(out["report"]["alert_ids"]) == set(alerts), alert_id
            assert len(out["report"]["incident"]["evidence_ids"]) == 27, alert_id
            assert out["severity"] == "critical" and out["sla"] == "15 min", alert_id
            assert out["routing"]["recommendation"] == "escalate" and not out["routing"]["automatic"], alert_id
            assert "N2 de guardia (teléfono)" in out["routing"]["recipients"], alert_id
            assert not out["report"]["executed_actions"], alert_id

    # An original citation is required even if the related events reveal the full incident.
    mail, analysis, direct = case(LINKED_ALERTS[0])
    unlinked = _proof("true_positive", [direct[0]], "Confirmación de adjunto malicioso.")
    analysis["requested"] = []
    assert not link_incident(mail, analysis, unlinked).get("incident")


def verify_smb_and_recovery():
    alert, analysis, direct = case("ALR-20261010-011797")
    service = next(event for event in direct if event.get("event_type") == "service_install")
    original = db.events_for_entity
    for fields in (
        {"proto": "UDP"},
        {"timestamp": (madrid(service["timestamp"]) + timedelta(minutes=2)).isoformat()},
    ):
        def mutate(events):
            return [{**event, **fields} if event["event_id"] == "FW-0025321" else event for event in events]

        assert check(alert, analysis, mutate(direct), _proof) is None
        with patch.object(db, "events_for_entity", side_effect=lambda *a, **k: mutate(original(*a, **k))):
            lsass = investigate(db.get_alert("ALR-20261010-011795"), triage=True)
        assert lsass["verdict"] == "true_positive" and not lsass["report"]["incident"]

    recovery = {**db.get_alert("ALR-20261010-011798"), "severity": "low", "external": True}
    out = investigate(recovery, triage=True, mode="guardia")
    assert out["severity"] == "critical" and out["sla"] == "15 min"
    assert "N2 de guardia (teléfono)" in out["routing"]["recipients"]


def verify_chain_evidence():
    installer = db.get_event("EDR-0123401")
    before_installer = (madrid(installer["timestamp"]) - timedelta(minutes=1)).isoformat()
    launch = db.get_event("EDR-0123403")
    before_launch = (madrid(launch["timestamp"]) - timedelta(seconds=1)).isoformat()
    get_events, events_for_entity = db.get_events, db.events_for_entity
    for alert_id, changes, incident_stays in (
        ("ALR-20261009-011791", {"EDR-0123402": {"timestamp": before_installer}}, False),
        ("ALR-20261010-011795", {
            event_id: {"user": r"OTHER\adm.aortega"} for event_id in ("EDR-0123415", "EDR-0123416")
        }, False),
        ("ALR-20261010-011795", {"EDR-0123404": {"timestamp": before_launch}}, True),
    ):
        def mutate(events):
            return [{**event, **changes.get(event["event_id"], {})} for event in events]

        with (
            patch.object(db, "get_events", side_effect=lambda *args: mutate(get_events(*args))),
            patch.object(db, "events_for_entity",
                         side_effect=lambda *args, **kwargs: mutate(events_for_entity(*args, **kwargs))),
        ):
            out = investigate(db.get_alert(alert_id), triage=True, mode="guardia")
        assert out["routing"]["recommendation"] == "escalate"
        incident = out["report"]["incident"]
        assert bool(incident) is incident_stays
        if incident:
            assert "EDR-0123404" not in incident["evidence_ids"]
            assert "Persistencia" not in {phase["stage"] for phase in incident["timeline"]}


def verify_approved_psexec():
    alert, analysis, direct = case("ALR-20261013-011869")
    service = next(event for event in direct if event.get("event_type") == "service_install")
    result = check(alert, analysis, direct, _proof)
    assert result["verdict"] == "benign_true_positive" and result["auto_close"]
    child = {
        **db.get_event("EDR-0123414"), "event_id": "EDR-0990002", "hostname": service["hostname"],
        "user": service["user"], "timestamp": (madrid(service["timestamp"]) + timedelta(seconds=10)).isoformat(),
    }
    unknown = {**child, "event_id": "EDR-0990003", "sha256": ""}
    inconclusive = check(alert, deepcopy(analysis), [*direct, unknown], _proof)
    assert inconclusive["verdict"] == "needs_more_info" and not inconclusive.get("auto_close")
    original = db.events_for_entity

    def pivot(value, *args, **kwargs):
        events = original(value, *args, **kwargs)
        if value == service["hostname"] and kwargs.get("source") == "edr_events":
            return [*events, unknown, child]
        return events

    direct_result = check(alert, deepcopy(analysis), [*direct, unknown, child], _proof)
    with patch.object(db, "events_for_entity", side_effect=pivot):
        linked_result = check(alert, deepcopy(analysis), direct, _proof)
    for result in (direct_result, linked_result):
        assert result["verdict"] == "true_positive" and "N2" in result["escalate"]
        assert child["event_id"] in result["citations"] and not result.get("auto_close")

    origin = db.asset("WS-BCN-1770")
    mixed = deepcopy(analysis)
    mixed["context"]["activos"].append(origin)
    rogue = {**service, "event_id": "EDR-0990015", "details": {**service["details"], "remote_host": origin["hostname"]}}
    flow = {**db.get_event("FW-0025321"), "timestamp": service["timestamp"],
            "src_ip": origin["ip"], "dst_ip": db.asset(service["hostname"])["ip"]}
    for events in ([*direct, rogue, flow], [rogue, *direct, flow]):
        result = check(alert, deepcopy(mixed), events, _proof)
        assert result["verdict"] == "true_positive" and rogue["event_id"] in result["citations"]
        assert not result.get("auto_close")
    result = check(alert, mixed, [*direct, rogue], _proof)
    assert result["verdict"] == "needs_more_info" and not result.get("auto_close")


def verify_direct_edr_evidence():
    maintenance = db.get_alert("ALR-20261024-011916")
    result = investigate(maintenance, triage=True)
    assert result["verdict"] == "benign_true_positive" and result["severity"] == "informational"
    assert not result["routing"]["automatic"]
    incomplete = {**maintenance, "related_events": [*maintenance["related_events"], "EDR-0990017"]}
    result = investigate(incomplete, triage=True)
    assert result["severity"] == "critical" and result["routing"]["recommendation"] == "escalate"

    wmic = {"event_type": "process_start", "process_name": "wmic.exe"}
    assert recovery_attempt({**wmic, "command_line": r'"C:\Windows\wmic.exe" shadowcopy delete'})
    assert recovery_attempt({**wmic, "command_line": 'wmic.exe path "Win32_ShadowCopy" delete'})
    assert not recovery_attempt({**wmic, "command_line": "wmic.exe path Win32_ShadowCopy get ID"})
    assert not recovery_attempt({**wmic, "command_line": 'wmic.exe process where "wmic shadowcopy delete" get Name'})

    lsass = db.get_event("EDR-0123412")
    assert lsass_attempt(lsass)
    assert not lsass_attempt({**lsass, "command_line": 'rundll32.exe shell32.dll,Info "comsvcs.dll MiniDump 708"'})
    assert not lsass_attempt({**lsass, "command_line": lsass["command_line"].replace("708", "709")})


def verify_antivirus_evidence_order():
    alert, analysis, direct = case("ALR-20261006-000578")
    quarantine = direct[0]
    detection = {**quarantine, "event_id": "EDR-0990090", "sha256": "ab" * 32,
                 "details": {**quarantine["details"], "action": "detected_only"}}
    execution = {**detection, "event_id": "EDR-0990091", "event_type": "process_start", "details": {}}
    for detections in ([quarantine, detection], [detection, quarantine]):
        result = check(alert, deepcopy(analysis), [*detections, execution], _proof)
        assert not result.get("resolved") and result["escalate"] == ["N2"]
        assert result["verified_impact"] and set(result["citations"]) == {
            quarantine["event_id"], detection["event_id"], execution["event_id"],
        }
        without_execution = check(alert, deepcopy(analysis), detections, _proof)
        assert not without_execution.get("resolved") and not without_execution.get("verified_impact")
        assert without_execution["escalate"] == ["N2"]


def verify_edr_stop_command():
    alert = db.get_alert("ALR-20261018-011896")
    get_events, events_for_entity = db.get_events, db.events_for_entity

    def replace(events):
        return [{**event, "command_line": 'sc.exe description EDRAgentSvc "Manual: sc.exe stop EDRAgentSvc"'}
                if event["event_id"] == "EDR-0123436" else event for event in events]

    with (
        patch.object(db, "get_events", side_effect=lambda *args: replace(get_events(*args))),
        patch.object(db, "events_for_entity",
                     side_effect=lambda *args, **kwargs: replace(events_for_entity(*args, **kwargs))),
    ):
        out = investigate(alert, triage=True, mode="guardia")
    assert out["severity"] == "critical" and out["routing"]["recommendation"] == "escalate"
    assert not out["report"]["incident"]
    assert "EDR-0123436" not in (out.get("decision_basis") or {}).get("citations", [])


def verify_external_entity_provenance():
    alert, analysis, direct = case("ALR-20261010-011798")
    event = next(event for event in direct if event["event_id"] == "EDR-0123415")
    alert = {**alert, "external": True, "severity": "low", "related_events": [event["event_id"]],
             "entities": {"hosts": [{"hostname": "FS01", "ip": "10.20.1.10"}],
                          "users": [{"upn": "adm.dnavarro@tarvia.example"}],
                          "processes": [{"name": "vssadmin.exe", "pid": 7002}]}}
    result = check(alert, deepcopy(analysis), [event], _proof)
    assert result["severity_override"] == "critical" and result["incident"]
    entities = result["entity_verification"]
    assert entities["verified"] == {
        "hosts": [{"hostname": "FS01", "ip": "10.20.2.20"}],
        "users": [{"upn": "adm.aortega@tarvia.example"}],
        "processes": [{"hostname": "FS01", "name": "vssadmin.exe", "pid": 7001}],
    }
    assert {row["field"] for row in entities["discrepancies"]} == {"hosts.ip", "users.upn", "processes.pid"}
    alert["entities"] = {"hosts": [{"ip": "10.20.2.20"}], "users": [{"upn": r"TARVIA\adm.aortega"}],
                         "processes": [{"name": "VSSADMIN.EXE", "pid": "7001"}]}
    result = check(alert, deepcopy(analysis), [event], _proof)
    assert result["entity_verification"]["verified"] == entities["verified"]
    assert not result["entity_verification"]["discrepancies"]
    alert["entities"]["users"] = [{"upn": r"OTHER\adm.aortega"}]
    result = check(alert, deepcopy(analysis), [event], _proof)
    assert [row["field"] for row in result["entity_verification"]["discrepancies"]] == ["users.upn"]


def verify_correlated_edr_stop():
    official = db.get_alert("ALR-20261018-011896")
    command, status = "EDR-0123436", "EDR-0123437"
    alert = {**official, "alert_id": "ALR-20261018-999995", "external": True, "severity": "low",
             "related_events": [status]}
    analysis = _collect(alert, correlate=False)
    assert [event["event_id"] for event in analysis["events"]] == [status]
    out = check(alert, analysis, analysis["events"].copy(), _proof)
    assert out["severity_override"] == "critical" and {command, status} <= set(out["incident"]["evidence_ids"])
    assert command in {event["event_id"] for event in analysis["events"]}
    for mode in ("diurno", "guardia"):
        result = investigate(alert, triage=True, mode=mode)
        assert result["report"]["ticket_id"] == "VIG-INC-FW-0025321"
        assert result["severity"] == "critical" and result["sla"] == "15 min"
        assert "N2 de guardia (teléfono)" in result["routing"]["recipients"]

    search = db.search_logs
    for mutation in ({"hostname": "FS01"}, {"timestamp": db.get_event("EDR-0123435")["timestamp"]},
                     {"command_line": "sc.exe stop DifferentService"}):
        def mismatch(*args, **kwargs):
            return [{**event, **mutation} if event["event_id"] == command else event
                    for event in search(*args, **kwargs)]

        with patch.object(db, "search_logs", side_effect=mismatch):
            analysis = _collect(alert, correlate=False)
            assert check(alert, analysis, analysis["events"].copy(), _proof) is None

    with patch.object(db, "search_logs", side_effect=lambda text, **kwargs: [] if text == "PSEXESVC"
                      else search(text, **kwargs)):
        analysis = _collect(alert, correlate=False)
        out = check(alert, analysis, analysis["events"].copy(), _proof)
    assert out["verdict"] == "true_positive" and not out.get("incident") and not out.get("severity_override")


def verify_dispositions():
    for alert_id, verdict, flag in (
        ("ALR-20261005-000212", "false_positive", "auto_close"),
        ("ALR-20261006-000578", "true_positive", "resolved"),
        ("ALR-20261012-011829", "true_positive", "escalate"),
        ("ALR-20261006-011825", "true_positive", "escalate"),
        ("ALR-20261024-011916", "benign_true_positive", None),
        ("ALR-20261020-011897", "true_positive", "escalate"),
        ("ALR-20261013-011869", "benign_true_positive", "auto_close"),
    ):
        alert, analysis, direct = case(alert_id)
        out = check(alert, analysis, direct, _proof)
        assert out and out["verdict"] == verdict, alert_id
        assert flag is None or out.get(flag), alert_id
        assert not out.get("incident"), alert_id

    alert, analysis, direct = case("ALR-20261005-000212")
    assert check(alert, analysis, [{**direct[0], "signer": ""}], _proof) is None
    assert check(alert, analysis, [{**direct[0], "hostname": "HOST-AJENO"}], _proof) is None
    analysis["events"].append({
        **direct[0], "event_id": "SYN-EDR-SAP-CHILD", "process_name": "powershell.exe",
        "parent_pid": direct[0]["pid"], "parent_name": direct[0]["process_name"],
    })
    assert check(alert, analysis, direct, _proof) is None

    alert, analysis, direct = case("ALR-20261006-000578")
    external = check({**alert, "external": True}, analysis, direct, _proof)
    assert not external.get("resolved") and not external.get("auto_close")

    for alert_id in ("ALR-20261005-000130", "ALR-20261101-010878"):
        alert, analysis, direct = case(alert_id)
        result = check(alert, analysis, direct, _proof)
        assert result and result["verdict"] == "true_positive", alert_id
        assert "no abarca toda la ventana" in result["summary"], alert_id
        assert not result.get("resolved") and not result.get("verified_prevention"), alert_id

    alert, analysis, direct = case("ALR-20261010-011798")
    replay = deepcopy(direct[0])
    replay["event_id"] = "SYN-EDR-UNRELATED-RECOVERY"
    replay["parent_pid"] = 90001
    out = check(alert, analysis, [replay], _proof)
    assert out and out["verdict"] == "true_positive" and not out.get("incident")
    assert out["severity_override"] == "critical"
    replay.update(process_name="cmd.exe", command_line="cmd.exe /c echo vssadmin delete shadows")
    assert check(alert, analysis, [replay], _proof) is None
    replay["process_name"] = "powershell.exe"
    for command, destructive in (
        ("Get-CimInstance Win32_ShadowCopy | Remove-CimInstance", True),
        ("Get-CimInstance -ClassName 'Win32_ShadowCopy' | Remove-CimInstance", True),
        ("Get-CimInstance -ClassName 'Win32_ShadowCopy' | Remove-CimInstance -Confirm:$false", True),
        ("Get-CimInstance Win32_ShadowCopy | Remove-CimInstance -Confirm:$false -WhatIf", False),
        ("Get-CimInstance Win32_ShadowCopy | Remove-CimInstance -WhatIf", False),
        ("Get-CimInstance Win32_ShadowCopy <# | Remove-CimInstance #>", False),
        ("Write-Output 'Get-CimInstance Win32_ShadowCopy | Remove-CimInstance'", False),
    ):
        payload = b64encode(command.encode("utf-16-le")).decode()
        for rule, arguments in (
            ("UC-EDR-007", f'-NoProfile -Command "{command}"'),
            ("UC-EDR-002", f"-NoProfile -EncodedCommand {payload}"),
        ):
            replay["command_line"] = f"powershell.exe {arguments}"
            result = check({**alert, "rule_id": rule}, analysis, [replay], _proof)
            if destructive:
                assert result["verdict"] == "true_positive" and result["severity_override"] == "critical"
            else:
                assert result is None


def verify_rules_without_original_positives():
    base_alert, base_analysis, events = case("ALR-20261009-011791")
    original = events[0]
    analysis = deepcopy(base_analysis)
    web_shell = {
        **original, "event_id": "SYN-EDR-WEBSHELL", "process_name": "bash", "parent_name": "nginx",
        "command_line": "bash -c 'echo a | base64 -d | sh'",
    }
    analysis["context"]["activos"] = [{"hostname": original["hostname"], "type": "web server", "vulnerabilities": []}]
    alert = {**base_alert, "rule_id": "UC-EDR-009"}
    assert check(alert, analysis, [web_shell], _proof)["verdict"] == "true_positive"
    ordinary_shell = {**web_shell, "command_line": "bash -c /usr/local/bin/healthcheck"}
    assert check(alert, analysis, [ordinary_shell], _proof)["verdict"] == "needs_more_info"

    browser_read = {
        **original, "event_id": "SYN-EDR-BROWSER", "event_type": "file_read",
        "sha256": "49667c17ddace2eac78851676274b08c4686c8ac1e78f0e6a617f936a840e50b",
        "process_name": "npp.8.7.Installer.x64.exe",
        "details": {"target_path": r"C:\Users\demo\AppData\Local\Google\Chrome\User Data\Default\Login Data"},
    }
    alert = {**base_alert, "rule_id": "UC-EDR-010"}
    assert check(alert, analysis, [browser_read], _proof)["verdict"] == "true_positive"
    assert check(alert, analysis, [{**browser_read, "process_name": "chrome.exe"}], _proof) is None


def main():
    with db.read_session():
        timings = verify_incidents()
        verify_incident_routing()
        verify_smb_and_recovery()
        verify_chain_evidence()
        verify_approved_psexec()
        verify_direct_edr_evidence()
        verify_antivirus_evidence_order()
        verify_edr_stop_command()
        verify_external_entity_provenance()
        verify_correlated_edr_stop()
        verify_dispositions()
        verify_rules_without_original_positives()
    print(f"9 alertas del incidente en ambos turnos, 7 disposiciones y comprobaciones adversariales. "
          f"Investigación local {min(timings)}–{max(timings)} ms por alerta del incidente en una sesión DuckDB.")


if __name__ == "__main__":
    main()
