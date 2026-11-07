"""Verifica clasificación EDR y enlaces del incidente contra un índice oficial de solo lectura."""

from base64 import b64encode
from copy import deepcopy
from time import perf_counter

from apps.backend.rules.coverage_edr import check
from apps.backend.rules.triage import _proof
from apps.backend.tools import db
from apps.desktop.review import _collect

INCIDENT_ALERTS = (
    "ALR-20261009-011791",
    "ALR-20261010-011794",
    "ALR-20261010-011795",
    "ALR-20261010-011797",
    "ALR-20261010-011798",
    "ALR-20261018-011896",
)
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
    replay.update(process_name="cmd.exe", command_line="cmd.exe /c echo vssadmin delete shadows")
    assert check(alert, analysis, [replay], _proof) is None
    replay.update(process_name="powershell.exe",
                  command_line="powershell.exe -Command Get-CimInstance Win32_ShadowCopy | Remove-CimInstance")
    assert check(alert, analysis, [replay], _proof)["verdict"] == "true_positive"
    payload = b64encode("Get-CimInstance Win32_ShadowCopy | Remove-CimInstance".encode("utf-16-le")).decode()
    replay["command_line"] = f"powershell.exe -EncodedCommand {payload}"
    assert check({**alert, "rule_id": "UC-EDR-002"}, analysis, [replay], _proof)["verdict"] == "true_positive"


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
        verify_dispositions()
        verify_rules_without_original_positives()
    print(f"6 alertas del incidente, 7 disposiciones y 14 comprobaciones adversariales. "
          f"Investigación local {min(timings)}–{max(timings)} ms por alerta del incidente en una sesión DuckDB.")


if __name__ == "__main__":
    main()
