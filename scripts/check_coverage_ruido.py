"""Verifica el triaje WAF/red/DNS con el índice oficial en VIGIA_OUT_DIR."""
from copy import deepcopy
from datetime import timedelta
from unittest.mock import patch

from apps.backend.rules.coverage_ruido import check
from apps.backend.rules.triage import _proof
from apps.backend.tools import db
from apps.desktop.review import _collect


def _case(key):
    alert = db.get_alert(f"ALR-{key}")
    assert alert, f"Falta el caso oficial {key} en el índice."
    analysis = _collect(alert, correlate=False)
    return alert, analysis, analysis["events"]


def _result(case, *, verdict, auto=False, resolved=False, escalate=False, pivot=False):
    result = check(*case, _proof)
    assert result is not None, case[0]["alert_id"]
    assert result["verdict"] == verdict, result
    assert bool(result.get("auto_close")) == auto, result
    assert bool(result.get("resolved")) == resolved, result
    assert ("N2" in result.get("escalate", [])) == escalate, result
    evidence = {event["event_id"] for event in case[1]["events"]} if pivot else set(case[0]["related_events"])
    assert result["citations"] and set(result["citations"]) <= evidence, result
    return result


def _no_closure(case):
    result = check(*case, _proof) or {}
    assert not result.get("auto_close") and not result.get("resolved"), result


def main():
    with db.read_session():
        blocked = _case("20261005-000173")
        _result(blocked, verdict="true_positive", resolved=True)
        assert blocked[1]["trace"][-1]["tool"] == "Actividad posterior del origen"

        scanner = _case("20261005-000440")
        _result(scanner, verdict="false_positive", auto=True)
        spoof = deepcopy(scanner)
        spoof[2][0]["uri"] = "/wp-login.php?payload=UNION%20SELECT"
        _no_closure(spoof)
        _no_closure((*scanner[:2], []))

        allowed = {
            **blocked[2][0], "event_id": "WAF-SYNTHETIC-ALLOW", "action": "allowed", "status": 200,
            "timestamp": blocked[0]["created_at"],
        }
        with patch.object(db, "events_for_entity", return_value=[*blocked[2], allowed]):
            _result(blocked, verdict="true_positive")
        with patch.object(db, "events_for_entity", return_value=[blocked[2][0]] * 500):
            _result(blocked, verdict="true_positive")
        with patch.object(db, "events_for_entity", return_value=[]):
            _no_closure(scanner)

        boundary = _case("20261101-010834")
        _result(boundary, verdict="true_positive")
        assert "Ventana sin cubrir" in boundary[1]["trace"][-1]["note"]
        assert "Referencias corroboradas y consulta sin truncar" in boundary[1]["trace"][-1]["note"]

        boundary = _case("20261005-000172")
        _result(boundary, verdict="true_positive")
        assert "Ventana sin cubrir en ecom_auth." in boundary[1]["trace"][-1]["note"]

        first, last = db.source_bounds("waf")
        with patch.object(db, "source_bounds", side_effect=lambda source: (first, last) if source == "waf" else None):
            _result(blocked, verdict="true_positive")
            assert "Ventana sin cubrir en ecom_auth." in blocked[1]["trace"][-1]["note"]
        with patch.object(db, "source_bounds", return_value=(last - timedelta(hours=1), last)):
            _no_closure(scanner)

        pentest = _case("20261008-011833")
        _result(pentest, verdict="benign_true_positive", auto=True)
        spoof = deepcopy(pentest)
        spoof[1]["context"]["cambios"] = []
        _no_closure(spoof)
        spoof = deepcopy(pentest)
        spoof[2][0]["user_agent"] += "-suplantado"
        _no_closure(spoof)
        spoof = deepcopy(pentest)
        spoof[2][0]["host"] = "otra-tienda.example"
        _no_closure(spoof)
        spoof = deepcopy(pentest)
        spoof[0]["created_at"] = "2026-10-08T05:59:14.000Z"
        for event in spoof[2]:
            event["timestamp"] = spoof[0]["created_at"]
        _no_closure(spoof)

        heartbeat = _case("20261005-000057")
        _result(heartbeat, verdict="false_positive", auto=True)
        _result(_case("20261005-000144"), verdict="false_positive", auto=True)
        spoof = deepcopy(heartbeat)
        for event in spoof[2]:
            event["dst_ip"] = "203.0.113.1"
        _no_closure(spoof)
        spoof = deepcopy(heartbeat)
        spoof[2][0]["src_ip"] = "10.255.255.255"
        _no_closure(spoof)
        spoof = deepcopy(heartbeat)
        spoof[2][0]["method"] = "POST"
        _no_closure(spoof)
        _result(_case("20261009-011792"), verdict="true_positive", escalate=True)
        pos = _case("20261021-011900")
        assert not pos[2]
        finding = _result(pos, verdict="true_positive", escalate=True, pivot=True)
        assert len(finding["citations"]) == 6 and finding["verified_impact"]
        with patch.object(db, "sandbox", return_value=None):
            assert check(*_case("20261021-011900"), _proof) is None

        blocklist = _case("20261009-011793")
        _result(blocklist, verdict="true_positive", escalate=True)
        spoof = deepcopy(blocklist)
        spoof[2][0]["action"] = "deny"
        assert check(*spoof, _proof) is None

        nessus = _case("20261007-011850")
        _result(nessus, verdict="benign_true_positive", auto=True)
        _result(_case("20261007-011853"), verdict="benign_true_positive", auto=True)
        spoof = deepcopy(nessus)
        spoof[2][0]["dst_ip"] = "10.40.18.40"
        _no_closure(spoof)
        spoof = deepcopy(nessus)
        spoof[2][0]["rule"] = "INTER-ZONA"
        _no_closure(spoof)
        spoof = deepcopy(nessus)
        spoof[0]["created_at"] = "2026-10-07T03:08:22.000Z"
        _no_closure(spoof)
        _result(_case("20261010-011796"), verdict="true_positive", escalate=True)

        _result(_case("20261005-000240"), verdict="needs_more_info")
        reputation = _case("20261005-000453")
        _result(reputation, verdict="false_positive", auto=True)
        spoof = deepcopy(reputation)
        spoof[2][0]["query"] += ".untrusted.example"
        _no_closure(spoof)
        spoof = deepcopy(reputation)
        spoof[2][0]["qtype"] = "TXT"
        _no_closure(spoof)
        _result(_case("20261011-011883"), verdict="true_positive", escalate=True)
    print("WAF, red y DNS: ejemplos oficiales y comprobaciones contra suplantación superados.")


if __name__ == "__main__":
    main()
