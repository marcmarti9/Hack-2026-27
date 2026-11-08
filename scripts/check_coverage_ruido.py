"""Verifica el triaje WAF/red/DNS con el índice oficial en VIGIA_OUT_DIR."""
from copy import deepcopy
from datetime import timedelta
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from apps.backend.rules.coverage_ruido import check
from apps.backend.rules.engine import madrid
from apps.backend.rules.triage import _proof
from apps.backend.tools import db
from apps.engine.defense import load_alerts
from apps.engine.review import _collect, investigate


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


def verify_stuffing():
    blocked = _case("20261018-005422")
    _result(blocked, verdict="true_positive")
    fingerprint = "91b782fd09d448699b94278f25feddae"
    for event in blocked[2]:
        event["device_fp"] = fingerprint
    _result(blocked, verdict="true_positive")
    first = _case("20261011-011799")
    first_failures = [row for row in first[2] if row["result"] == "failure"]
    first_failure_ids = {row["event_id"] for row in first_failures}
    for number, successes, purchases in ((11799, 6, 6), (11800, 6, 6), (11801, 4, 0), (11802, 7, 0)):
        case = _case(f"20261011-{number:06}")
        known = _result(case, verdict="true_positive", escalate=True, pivot=True)
        assert known["escalate"] == ["N2", "Fraude"]
        assert f"{successes} accesos correctos" in known["summary"]
        assert len([key for key in known["citations"] if key.startswith("ECO-")]) == purchases * 2
        assert len(known["affected_customers"]) == successes
        block, protect, reset, fraud = known["action_plan"]
        assert "bloqueo" in block["action"] and not block["requires_approval"]
        assert "CAPTCHA" in protect["action"] and protect["requires_approval"]
        assert reset["requires_approval"] and reset["approver"] == "N2"
        assert set(reset["target"].split(", ")) == set(known["affected_customers"])
        assert "Fraude" in fraud["action"]
        if number != 11799:
            assert not set(known["citations"]) & first_failure_ids
        assert case[1]["trace"][-1]["tool"] == "Pivote de accesos a la tienda"

    spoof = deepcopy(first)
    for event in spoof[2]:
        if event.get("result") == "success":
            event["src_ip"] = "203.0.113.123"
    assert check(*spoof, _proof) is None
    with patch.object(db, "search_logs", return_value=first_failures):
        assert check(*_case("20261011-011800"), _proof) is None
    latest = max(madrid(row["timestamp"]) for row in first[2] if row["result"] == "success")
    later = [{**row, "timestamp": (latest + timedelta(seconds=1)).isoformat()} for row in first_failures]
    with patch.object(db, "search_logs", return_value=later):
        assert check(*first, _proof) is None

    opaque = deepcopy(first)
    for event in opaque[2]:
        event["device_fp"] = fingerprint
    search = db.search_logs

    def opaque_search(value, **kwargs):
        assert value == fingerprint
        return [{**row, "device_fp": fingerprint} for row in search("fp-headless-0", **kwargs)]

    with patch.object(db, "search_logs", side_effect=opaque_search):
        detected = _result(deepcopy(opaque), verdict="true_positive", escalate=True, pivot=True)
        assert detected["escalate"] == ["N2", "Fraude"]
        assert "6 accesos correctos" in detected["summary"]
    with patch.object(db, "search_logs", return_value=opaque[2][:1]):
        assert check(*opaque, _proof) is None

    original = db.events_for_entity
    customer = next(row["customer_id"] for row in first[2] if row["result"] == "success")

    def changed_address(*args, **kwargs):
        rows = original(*args, **kwargs)
        if args[0] != customer:
            return rows
        return [{**row, "event": "address_change", "details": {"new_city": "Lisboa"}}
                if row["event"] == "email_change" else row for row in rows]

    with patch.object(db, "events_for_entity", side_effect=changed_address):
        detected = _result(deepcopy(first), verdict="true_positive", escalate=True, pivot=True)
        assert "5 cambios a correo temporal y 1 de dirección" in detected["summary"]
        assert {"ECO-0008092", "ECO-0008093"} <= set(detected["citations"])

    def different_customer(*args, **kwargs):
        return [{**row, "customer_id": "otro-cliente"} for row in original(*args, **kwargs)]

    with patch.object(db, "events_for_entity", side_effect=different_customer):
        known = _result(_case("20261011-011799"), verdict="true_positive", escalate=True, pivot=True)
        assert not any(key.startswith("ECO-") for key in known["citations"])

    second = _case("20261011-011800")
    login = next(row for row in second[2] if row["result"] == "success")
    for omitted, kept, changes, purchases in (("ECO-0008104", "ECO-0008105", 5, 6),
                                              ("ECO-0008105", "ECO-0008104", 6, 5)):
        def independent_activity(*args, **kwargs):
            return [row for row in original(*args, **kwargs) if row["event_id"] != omitted]

        with patch.object(db, "events_for_entity", side_effect=independent_activity):
            known = _result(deepcopy(second), verdict="true_positive", escalate=True, pivot=True)
            assert kept in known["citations"] and omitted not in known["citations"]
            assert f"{changes} cambios a correo temporal" in known["summary"]
            assert f"{purchases} compras de tarjeta regalo" in known["summary"]
            assert "5 compras siguieron" in known["summary"]

    def late_purchase(*args, **kwargs):
        delayed = (madrid(login["timestamp"]) + timedelta(hours=2)).isoformat()
        return [{**row, "timestamp": delayed} if row["event_id"] == "ECO-0008105" else row
                for row in original(*args, **kwargs)]

    with patch.object(db, "events_for_entity", side_effect=late_purchase):
        known = _result(deepcopy(second), verdict="true_positive", escalate=True, pivot=True)
        assert "ECO-0008104" in known["citations"] and "ECO-0008105" not in known["citations"]

    def different_purchase_origin(*args, **kwargs):
        return [{**row, "src_ip": "203.0.113.200"} if row["event_id"] == "ECO-0008105" else row
                for row in original(*args, **kwargs)]

    with patch.object(db, "events_for_entity", side_effect=different_purchase_origin):
        case = deepcopy(second)
        known = _result(case, verdict="true_positive", escalate=True, pivot=True)
        assert "ECO-0008105" not in known["citations"] and "ECO-0008105" in known["context_citations"]
        assert any(event["event_id"] == "ECO-0008105" for event in case[1]["events"])
        assert "5 compras de tarjeta regalo, 5 con tarjeta guardada" in known["summary"]
        assert "otras IP en las mismas cuentas incluyen compras de tarjeta regalo (1)" in known["summary"]

    verify_stuffing_scope(second[0])


def verify_stuffing_scope(official):
    origin = "198.51.100.101"
    customer = {"customer_id": "C702404"}
    store_login = official["entities"]["urls"]
    declarations = (
        {"ips": [origin], "urls": ["https://unrelated.example/api/v1/auth/login"]},
        {"ips": [origin], "urls": ["https://www.tarvia.example/unrelated"]},
        {"ips": [origin], "urls": store_login, "customers": [{"customer_id": "C703637"}]},
        {"ips": [origin], "urls": store_login, "customers": [customer]},
        {"urls": store_login, "customers": [customer]},
        {"urls": store_login},
    )
    fixtures = [{**official, "alert_id": f"ALR-20261011-{990803 + index:06}", "entities": entities}
                for index, entities in enumerate(declarations)]
    with TemporaryDirectory() as directory:
        path = Path(directory) / "scope.jsonl"
        path.write_text("".join(json.dumps(alert) + "\n" for alert in fixtures), encoding="utf-8")
        alerts = load_alerts(path)
    reports = [investigate(alert, triage=True, mode="guardia")["report"] for alert in alerts]
    for report in reports[:3]:
        finding = report["criterio_verificado"]
        assert report["verdict"] == "needs_more_info"
        assert not finding["citations"] and not finding.get("action_plan")
        assert "Fraude" not in report["routing"]["recipients"] and not report["routing"]["automatic"]
        assert any(row["relation"] == "contexto" and not row["cited"] for row in report["evidence"])
    assert "URL declarada no coincide" in reports[0]["summary"]
    assert "fuera del alcance declarado" in reports[2]["summary"]
    for report in reports[3:5]:
        finding = report["criterio_verificado"]
        assert report["verdict"] == "true_positive" and "Fraude" in report["routing"]["recipients"]
        assert finding["affected_customers"] == [customer["customer_id"]]
        assert finding["action_plan"][0]["target"] == origin
        assert finding["action_plan"][2]["target"] == customer["customer_id"]
        assert "ECA-0045102" in finding["citations"] and "ECA-0045099" in finding["context_citations"]
    assert len(reports[-1]["criterio_verificado"]["affected_customers"]) == 6
    assert "Fraude" in reports[-1]["routing"]["recipients"] and not reports[-1]["routing"]["automatic"]


def main():
    with db.read_session():
        blocked = _case("20261005-000173")
        _result(blocked, verdict="true_positive", resolved=True)
        assert blocked[1]["trace"][-1]["tool"] == "Actividad posterior del origen"

        scanner = _case("20261005-000440")
        _result(scanner, verdict="false_positive", auto=True)
        unrelated = deepcopy(scanner)
        unrelated[0]["entities"]["urls"] = ["https://www.tarvia.example/vendor/phpunit/src/Util/PHP/eval-stdin.php"]
        result = _result(unrelated, verdict="needs_more_info")
        assert "La URL declarada no coincide" in result["summary"]
        unrelated[0]["entities"]["urls"] = ["https://otra-tienda.example/wp-login.php"]
        _result(unrelated, verdict="needs_more_info")
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
        boundary[2][0]["uri"] += "?param=1"
        boundary[0]["entities"]["urls"][0] += "?param=1"
        _result(boundary, verdict="true_positive")
        with TemporaryDirectory() as directory:
            path = Path(directory) / "aviso.jsonl"
            stale = {**boundary[0], "alert_id": "ALR-20261008-999001", "created_at": "2026-10-08T22:13:15.000Z"}
            path.write_text(json.dumps(stale) + "\n", encoding="utf-8")
            new, = load_alerts(path)
            assert investigate(new, triage=True, mode="guardia")["verdict"] == "needs_more_info"
        verify_stuffing()

        first, last = db.source_bounds("waf")
        with patch.object(db, "source_bounds", side_effect=lambda source: (first, last) if source == "waf" else None):
            _result(blocked, verdict="true_positive")
            assert "Ventana sin cubrir en ecom_auth." in blocked[1]["trace"][-1]["note"]
        with patch.object(db, "source_bounds", return_value=(last - timedelta(hours=1), last)):
            _no_closure(scanner)

        pentest = _case("20261008-011833")
        _result(pentest, verdict="benign_true_positive", auto=True)
        future = deepcopy(pentest)
        for event in future[2]:
            event["timestamp"] = (madrid(future[0]["created_at"]) + timedelta(minutes=25)).isoformat()
        assert check(*future, _proof) is None
        assert set(future[1]["followup_event_ids"]) == set(future[0]["related_events"])
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
        matching = deepcopy(heartbeat)
        matching[0]["entities"]["ips"] = [matching[2][0]["dst_ip"]]
        _result(matching, verdict="false_positive", auto=True)
        matching[0]["entities"]["ips"] = ["203.0.113.200"]
        _result(matching, verdict="needs_more_info")
        mixed = _case("20261005-000144")
        finding = _result(mixed, verdict="false_positive", auto=True)
        assert len(finding["citations"]) == 2 and len(mixed[1]["followup_event_ids"]) == 2
        assert not set(finding["citations"]) & set(mixed[1]["followup_event_ids"])
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
        c2 = _case("20261009-011792")
        confirmed = _result(c2, verdict="true_positive", escalate=True)
        assert "PRX-0211359" in confirmed["citations"]
        for urls in (["ftp://aplihartom.com/transfer"], ["https://unrelated.example/live/"],
                     ["https://aplihartom.com/live/?unobserved=1"], ["https://aplihartom.com:8443/live/"],
                     ["https://aplihartom.com/live/", "http://aplihartom.com/live/"]):
            clone = deepcopy(c2)
            clone[0].update(alert_id="ALR-20261009-997001", external=True)
            clone[0]["entities"]["urls"] = urls
            result = check(*clone, _proof)
            assert result["verdict"] == "needs_more_info" and not result["citations"] and not result["actions"]
            assert set(result["context_citations"]) == set(c2[0]["related_events"])
            assert result["entity_verification"]["discrepancies"] == [
                {"field": "urls", "declared": urls, "verified": ["https://aplihartom.com/live/"]}]
        clone = deepcopy(c2)
        clone[0]["external"] = True
        clone[0]["entities"]["urls"] = ["HTTPS://APLIHARTOM.COM:443/live/"]
        matching = _result(clone, verdict="true_positive", escalate=True)
        assert matching["citations"] == confirmed["citations"]
        clone[2][0]["url"] = "https://aplihartom.com/other/"
        matching = _result(clone, verdict="true_positive", escalate=True)
        assert "PRX-0211359" not in matching["citations"] and "PRX-0211359" in clone[1]["context_event_ids"]
        future = deepcopy(c2)
        for event in future[2]:
            event["timestamp"] = (madrid(future[0]["created_at"]) + timedelta(minutes=45)).isoformat()
        assert check(*future, _proof) is None
        assert set(future[1]["followup_event_ids"]) == set(future[0]["related_events"])
        future[2][0]["timestamp"] = c2[2][0]["timestamp"]
        future[1]["followup_event_ids"].clear()
        supported = _result(future, verdict="true_positive", escalate=True)
        assert supported["citations"] == ["PRX-0211359"] and len(future[1]["followup_event_ids"]) == 9
        for edit in ({"url": "https://unrelated.example/health"}, {"dst_ip": "203.0.113.100"}):
            spoof = deepcopy(c2)
            for event in spoof[2]:
                event.update(edit)
            assert check(*spoof, _proof) is None
        failed = deepcopy(c2)
        for event in failed[2]:
            event.update(status="502", bytes_out="0", bytes_in="0")
        limited = _result(failed, verdict="needs_more_info", escalate=True)
        assert "permitidas por política" in limited["summary"]
        pos = _case("20261021-011900")
        assert not pos[2]
        finding = _result(pos, verdict="true_positive", escalate=True, pivot=True)
        assert len(finding["citations"]) == 6 and finding["verified_impact"]
        clone = _case("20261021-011900")
        clone[0]["external"] = True
        clone[0]["entities"]["urls"] = ["https://pos-update-service.example:443/api/v2/sync"]
        matching = _result(clone, verdict="true_positive", escalate=True, pivot=True)
        assert matching["citations"] == finding["citations"]
        for url in ("ftp://pos-update-service.example/api/v2/sync", "https://pos-update-service.example/not-observed"):
            clone = _case("20261021-011900")
            clone[0]["external"] = True
            clone[0]["entities"]["urls"] = [url]
            result = check(*clone, _proof)
            assert result["verdict"] == "needs_more_info" and not result["citations"] and not result["actions"]
            assert result["context_citations"] and all(key.startswith("PRX-") for key in result["context_citations"])
            assert "Responsable de pagos" not in result.get("escalate", [])
        for address, expected in (("203.0.113.160", "true_positive"), ("203.0.113.209", "needs_more_info")):
            clone = _case("20261021-011900")
            clone[0]["external"] = True
            clone[0]["entities"]["ips"] = [address]
            finding = _result(clone, verdict=expected, escalate=expected == "true_positive", pivot=True)
            if expected == "needs_more_info":
                assert "no coinciden con las declaradas" in finding["summary"]
                assert all(key.startswith("PRX-") for key in finding["citations"])
        with patch.object(db, "sandbox", return_value=None):
            assert check(*_case("20261021-011900"), _proof) is None

        blocklist = _case("20261009-011793")
        verified = _result(blocklist, verdict="true_positive", escalate=True)
        assert "contiene bytes de tráfico" in verified["summary"]
        incomplete = deepcopy(blocklist)
        incomplete[2][0]["bytes"] = "0"
        limited = _result(incomplete, verdict="needs_more_info", escalate=True)
        assert "permitió un intento" in limited["summary"] and "no confirma una conexión establecida" in limited["summary"]
        spoof = deepcopy(blocklist)
        spoof[2][0]["action"] = "deny"
        assert check(*spoof, _proof) is None

        nessus = _case("20261007-011850")
        _result(nessus, verdict="benign_true_positive", auto=True)
        _result(_case("20261007-011853"), verdict="benign_true_positive", auto=True)
        spoof = deepcopy(nessus)
        for index, event in enumerate(spoof[2]):
            event["timestamp"] = (madrid(spoof[2][0]["timestamp"]) - timedelta(minutes=20 * index)).isoformat()
        assert check(*spoof, _proof) is None
        spoof = deepcopy(nessus)
        runner = db.asset("CI-RUNNER01")
        spoof[2][0].update(dst_ip=runner["ip"], zone_dst=runner["zone"])
        _result(spoof, verdict="benign_true_positive", auto=True)
        spoof[2][0]["zone_dst"] = "DC-SERVERS"
        _no_closure(spoof)
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
        tunnel = _case("20261011-011883")
        _result(tunnel, verdict="true_positive", escalate=True)
        distributed = tunnel[2][:3]
        hosts = []
        for event, hostname in zip(distributed, ("WMS01", "PRINT01", "NESSUS01")):
            asset = db.asset(hostname)
            hosts.append({"hostname": hostname, "ip": asset["ip"]})
            event.update(hostname=hostname, src_ip=asset["ip"])
        tunnel[0]["entities"]["hosts"] = hosts
        tunnel[0]["related_events"] = [event["event_id"] for event in distributed]
        tunnel[1]["context"]["activos"] = [db.asset(host["hostname"]) for host in hosts]
        _result((tunnel[0], tunnel[1], distributed), verdict="needs_more_info")
    print("WAF, accesos al comercio, red y DNS: casos oficiales y contrapruebas superados.")


if __name__ == "__main__":
    main()
