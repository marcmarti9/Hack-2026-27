"""Comprueba L4 contra una instancia desechable del simulador oficial."""
import json
import os
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from http.client import HTTPConnection
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from apps.backend.tools import db
from apps.engine import sim_response
from apps.engine.practice import DEMO_USER
from apps.engine.review import Reviews, investigate
from apps.engine.session import Account

ALERT = "ALR-20261010-011795"
DEMO_PASSWORD = "VigiaDemo2026"
REASON = "N2 de práctica verifica la ejecución de MiniDump sobre LSASS."


def simulator_log(port):
    with closing(HTTPConnection("127.0.0.1", port, timeout=5)) as connection:
        connection.request("GET", "/containment/log")
        with connection.getresponse() as response:
            assert response.status == 200
            return json.load(response)


def reject(operation, expected):
    try:
        operation()
    except ValueError as error:
        assert expected in str(error)
    else:
        raise AssertionError("La operación debía rechazarse.")


def make_profile(directory):
    directory.mkdir()
    account = Account(directory)
    account.create(DEMO_USER, DEMO_PASSWORD)
    return Reviews(directory), account


def main():
    if os.getenv("VIGIA_SIM_TEST") != "1" or not (port := sim_response._configured_port()):
        raise SystemExit("Ejecuta la prueba solo con un simulador desechable y VIGIA_SIM_TEST=1.")
    assert simulator_log(port) == [], "La instancia de prueba debe comenzar sin contenciones."
    proposal = sim_response.isolation_proposal(ALERT, practice=True)
    assert proposal["target"] == "WS-BCN-1770" and proposal["required_role"] == "N2"
    assert proposal["citations"] == ["EDR-0123412"]
    params = {"practice": True, "target": proposal["target"], "confirmed": True,
              "password": DEMO_PASSWORD, "justification": REASON}

    with TemporaryDirectory(prefix="vigia-l4-") as directory:
        root = Path(directory)
        store, account = make_profile(root / "normal")
        analysis = investigate(db.get_alert(ALERT), triage=True)
        assert store.save_analysis(ALERT, analysis)
        ticket_id = analysis["report"]["ticket_id"]
        assert ticket_id.startswith("VIG-INC-")

        sibling_alert = db.get_alert("ALR-20261010-011794")
        sibling = investigate(sibling_alert, triage=True)
        old_alert = "ALR-20261010-999998"
        with closing(sqlite3.connect(store.path)) as connection, connection:
            connection.execute(sim_response.TABLE.replace(", ticket_id TEXT", ""))
            connection.execute("""
                INSERT INTO simulated_isolations
                VALUES (?, 'isolate_host', 'old-host', ?, 'N2', 'executed',
                        '2026-10-10', '2026-10-10', 'ok', 'Registro histórico', '[]')
            """, (old_alert, DEMO_USER))
        old_record = sim_response.isolation_status(store, old_alert)
        assert old_record["ticket_id"] == f"VIG-{old_alert}"
        assert sim_response.isolation_records(store, sibling_alert["alert_id"], sibling) == []

        def execute(**overrides):
            return sim_response.execute_isolation(store, account, ALERT, **{**params, **overrides})

        with patch.object(sim_response, "_request") as transport:
            for overrides, expected in (
                ({"practice": False}, "confirmación humana"),
                ({"confirmed": False}, "confirmación humana"),
                ({"password": "incorrecta"}, "no coincide"),
                ({"target": "otro-equipo"}, "ese puesto"),
                ({"justification": "   "}, "justificación"),
                ({"justification": f"Por {DEMO_PASSWORD}"}, "credenciales"),
            ):
                reject(lambda: execute(**overrides), expected)
            reject(lambda: sim_response.execute_isolation(store, account, "ALR-20261010-999999", **params), "ese puesto")
            with patch.dict(os.environ, {"VIGIA_SIM_PORT": "http://127.0.0.1:8000"}):
                assert sim_response.isolation_proposal(ALERT, practice=True) is None
                reject(execute, "simulador habilitado")
            other_account = Account(root / "other")
            other_account.create("operador.normal", DEMO_PASSWORD)
            other = Reviews(root / "other")
            reject(lambda: sim_response.execute_isolation(other, account, ALERT, **params), "cuenta N2")
            reject(lambda: sim_response.execute_isolation(other, other_account, ALERT, **params), "cuenta N2")
            external = {**db.get_alert(ALERT), "external": True}
            with patch.object(db, "get_alert", return_value=external):
                reject(execute, "ese puesto")
            actual_asset = db.asset
            for changes in ({"zone": "LOGISTICS-OT"}, {"type": "Servidor"},
                            {"ip": actual_asset("PLC-SORT01")["ip"]}):
                with patch.object(db, "asset", side_effect=lambda key: (
                    {**actual_asset(key), **changes} if key.upper() == proposal["target"] else actual_asset(key)
                )):
                    reject(execute, "ese puesto")
            with patch.object(db, "get_events", return_value=[]):
                reject(execute, "ese puesto")
            transport.assert_not_called()

        def race(_):
            try:
                return execute()
            except ValueError as error:
                assert "intento registrado" in str(error)
                return None

        with ThreadPoolExecutor(max_workers=2) as pool:
            responses = list(pool.map(race, range(2)))
        assert sum(response is not None for response in responses) == 1
        result = next(response for response in responses if response)
        assert result == sim_response.isolation_status(Reviews(root / "normal"), ALERT)
        assert result["ticket_id"] == ticket_id
        assert sim_response.isolation_status(store, old_alert) == old_record
        with patch.dict(os.environ, {"VIGIA_SIM_PORT": ""}):
            assert sim_response.isolation_proposal(ALERT, practice=True) is None
            assert sim_response.isolation_records(store, sibling_alert["alert_id"], sibling) == [result]
            assert sim_response.isolation_records(store, sibling_alert["alert_id"]) == []
            assert sim_response.isolation_records(store, old_alert, sibling) == [old_record]
        assert result["status"] == "executed" and result["actor"] == DEMO_USER
        assert result["approved_at"] <= result["finished_at"] and result["justification"] == REASON
        reject(execute, "intento registrado")
        history = store.history(ALERT)
        assert [row["kind"] for row in history] == ["Aislamiento simulado", "Aislamiento simulado aprobado", "Análisis"]
        assert all(row["data"]["ticket_id"] == ticket_id for row in history[:2])
        assert "APR-" not in json.dumps(history) and DEMO_PASSWORD not in json.dumps(history)
        executed = simulator_log(port)
        assert len(executed) == 1 and executed[0]["ticket_id"] == ticket_id
        assert executed[0]["target"] == proposal["target"] and executed[0]["action"] == "isolate_host"
        assert executed[0]["approval_token"].startswith("APR-") and executed[0]["result"] == "ok (simulado)"
        assert DEMO_PASSWORD not in json.dumps(executed)

        with closing(sqlite3.connect(store.path)) as connection, connection:
            connection.execute("UPDATE simulated_isolations SET ticket_id = NULL WHERE alert_id = ?", (ALERT,))
        historical_result = {**result, "ticket_id": f"VIG-{ALERT}"}
        assert sim_response.isolation_records(store, sibling_alert["alert_id"], sibling) == [historical_result]
        with closing(sqlite3.connect(store.path)) as connection, connection:
            connection.execute("UPDATE simulated_isolations SET ticket_id = ? WHERE alert_id = ?",
                               ("VIG-INC-FW-0000001", ALERT))
        assert sim_response.isolation_records(store, sibling_alert["alert_id"], sibling) == []
        assert sim_response.isolation_records(store, ALERT, analysis) == []
        assert sim_response.isolation_status(store, ALERT)["ticket_id"] == "VIG-INC-FW-0000001"

        unknown_store, unknown_account = make_profile(root / "unknown")
        request = sim_response._request

        def lose_reply(port, method, path, payload=None):
            reply = request(port, method, path, payload)
            if path == sim_response.CONTAINMENT:
                raise sim_response._SimulatorError("Confirmación perdida.")
            return reply

        with patch.object(sim_response, "_request", side_effect=lose_reply):
            outcome = sim_response.execute_isolation(unknown_store, unknown_account, ALERT, **params)
        assert outcome["status"] == "unknown"
        assert outcome["ticket_id"] == f"VIG-{ALERT}"
        reject(lambda: sim_response.execute_isolation(unknown_store, unknown_account, ALERT, **params),
               "intento registrado")
        assert len(simulator_log(port)) == 2

        failed_store, failed_account = make_profile(root / "bad-service")
        with patch.object(sim_response, "_request", return_value={"info": {"title": "otro"}}) as transport:
            failure = sim_response.execute_isolation(failed_store, failed_account, ALERT, **params)
            transport.assert_called_once_with(port, "GET", "/openapi.json")
        assert failure["status"] == "failed" and len(simulator_log(port)) == 2
    print("L4: aprobación N2 y aislamiento por HTTP en el mock, resultado persistido, credenciales y OT denegadas.")
    print("L4: un envío para dos solicitantes, sin reintento tras éxito ni respuesta perdida y sin token en historial.")


if __name__ == "__main__":
    main()
