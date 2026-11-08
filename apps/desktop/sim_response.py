"""Aislamiento de un puesto acreditado, solo en el simulador de práctica."""
import json
import os
import re
import sqlite3
from contextlib import closing
from http.client import HTTPConnection, HTTPException

from apps.backend.rules.approvals import aprobacion
from apps.backend.rules.engine import madrid
from apps.backend.rules.triage import local_finding
from apps.backend.tools import db
from apps.desktop.assistant import ALERT_ID
from apps.desktop.defense import report_ticket_id
from apps.desktop.demo import DEMO_USER
from apps.desktop.review import now

ACTION = "isolate_host"
CONTAINMENT = "/containment/" + ACTION
MAX_RESPONSE = 128_000
TABLE = """
    CREATE TABLE IF NOT EXISTS simulated_isolations (
        alert_id TEXT NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL,
        actor TEXT NOT NULL, required_role TEXT NOT NULL,
        status TEXT NOT NULL CHECK (status IN ('reserved', 'executed', 'failed', 'unknown')),
        approved_at TEXT NOT NULL, finished_at TEXT, result TEXT NOT NULL,
        justification TEXT NOT NULL, citations TEXT NOT NULL, ticket_id TEXT,
        PRIMARY KEY (alert_id, action, target)
    )
"""


def _configured_port():
    value = os.getenv("VIGIA_SIM_PORT", "")
    if re.fullmatch(r"[0-9]{1,5}", value):
        port = int(value)
        if 1 <= port <= 65535:
            return port
    return None


def _propose(alert_id):
    if not ALERT_ID.fullmatch(alert_id):
        return None
    with db.read_session():
        alert = db.get_alert(alert_id)
        if not alert or alert["rule_id"] != "UC-EDR-004" or alert.get("external"):
            return None
        hosts = alert.get("entities", {}).get("hosts", [])
        if len(hosts) != 1 or not (asset := db.asset(hosts[0].get("hostname", ""))):
            return None
        target = asset["hostname"]
        if asset["type"] not in {"Portátil", "Sobremesa"} or asset["zone"] == "LOGISTICS-OT":
            return None
        for key in (target, asset["ip"]):
            policy = aprobacion(ACTION, key)
            if not policy.permitted or policy.roles != ("N2",):
                return None
        references = alert.get("related_events", [])
        stamp = madrid(alert["created_at"])
        events = [event for event in db.get_events(references)
                  if abs((madrid(event["timestamp"]) - stamp).total_seconds()) <= 300]
        finding = local_finding(alert, {"events": events, "requested": references})
        if finding and finding["verdict"] == "true_positive":
            return {"alert_id": alert_id, "action": ACTION, "target": target,
                    "required_role": "N2", "citations": finding["citations"]}
    return None


def isolation_proposal(alert_id: str, *, practice: bool) -> dict | None:
    """Sugiere un objetivo desde evidencia canónica. No contacta el simulador."""
    if practice is not True or _configured_port() is None:
        return None
    return _propose(alert_id)


def isolation_records(store, alert_id: str, analysis=None) -> list[dict]:
    """Devuelve los registros persistidos de la alerta y su expediente acreditado."""
    with closing(sqlite3.connect(store.path)) as connection:
        connection.row_factory = sqlite3.Row
        columns = {column[1] for column in connection.execute("PRAGMA table_info(simulated_isolations)")}
        if not columns:
            return []
        ticket_id = report_ticket_id(alert_id, analysis)
        condition = "alert_id = ?"
        params = [alert_id]
        if ticket_id.startswith("VIG-INC-"):
            params = [member for member in analysis["report"]["alert_ids"]
                      if isinstance(member, str) and ALERT_ID.fullmatch(member)]
            condition = f"alert_id IN ({', '.join('?' for _ in params)})"
            if "ticket_id" in columns:
                condition = f"ticket_id = ? OR (ticket_id IS NULL AND {condition})"
                params.insert(0, ticket_id)
        rows = connection.execute(f"""
            SELECT * FROM simulated_isolations WHERE {condition}
            ORDER BY approved_at DESC, rowid DESC
        """, params).fetchall()
    records = []
    for row in rows:
        record = dict(row)
        record["ticket_id"] = record.get("ticket_id") or report_ticket_id(row["alert_id"], None)
        record["citations"] = json.loads(row["citations"])
        records.append(record)
    return records


def isolation_status(store, alert_id: str) -> dict | None:
    return next(iter(isolation_records(store, alert_id)), None)


class _SimulatorError(ValueError):
    pass


def _request(port, method, path, payload=None):
    # Una dirección literal evita DNS y HTTPConnection no aplica proxies ni redirecciones.
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8") if payload is not None else None
    headers = {"Accept": "application/json"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    try:
        with closing(HTTPConnection("127.0.0.1", port, timeout=4)) as connection:
            connection.request(method, path, body, headers)
            with connection.getresponse() as response:
                if response.status != 200:
                    raise _SimulatorError(f"El simulador respondió HTTP {response.status}.")
                raw = response.read(MAX_RESPONSE + 1)
        if len(raw) > MAX_RESPONSE:
            raise _SimulatorError("Respuesta del simulador demasiado grande.")
        data = json.loads(raw)
        if not isinstance(data, dict):
            raise _SimulatorError("Respuesta del simulador incompatible.")
        return data
    except (OSError, HTTPException, json.JSONDecodeError, UnicodeError, RecursionError) as error:
        raise _SimulatorError("No se pudo verificar la respuesta del simulador local.") from error


def _verify_simulator(port):
    schema = _request(port, "GET", "/openapi.json")
    info, paths = schema.get("info"), schema.get("paths")
    if (info != {"title": "Tarvia SOC (simulado)", "version": "1.0"}
            or not isinstance(paths, dict)
            or not all(isinstance(paths.get(path), dict) and "post" in paths[path]
                       for path in ("/approvals", "/containment/{action}"))):
        raise _SimulatorError("El servicio local no coincide con el simulador de Tarvia.")


def _reserve(store, proposal, actor, justification):
    entry = {**proposal, "actor": actor, "status": "reserved", "approved_at": now(),
             "finished_at": None, "result": "Aprobado y reservado. Verificación del simulador pendiente.",
             "justification": justification}
    with closing(sqlite3.connect(store.path)) as connection, connection:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(TABLE)
        columns = {column[1] for column in connection.execute("PRAGMA table_info(simulated_isolations)")}
        if "ticket_id" not in columns:
            connection.execute("ALTER TABLE simulated_isolations ADD COLUMN ticket_id TEXT")
        saved = connection.execute("SELECT analysis FROM reviews WHERE alert_id = ?", (entry["alert_id"],)).fetchone()
        analysis = json.loads(saved[0]) if saved and saved[0] else None
        entry["ticket_id"] = report_ticket_id(entry["alert_id"], analysis)
        values = {**entry, "citations": json.dumps(entry["citations"])}
        insert = connection.execute("""
            INSERT INTO simulated_isolations
                (alert_id, action, target, actor, required_role, status, approved_at, finished_at,
                 result, justification, citations, ticket_id)
            VALUES (:alert_id, :action, :target, :actor, :required_role, :status, :approved_at,
                    :finished_at, :result, :justification, :citations, :ticket_id)
            ON CONFLICT(alert_id, action, target) DO NOTHING
        """, values)
        if not insert.rowcount:
            raise ValueError("Este aislamiento ya tiene un intento registrado. Consulta el historial.")
        store._record(connection, entry["alert_id"], "Aislamiento simulado aprobado", actor, entry)
    return entry


def _finish(store, entry, status, result):
    record = {**entry, "status": status, "result": result, "finished_at": now()}
    with closing(sqlite3.connect(store.path)) as connection, connection:
        connection.execute("""
            UPDATE simulated_isolations SET status = :status, result = :result, finished_at = :finished_at
            WHERE alert_id = :alert_id AND action = :action AND target = :target AND status = 'reserved'
        """, {key: record[key] for key in ("status", "result", "finished_at", "alert_id", "action", "target")})
        store._record(connection, record["alert_id"], "Aislamiento simulado", record["actor"], record)
    return record


def execute_isolation(store, account, alert_id: str, *, practice: bool, target: str, confirmed: bool,
                      password: str, justification: str) -> dict:
    """Revalida la decisión humana y realiza un único intento contra el mock."""
    port = _configured_port()
    if practice is not True or port is None or confirmed is not True:
        raise ValueError("El aislamiento requiere práctica, simulador habilitado y confirmación humana.")
    if account.path.parent.resolve() != store.path.parent.resolve() or account.name() != DEMO_USER:
        raise ValueError("El aislamiento requiere la cuenta N2 de práctica del expediente.")
    if not password or not account.verify(password):
        raise ValueError("La contraseña de la cuenta de práctica no coincide.")
    reason = justification.strip()
    if not 1 <= len(reason) <= 500 or not reason.isprintable() or password in reason:
        raise ValueError("Escribe una justificación de 1 a 500 caracteres sin incluir credenciales.")
    proposal = _propose(alert_id)
    if not proposal or target != proposal["target"]:
        raise ValueError("No hay una propuesta de aislamiento acreditada para ese puesto.")
    entry = _reserve(store, proposal, DEMO_USER, reason)
    approval = {"action": ACTION, "target": target, "approver": DEMO_USER, "reason": reason}
    try:
        _verify_simulator(port)
        response = _request(port, "POST", "/approvals", approval)
        token = response.get("approval_token")
        if (not isinstance(token, str) or not re.fullmatch(r"APR-[0-9a-f]{10}", token)
                or any(response.get(key) != value for key, value in approval.items())):
            raise _SimulatorError("El simulador no confirmó la aprobación para ese objetivo.")
    except _SimulatorError as error:
        return _finish(store, entry, "failed", str(error))

    payload = {"target": target, "justification": reason, "approval_token": token, "ticket_id": entry["ticket_id"]}
    try:
        response = _request(port, "POST", CONTAINMENT, payload)
        if (response.get("action") != ACTION or response.get("result") != "ok (simulado)"
                or any(response.get(key) != value for key, value in payload.items())):
            raise _SimulatorError("El simulador no confirmó el aislamiento solicitado.")
    except _SimulatorError:
        return _finish(store, entry, "unknown", "Resultado sin confirmar. Consulta el registro del simulador.")
    return _finish(store, entry, "executed", "Aislamiento registrado por el simulador de Tarvia.")
