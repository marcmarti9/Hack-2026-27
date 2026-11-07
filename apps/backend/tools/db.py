"""Consultas locales de solo lectura para Vigía."""
import json
from datetime import datetime, timedelta

import duckdb

from apps.backend.config import DB


def _rows(sql: str, params=()) -> list[dict]:
    # https://duckdb.org/docs/current/clients/python/dbapi
    with duckdb.connect(str(DB), read_only=True, config={"enable_external_access": False}) as con:
        result = con.execute(sql, params)
        columns = [column[0] for column in result.description]
        return [dict(zip(columns, row)) for row in result.fetchall()]


def _normalize(value: str) -> str:
    value = value.strip().lower()
    if "\\" in value or value.endswith("@tarvia.example"):
        return value.rsplit("\\", 1)[-1].split("@", 1)[0]
    return value


def _event(row: dict) -> dict:
    return {**json.loads(row["raw"]), "source": row["source"]}


def _date(value: str) -> datetime:
    timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if timestamp.utcoffset() is None:
        raise ValueError("Indica una fecha ISO con zona horaria.")
    return timestamp


def _limit(limit: int) -> int:
    if type(limit) is not int or not 1 <= limit <= 500:
        raise ValueError("El límite de resultados debe estar entre 1 y 500.")
    return limit


def get_event(event_id: str) -> dict | None:
    rows = _rows("SELECT source, raw FROM events WHERE event_id = ?", [event_id])
    return _event(rows[0]) if rows else None


def get_alert(alert_id: str) -> dict | None:
    rows = _rows("SELECT raw FROM alerts WHERE alert_id = ?", [alert_id])
    return json.loads(rows[0]["raw"]) if rows else None


def events_for_entity(value: str, around: str | None = None, horas: int = 24,
                      source: str | None = None, limit: int = 100) -> list[dict]:
    value = _normalize(value)
    if not value:
        raise ValueError("Indica una entidad para buscar eventos.")
    if type(horas) is not int or not 1 <= horas <= 336:
        raise ValueError("La ventana debe estar entre 1 y 336 horas.")
    sql = """
        SELECT source, raw FROM events
        WHERE event_id IN (SELECT event_id FROM event_entities WHERE value = ?)
    """
    params = [value]
    if around:
        timestamp, delta = _date(around), timedelta(hours=horas)
        sql += " AND ts BETWEEN ? AND ?"
        params += [timestamp - delta, timestamp + delta]
    if source:
        sql += " AND source = ?"
        params.append(source)
    return [_event(row) for row in _rows(sql + " ORDER BY ts, event_id LIMIT ?", [*params, _limit(limit)])]


def search_logs(text: str, source: str | None = None, desde: str | None = None,
                hasta: str | None = None, limit: int = 50) -> list[dict]:
    if not text.strip():
        raise ValueError("Indica un texto para buscar en los logs.")
    sql, params = "SELECT source, raw FROM events WHERE contains(lower(raw::VARCHAR), ?)", [text.lower()]
    for value, condition in ((source, "source = ?"), (desde, "ts >= ?"), (hasta, "ts <= ?")):
        if value:
            sql += f" AND {condition}"
            params.append(value if condition == "source = ?" else _date(value))
    return [_event(row) for row in _rows(sql + " ORDER BY ts, event_id LIMIT ?", [*params, _limit(limit)])]


def asset(key: str) -> dict | None:
    rows = _rows("SELECT * FROM assets WHERE lower(hostname) = lower(?) OR ip = ? ORDER BY hostname",
                 [key, key])
    if not rows:
        return None
    record = rows[0]
    record["vulnerabilities"] = _rows("SELECT * FROM vulns WHERE hostname = ? ORDER BY id",
                                      [record["hostname"]])
    return record


def user(key: str) -> dict | None:
    rows = _rows("SELECT * FROM users WHERE lower(username) = ?", [_normalize(key)])
    if not rows:
        return None
    record = rows[0]
    record["hr_events"] = _rows("SELECT * FROM hr_events WHERE usuario = ?", [record["upn"]])
    return record


def changes(q: str = "") -> list[dict]:
    return _rows("SELECT * FROM changes WHERE contains(lower(concat_ws(' ', id, titulo, detalle, alcance)), ?) "
                 "ORDER BY inicio, id", [q.lower()])


def intel(indicator: str) -> dict:
    indicator = indicator.strip().lower()
    tip = _rows("SELECT * FROM ti WHERE lower(value) = ?", [indicator])
    geo = _rows("SELECT * FROM geoip WHERE ip = ?", [indicator])
    return {"indicator": indicator, "tip": tip[0] if tip else None, "geo": geo[0] if geo else None}


def sandbox(sha256: str) -> dict | None:
    rows = _rows("SELECT * FROM sandbox WHERE lower(sha256) = ?", [sha256.strip().lower()])
    return rows[0] if rows else None


def alerts_for_entity(value: str, limit: int = 50) -> list[dict]:
    return [json.loads(row["raw"]) for row in _rows("""
        SELECT raw FROM alerts
        WHERE alert_id IN (SELECT alert_id FROM alert_entities WHERE value = ?)
        ORDER BY ts, alert_id LIMIT ?
    """, [_normalize(value), _limit(limit)])]


def network_zones(zone: str) -> list[dict]:
    return _rows("SELECT * FROM zones WHERE zona = ?", [zone])


def alert_page(query: str, offset: int, limit: int = 100, *, day: str = "", severity: str = "",
               sort: str = "latest", selected_ids: list[str] | None = None,
               exclude_ids: list[str] | None = None) -> tuple[list[dict], int]:
    clauses, params = [], []
    if pattern := query.strip().lower():
        clauses.append("contains(lower(alert_id || ' ' || rule_id || ' ' || raw::VARCHAR), ?)")
        params.append(pattern)
    if day:
        clauses.append("CAST(ts AT TIME ZONE 'UTC' AS DATE) = CAST(? AS DATE)")
        params.append(day)
    if severity:
        clauses.append("severity = ?")
        params.append(severity)
    if selected_ids is not None:
        clauses.append("alert_id IN (SELECT unnest(?::VARCHAR[]))")
        params.append(selected_ids)
    if exclude_ids:
        clauses.append("alert_id NOT IN (SELECT unnest(?::VARCHAR[]))")
        params.append(exclude_ids)
    predicate = "WHERE " + " AND ".join(clauses) if clauses else ""
    order = {
        "latest": "ts DESC",
        "oldest": "ts ASC",
        "severity": "CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
                    "WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, ts DESC",
    }[sort]
    rows = _rows(f"""
        SELECT raw, count(*) OVER () AS total FROM alerts {predicate}
        ORDER BY {order}, alert_id LIMIT ? OFFSET ?
    """, [*params, _limit(limit), offset])
    return [json.loads(row["raw"]) for row in rows], rows[0]["total"] if rows else 0


def alert_totals(day: str = "") -> list[dict]:
    predicate = "WHERE CAST(ts AT TIME ZONE 'UTC' AS DATE) = CAST(? AS DATE)" if day else ""
    return _rows(f"""
        SELECT severity, source_product AS source, count(*) AS total FROM alerts {predicate}
        GROUP BY severity, source_product ORDER BY total DESC
    """, [day] if day else [])


def alert_timeline(day: str) -> list[dict]:
    return _rows("""
        SELECT hour(ts AT TIME ZONE 'UTC') AS hour, count(*) AS total,
            list(DISTINCT source_product || ' · ' || (raw->>'rule_name')
                 ORDER BY source_product || ' · ' || (raw->>'rule_name'))[:3] AS signals
        FROM alerts WHERE CAST(ts AT TIME ZONE 'UTC' AS DATE) = CAST(? AS DATE)
        GROUP BY hour ORDER BY hour
    """, [day])


def latest_alert_day() -> str:
    result = _rows("SELECT CAST(max(ts AT TIME ZONE 'UTC') AS DATE) AS day FROM alerts")[0]["day"]
    return result.isoformat() if result else ""
