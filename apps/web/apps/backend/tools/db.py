"""Consultas sobre tarvia.duckdb. Todas devuelven listas o dicts listos para JSON."""
import json
from datetime import datetime, timedelta
import duckdb
from apps.backend.config import DB

_con = None
def con():
    global _con
    if _con is None:
        if not DB.exists():
            raise RuntimeError(f"No existe {DB}. Ejecuta antes: python -m apps.backend.ingest")
        _con = duckdb.connect(str(DB), read_only=True)      # solo lectura: varios procesos a la vez
    return _con.cursor()

def _rows(sql, params=()):
    cur = con().execute(sql, params)
    cols = [d[0] for d in cur.description]
    return [dict(zip(cols, r)) for r in cur.fetchall()]

def _norm(v: str) -> str:
    v = str(v).strip().lower()
    if "@tarvia.example" in v or "\\" in v:
        v = v.split("\\")[-1].split("@")[0]
    return v

def _ventana(ts: str, horas: int):
    t = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    return t - timedelta(hours=horas), t + timedelta(hours=horas)

def get_event(event_id: str) -> dict | None:
    r = _rows("SELECT source, raw FROM events WHERE event_id = ?", [event_id])
    return {"source": r[0]["source"], **json.loads(r[0]["raw"])} if r else None

def events_for_entity(value, around=None, horas=24, source=None, limit=100) -> list[dict]:
    """Eventos de una entidad (equipo, usuario, IP, dominio, hash...) en ±horas alrededor de 'around'."""
    sql = "SELECT DISTINCT e.source, e.ts, e.raw FROM event_entities x JOIN events e USING(event_id) WHERE x.value = ?"
    p = [_norm(value)]
    if around:
        a, b = _ventana(around, int(horas or 24)); sql += " AND e.ts BETWEEN ? AND ?"; p += [a, b]
    if source:
        sql += " AND e.source = ?"; p.append(source)
    sql += " ORDER BY e.ts LIMIT ?"; p.append(limit)
    return [{"source": r["source"], **json.loads(r["raw"])} for r in _rows(sql, p)]

def search_logs(text, source=None, desde=None, hasta=None, limit=50) -> list[dict]:
    sql, p = "SELECT source, raw FROM events WHERE raw ILIKE ?", [f"%{text}%"]
    if source: sql += " AND source = ?"; p.append(source)
    if desde:  sql += " AND ts >= ?"; p.append(desde)
    if hasta:  sql += " AND ts <= ?"; p.append(hasta)
    sql += " ORDER BY ts LIMIT ?"; p.append(limit)
    return [{"source": r["source"], **json.loads(r["raw"])} for r in _rows(sql, p)]

def asset(key: str) -> dict | None:
    r = _rows("SELECT * FROM assets WHERE lower(hostname) = lower(?) OR ip = ?", [key, key])
    if not r:
        return None
    r[0]["vulnerabilities"] = _rows("SELECT * FROM vulns WHERE hostname = ?", [r[0]["hostname"]])
    return r[0]

def user(key: str) -> dict | None:
    r = _rows("SELECT * FROM users WHERE lower(username) = ?", [_norm(key)])
    if not r:
        return None
    r[0]["hr_events"] = _rows("SELECT * FROM hr_events WHERE usuario = ?", [r[0]["upn"]])
    return r[0]

def changes(q: str = "") -> list[dict]:
    return _rows("SELECT * FROM changes WHERE lower(id||titulo||detalle||alcance) LIKE ?", [f"%{q.lower()}%"])

def intel(indicator: str) -> dict:
    tip = _rows("SELECT * FROM ti WHERE value = ?", [indicator])
    geo = _rows("SELECT * FROM geoip WHERE ip = ?", [indicator])
    return {"indicator": indicator, "tip": tip[0] if tip else None, "geo": geo[0] if geo else None}

def sandbox(sha256: str) -> dict | None:
    r = _rows("SELECT * FROM sandbox WHERE sha256 = ?", [sha256])
    return r[0] if r else None

def alerts_for_entity(value: str, limit: int = 50) -> list[dict]:
    return [json.loads(r["raw"]) for r in _rows(
        "SELECT DISTINCT a.ts, a.raw FROM alert_entities x JOIN alerts a USING(alert_id) "
        "WHERE x.value = ? ORDER BY a.ts LIMIT ?", [_norm(value), limit])]
