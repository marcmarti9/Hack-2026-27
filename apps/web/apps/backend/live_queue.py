"""Bandeja de entradas en directo, separada de los expedientes del corpus."""
import json
import sqlite3
from contextlib import closing
from hashlib import sha256

from apps.backend.rules.engine import fuera_de_horario


class LiveQueue:
    def __init__(self, path):
        self.path = path
        with closing(sqlite3.connect(path)) as db, db:
            db.execute("""
                CREATE TABLE IF NOT EXISTS web_live_alerts (
                    alert_id TEXT PRIMARY KEY,
                    job_id TEXT NOT NULL,
                    title TEXT NOT NULL,
                    primera TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    fingerprint TEXT NOT NULL,
                    origin TEXT NOT NULL,
                    estado TEXT NOT NULL,
                    asignado TEXT,
                    error TEXT NOT NULL DEFAULT '',
                    verdict TEXT,
                    recommendation TEXT,
                    summary TEXT,
                    fiscal TEXT,
                    motivo_cierre TEXT,
                    has_report INTEGER NOT NULL DEFAULT 0
                )
            """)
            db.execute("""
                UPDATE web_live_alerts SET estado='interrumpida', error='El servidor se reinició durante el análisis.'
                WHERE estado IN ('pendiente', 'en_curso')
            """)

    def add(self, job_id, alerts, origin):
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("BEGIN IMMEDIATE")
            for alert in alerts:
                aid = alert["alert_id"]
                fingerprint = sha256(json.dumps(alert, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
                previous = db.execute("SELECT fingerprint FROM web_live_alerts WHERE alert_id=?", (aid,)).fetchone()
                if previous and previous[0] != fingerprint:
                    raise ValueError(f"Conflicto de identidad en {aid}. El ID ya corresponde a otra alerta.")
                db.execute("""
                    INSERT INTO web_live_alerts
                        (alert_id, job_id, title, primera, severity, fingerprint, origin, estado)
                    VALUES (?, ?, ?, ?, ?, ?, ?, 'pendiente')
                    ON CONFLICT(alert_id) DO UPDATE SET job_id=excluded.job_id, origin=excluded.origin,
                        estado='pendiente', error=''
                """, (aid, job_id, alert["rule_name"], alert["created_at"], alert["severity"], fingerprint, origin))

    def running(self, aid):
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("UPDATE web_live_alerts SET estado='en_curso' WHERE alert_id=?", (aid,))

    def fail(self, aid, error):
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("UPDATE web_live_alerts SET estado='error', error=? WHERE alert_id=?", (error, aid))

    def finish(self, db, aid, report):
        proposal, challenge = report.get("propuesta") or {}, report.get("contraste") or {}
        fiscal = None
        if proposal and challenge and report.get("provider") != "Reglas locales":
            fiscal = "acuerdo" if proposal["verdict"] == challenge["verdict"] else "discrepa"
        route = report["routing"]
        db.execute("""
            UPDATE web_live_alerts SET estado='investigada', error='', severity=?, verdict=?,
                recommendation=?, summary=?, fiscal=?, motivo_cierre=?, has_report=1 WHERE alert_id=?
        """, (report["severity"], report["verdict"], route["recommendation"], report["summary"], fiscal,
              route["reason"] if route["automatic"] else None, aid))

    def fail_pending(self, job_id, error):
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("""
                UPDATE web_live_alerts SET estado='error', error=? WHERE job_id=? AND estado IN ('pendiente', 'en_curso')
            """, (error, job_id))

    def reuse(self, aid, fallback):
        """Proyecta un expediente decidido en el nuevo lote sin volver a analizarlo."""
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("""
                SELECT analysis, decision, verdict FROM reviews WHERE alert_id=? AND decision IS NOT NULL
            """, (aid,)).fetchone()
            if row:
                previous, decision, verdict = row
                report = (json.loads(previous or "null") or {}).get("report") or fallback(aid)
                if report:
                    self.finish(db, aid, report)
                    return report, {"decision": decision, "verdict": verdict}
        return None

    def assign(self, aid, actor, assigning):
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT asignado FROM web_live_alerts WHERE alert_id=?", (aid,)).fetchone()
            if not row:
                raise LookupError("La alerta no está en la mesa en directo.")
            if row[0] and row[0] != actor:
                raise ValueError("La alerta ya está asignada a otro rol de práctica.")
            assigned = actor if assigning else None
            db.execute("UPDATE web_live_alerts SET asignado=? WHERE alert_id=?", (assigned, aid))
            return assigned

    def rows(self):
        with closing(sqlite3.connect(self.path)) as db:
            db.row_factory = sqlite3.Row
            records = db.execute("""
                SELECT live.alert_id, live.job_id, live.title, live.primera, live.severity, live.origin,
                    live.estado, live.asignado, live.error, live.recommendation, live.summary,
                    live.has_report, live.fiscal, live.motivo_cierre, coalesce(reviews.verdict, live.verdict) AS verdict,
                    reviews.decision, reviews.reviewer
                FROM web_live_alerts AS live LEFT JOIN reviews ON reviews.alert_id=live.alert_id
                ORDER BY live.primera DESC, live.alert_id DESC
            """).fetchall()
        rows = []
        for record in records:
            row = dict(record)
            row["ticket_id"] = f"VIG-{row['alert_id']}" if row.pop("has_report") else None
            row["fuera_de_horario"] = fuera_de_horario(row["primera"])
            row["rol"] = {"analista.n1": "N1", "analista.n2": "N2", "analista.responsable": "Responsable"}.get(row["asignado"])
            row["provisional"] = row["verdict"] == "needs_more_info"
            if row["estado"] == "investigada":
                if row["decision"]:
                    row["estado"] = "cerrada" if row["decision"] == "automatic" or row["recommendation"] != "escalate" else "escalada"
                elif row["recommendation"] == "escalate":
                    row["estado"] = "escalada"
            rows.append(row)
        return rows
