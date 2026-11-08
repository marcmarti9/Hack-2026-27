"""Carga todo el dataset de Tarvia en DuckDB. Uso: python -m apps.backend.ingest"""
import csv, json, time
import duckdb, pandas as pd
from apps.backend.config import DATA, DB

ENTITY_FIELDS = {
    "hostname": "host", "client_host": "host", "src_host": "host", "dc": "host", "runner": "host",
    "user": "user", "user_upn": "user", "actor_upn": "user", "subject": "user",
    "src_ip": "ip", "dst_ip": "ip", "sourceIPAddress": "ip", "sender_ip": "ip", "assigned_ip": "ip",
    "domain": "domain", "sha256": "hash", "sender": "email", "customer_id": "customer",
    "session_id": "session", "message_id": "message",
}

def norm(etype, v):
    v = str(v).strip().lower()
    if etype == "user":
        v = v.split("\\")[-1].split("@")[0]
    return v

def rows_from(path):
    with open(path, encoding="utf-8") as f:
        if path.suffix == ".jsonl":
            for line in f:
                if line.strip():
                    yield json.loads(line)
        else:
            yield from csv.DictReader(f)

def main():
    t0 = time.time()
    DB.parent.mkdir(parents=True, exist_ok=True)
    for f in (DB, DB.with_name(DB.name + ".wal")):     # base nueva cada vez
        if f.exists():
            f.unlink()
    con = duckdb.connect(str(DB))
    events, ents = [], []
    for path in sorted((DATA / "04_logs").iterdir()):
        if path.suffix not in (".jsonl", ".csv"):
            continue
        src, n = path.stem, 0
        for e in rows_from(path):
            events.append((src, e["event_id"], e["timestamp"], json.dumps(e, ensure_ascii=False)))
            for k, et in ENTITY_FIELDS.items():
                v = e.get(k)
                if v not in (None, "", "-"):
                    ents.append((e["event_id"], src, e["timestamp"], et, norm(et, v)))
            n += 1
        print(f"{src:14s} {n:>8d}")

    con.register("ev", pd.DataFrame(events, columns=["source", "event_id", "ts", "raw"]))
    con.execute("CREATE OR REPLACE TABLE events AS SELECT source, event_id, CAST(ts AS TIMESTAMPTZ) ts, raw FROM ev")
    con.register("en", pd.DataFrame(ents, columns=["event_id", "source", "ts", "etype", "value"]))
    con.execute("CREATE OR REPLACE TABLE event_entities AS SELECT event_id, source, CAST(ts AS TIMESTAMPTZ) ts, etype, value FROM en")

    alerts = [json.loads(l) for l in open(DATA / "03_alertas" / "alertas.jsonl", encoding="utf-8") if l.strip()]
    con.register("al", pd.DataFrame([(a["alert_id"], a["created_at"], a["rule_id"], a["severity"], a["source_product"],
                                      json.dumps(a, ensure_ascii=False)) for a in alerts],
                                     columns=["alert_id", "ts", "rule_id", "severity", "source_product", "raw"]))
    con.execute("CREATE OR REPLACE TABLE alerts AS SELECT alert_id, CAST(ts AS TIMESTAMPTZ) ts, rule_id, severity, source_product, raw FROM al")
    aent = []
    for a in alerts:
        E = a.get("entities", {})
        for h in E.get("hosts", []):     aent.append((a["alert_id"], "host", norm("host", h.get("hostname", ""))))
        for u in E.get("users", []):     aent.append((a["alert_id"], "user", norm("user", u.get("upn", ""))))
        for i in E.get("ips", []):       aent.append((a["alert_id"], "ip", norm("ip", i)))
        for d in E.get("domains", []):   aent.append((a["alert_id"], "domain", norm("domain", d)))
        for f in E.get("files", []):     aent.append((a["alert_id"], "hash", norm("hash", f.get("sha256", ""))))
        for c in E.get("customers", []): aent.append((a["alert_id"], "customer", norm("customer", c.get("customer_id", ""))))
    con.register("ae", pd.DataFrame(aent, columns=["alert_id", "etype", "value"]))
    con.execute("CREATE OR REPLACE TABLE alert_entities AS SELECT * FROM ae WHERE value <> ''")

    for name, rel in [("assets", "02_inventario/activos.csv"), ("users", "02_inventario/usuarios.csv"),
                      ("changes", "02_inventario/calendario_cambios.csv"), ("hr_events", "02_inventario/eventos_rrhh.csv"),
                      ("services", "02_inventario/servicios_negocio.csv"), ("vulns", "02_inventario/vulnerabilidades.csv"),
                      ("zones", "02_inventario/zonas_red.csv"), ("stores", "02_inventario/tiendas.csv"),
                      ("geoip", "05_inteligencia/geoip_asn.csv")]:
        con.execute(f"CREATE OR REPLACE TABLE {name} AS SELECT * FROM read_csv('{(DATA / rel).as_posix()}', header=true, all_varchar=true)")
    for name, rel in [("ti", "05_inteligencia/ti_feed.jsonl"), ("sandbox", "05_inteligencia/sandbox_informes.jsonl")]:
        con.execute(f"CREATE OR REPLACE TABLE {name} AS SELECT * FROM read_json_auto('{(DATA / rel).as_posix()}', format='newline_delimited')")
    con.execute("CREATE INDEX IF NOT EXISTS ix_ev ON events(event_id)")
    con.execute("CREATE INDEX IF NOT EXISTS ix_en ON event_entities(value)")
    print("eventos:", con.sql("select count(*) from events").fetchone()[0],
          "| entidades:", con.sql("select count(*) from event_entities").fetchone()[0],
          "| alertas:", con.sql("select count(*) from alerts").fetchone()[0], f"| {time.time() - t0:.0f}s")
    con.close()

if __name__ == "__main__":
    main()
