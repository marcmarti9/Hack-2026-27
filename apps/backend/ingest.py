"""Importa el dataset oficial de Tarvia a un índice DuckDB local."""
import argparse
import os
import tempfile
import time
from pathlib import Path

import duckdb

from apps.backend.config import DATA, DB

CSV_LOGS = ("dns", "firewall", "proxy")
JSON_LOGS = (
    "ad_events", "ai_gateway", "cicd_builds", "cloudtrail", "dlp", "ecom_account",
    "ecom_auth", "edr_events", "email", "email_clicks", "idp_audit", "idp_signins",
    "sql_audit", "vpn", "waf",
)
CSV_TABLES = {
    "assets": "02_inventario/activos.csv",
    "users": "02_inventario/usuarios.csv",
    "changes": "02_inventario/calendario_cambios.csv",
    "hr_events": "02_inventario/eventos_rrhh.csv",
    "services": "02_inventario/servicios_negocio.csv",
    "vulns": "02_inventario/vulnerabilidades.csv",
    "zones": "02_inventario/zonas_red.csv",
    "stores": "02_inventario/tiendas.csv",
    "geoip": "05_inteligencia/geoip_asn.csv",
}
JSON_TABLES = {
    "ti": "05_inteligencia/ti_feed.jsonl",
    "sandbox": "05_inteligencia/sandbox_informes.jsonl",
}
ENTITY_FIELDS = {
    "hostname": "host", "client_host": "host", "src_host": "host", "dc": "host",
    "runner": "host", "user": "user", "user_upn": "user", "actor_upn": "user",
    "subject": "user", "src_ip": "ip", "dst_ip": "ip", "sourceIPAddress": "ip",
    "sender_ip": "ip", "assigned_ip": "ip", "domain": "domain", "sha256": "hash",
    "sender": "email", "customer_id": "customer", "session_id": "session",
    "message_id": "message",
}
ALERT_ENTITY_FIELDS = (
    ("hosts", "hostname", "host"), ("users", "upn", "user"),
    ("ips", "", "ip"), ("domains", "", "domain"), ("files", "sha256", "hash"),
    ("customers", "customer_id", "customer"),
)


def _import(con: duckdb.DuckDBPyConnection, data: Path) -> dict[str, int]:
    # read_ndjson_objects conserva el JSON original de cada evento.
    # https://duckdb.org/docs/lts/data/json/loading_json
    con.execute("""
        CREATE TABLE events (
            source VARCHAR NOT NULL, event_id VARCHAR NOT NULL,
            ts TIMESTAMPTZ NOT NULL, raw JSON NOT NULL
        )
    """)
    for source in JSON_LOGS:
        path = data / "04_logs" / f"{source}.jsonl"
        con.execute("""
            INSERT INTO events
            SELECT ?, json->>'event_id', CAST(json->>'timestamp' AS TIMESTAMPTZ), json
            FROM read_ndjson_objects(?)
        """, [source, str(path)])
    for source in CSV_LOGS:
        path = data / "04_logs" / f"{source}.csv"
        con.execute("""
            INSERT INTO events
            SELECT ?, row.event_id, CAST(row.timestamp AS TIMESTAMPTZ), to_json(row)
            FROM read_csv(?, header=true, all_varchar=true) AS row
        """, [source, str(path)])

    con.execute("""
        CREATE MACRO entity_value(etype, value) AS (
            CASE WHEN etype = 'user'
                 THEN split_part(list_last(string_split(lower(trim(value)), chr(92))), '@', 1)
                 ELSE lower(trim(value))
            END
        )
    """)
    paths = [f"$.{field}" for field in ENTITY_FIELDS]
    con.execute("""
        CREATE TABLE event_entities AS
        SELECT event_id, source, ts, etype, entity_value(etype, value) AS value
        FROM (
            SELECT event_id, source, ts, unnest(?) AS etype,
                   unnest(json_extract_string(raw, ?)) AS value
            FROM events
        )
        WHERE value IS NOT NULL AND trim(value) NOT IN ('', '-')
    """, [list(ENTITY_FIELDS.values()), paths])
    con.execute("""
        CREATE TABLE alerts AS
        SELECT json->>'alert_id' AS alert_id, CAST(json->>'created_at' AS TIMESTAMPTZ) AS ts,
               json->>'rule_id' AS rule_id, json->>'severity' AS severity,
               json->>'source_product' AS source_product, json AS raw
        FROM read_ndjson_objects(?)
    """, [str(data / "03_alertas" / "alertas.jsonl")])
    con.execute("CREATE TABLE alert_entities (alert_id VARCHAR, etype VARCHAR, value VARCHAR)")
    for array, field, kind in ALERT_ENTITY_FIELDS:
        con.execute("""
            INSERT INTO alert_entities
            SELECT alert_id, ?, entity_value(?, value)
            FROM (
                SELECT alert_id, json_extract_string(item.value, ?) AS value
                FROM alerts, json_each(raw, ?) AS item
            )
            WHERE value IS NOT NULL AND trim(value) NOT IN ('', '-')
        """, [kind, kind, f"$.{field}" if field else "$", f"$.entities.{array}"])

    for table, path in CSV_TABLES.items():
        con.execute(f"CREATE TABLE {table} AS SELECT * FROM read_csv(?, header=true, all_varchar=true)",
                    [str(data / path)])
    for table, path in JSON_TABLES.items():
        con.execute(f"CREATE TABLE {table} AS SELECT * FROM read_ndjson(?)", [str(data / path)])

    con.execute("CREATE UNIQUE INDEX ix_events_id ON events(event_id)")
    con.execute("CREATE UNIQUE INDEX ix_alerts_id ON alerts(alert_id)")
    con.execute("CREATE INDEX ix_events_entity ON event_entities(value)")
    con.execute("CREATE INDEX ix_alerts_entity ON alert_entities(value)")
    return {
        "eventos": con.execute("SELECT count(*) FROM events").fetchone()[0],
        "entidades": con.execute("SELECT count(*) FROM event_entities").fetchone()[0],
        "alertas": con.execute("SELECT count(*) FROM alerts").fetchone()[0],
    }


def ingest(data: Path, destination: Path) -> dict[str, int]:
    data, destination = data.resolve(), destination.resolve()
    if destination.is_relative_to(data):
        raise ValueError("La base generada debe estar fuera del dataset original.")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".ingesta-", dir=destination.parent) as directory:
        temporary_db = Path(directory) / destination.name
        with duckdb.connect(str(temporary_db), config={"threads": 4}) as con:
            totals = _import(con, data)
        # Si la importación falla, la base anterior sigue disponible.
        os.replace(temporary_db, destination)
    return totals


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=DATA)
    parser.add_argument("--db", type=Path, default=DB)
    args = parser.parse_args()
    started = time.perf_counter()
    totals = ingest(args.dataset, args.db)
    print(" | ".join(f"{key}: {value}" for key, value in totals.items()))
    print(f"Base generada en {args.db} en {time.perf_counter() - started:.1f} s")


if __name__ == "__main__":
    main()
