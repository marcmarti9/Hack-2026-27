"""Caza: consultas que buscan lo que no generó alerta. Cada hallazgo cita sus event_id."""
import json
from apps.backend.tools import db

CAZAS = {
    "servicio_sin_firma": ("Servicio instalado con un binario sin firma",
        "SELECT event_id, ts, raw FROM events WHERE source='edr_events' AND raw ILIKE '%service_install%' AND raw ILIKE '%(sin firma)%'"),
    "proveedor_origen_nuevo": ("Proveedor conectado desde una IP que no es la suya",
        "SELECT event_id, ts, raw FROM events WHERE source='vpn' AND raw ILIKE '%ext.logisoft%' AND raw NOT ILIKE '%198.18.240.10%'"),
    "volcado_clientes": ("Consulta masiva a datos de clientes desde un equipo que no es del CRM",
        "SELECT event_id, ts, raw FROM events WHERE source='edr_events' AND raw ILIKE '%sqlcmd%' AND (raw ILIKE '%customer%' OR raw ILIKE '%Shipments%')"),
    "cuenta_nueva_privilegiada": ("Cuenta creada y añadida a un grupo privilegiado",
        "SELECT event_id, ts, raw FROM events WHERE source='ad_events' AND (raw ILIKE '%Domain Admins%' OR raw ILIKE '%4720%')"),
    "sql_masivo": ("Más de 100.000 filas devueltas por una consulta",
        "SELECT event_id, ts, raw FROM events WHERE source='sql_audit' AND TRY_CAST(json_extract_string(raw, '$.rows_returned') AS BIGINT) > 100000"),
}

def cazar() -> list[dict]:
    out = []
    for clave, (titulo, sql) in CAZAS.items():
        filas = db._rows(sql + " ORDER BY ts LIMIT 200")
        if filas:
            out.append({"caza": clave, "titulo": titulo, "n": len(filas),
                        "event_ids": [f["event_id"] for f in filas],
                        "ejemplos": [json.loads(f["raw"]) for f in filas[:3]]})
    return out

if __name__ == "__main__":
    for h in cazar():
        print(h["caza"], h["n"], h["event_ids"][:5], json.dumps(h["ejemplos"][0], ensure_ascii=False)[:220])
