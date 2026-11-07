"""Verifica los dos primeros pasos ejecutables de la guía con el dataset oficial."""
from apps.backend.tools import db


def main() -> None:
    totals = db._rows("""
        SELECT (SELECT count(*) FROM events) AS eventos,
               (SELECT count(*) FROM event_entities) AS entidades,
               (SELECT count(*) FROM alerts) AS alertas,
               (SELECT count(DISTINCT source) FROM events) AS fuentes
    """)[0]
    print(" | ".join(f"{key}: {value}" for key, value in totals.items()))
    assert totals == {"eventos": 814471, "entidades": 2467451, "alertas": 11061, "fuentes": 18}

    asset = db.asset("JENKINS-DEV01")
    assert asset and asset["vulnerabilities"][0]["id"] == "CVE-2024-23897"
    events = db.events_for_entity("WS-BCN-1770", "2026-10-10T00:23:00Z", 24)
    assert len(events) == 100
    tip = db.intel("203.0.113.88")["tip"]
    assert tip and tip["malware_family"] == "Latrodectus"
    print("Consultas: CVE-2024-23897 | 100 | Latrodectus")

    alert = db.get_alert("ALR-20261010-011795")
    event = db.get_event(alert["related_events"][0]) if alert else None
    assert event and event["source"] == "edr_events" and event["event_id"] == "EDR-0123412"
    assert db.get_event("EDR-9999999") is None
    assert db.get_event("' OR 1=1 --") is None
    assert db.alerts_for_entity("TARVIA\\marta.puig") == db.alerts_for_entity("marta.puig@tarvia.example")
    print("Evidencia EDR-0123412 recuperada; IDs inexistentes y entradas SQL rechazados como coincidencias.")


if __name__ == "__main__":
    main()
