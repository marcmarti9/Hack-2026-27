"""Resultados históricos de la demo estática, separados de las decisiones locales."""
import gzip
import json
from functools import lru_cache
from pathlib import Path

RESOURCES = Path(__file__).with_name("resources")
DEMO_ALERT = "ALR-20261010-011795"
DEMO_USER = "analista.demo"
DEMO_PASSWORD = "VigiaDemo2026"


def display_questions(record: dict) -> list[str]:
    return [question.replace(" con Claude", "") for question in record.get("open_questions", [])]


@lru_cache(maxsize=1)
def archive() -> dict:
    with gzip.open(RESOURCES / "demo.json.gz", "rt", encoding="utf-8") as stream:
        data = json.load(stream)
    data["ticket_by_alert"] = {
        alert_id: ticket for ticket in data["tickets"] for alert_id in ticket["alert_ids"]
    }
    data["incident_by_alert"] = {
        alert_id: incident for incident in data["incidents"] for alert_id in incident["alert_ids"]
    }
    data["closed_by_alert"] = {entry["alert_id"]: entry for entry in data["closed"]}
    return data


def for_alert(alert_id: str) -> tuple[dict, dict, dict]:
    data = archive()
    ticket = data["ticket_by_alert"].get(alert_id, {})
    incident = next((data["incident_by_alert"][key] for key in ticket.get("alert_ids", [alert_id])
                     if key in data["incident_by_alert"]), {})
    return ticket, incident, data["closed_by_alert"].get(alert_id, {})
