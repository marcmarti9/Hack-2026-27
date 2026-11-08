"""Carga de alertas para la defensa y ensayo de triaje desde la terminal."""
import argparse
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

from apps.backend.rules.engine import LEVELS
from apps.backend.tools import db

MAX_ALERTS = 10
MAX_BYTES = 1_000_000
ALERT_ID = re.compile(r"ALR-[0-9]{8}-[0-9]{6}")
EVENT_ID = re.compile(r"[A-Z][A-Z0-9]{1,12}-[0-9]{4,10}")
INCIDENT_TICKET_ID = re.compile(rf"VIG-INC-{EVENT_ID.pattern}")
TECHNIQUE_ID = re.compile(r"T[0-9]{4}(?:\.[0-9]{3})?")
UTC_STAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?(?:Z|\+00:00)")
# Reserva espacio para las ventanas de búsqueda, los plazos y la conversión a Madrid.
TIME_MARGIN = timedelta(days=14, hours=3)
MIN_ALERT_DATE = datetime.min.replace(tzinfo=timezone.utc) + TIME_MARGIN
MAX_ALERT_DATE = datetime.max.replace(tzinfo=timezone.utc) - TIME_MARGIN
TEXT_ENTITIES = {"ips", "domains", "urls"}
RECORD_ENTITIES = {
    "hosts": ("hostname", "ip"),
    "users": ("upn", "display_name"),
    "files": ("sha256", "name", "path"),
    "processes": ("name", "parent", "command_line", "pid"),
    "customers": ("customer_id", "role"),
    "cloud": ("identity", "bucket", "account", "access_key", "new_user"),
}


def _object(pairs):
    item = dict(pairs)
    if len(item) != len(pairs):
        raise ValueError("Hay un campo JSON repetido.")
    return item


def _text(value, name, limit):
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise ValueError(f"Campo {name} inválido.")
    try:
        value.encode("utf-8")
    except UnicodeError:
        raise ValueError(f"Campo {name} inválido.") from None
    if any(ord(char) < 32 and char not in "\n\r\t" for char in value):
        raise ValueError(f"Campo {name} inválido.")
    return value


def _entity_record(value, name):
    if not isinstance(value, dict):
        raise ValueError(f"Entidad {name} inválida.")
    record = {}
    for field in RECORD_ENTITIES[name]:
        if field not in value:
            continue
        if field == "pid":
            if type(value[field]) is not int or not 0 <= value[field] <= 2**32 - 1:
                raise ValueError("PID inválido.")
            record[field] = value[field]
        else:
            record[field] = _text(value[field], field, 1500 if field == "command_line" else 500)
    if not record:
        raise ValueError(f"Entidad {name} vacía.")
    return record


def _entities(value):
    if not isinstance(value, dict):
        raise ValueError("El campo entities debe ser un objeto.")
    result = {}
    for name, entries in value.items():
        if name == "ai_session":
            result[name] = _text(entries, name, 200)
        elif name == "cloud":
            result[name] = _entity_record(entries, name)
        elif name in TEXT_ENTITIES or name in RECORD_ENTITIES:
            if not isinstance(entries, list) or len(entries) > 32:
                raise ValueError(f"Lista de entidades {name} inválida.")
            result[name] = ([_text(entry, name, 1500) for entry in entries] if name in TEXT_ENTITIES
                            else [_entity_record(entry, name) for entry in entries])
        else:
            raise ValueError("Hay un tipo de entidad no reconocido.")
    return result


def _external(item):
    stamp = _text(item.get("created_at"), "created_at", 35)
    if not UTC_STAMP.fullmatch(stamp):
        raise ValueError("La fecha debe estar en UTC (Z o +00:00).")
    try:
        date = datetime.fromisoformat(stamp)
    except ValueError:
        raise ValueError("La fecha de la alerta no es válida.") from None
    if not MIN_ALERT_DATE <= date <= MAX_ALERT_DATE:
        raise ValueError("La fecha de la alerta queda fuera del rango operativo.")
    source = _text(item.get("source_product"), "source_product", 32)
    runbook = _text(item.get("runbook"), "runbook", 5)
    rule_id = _text(item.get("rule_id"), "rule_id", 24)
    severity = item.get("severity")
    if (severity not in LEVELS or not re.fullmatch(r"[A-Z][A-Z0-9_]*", source)
            or not re.fullmatch(r"RB-(?:0[1-9]|10)", runbook)):
        raise ValueError("Fuente, severidad o runbook inválido.")
    if not re.fullmatch(r"UC-[A-Z]+-[0-9]{3}", rule_id):
        raise ValueError("ID de regla inválido.")
    references = item.get("related_events")
    if (not isinstance(references, list) or len(references) > 50
            or any(not isinstance(key, str) or not EVENT_ID.fullmatch(key) for key in references)
            or len(set(references)) != len(references)):
        raise ValueError("Referencias de eventos inválidas o repetidas.")
    alert = {
        "alert_id": item["alert_id"], "created_at": stamp, "source_product": source,
        "rule_id": rule_id, "rule_name": _text(item.get("rule_name"), "rule_name", 300),
        "description": _text(item.get("description"), "description", 4000),
        "runbook": runbook, "severity": severity, "entities": _entities(item.get("entities")),
        "related_events": references, "external": True,
    }
    mitre = item.get("mitre")
    technique = mitre.get("technique_id") if isinstance(mitre, dict) else None
    if isinstance(technique, str) and TECHNIQUE_ID.fullmatch(technique):
        alert["mitre"] = {"technique_id": technique}
    return alert


def report_ticket_id(alert_id, analysis):
    """Resuelve el identificador de un expediente local y mantiene el formato histórico."""
    report = (analysis or {}).get("report") or {}
    ticket_id = report.get("ticket_id")
    if (isinstance(ticket_id, str) and INCIDENT_TICKET_ID.fullmatch(ticket_id)
            and alert_id in report.get("alert_ids", [])):
        return ticket_id
    return f"VIG-{alert_id}"


def load_alerts(path: Path) -> list[dict]:
    """Resuelve el lote sin admitir sustituciones de alertas del índice."""
    if not path.is_file():
        raise ValueError("Selecciona un archivo JSONL.")
    with path.open("rb") as stream:
        payload = stream.read(MAX_BYTES + 1)
    return parse_alerts(payload)


def parse_alerts(payload: bytes) -> list[dict]:
    """Comparte la validación del lote entre archivos y la entrada web."""
    if len(payload) > MAX_BYTES:
        raise ValueError("El lote supera 1 MB.")
    try:
        lines = payload.decode("utf-8-sig").split("\n")
    except UnicodeError:
        raise ValueError("El lote debe estar en UTF-8.") from None
    entries = {}
    for number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            item = json.loads(line, object_pairs_hook=_object)
            key = item.get("alert_id") if isinstance(item, dict) else item
            if not isinstance(key, str) or not ALERT_ID.fullmatch(key):
                raise ValueError("ID de alerta inválido.")
            if key in entries:
                raise ValueError(f"Alerta repetida: {key}.")
            if len(entries) == MAX_ALERTS:
                raise ValueError(f"El lote admite hasta {MAX_ALERTS} alertas.")
        except json.JSONDecodeError:
            raise ValueError(f"Línea {number}: JSON no válido.") from None
        except RecursionError:
            raise ValueError(f"Línea {number}: JSON demasiado anidado.") from None
        except ValueError as error:
            raise ValueError(f"Línea {number}: {error}") from None
        entries[key] = (number, item)
    if not entries:
        raise ValueError("El lote no contiene alertas.")

    result, missing = [], []
    with db.read_session():
        for key, (number, item) in entries.items():
            canonical = db.get_alert(key)
            if canonical is not None:
                result.append(canonical)
            elif isinstance(item, dict) and len(item) > 1:
                try:
                    result.append(_external(item))
                except ValueError as error:
                    raise ValueError(f"Línea {number} ({key}): {error}") from None
            else:
                missing.append(key)
    if missing:
        raise ValueError("No están en el índice: " + ", ".join(missing) + ".")
    return result


def _ticket(alert, analysis):
    from apps.desktop.triage_report import build_report

    return analysis.get("report") or build_report(alert, analysis)


def main():
    from apps.desktop.assistant import available_model
    from apps.desktop.review import PLAYBOOKS, investigate
    from apps.desktop.triage_report import merge_incident_memberships

    parser = argparse.ArgumentParser(description="Ensaya el triaje de hasta diez alertas de defensa.")
    parser.add_argument("batch", type=Path, help="Archivo JSONL con IDs o alertas")
    parser.add_argument("--mode", choices=("diurno", "guardia"), default="diurno")
    parser.add_argument("--remote", action="store_true", help="Envía evidencias a OpenAI de forma explícita")
    args = parser.parse_args()
    if args.remote and not available_model():
        parser.error("Configura OPENAI_API_KEY para usar --remote.")
    try:
        alerts = load_alerts(args.batch)
    except (ValueError, OSError) as error:
        parser.error(str(error))
    playbooks = Path(__file__).with_name("resources") / "playbooks"
    reports = []
    for alert in alerts:
        names = ("SKILL", alert["runbook"]) if alert["runbook"] in PLAYBOOKS else ("SKILL",)
        guidance = {name: {"revision": 0, "text": (playbooks / f"{name}.md").read_text(encoding="utf-8")}
                    for name in names} if args.remote else None
        analysis = investigate(alert, remote=args.remote, guidance=guidance, triage=True, mode=args.mode)
        reports.append({**_ticket(alert, analysis), "alert_id": alert["alert_id"]})
    merge_incident_memberships(reports)
    for report in reports:
        print(json.dumps(report))


if __name__ == "__main__":
    main()
