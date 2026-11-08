"""Consultas de chat acotadas a entidades y registros del índice de Tarvia."""
import re
from unicodedata import combining, normalize

from apps.backend.tools import db
from apps.engine import assistant

SOURCE_TERMS = (
    ("idp_signins", r"\b(?:inicios? de sesion|inicio sesion|autenticaciones?|sign[ -]?ins?|logins?)\b"),
    ("vpn", r"\bvpn\b"),
    ("email", r"\b(?:correos?|mensajes de correo|emails?)\b"),
    ("dns", r"\bdns\b"),
    ("firewall", r"\b(?:firewall|cortafuegos|rdp)\b"),
    ("edr_events", r"\b(?:edr|procesos?|ejecuciones?)\b"),
)
PROFILE = re.compile(r"\b(?:quien es|quienes son|perfil|titular|a quien pertenece|que cargo tiene|que rol tiene)\b")


def _words(text):
    plain = "".join(char for char in normalize("NFKD", text.casefold()) if not combining(char))
    return tuple(re.findall(r"[^\W_]+", plain))


def _subjects(question):
    words = _words(question)
    positions = {}
    for start in range(len(words)):
        for end in range(start + 1, min(start + 9, len(words) + 1)):
            positions.setdefault(words[start:end], []).append((start, end))

    matches = []
    for entity in db.chat_directory():
        name = _words((entity["name"] or "").split(" (")[0])
        aliases = {_words(entity["key"]), _words(entity["address"] or "")}
        if entity["kind"] == "cuenta" and entity["key"].startswith("ext."):
            aliases.add(_words(entity["key"].removeprefix("ext.")))
        if len(name) >= 2:
            aliases.add(name)
            if len(name) == 2 and entity["kind"] == "cuenta":
                aliases.add(name[::-1])
        for alias in aliases:
            matches.extend((span, entity) for span in positions.get(alias, []))
    distinct = {}
    for (start, end), entity in matches:
        if not any(other_start <= start and end <= other_end and other_end - other_start > end - start
                   for (other_start, other_end), _ in matches):
            distinct[entity["key"]] = entity
    return list(distinct.values())


def _profile(entity):
    fields = (("address", "Identificador"), ("role", "Función"), ("area", "Área o servicio"),
              ("workstation", "Equipo asignado"))
    details = [f"{label}: {entity[key]}" for key, label in fields if entity[key]]
    return "\n".join([entity["name"], *details, "Fuente: inventario de Tarvia."])


def _activity(question, entity):
    normalized = " ".join(_words(question))
    source = next((source for source, term in SOURCE_TERMS if re.search(term, normalized)), None)
    if PROFILE.search(normalized) and source is None:
        return _profile(entity), [], []

    key = entity["key"]
    alerts = [] if source else db.alerts_for_entity(key, limit=2, priority=True)
    events = db.get_events([ref for alert in alerts for ref in alert.get("related_events", [])[:4]])
    if not events:
        search_key = entity["address"] if entity["kind"] == "equipo" and source == "firewall" else key
        preferred = source or ("edr_events" if entity["kind"] == "equipo" else None)
        events = db.events_for_entity(search_key or key, source=preferred, limit=6, latest=True)
        if not events and preferred and not source:
            events = db.events_for_entity(key, limit=6, latest=True)

    display = entity["name"] if entity["name"] == key else f"{entity['name']} ({key})"
    label = f"Actividad de {display}."
    if alerts:
        label += "\nAlertas relacionadas en el índice:\n" + "\n".join(
            f"{alert['alert_id']} · {alert['rule_name']}" for alert in alerts
        )
    if not events:
        label += "\nNo hay registros para esa consulta en el índice."
    return label, alerts, events


def answer(question, remote=False):
    with db.read_session():
        alert, events = assistant.context_for(question, None)
        label, alerts = "", [alert] if alert else []
        if not alert and not events:
            subjects = _subjects(question)
            if len(subjects) == 1:
                label, alerts, events = _activity(question, subjects[0])
            elif subjects:
                names = ", ".join(f"{item['name']} ({item['key']})" for item in subjects)
                label = f"He encontrado varias coincidencias: {names}. Indica la cuenta o el equipo que quieres consultar."
            else:
                for value in re.findall(r"[\w@.-]+", question)[:30]:
                    if ("." in value or "-" in value or value.isupper()) and (
                        events := db.events_for_entity(value.rstrip("."), limit=6, latest=True)
                    ):
                        break

    records = assistant.local_answer(alert, events).strip() if events or alert else ""
    local = "\n\n".join(part for part in (label, records) if part)
    if not local:
        local = "Indica un nombre completo, una cuenta, un equipo o el ID de una alerta o evento del índice de Tarvia."
    response = local
    if remote and events:
        try:
            response = assistant.openai_answer(question, alerts[0] if alerts else None, events)
            if label:
                response = f"{label}\n\n{response}"
        except ValueError:
            response = f"El resumen de IA no está disponible.\n\n{local}"
    return {"respuesta": response, "pasos": [{"herramienta": "Registro recuperado", "entrada": item["event_id"]}
                                             for item in events]}
