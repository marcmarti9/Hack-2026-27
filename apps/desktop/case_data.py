"""Secciones compartidas del expediente y exportación."""
import json
from datetime import datetime, timezone

from apps.backend.rules.engine import fuera_de_horario
from apps.desktop.demo import display_questions, for_alert

SECTION_NAMES = ("Entidades", "Línea de tiempo", "Acciones", "Historial")


def pretty(data) -> str:
    return json.dumps(data, ensure_ascii=False, indent=2, default=str)


def case_sections(alert: dict, analysis: dict, history: list[dict]) -> dict:
    demo, incident, closed = for_alert(alert["alert_id"])
    scope = incident.get("scope") or {}
    entities = [
        "Entidades de la alerta", pretty(alert.get("entities", {})),
        "Contexto recuperado en Vigía", pretty(analysis.get("context", {})),
    ]
    if demo:
        entities.extend(["Entidades y servicios del ticket archivado", pretty(demo.get("affected", {})),
                         "Enriquecimiento", pretty(demo.get("enrichment", [])),
                         "Alertas vinculadas", "\n".join(demo["alert_ids"]),
                         "Técnicas MITRE", ", ".join(demo.get("mitre", []))])
    if scope:
        entities.extend(["Alcance e impacto (informe N2)", pretty(scope)])

    timeline = [
        f"{event.get('timestamp', 'Fecha desconocida')} · {event['event_id']} · {event['source']}"
        for event in sorted(analysis.get("events", []), key=lambda item: item.get("timestamp", ""))
    ]
    if incident:
        timeline.extend(["", f"Informe N2 archivado · {incident['incident_id']}",
                         f"{incident.get('title', '')} · confianza del archivo {incident.get('confidence', 0):.0%}",
                         f"Paciente cero: {incident.get('patient_zero', 'Sin determinar')}",
                         f"Acceso inicial: {incident.get('initial_access', 'Sin determinar')}"])
        timeline.extend(f"{point['timestamp']} · {point['event_id']} · {point.get('mitre', '')}\n{point['description']}"
                        for point in incident.get("timeline", []))
        timeline.extend(["", "Causa raíz", incident.get("root_cause", ""),
                         "Notificaciones", "\n".join(incident.get("notifications", [])),
                         "Límites y preguntas N2", "\n".join(display_questions(incident)),
                         "Brechas de detección", "\n".join(incident.get("detection_gaps", [])),
                         "Incidentes relacionados", ", ".join(incident.get("related_incidents", []))])

    proposal = analysis.get("proposal") or {}
    challenge = analysis.get("challenge") or {}
    actions = ["Sugerencias de la propuesta", *proposal.get("actions", []),
               "", "Sugerencias del contraste", *challenge.get("actions", [])]
    if demo:
        actions.extend(["", "Acciones propuestas en el expediente de referencia", pretty(demo.get("recommended_actions", [])),
                        "Escalado", pretty(demo.get("escalation", {})),
                        "Ejecuciones registradas en el expediente de referencia", pretty(demo.get("executed_actions", []))])
    if incident:
        actions.extend(["", "Plan N2 de contención", pretty(incident.get("containment_plan", [])),
                        "Erradicación y recuperación", "\n".join(incident.get("eradication_and_recovery", []))])

    activity = [
        f"{entry['created_at']} · {entry['kind']} · {entry['actor']}\n" + (
            (entry["data"].get("proposal") or {}).get("summary", "Consulta de datos") if entry["kind"] == "Análisis"
            else pretty(entry["data"])
        ) for entry in history
    ]
    if closed:
        activity.extend(["", "Descarte de referencia en el expediente de referencia", pretty(closed)])

    return {
        "Entidades": "\n\n".join(entities),
        "Línea de tiempo": "\n\n".join(timeline).strip() or "Todavía no hay eventos recuperados para esta alerta.",
        "Acciones": "\n".join(actions) if demo or proposal or challenge else "Todavía no hay acciones propuestas.",
        "Historial": "\n\n".join(activity).strip() or "Todavía no hay actividad registrada para esta alerta.",
    }


def demo_process(ticket: dict, closed: dict) -> list[str]:
    if not ticket:
        if closed:
            return ["", "Expediente de referencia · descarte por regla", closed.get("reason", "")]
        return []
    fiscal = ticket.get("fiscal") or {}
    confidence = ticket.get("confidence")
    return [
        "", f"Expediente de referencia · {ticket['ticket_id']} (agentes simulados)", ticket["title"],
        ticket.get("summary", ""), ticket.get("severity_rationale", ""),
        f"Severidad del expediente: {ticket.get('severity', '')} · "
        f"{len(ticket['alert_ids'])} alertas · "
        + ("SOC cerrado al inicio del grupo" if ticket.get("out_of_hours") else "SOC abierto al inicio del grupo"),
        f"Tiempo de triaje registrado en el expediente de referencia: {ticket.get('triage_seconds', 0):g} s",
        f"Resultado del expediente: {ticket.get('verdict', '')}  ·  "
        + (f"{confidence:.0%} de confianza en el expediente de referencia" if isinstance(confidence, (int, float)) else "Sin estimación"),
        "Manipulación detectada: " + (
            ticket["manipulation_detected"].get("where") or "Sí"
            if ticket.get("manipulation_detected", {}).get("detected") else "Sin señal registrada en el expediente de referencia"
        ),
        "", "Traza de investigación archivada",
        *[f"{step.get('nombre', 'Resumen')} · {step.get('texto') or pretty(step.get('entrada', {}))}"
          + (f"\nResultado de herramienta: {step['resultado']}" if step.get("resultado") else "")
          for step in ticket.get("trace", [])],
        "", "Contraste archivado", fiscal.get("comment", "Sin contraste en este ticket."),
        ("El fiscal coincidió con el veredicto." if fiscal.get("agrees")
         else "El fiscal presentó objeciones.") if fiscal else "",
        f"Veredicto alternativo: {fiscal['alternative_verdict']}" if fiscal.get("alternative_verdict") else "",
        *fiscal.get("objections", []), "", "Preguntas abiertas del expediente", *display_questions(ticket),
    ]


def soc_status(stamp: str | None = None) -> str:
    return "SOC cerrado" if fuera_de_horario(stamp or datetime.now(timezone.utc).isoformat()) else "SOC abierto"


def fraction(total: int, closed: int) -> str:
    percentage = f"{100 * closed / total:.1f}".replace(".", ",") if total else "—"
    return f"{percentage}% ({closed}/{total})" if total else "— (0 alertas)"
