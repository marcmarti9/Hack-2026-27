"""Secciones compartidas del expediente y exportación."""
import json
from datetime import datetime, timezone
from textwrap import indent

from apps.backend.rules.engine import fuera_de_horario
from apps.desktop.demo import display_questions, for_alert
from apps.desktop.review import VERDICTS

SECTION_NAMES = ("Entidades", "Línea de tiempo", "Acciones", "Historial")

_LABELS = {
    "alert_id": "Alerta", "event_id": "Evento", "hostname": "Equipo", "hosts": "Equipos",
    "ip": "IP", "ips": "Direcciones IP", "upn": "Cuenta", "users": "Identidades",
    "display_name": "Nombre", "business_service": "Servicio de negocio",
    "business_services": "Servicios de negocio", "business_impact": "Impacto en el negocio",
    "criticality": "Criticidad", "zone": "Zona", "privileged": "Privilegios",
    "account_type": "Tipo de cuenta", "indicator": "Indicador", "source": "Fuente",
    "result": "Resultado", "reason": "Motivo", "to": "Destinatario",
    "customers": "Clientes", "data": "Datos afectados", "target": "Objetivo",
    "requires_approval": "Requiere autorización", "approver": "Responsable de autorizar",
    "justification": "Justificación", "verdict": "Veredicto", "rule_id": "ID de regla",
    "rule": "Regla", "closed": "Cierre registrado", "severity": "Severidad",
    "created_at": "Fecha", "timestamp": "Fecha y hora", "escalate": "Escalar",
    "citations": "Evidencias citadas", "summary": "Resumen", "confidence": "Confianza",
    "proposal": "Propuesta", "challenge": "Contraste", "questions": "Preguntas abiertas",
    "actions": "Acciones", "proposal_error": "Incidencia en la propuesta",
    "review_error": "Incidencia en el contraste", "requested": "Referencias solicitadas",
    "timing": "Tiempos de análisis", "guidance": "Versiones de las guías consultadas",
    "evidence_ms": "Recuperación de evidencia (ms)", "proposal_ms": "Propuesta (ms)",
    "challenge_ms": "Contraste (ms)", "total_ms": "Total (ms)", "revision": "Versión",
    "provider": "Proveedor", "message": "Mensaje", "event_type": "Tipo de evento",
    "host": "Equipo", "user": "Usuario", "src_ip": "IP de origen", "dst_ip": "IP de destino",
}

_ACTION_LABELS = {
    "isolate_host": "Aislar equipo", "disable_user": "Deshabilitar cuenta",
    "revoke_sessions": "Revocar sesiones", "reset_password": "Restablecer contraseña",
    "block_ioc": "Bloquear indicador", "purge_email": "Purgar correo",
    "disable_access_key": "Desactivar clave cloud",
}


def pretty(data) -> str:
    return json.dumps(data, ensure_ascii=False, indent=2, default=str)


def _label(key: str) -> str:
    return _LABELS.get(key, key.replace("_", " ").capitalize())


def display_record(value: object) -> str:
    """Convierte campos a texto legible sin interpretar marcas ni URLs."""
    if isinstance(value, dict):
        rows = []
        for key, item in value.items():
            text = display_record(item)
            if key == "verdict" and isinstance(item, str) and item in VERDICTS:
                text = VERDICTS[item][0]
            elif key == "confidence" and type(item) is int:
                text = f"{item} %"
            title = _label(key)
            if isinstance(item, (dict, list)):
                rows.append(f"{title}\n{indent(text, '  ')}")
            else:
                rows.append(f"{title}: {text}")
        return "\n".join(rows) or "Sin datos"
    if isinstance(value, list):
        return "\n\n".join(display_record(item) for item in value) or "Sin datos"
    if isinstance(value, bool):
        return "Sí" if value else "No"
    return str(value) if value is not None and value != "" else "Sin datos"


def _event_line(event: dict) -> str:
    return " · ".join(filter(None, (event.get("timestamp"), event.get("source"), event.get("event_id"))))


def evidence_sections(alert: dict, analysis: dict, ticket: dict) -> list[tuple[str, str]]:
    events = analysis.get("events", [])
    recovered = {event["event_id"] for event in events}
    declared = list(dict.fromkeys(alert.get("related_events", [])))
    requested = list(dict.fromkeys(analysis.get("requested", declared)))
    sent = [event["event_id"] for event in analysis.get("sent_events", [])]
    additional = [event["event_id"] for event in analysis.get("challenge_events", [])]
    coverage = "Aún no se han consultado los registros del índice."
    if analysis:
        found = f"{len(events)} eventos recuperados" if len(events) != 1 else "1 evento recuperado"
        declared_text = f"{len(declared)} referencias de la alerta" if len(declared) != 1 else "1 referencia de la alerta"
        coverage = f"{found} · {declared_text}"
        if "sent_events" in analysis:
            coverage += f" · {len(sent)} registros para la propuesta"
        if additional:
            coverage += f" · {len(additional)} adicionales para el contraste"
    sections = [("Cobertura de las evidencias", coverage)]
    if declared:
        sections.append(("Referencias de la alerta", ", ".join(declared)))
    if analysis and (missing := [key for key in requested if key not in recovered]):
        sections.append(("Referencias no recuperadas", ", ".join(missing)))
    if ticket.get("evidence"):
        sections.append(("Hallazgos del expediente de referencia",
                         "\n\n".join(f"{row['event_id']} · {row['source']}\n{row['finding']}"
                                      for row in ticket["evidence"])))
    if events:
        sections.append(("Registros recuperados del índice", "\n".join(_event_line(row) for row in events)))
    elif analysis:
        sections.append(("Registros del índice", "No se recuperaron eventos."))
    for report in analysis.get("context", {}).get("sandbox", []):
        sections.append(("Informe de sandbox · " + (report.get("file_name") or "Archivo"),
                         f"SHA-256: {report['sha256']}\nVeredicto: {report.get('verdict', 'Sin dato')}\n"
                         f"Familia: {report.get('malware_family') or 'Sin identificar'}"))
    if "sent_events" in analysis:
        sections.append(("Registros incluidos en la propuesta al modelo", ", ".join(sent) or "Ninguno"))
    if "challenge_events" in analysis:
        sections.append(("Registros adicionales del contraste", ", ".join(additional) or "Ninguno"))
    for key, title in (("proposal", "Citas de la propuesta"), ("challenge", "Citas del contraste")):
        result = analysis.get(key)
        if result:
            sections.append((title, ", ".join(result.get("citations", [])) or "Ninguna cita registrada"))
    return sections


def case_panels(alert: dict, analysis: dict, history: list[dict], *,
                hide_archive: bool = False) -> dict[str, list[tuple[str, str]]]:
    demo, incident, closed = ({}, {}, {}) if hide_archive else for_alert(alert["alert_id"])
    entities = [(f"{_label(key)} de la alerta", display_record(value))
                for key, value in alert.get("entities", {}).items() if value]
    if not entities:
        entities.append(("Entidades de la alerta", "La alerta no identifica entidades."))
    for name, records in analysis.get("context", {}).items():
        if records:
            entities.append((f"{_label(name)} · índice local", display_record(records)))
    if demo:
        entities.extend([
            ("Entidades y servicios · ticket de referencia", display_record(demo.get("affected", {}))),
            ("Enriquecimiento · ticket de referencia", display_record(demo.get("enrichment", []))),
            ("Alertas vinculadas", "\n".join(demo["alert_ids"])),
            ("Técnicas MITRE", ", ".join(demo.get("mitre", [])) or "Sin técnicas registradas"),
        ])
    if incident.get("scope"):
        entities.append(("Alcance e impacto · informe N2", display_record(incident["scope"])))

    timeline = []
    live_incident = analysis.get("incident")
    live_report = (analysis.get("report") or {}).get("incident") or {}
    if live_incident:
        scope = live_incident.get("scope")
        if scope:
            entities.append(("Alcance investigado · índice local", display_record(scope)))
        timeline.extend([
            (live_incident.get("title") or "Cadena investigada", "\n\n".join(
                f"{_event_line(point)} · {point.get('host') or 'Equipo sin determinar'}\n"
                f"{point.get('stage') or 'Observación'} · {point.get('finding') or 'Consulta el evento original.'}"
                for point in live_incident.get("timeline", [])) or "Sin eventos enlazados."),
            ("Límites del análisis", "\n".join(live_incident.get("limits", [])) or "Alcance por confirmar."),
        ])
    if live_report:
        timeline.insert(0, (f"Informe N2 · {live_report['incident_id']}", "\n".join([
            live_report["patient_zero"], live_report["initial_access"], live_report["root_cause"],
            "Alertas vinculadas", ", ".join(live_report["alert_ids"]),
        ])))
        timeline.append(("Preguntas abiertas de N2", "\n".join(live_report["open_questions"])))
    if incident:
        confidence = incident.get("confidence")
        timeline.append((f"Informe N2 archivado · {incident['incident_id']}", "\n".join([
            incident.get("title", ""),
            f"Paciente cero: {incident.get('patient_zero') or 'Sin determinar'}",
            f"Acceso inicial: {incident.get('initial_access') or 'Sin determinar'}",
            f"Confianza del archivo: {confidence:.0%}" if confidence is not None else "Sin estimación",
        ])))
        points = sorted(incident.get("timeline", []), key=lambda item: item.get("timestamp") or "")
        timeline.extend([
            ("Cadena del incidente de referencia",
             "\n\n".join(f"{_event_line(point)} · {point.get('mitre') or 'Sin técnica MITRE'}\n{point['description']}"
                         for point in points) or "Sin pasos registrados."),
            ("Causa raíz", incident.get("root_cause") or "Sin determinar"),
            ("Notificaciones archivadas", "\n".join(incident.get("notifications", [])) or "Sin registros"),
            ("Límites y preguntas N2", "\n".join(display_questions(incident)) or "Sin preguntas registradas"),
            ("Brechas de detección", "\n".join(incident.get("detection_gaps", [])) or "Sin brechas registradas"),
            ("Incidentes relacionados", ", ".join(incident.get("related_incidents", [])) or "Sin vínculos registrados"),
        ])
    elif not live_incident:
        timeline.append(("Informe N2", "No hay un informe N2 asociado a esta alerta."))
    events = sorted(analysis.get("events", []), key=lambda item: item.get("timestamp") or "")
    timeline.append(("Eventos recuperados del índice",
                     "\n".join(_event_line(event) for event in events)
                     or "Todavía no hay eventos recuperados para esta alerta."))

    actions = []
    proposal = analysis.get("proposal") or {}
    challenge = analysis.get("challenge") or {}
    if analysis.get("origin") != "demo" and proposal.get("actions"):
        actions.append(("Sugerencias de la propuesta", "\n".join(proposal["actions"])))
    if challenge.get("actions"):
        actions.append(("Sugerencias del contraste", "\n".join(challenge["actions"])))
    if live_report:
        actions.extend([
            ("Contención propuesta · requiere aprobación", "\n\n".join(
                f"{row['action']} · {row['target']}\nAprueba {row['approver']}\n{row['business_impact']}"
                for row in live_report["containment_plan"])),
            ("Recuperación y notificaciones", "\n".join([
                *live_report["eradication_and_recovery"], *live_report["notifications"],
            ])),
        ])
    if demo:
        recommendations = []
        for row in demo.get("recommended_actions", []):
            action = _ACTION_LABELS.get(row.get("action"), display_record(row.get("action")))
            approval = ("Requiere autorización" if row.get("requires_approval")
                        else "El archivo no indica autorización adicional")
            recommendations.append(f"{action} · {row['target']}\n{row['justification']}\nPropuesta de referencia · {approval}")
        actions.extend([
            ("Escalado · ticket de referencia", display_record(demo.get("escalation", {}))),
            ("Propuestas del ticket de referencia", "\n\n".join(recommendations) or "Sin propuestas registradas"),
            ("Ejecuciones en el ticket de referencia",
             display_record(demo["executed_actions"]) if demo.get("executed_actions") else "Sin ejecuciones registradas"),
        ])
    if incident:
        actions.extend([
            ("Plan N2 de contención", display_record(incident["containment_plan"])
             if incident.get("containment_plan") else "El informe de referencia no registra un plan."),
            ("Erradicación y recuperación", "\n".join(incident.get("eradication_and_recovery", []))
             or "Sin pasos registrados"),
        ])

    activity = []
    for entry in history:
        data = entry["data"]
        if entry["kind"] == "Análisis":
            source = "Análisis de referencia" if data.get("origin") == "demo" else "Análisis registrado"
            outcome = (data.get("proposal") or {}).get("summary", "Consulta de datos")
            content = f"{source}\n{outcome}"
        else:
            content = display_record(data)
        activity.append((f"{entry['kind']} · {entry['actor']}", f"{entry['created_at']}\n{content}"))
    if closed:
        activity.append(("Descarte · expediente de referencia", display_record(closed)))

    return {
        "Entidades": entities,
        "Línea de tiempo": timeline,
        "Acciones": actions or [("Acciones", "Todavía no hay acciones propuestas.")],
        "Historial": activity or [("Actividad", "Todavía no hay actividad registrada para esta alerta.")],
    }


def case_sections(alert: dict, analysis: dict, history: list[dict]) -> dict[str, str]:
    return {name: "\n\n".join(f"{title}\n{body}" for title, body in sections)
            for name, sections in case_panels(alert, analysis, history).items()}


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
        *[f"{step.get('nombre', 'Resumen')} · {step.get('texto') or display_record(step.get('entrada', {}))}"
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
