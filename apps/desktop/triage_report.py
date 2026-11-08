"""Expediente N1 a partir de observaciones y decisiones registradas."""
from datetime import datetime


FACT_FIELDS = {
    "hostname": "Equipo", "user": "Usuario", "user_upn": "Identidad", "src_ip": "IP de origen",
    "dst_ip": "IP de destino", "domain": "Dominio", "event_type": "Tipo de evento", "eventName": "Operación",
    "process_name": "Proceso", "result": "Resultado", "action": "Acción observada", "status": "Estado",
    "rule": "Regla de red", "sha256": "SHA-256",
}

SOURCE_FACT_FIELDS = {
    "waf": {"host": "Frontal", "method": "Método", "uri": "Ruta", "rule_id": "Firma WAF"},
    "dns": {"query": "Consulta DNS", "qtype": "Tipo DNS", "rcode": "Código DNS", "response": "Respuesta DNS"},
    "ecom_auth": {"customer_id": "Cuenta de cliente", "device_fp": "Huella",
                  "failure_reason": "Motivo del fallo", "captcha": "CAPTCHA"},
    "ecom_account": {"customer_id": "Cuenta de cliente", "event": "Operación", "amount": "Importe"},
    "proxy": {"method": "Método", "url": "URL", "bytes_out": "Bytes salientes", "bytes_in": "Bytes entrantes"},
    "firewall": {"dst_port": "Puerto de destino", "proto": "Protocolo", "bytes": "Bytes registrados"},
    "dlp": {"destination": "Destino", "file_name": "Archivo", "file_size": "Tamaño", "policy": "Política DLP"},
}

PHASE_TECHNIQUES = {
    "Correo de entrada": "T1566.001", "Persistencia": "T1547.001", "Acceso a credenciales": "T1003.001",
    "Movimiento lateral": "T1021.002", "Inhibición de recuperación": "T1490",
    "Privilegios persistentes": "T1098", "Defensa desactivada": "T1562.001",
}


def _observed(event):
    fields = {**FACT_FIELDS, **SOURCE_FACT_FIELDS.get(event["source"], {})}
    parts = [f"{label} {event[key]}" for key, label in fields.items()
             if isinstance(event.get(key), (str, int, float)) and event[key] != ""]
    if event["source"] == "ecom_account" and (payment := (event.get("details") or {}).get("payment")):
        parts.append(f"Forma de pago {payment}")
    return " · ".join(parts) or "Registro recuperado. Consulta el original para verificar los campos."


def _timestamp(item):
    try:
        date = datetime.fromisoformat(item.get("timestamp", "").replace("Z", "+00:00"))
        if date.utcoffset() is not None:
            return date.timestamp()
    except (TypeError, ValueError, AttributeError):
        pass
    return float("inf")


def _enrichment(context):
    results = []
    for item in context.get("inteligencia", []):
        tip = item.get("tip") or {}
        geo = item.get("geo") or {}
        result = tip.get("reputation") or "Sin coincidencia en TIP"
        if tip.get("malware_family"):
            result += f" · {tip['malware_family']}"
        if geo.get("asn"):
            result += f" · {geo['asn']}"
        results.append({"indicator": item["indicator"], "type": tip.get("indicator_type") or "IOC",
                        "source": "TIP / GeoIP de Tarvia", "result": result})
    for item in context.get("sandbox", []):
        results.append({"indicator": item["sha256"], "type": "sha256", "source": "Sandbox de Tarvia",
                        "result": item.get("verdict", "Sin veredicto"), "family": item.get("malware_family")})
    return results


def _incident_report(identifier, incident, analysis):
    phases = {row["stage"]: row for row in incident["timeline"]}
    origin, target = incident["affected"][:2]
    delivery = phases.get("Correo de entrada")
    movement = phases["Movimiento lateral"]
    return {
        **incident,
        "incident_id": f"VIG-INC-{movement['event_id']}",
        "alert_ids": incident.get("alert_ids", [identifier]),
        "patient_zero": f"{origin}, primer equipo observado en esta cadena.",
        "initial_access": (f"Posible adjunto de phishing entregado en {delivery['event_id']}. "
                           "La ejecución posterior coincide por nombre."
                           if delivery else "El acceso inicial no se pudo determinar."),
        "timeline": [{**row, "description": row["finding"], "mitre": PHASE_TECHNIQUES.get(row["stage"], "")}
                     for row in incident["timeline"]],
        "scope": {
            "hosts": incident["affected"],
            "users": sorted({event["user"] for event in analysis["events"]
                             if event["event_id"] in incident["evidence_ids"] and event.get("user")}),
            "data": "Se desconoce si se extrajeron o cifraron datos.",
            "business_impact": incident["scope"] + " La interrupción de servicios queda por verificar.",
        },
        "root_cause": "La evidencia vincula una ejecución maliciosa con movimiento lateral e inhibición de "
                      "recuperación. Sigue pendiente confirmar cómo se obtuvo la cuenta privilegiada.",
        "containment_plan": [
            {"action": "Evaluar aislamiento y preservar telemetría", "target": origin,
             "approver": "N2", "business_impact": "Interrumpe la sesión del puesto."},
            {"action": "Validar alcance y evaluar segmentación controlada", "target": target,
             "approver": "N2 y responsable del activo", "business_impact": "Puede afectar a servicios dependientes."},
        ],
        "eradication_and_recovery": ["Validar la integridad y restauración de copias aisladas.",
                                     "Revisar persistencia, salud del EDR y cuentas privilegiadas con N2."],
        "notifications": ["N2 de guardia, responsable SOC y CISO según la política de Tarvia."],
        "detection_gaps": incident["limits"],
        "open_questions": ["¿Funcionaron los comandos contra las copias y qué puntos de restauración siguen íntegros?",
                           "¿Por qué ruta se ejecutó el mismo binario en el tercer equipo?"],
    }


def merge_incident_memberships(reports):
    """Unifica los IDs acreditados de un mismo incidente dentro de un lote."""
    groups = {}
    for report in reports:
        if (incident := report.get("incident")) and incident["incident_id"] == report["ticket_id"]:
            group = groups.setdefault(report["ticket_id"], set())
            group.update(report["alert_ids"])
            group.update(incident["alert_ids"])
    for report in reports:
        if (incident := report.get("incident")) and incident["incident_id"] == report["ticket_id"]:
            members = sorted(groups[incident["incident_id"]])
            incident["alert_ids"] = members
            report["alert_ids"] = members


def build_report(alert, analysis):
    """Representación exportable con hechos recuperados, criterio, contraste y decisión."""
    identifier = alert["alert_id"]
    proposal = analysis.get("proposal") or {}
    contrast = analysis.get("challenge") or {}
    basis = analysis.get("decision_basis") or analysis.get("verified_finding") or {}
    route = analysis["routing"]
    events = analysis.get("events", [])
    context = analysis.get("context", {})
    direct = set(analysis.get("requested", []))
    cited = set(proposal.get("citations", [])) | set(contrast.get("citations", [])) | set(basis.get("citations", []))
    followup = set(analysis.get("followup_event_ids", []))
    context_only = set(basis.get("context_citations", [])) | set(analysis.get("context_event_ids", []))
    selected = direct | cited | followup | context_only
    candidate_sample = {key for key in [event["event_id"] for event in events
                                        if event["event_id"] not in selected][:6]}
    confidence = analysis.get("confidence")
    if confidence is not None:
        confidence, confidence_basis = confidence / 100, "Estimación declarada por el modelo."
    elif analysis["verdict"] == "needs_more_info":
        confidence, confidence_basis = 0.0, "Sin confianza para afirmar una clasificación."
    elif route["automatic"]:
        confidence, confidence_basis = 0.95, "Escala operativa de evidencia verificada y cierre elegible."
    else:
        confidence, confidence_basis = 0.8, "Escala operativa de evidencia verificada con revisión pendiente."
    evidence = []
    for event in events:
        key = event["event_id"]
        if key not in selected and key not in candidate_sample:
            continue
        relation = "correlación"
        if key in followup:
            relation = "seguimiento"
        elif key in context_only:
            relation = "contexto"
        elif key in direct:
            relation = "directa"
        evidence.append({"event_id": key, "source": event["source"], "timestamp": event.get("timestamp"),
                         "finding": _observed(event), "relation": relation, "cited": key in cited})
    incident = analysis.get("incident") or basis.get("incident")
    if incident:
        incident = _incident_report(identifier, incident, analysis)
    timeline = (incident or {}).get("timeline") or [
        {"timestamp": row["timestamp"], "event_id": row["event_id"], "source": row["source"],
         "finding": row["finding"]} for row in sorted(evidence, key=_timestamp)]
    vulnerabilities = [{"asset": asset["hostname"], **vulnerability}
                       for asset in context.get("activos", [])
                       for vulnerability in asset.get("vulnerabilities", [])]
    missing = sorted(direct - {event["event_id"] for event in events})
    questions = list(dict.fromkeys(basis.get("questions", [])))
    if missing:
        questions.append("Recuperar las referencias faltantes: " + ", ".join(missing))
    if analysis["verdict"] == "needs_more_info" and not questions:
        questions.append("¿Qué registro adicional permite confirmar impacto, autorización o una explicación alternativa?")
    summary = (basis.get("summary") or analysis.get("proposal_error") or analysis.get("review_error")
               or "Se revisaron la regla y las evidencias recuperadas. " + route["reason"])
    declared = alert.get("entities", {})
    affected = declared
    entity_verification = basis.get("entity_verification") or {}
    discrepancies = list(entity_verification.get("discrepancies", []))
    if alert.get("external"):
        original_cites = set(basis.get("citations", []))
        verified_events = [event for event in events if event["event_id"] in original_cites]
        verified_hosts = {event["hostname"] for event in verified_events if event.get("hostname")}
        verified_users = {name for event in verified_events if (name := event.get("user_upn") or event.get("user"))}
        affected = {
            "hosts": [{"hostname": hostname} for hostname in sorted(verified_hosts)],
            "users": [{"upn": user} for user in sorted(verified_users)],
            **entity_verification.get("verified", {}),
        }
    affected_hostnames = {host.get("hostname") for host in affected.get("hosts", [])}
    if alert.get("external") and affected_hostnames:
        matched_hosts = {hostname.casefold() for hostname in affected_hostnames if hostname}
        unconfirmed = [host["hostname"] for host in declared.get("hosts", [])
                       if host.get("hostname") and host["hostname"].casefold() not in matched_hosts]
        if unconfirmed:
            discrepancies.append({"field": "hosts", "declared": unconfirmed,
                                  "verified": sorted(hostname for hostname in affected_hostnames if hostname)})
    declared_customers = affected.get("customers", [])
    customer_ids = {row.get("customer_id") for row in declared_customers}
    basis_ids = set(basis.get("citations", []))
    if "affected_customers" in basis:
        verified_customers = set(basis["affected_customers"])
    else:
        verified_customers = {event["customer_id"] for event in events
                              if event["event_id"] in basis_ids and event.get("customer_id")
                              and (event["source"] != "ecom_auth" or event.get("result") == "success")}
    customers = [*declared_customers, *({"customer_id": key} for key in sorted(verified_customers - customer_ids))]
    mitigations = [] if route.get("ot") else list(dict.fromkeys(basis.get("actions", [])))
    actions = [] if route.get("ot") else list(basis.get("action_plan", []))
    if not actions:
        actions = [{"action": note, "target": "Entidades y registros citados en el expediente",
                    "requires_approval": True, "justification": route["reason"]} for note in mitigations]
    if route["recommendation"] == "escalate" and not actions:
        actions.append({"action": "Derivar el expediente", "target": ", ".join(route["recipients"]),
                        "requires_approval": False, "justification": route["reason"]})
    provider_errors = {phase: analysis[f"{phase}_error"]
                       for phase, timing in (("proposal", "proposal_ms"), ("review", "challenge_ms"))
                       if timing in analysis["timing"] and analysis.get(f"{phase}_error")}
    return {
        "ticket_id": incident["incident_id"] if incident else f"VIG-{identifier}",
        "alert_ids": incident["alert_ids"] if incident else [identifier],
        "title": (basis.get("summary") or alert["rule_name"]).split(". ", 1)[0],
        "rule_id": alert.get("rule_id"), "runbook": alert.get("runbook"),
        "detected_at": alert.get("created_at"), "investigated_at": analysis.get("created_at"),
        "verdict": analysis["verdict"], "severity": analysis["severity"], "sla": analysis["sla"],
        "severity_rationale": analysis["severity_rationale"],
        "confidence": confidence, "confidence_basis": confidence_basis,
        "summary": summary, "description": alert.get("description"),
        "affected": {"hosts": affected.get("hosts", []), "users": affected.get("users", []),
                     "customers": customers,
                     "business_services": sorted({row["business_service"] for row in context.get("activos", [])
                                                  if row.get("business_service") and
                                                  (not alert.get("external") or row["hostname"] in affected_hostnames)})},
        "evidence": evidence, "enrichment": _enrichment(context), "timeline": timeline,
        "vulnerabilities": vulnerabilities, "mitre": [alert["mitre"]["technique_id"]]
        if isinstance(alert.get("mitre"), dict) and alert["mitre"].get("technique_id") else [],
        "related_alerts": context.get("alertas_relacionadas", []),
        "incident": incident,
        "recommended_actions": actions, "action_notes": mitigations, "executed_actions": [],
        "escalation": {"escalate": route["recommendation"] == "escalate",
                       "to": ", ".join(route["recipients"]), "reason": route["reason"]},
        "open_questions": questions, "external": alert.get("external", False),
        **({"declared_entities": declared, "entity_discrepancies": discrepancies}
           if alert.get("external") else {}),
        "provider": analysis.get("provider"), "routing": route, "timing_ms": analysis["timing"]["total_ms"],
        "provider_errors": provider_errors,
        "triage_seconds": analysis["timing"]["total_ms"] / 1000,
        "consultas": analysis.get("trace", []), "propuesta": proposal, "contraste": contrast,
        "criterio_verificado": basis,
        **({"declared_evidence": alert["declared_evidence"]} if alert.get("external") and alert.get("declared_evidence") else {}),
    }
