"""Modo demo sin API (VIGIA_MOCK=1): imita a Claude con el MISMO interfaz (client.messages.create) y datos REALES.
No razona como un LLM: aplica heurísticas por regla, pero consulta las herramientas de verdad y solo cita
event_id que existen. Sirve para enseñar la web completa si no hay clave o falla la conexión."""
import itertools, json, re
from types import SimpleNamespace as NS
from apps.backend.tools import db
from apps.backend.rules.approvals import aprobacion

_ids = itertools.count(1)
def _tool(name, args):
    return NS(type="tool_use", id=f"mock{next(_ids)}", name=name, input=args)
def _text(t):
    return NS(type="text", text=t)
def _resp(*blocks):
    return NS(content=list(blocks), stop_reason="tool_use" if any(b.type == "tool_use" for b in blocks) else "end_turn")

def _datos(messages):
    txt = messages[0]["content"] if isinstance(messages[0]["content"], str) else ""
    m = re.search(r"<datos_no_confiables>\n(.*)\n</datos_no_confiables>", txt, re.S)
    return json.loads(m.group(1)) if m else None

def _turno(messages):
    return sum(1 for m in messages if m["role"] == "assistant")

TITULOS = {
    "UC-EML": "Campaña de phishing", "UC-EML-004": "Fraude de cambio de IBAN tras robo de sesión",
    "UC-EML-002": "Adjunto malicioso entregado", "UC-AI-002": "Fuga de información en el asistente Vela",
    "UC-NET-002": "Conexión a infraestructura maliciosa", "UC-EDR-008": "Reconocimiento del dominio", "UC-IDP-003": "Fatiga MFA", "UC-IDP-004": "Inicio de sesión desde infraestructura anónima",
    "UC-IDP-005": "Regla de buzón maliciosa", "UC-IDP-006": "Robo de sesión (AiTM)", "UC-IDP-008": "Cuenta añadida a grupo privilegiado",
    "UC-IDP-001": "Viaje imposible", "UC-IDP-002": "Password spraying con acceso correcto", "UC-EDR-004": "Robo de credenciales (LSASS)",
    "UC-EDR-007": "Preparación de ransomware", "UC-EDR-006": "Minero de criptomonedas", "UC-EDR-012": "RAM scraper en TPV",
    "UC-EDR-005": "Acceso remoto no autorizado (AnyDesk)", "UC-EDR-009": "Web shell en frontal web", "UC-EDR-010": "Robo de credenciales de navegador",
    "UC-EDR-011": "Agente EDR detenido", "UC-EDR": "Ejecución maliciosa en el puesto", "UC-NET-006": "Exfiltración por túnel DNS",
    "UC-NET-004": "Movimiento lateral", "UC-NET": "Comunicación con infraestructura maliciosa", "UC-WEB-003": "Tomas de cuenta de clientes",
    "UC-WEB-002": "Credential stuffing con accesos correctos", "UC-CLD-004": "Descarga masiva de datos desde AWS",
    "UC-CLD": "Credenciales cloud comprometidas", "UC-DLP": "Fuga de datos personales", "UC-DEV-001": "Paquete malicioso en el pipeline de CI",
    "UC-VPN-001": "Proveedor conectado fuera de horario", "UC-AI": "Ataque al asistente Vela", "UC-OT-001": "Acceso a red OT",
}
GRAVEDAD = ["UC-EDR-007", "UC-CLD-004", "UC-EDR-012", "UC-EML-004", "UC-EDR-004", "UC-NET-006", "UC-CLD-002", "UC-EDR-009",
            "UC-WEB-003", "UC-AI-002", "UC-IDP-006", "UC-IDP-003", "UC-EDR-006", "UC-IDP-002", "UC-DLP-001", "UC-DEV-001", "UC-EDR-005"]
NIVEL = ["informational", "low", "medium", "high", "critical"]

def _titulo(alertas):
    reglas = {a["rule_id"] for a in alertas}
    clave = next((g for g in GRAVEDAD if g in reglas),
                 max(alertas, key=lambda a: NIVEL.index(a["severity"]))["rule_id"])
    base = next((v for k, v in sorted(TITULOS.items(), key=lambda kv: -len(kv[0])) if clave.startswith(k)), alertas[0]["rule_name"])
    E = _ents(alertas)
    nube = [a["entities"]["cloud"].get("identity") for a in alertas if a.get("entities", {}).get("cloud")]
    sujeto = ([f"{len(E['customers'])} clientes"] if len(E["customers"]) > 2 else None) or nube[:1] or \
             (E["users"][:1] if any(r.startswith("UC-DLP") for r in reglas) else []) or \
             E["hosts"][:2] or E["users"][:1] or E["customers"][:1] or E["ips"][:1] or ["Tarvia"]
    extra = f" ({len(alertas)} alertas)" if len(alertas) > 1 else ""
    return f"{base}: {', '.join(sujeto)}{extra}"

def _ents(alertas):
    E = {"hosts": [], "users": [], "ips": [], "customers": [], "domains": []}
    for a in alertas:
        e = a.get("entities", {})
        for h in e.get("hosts", []): E["hosts"].append(h.get("hostname"))
        for u in e.get("users", []):
            if "@" in u.get("upn", ""): E["users"].append(u["upn"].split("@")[0])
        for c in e.get("customers", []): E["customers"].append(c.get("customer_id"))
        E["ips"] += e.get("ips", []); E["domains"] += e.get("domains", [])
    return {k: list(dict.fromkeys(x for x in v if x)) for k, v in E.items()}

def _n1(messages):
    alertas = _datos(messages)
    E, t0 = _ents(alertas), alertas[0]["created_at"]
    if _turno(messages) == 0:
        calls = []
        if E["hosts"]: calls += [_tool("get_asset", {"key": E["hosts"][0]}), _tool("events_for_entity", {"value": E["hosts"][0], "around": t0, "horas": 6})]
        if E["users"]: calls += [_tool("get_user", {"key": E["users"][0]}), _tool("events_for_entity", {"value": E["users"][0], "around": t0, "horas": 6})]
        if E["ips"]: calls.append(_tool("get_intel", {"indicator": E["ips"][0]}))
        calls.append(_tool("get_changes", {"q": (E["hosts"] or E["users"] or ["CHG"])[0]}))
        return _resp(_text("[modo demo] Reviso equipo, usuario, inteligencia y cambios aprobados."), *calls[:5])
    # Turno 2: ticket con datos reales
    evid = []
    for a in alertas:
        for eid in a.get("related_events", []):
            ev = db.get_event(eid)
            if ev and len(evid) < 6 and eid not in {x["event_id"] for x in evid}:
                evid.append({"source": ev["source"], "event_id": eid, "finding": _resumen_evento(ev)})
    for ent in (E["hosts"] + E["users"])[:2]:
        for ev in db.events_for_entity(ent, t0, 6, None, 40):
            if len(evid) >= 8: break
            ruido = ev["source"] == "edr_events" and any(f in str(ev.get("signer", "")) for f in ("Microsoft", "Google", "Mozilla", "Adobe", "SAP"))
            if not ruido and ev["source"] in ("edr_events", "idp_audit", "vpn", "dlp", "cloudtrail", "ad_events", "email_clicks", "sql_audit") and \
               ev["event_id"] not in {x["event_id"] for x in evid}:
                evid.append({"source": ev["source"], "event_id": ev["event_id"], "finding": _resumen_evento(ev)})
    escudo = [x for a in alertas for x in a.get("_escudo_vigia", [])]
    reglas = {a["rule_id"] for a in alertas}
    verdict = "true_positive"
    usr = db.user(E["users"][0]) if E["users"] else None
    if reglas == {"UC-IDP-001"} and usr and any(h["tipo"] == "viaje" for h in usr.get("hr_events", [])):
        verdict = "benign_true_positive"
    adj = []
    if any(r.startswith(("UC-DLP", "UC-CLD-004", "UC-EML-004", "UC-EDR-012", "UC-WEB-003", "UC-NET-006")) for r in reglas):
        adj.append({"delta": 1, "reason": "datos personales o pagos implicados"})
    elif any("AWS_" in str(a.get("evidence", {}).get("env_vars_read", "")) for a in alertas):
        adj.append({"delta": 1, "reason": "el paquete leyó secretos de AWS (acceso confirmado)"})
    elif any(a.get("evidence", {}).get("usual_src") for a in alertas):
        adj.append({"delta": 1, "reason": "proveedor conectado desde un origen que no es el suyo"})
    elif any(a.get("evidence", {}).get("edr_action") == "detected_only" for a in alertas):
        adj.append({"delta": 1, "reason": "ejecución confirmada (el EDR solo detectó)"})
    acciones = _acciones(alertas, E) if verdict == "true_positive" else []
    servicios = list({(db.asset(h) or {}).get("business_service") for h in E["hosts"]} - {None, ""})
    resumen = (f"{len(alertas)} alerta(s) entre {alertas[0]['created_at'][:16]} y {alertas[-1]['created_at'][:16]} UTC "
               f"({', '.join(sorted({a['rule_name'] for a in alertas}))[:220]}). "
               f"He comprobado activos, usuarios, inteligencia y el calendario de cambios: no hay ningún cambio aprobado que lo explique. "
               f"Cito {len(evid)} eventos de los logs como prueba.") if verdict == "true_positive" else \
              "La alerta coincide con un viaje registrado en RRHH y un dispositivo corporativo conocido: actividad legítima."
    ticket = {"title": _titulo(alertas), "verdict": verdict, "confidence": 0.9 if escudo else 0.8, "summary": resumen,
              "severity_adjustments": adj,
              "affected": {"users": E["users"], "hosts": E["hosts"], "business_services": servicios, "customers": E["customers"]},
              "evidence": evid,
              "enrichment": [{"indicator": i, "type": "ip", "source": "ti_feed + geoip",
                              "result": str((db.intel(i).get("tip") or {}).get("reputation", "sin coincidencias"))} for i in E["ips"][:3]],
              "mitre": sorted({a["mitre"]["technique_id"] for a in alertas}), "recommended_actions": acciones,
              "escalation": {"escalate": verdict == "true_positive", "to": "N2", "reason": ""},
              "manipulation_detected": {"detected": bool(escudo), "where": "; ".join(f"{x['tipo']}: {x['fragmento'][:90]}" for x in escudo[:2])},
              "open_questions": ["Ticket generado en modo demo (sin LLM): revisar el razonamiento con Claude antes de actuar."]}
    return _resp(_text("[modo demo] Tengo suficiente: entrego el ticket."), _tool("submit_ticket", ticket))

def _resumen_evento(ev):
    claves = ("event_type", "eventName", "operation", "action", "process_name", "command_line", "url", "query", "destination", "file_name", "result", "src_ip")
    return " · ".join(f"{k}={str(ev[k])[:70]}" for k in claves if ev.get(k))[:220] or ev["source"]

def _acciones(alertas, E):
    out, reglas = [], {a["rule_id"] for a in alertas}
    for h in E["hosts"][:2]:
        a = db.asset(h) or {}
        if a.get("zone") == "LOGISTICS-OT":
            out.append({"action": "escalar_operaciones", "target": h, "requires_approval": True, "justification": "OT: el SOC nunca actúa, solo escala"})
        elif any(r.startswith(("UC-EDR", "UC-NET")) for r in reglas):
            req = aprobacion("isolate_host", h, a)["requiere"]
            out.append({"action": "isolate_host", "target": h, "requires_approval": bool(req), "justification": f"Contener el equipo ({', '.join(req) or 'N1'})"})
    for u in E["users"][:2]:
        if any(r.startswith(("UC-IDP", "UC-EML-003", "UC-EML-004", "UC-VPN")) for r in reglas):
            out.append({"action": "revoke_sessions", "target": u, "requires_approval": True, "justification": "Cortar la sesión del atacante"})
            out.append({"action": "reset_password", "target": u, "requires_approval": True, "justification": "Credenciales expuestas"})
    for a in alertas:
        ev, c = a.get("evidence", {}), a.get("entities", {}).get("cloud", {})
        if a["rule_id"].startswith("UC-EML") and ev.get("message_id") and len(out) < 6:
            out.append({"action": "purge_email", "target": ev["message_id"], "requires_approval": False, "justification": "Retirar el correo de todos los buzones"})
        for k in ("access_key", "new_user"):
            if c.get(k):
                out.append({"action": "disable_access_key", "target": c[k], "requires_approval": True, "justification": "Clave o identidad cloud usada por el atacante"})
    for i in E["ips"][:2]:
        tip = db.intel(i).get("tip") or {}
        if tip.get("reputation") == "malicious":
            out.append({"action": "block_ioc", "target": i, "requires_approval": False, "justification": f"IOC malicioso en el TIP ({tip.get('malware_family') or 'sin familia'})"})
    if any(r.startswith(("UC-DLP", "UC-CLD-004", "UC-NET-006")) for r in reglas):
        out.append({"action": "escalar_dpo", "target": "DPO", "requires_approval": True, "justification": "Posible brecha de datos personales: plazo de 72 h (AEPD/CNPD)"})
    uniq = {(x["action"], x["target"]): x for x in out}
    return list(uniq.values())[:7]

def _fiscal(messages):
    txt = messages[0]["content"]
    dudoso = '"confidence": 0.' in txt and re.search(r'"confidence": 0\.[0-5]', txt)
    rev = {"agrees": not dudoso, "objections": ["La confianza es baja: faltan pruebas directas"] if dudoso else [],
           "alternative_verdict": "needs_more_info" if dudoso else "none",
           "comment": "[modo demo] He buscado cambios aprobados, viajes y reglas de la casa que lo expliquen y no he encontrado ninguno."}
    return _resp(_tool("submit_review", rev))

def _n2(messages):
    d = _datos(messages)
    if _turno(messages) == 0:
        return _resp(_text("[modo demo] Reconstruyo la línea de tiempo con las pruebas de los tickets y la caza."))
    tks, cazas = d["tickets"], d.get("caza", [])
    pasos = []
    for t in tks:
        for e in t.get("evidence", []):
            ev = db.get_event(e["event_id"])
            if ev:
                pasos.append({"timestamp": ev["timestamp"], "event_id": e["event_id"], "description": e["finding"][:160], "mitre": (t.get("mitre") or [""])[0]})
    for c in cazas:
        for eid in c["event_ids"][:3]:
            ev = db.get_event(eid)
            if ev:
                pasos.append({"timestamp": ev["timestamp"], "event_id": eid, "description": f"[caza] {c['titulo']}", "mitre": ""})
    pasos = sorted({p["event_id"]: p for p in pasos}.values(), key=lambda p: p["timestamp"])
    t = tks[0]
    af = t.get("affected") or {}
    plan = []
    for a in (t.get("recommended_actions") or []):
        ap = aprobacion(a["action"], a["target"], db.asset(a["target"]))
        plan.append({"action": a["action"], "target": a["target"], "approver": " + ".join(ap["requiere"]) or "N1",
                     "business_impact": ap["nota"] or "Bajo"})
    reglas = " ".join(t.get("mitre") or [])
    notif = ["Responsable del SOC y CISO (severidad alta o crítica)"]
    texto = json.dumps(d, ensure_ascii=False).lower()
    if any(k in texto for k in ("dlp", "crm", "customer", "shipments", "uc-net-006", "backup")):
        notif.append("DPO: posible brecha de datos personales, notificación a AEPD/CNPD en 72 h")
    if "pos-" in texto or "tpv" in texto:
        notif.append("Adquirente de tarjetas y responsable PCI DSS")
    if "logisoft" in texto:
        notif.append("Proveedor Logisoft: credenciales comprometidas")
    if "iban" in texto:
        notif.append("Tesorería: retener pagos al nuevo IBAN")
    rep = {"title": t["title"], "patient_zero": ", ".join((af.get("users") or [])[:1] + (af.get("hosts") or [])[:1]) or "por determinar",
           "initial_access": pasos[0]["description"] if pasos else "por determinar", "timeline": pasos,
           "scope": {"users": af.get("users", []), "hosts": af.get("hosts", []), "data": "Ver pruebas DLP/CRM" if len(notif) > 1 else "",
                     "business_impact": ", ".join(af.get("business_services", [])) or "por determinar"},
           "root_cause": "[modo demo] A confirmar por el N2 con la línea de tiempo.", "containment_plan": plan,
           "eradication_and_recovery": ["Reinstalar o limpiar los equipos afectados", "Rotar credenciales expuestas", "Vigilar 72 h las entidades implicadas"],
           "notifications": notif,
           "detection_gaps": [f"{c['titulo']}: no generó alerta; crear regla" for c in cazas] or ["Revisar si alguna fase del ataque no generó alerta"],
           "confidence": 0.7, "open_questions": ["Informe generado en modo demo: validar con Claude"]}
    return _resp(_tool("submit_report", rep))

def _chat(messages):
    q = messages[0]["content"]
    if _turno(messages) == 0:
        m = re.search(r"([a-z]+\.[a-z0-9]+(?:@tarvia\.example)?|[A-Za-z]{2,}-[A-Za-z0-9-]+|\d+\.\d+\.\d+\.\d+)", q)
        clave = m.group(1) if m else None
        if not clave:                                   # "marta puig" -> busca el usuario marta.puig
            pal = re.findall(r"[a-záéíóúñü0-9]+", q.lower())
            clave = next((f"{a}.{b}" for a, b in zip(pal, pal[1:]) if db.user(f"{a}.{b}")), None)
        if clave:
            clave = clave.upper() if "-" in clave else clave
            al = db.alerts_for_entity(clave, 200)
            al = [a for a in al if int(re.sub(r"\D", "", a["alert_id"][-6:]) or 0) >= 11785] or al   # la alerta más relevante
            args = {"value": clave, "horas": 12}
            if al:
                args["around"] = al[0]["created_at"]
            return _resp(_text(f"[modo demo] Busco la actividad de {clave} alrededor de su alerta más relevante."),
                         _tool("events_for_entity", args))
        return _resp(_tool("search_logs", {"text": max(re.findall(r"\w+", q), key=len)}))
    try:
        res = json.loads(messages[-1]["content"][0]["content"])
    except (ValueError, KeyError, IndexError, TypeError):
        res = []
    if not res:
        return _resp(_text("[modo demo] No he encontrado eventos para esa consulta."))
    raros = [e for e in res if e["source"] in ("edr_events", "idp_audit", "dlp", "sql_audit", "ad_events", "email_clicks", "cloudtrail", "vpn")
             and not any(f in str(e.get("signer", "")) for f in ("Microsoft", "Google", "Mozilla", "Adobe", "SAP"))]
    elegidos = (raros + [e for e in res if e not in raros])[:8]
    elegidos.sort(key=lambda e: e.get("timestamp", ""))
    lineas = [f"- {e.get('timestamp', '')[:16]} · {e['source']} · {e.get('event_id')}: {_resumen_evento(e)[:120]}" for e in elegidos]
    return _resp(_text(f"[modo demo] He encontrado {len(res)} eventos. Los más relevantes:\n" + "\n".join(lineas)))

class _Messages:
    def create(self, **kw):
        names = {t["name"] for t in kw.get("tools", [])}
        if "submit_ticket" in names: return _n1(kw["messages"])
        if "submit_review" in names: return _fiscal(kw["messages"])
        if "submit_report" in names: return _n2(kw["messages"])
        return _chat(kw["messages"])

class MockClient:
    messages = _Messages()
