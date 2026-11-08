"""Línea de tiempo enriquecida de un caso: alertas, eventos relacionados, informe N2 y caza, en lenguaje claro."""
import re
from datetime import datetime, timezone
from apps.backend.rules.engine import madrid, fuera_de_horario

# Fases de la cadena de ataque (MITRE ATT&CK) en el orden en que se cuentan
FASES = ["Acceso inicial", "Ejecución", "Persistencia", "Robo de credenciales", "Descubrimiento",
         "Movimiento lateral", "Recogida de datos", "Mando y control", "Exfiltración", "Deterioro de defensas", "Impacto"]
TACTICA = {"Initial Access": "Acceso inicial", "Execution": "Ejecución", "Persistence": "Persistencia",
           "Privilege Escalation": "Escalada de privilegios", "Defense Evasion": "Evasión de defensas",
           "Defense Impairment": "Deterioro de defensas", "Credential Access": "Robo de credenciales",
           "Discovery": "Descubrimiento", "Lateral Movement": "Movimiento lateral", "Collection": "Recogida de datos",
           "Command and Control": "Mando y control", "Exfiltration": "Exfiltración", "Impact": "Impacto"}
FUENTE = {"email": ("Correo", "✉"), "email_clicks": ("Clic en correo", "🖱"), "idp_signins": ("Inicio de sesión", "🔑"),
          "idp_audit": ("Cuenta y buzón", "👤"), "edr_events": ("Equipo (EDR)", "💻"), "proxy": ("Navegación", "🌐"),
          "dns": ("DNS", "🧭"), "firewall": ("Cortafuegos", "🧱"), "vpn": ("VPN", "🔒"), "waf": ("WAF tienda", "🛡"),
          "ecom_auth": ("Login de clientes", "🛒"), "ecom_account": ("Cuenta de cliente", "🛒"), "cloudtrail": ("AWS", "☁"),
          "dlp": ("Fuga de datos (DLP)", "📤"), "sql_audit": ("Base de datos", "🗄"), "ai_gateway": ("Asistente Vela", "🤖"),
          "ad_events": ("Directorio activo", "🏢"), "cicd_builds": ("Pipeline CI", "⚙"), "alerta": ("Alerta del SIEM", "🚨")}

FASES_N2 = {
    "Correo de entrada": "Acceso inicial", "Comunicación periódica": "Mando y control",
    "Reconocimiento": "Descubrimiento",
    "Acceso a credenciales": "Robo de credenciales", "Inhibición de recuperación": "Impacto",
    "Privilegios persistentes": "Persistencia", "Defensa desactivada": "Deterioro de defensas",
}


def _titulo(ev: dict) -> str:
    """Una frase que se entiende sin saber leer logs."""
    s, g = ev["source"], ev.get
    if s == "email":
        return f"Llega un correo de {g('sender', '?')}: '{str(g('subject', ''))[:70]}' ({g('verdict', '')}, SPF {g('spf', '?')})"
    if s == "email_clicks": return f"{g('user', 'Alguien')} hace clic en {str(g('url', ''))[:70]}"
    if s == "idp_signins":
        ok = "correcto" if g("result") == "success" else "fallido"
        return f"Inicio de sesión {ok} de {g('user_upn', '?').split('@')[0]} desde {g('src_ip', '?')} ({g('city') or g('country') or '?'})"
    if s == "idp_audit": return f"{g('actor_upn', '?').split('@')[0]}: {g('operation', '?')} {('sobre ' + str(g('target'))[:40]) if g('target') else ''}"
    if s == "edr_events":
        cmd = str(g("command_line") or "")[:90]
        return f"{g('hostname', '?')}: {g('event_type', '').replace('_', ' ')} de {g('process_name', '?')}" + (f" · {cmd}" if cmd and cmd != g('process_name') else "")
    if s == "proxy": return f"{g('hostname') or g('src_ip')}: navega a {str(g('url') or g('domain'))[:80]} ({g('action', '')})"
    if s == "dns": return f"{g('hostname') or g('src_ip')}: consulta DNS {str(g('query'))[:70]}"
    if s == "firewall": return f"Conexión {g('src_ip')} → {g('dst_ip')}:{g('dst_port')} ({g('action')})"
    if s == "vpn": return f"VPN: {g('user')} {g('action')} desde {g('src_ip')} ({g('country', '?')})"
    if s == "cloudtrail":
        ui = g("userIdentity") or {}
        quien = ui.get("userName") or ui.get("arn", "?") if isinstance(ui, dict) else ui
        return f"AWS: {g('eventName')} por {quien} desde {g('sourceIPAddress')}"
    if s == "dlp": return f"DLP: {g('user')} sube {g('file_name')} a {g('destination')} ({round(int(g('file_size') or 0) / 1e6)} MB)"
    if s == "sql_audit": return f"Base de datos: {g('user')} lanza {g('statement_type')} sobre {g('object')} ({g('rows_returned')} filas)"
    if s == "ad_events": return f"Directorio activo: {g('event')} · {g('subject')} → {g('target')}"
    if s == "ai_gateway": return f"Vela: '{str(g('prompt'))[:90]}'"
    if s == "ecom_account": return f"Cliente {g('customer_id')}: {g('event')}"
    if s == "ecom_auth": return f"Login cliente {g('customer_id')} {g('result')} desde {g('src_ip')}"
    if s == "cicd_builds": return f"CI {g('pipeline')} · {g('step')} ({g('status')})"
    return ev.get("event_id", "")

def _ip_info(ip: str, database) -> dict | None:
    if not ip or ip.startswith(("10.", "172.16.", "192.168.")):
        return None
    i = database.intel(ip)
    geo, tip = i.get("geo") or {}, i.get("tip") or {}
    tipo = "Tor" if geo.get("is_tor") == "True" else "VPN comercial" if geo.get("is_vpn_provider") == "True" else \
           "Hosting" if geo.get("is_hosting") == "True" else "Proxy residencial" if geo.get("is_residential_proxy") == "True" else ""
    if not geo and not tip:
        return None
    return {"ip": ip, "pais": geo.get("country", ""), "org": geo.get("as_org", ""), "tipo": tipo,
            "reputacion": tip.get("reputation", ""), "familia": tip.get("malware_family", ""), "confianza": tip.get("confidence")}

def _entidades(ev: dict, database) -> list[dict]:
    out = []
    for k, tipo in (("user", "usuario"), ("user_upn", "usuario"), ("actor_upn", "usuario"), ("hostname", "equipo"), ("customer_id", "cliente")):
        v = ev.get(k)
        if v:
            out.append({"tipo": tipo, "valor": str(v).split("\\")[-1].split("@")[0]})
    for k in ("src_ip", "dst_ip", "sourceIPAddress", "sender_ip"):
        info = _ip_info(ev.get(k, ""), database)
        if info:
            out.append({"tipo": "ip", "valor": info["ip"], "info": info})
    return out

def _agrupar(pasos: list[dict]) -> list[dict]:
    """Junta eventos seguidos casi iguales (beacon cada minuto, escaneo de puertos) en un solo paso con contador."""
    out = []
    for p in pasos:
        clave = (p["fuente"], p["fase"], re.sub(r"[\d.:]+", "#", p["titulo"])) if p["fase"] == "Contexto" else None
        if out and clave and out[-1].get("_clave") == clave:
            out[-1]["repeticiones"] += 1; out[-1]["hasta"] = p["ts"]
            continue
        p["_clave"], p["repeticiones"], p["hasta"] = clave, 1, p["ts"]
        out.append(p)
    for p in out:
        p.pop("_clave", None)
        if p["repeticiones"] > 1:
            p["detalle"] = f"Se repite {p['repeticiones']} veces hasta las {madrid(_instant(p['hasta']).isoformat()).strftime('%H:%M')}"
    return out


def _instant(value: str) -> datetime:
    stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return stamp if stamp.utcoffset() is not None else stamp.replace(tzinfo=timezone.utc)


def construir(ticket: dict, alertas: list[dict], incidente: dict | None, max_pasos: int = 60, *, database=None) -> dict:
    if database is None:
        from apps.backend.tools import db as database
    pasos = {}
    evidence = {row["event_id"]: row for row in ticket.get("evidence", [])}
    local = set((ticket.get("criterio_verificado") or {}).get("citations", []))
    n2 = {}
    for finding in (incidente or {}).get("timeline", []):
        ids = [finding["event_id"], *finding.get("evidence_ids", [])]
        for event_id in dict.fromkeys(ids):
            n2.setdefault(event_id, finding)

    event_ids = dict.fromkeys((*evidence, *n2))
    for alert in alertas:
        technique = alert.get("mitre") or {}
        entities = alert.get("entities") or {}
        ents = [{"tipo": "equipo", "valor": host["hostname"]} for host in entities.get("hosts", []) if host.get("hostname")]
        ents += [{"tipo": "usuario", "valor": user["upn"].split("@")[0]}
                 for user in entities.get("users", []) if user.get("upn")]
        pasos["A:" + alert["alert_id"]] = {
            "ts": alert["created_at"], "id": alert["alert_id"], "fuente": "alerta",
            "fase": "Alerta SIEM", "hito": True, "tactica_declarada": TACTICA.get(technique.get("tactic", ""), ""),
            "titulo": f"{alert['rule_name']} ({alert['rule_id']})", "detalle": alert.get("description", ""),
            "mitre": technique.get("technique_id", ""), "severidad": alert["severity"], "entidades": ents,
        }
        event_ids.update(dict.fromkeys(alert.get("related_events", [])))

    # A data source or a model citation alone cannot establish an attack phase.
    for event_id in event_ids:
        event = database.get_event(event_id)
        if not event:
            continue
        finding = n2.get(event_id, {})
        stage = finding.get("stage", "")
        if stage in FASES or stage in FASES_N2:
            phase = FASES_N2.get(stage, stage)
        elif finding or event_id in local or evidence.get(event_id, {}).get("verified"):
            phase = "Hallazgo"
        else:
            phase = "Contexto"
        main_event = finding.get("event_id") == event_id
        pasos[event_id] = {
            "ts": event["timestamp"], "id": event_id, "fuente": event["source"], "fase": phase,
            "hito": False, "titulo": _titulo(event),
            "detalle": (finding.get("finding") or finding.get("description", "")) if main_event else "",
            "mitre": finding.get("mitre", "") if main_event else "", "entidades": _entidades(event, database),
        }
    def by_time(step):
        return _instant(step["ts"])

    ordered = _agrupar(sorted(pasos.values(), key=by_time))
    highlights = [step for step in ordered if step["fase"] != "Contexto"][:max_pasos]
    context = [step for step in ordered if step["fase"] == "Contexto"][:max_pasos - len(highlights)]
    lista = sorted(highlights + context, key=by_time)
    for p in lista:
        stamp = _instant(p["ts"]).isoformat()
        l = madrid(stamp)
        p["hora_local"] = l.strftime("%d/%m %H:%M"); p["fuera_de_horario"] = fuera_de_horario(stamp)
        p["fuente_nombre"], p["icono"] = FUENTE.get(p["fuente"], (p["fuente"], "•"))
    fases = [{"fase": f, "n": sum(1 for p in lista if p["fase"] == f),
              "primera": next((p["hora_local"] for p in lista if p["fase"] == f), "")} for f in FASES]
    dur = ""
    if len(lista) > 1:
        d = _instant(lista[-1]["ts"]) - _instant(lista[0]["ts"])
        h = d.total_seconds() / 3600
        dur = f"{int(h * 60)} min" if h < 2 else f"{h:.0f} h" if h < 48 else f"{h / 24:.1f} días"
    return {"pasos": lista, "fases": fases, "duracion": dur,
            "fuera_de_horario": sum(p["fuera_de_horario"] for p in lista), "fuentes": sorted({p["fuente_nombre"] for p in lista})}
