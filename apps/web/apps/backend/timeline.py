"""Línea de tiempo enriquecida de un caso: alertas, eventos relacionados, informe N2 y caza, en lenguaje claro."""
import json, re
from apps.backend.tools import db
from apps.backend.rules.engine import madrid, fuera_de_horario

# Fases de la cadena de ataque (MITRE ATT&CK) en el orden en que se cuentan
FASES = ["Acceso inicial", "Ejecución", "Persistencia", "Robo de credenciales", "Descubrimiento",
         "Movimiento lateral", "Recogida de datos", "Mando y control", "Exfiltración", "Impacto"]
TACTICA = {"Initial Access": "Acceso inicial", "Execution": "Ejecución", "Persistence": "Persistencia",
           "Privilege Escalation": "Persistencia", "Defense Evasion": "Persistencia", "Credential Access": "Robo de credenciales",
           "Discovery": "Descubrimiento", "Lateral Movement": "Movimiento lateral", "Collection": "Recogida de datos",
           "Command and Control": "Mando y control", "Exfiltration": "Exfiltración", "Impact": "Impacto"}
FUENTE = {"email": ("Correo", "✉"), "email_clicks": ("Clic en correo", "🖱"), "idp_signins": ("Inicio de sesión", "🔑"),
          "idp_audit": ("Cuenta y buzón", "👤"), "edr_events": ("Equipo (EDR)", "💻"), "proxy": ("Navegación", "🌐"),
          "dns": ("DNS", "🧭"), "firewall": ("Cortafuegos", "🧱"), "vpn": ("VPN", "🔒"), "waf": ("WAF tienda", "🛡"),
          "ecom_auth": ("Login de clientes", "🛒"), "ecom_account": ("Cuenta de cliente", "🛒"), "cloudtrail": ("AWS", "☁"),
          "dlp": ("Fuga de datos (DLP)", "📤"), "sql_audit": ("Base de datos", "🗄"), "ai_gateway": ("Asistente Vela", "🤖"),
          "ad_events": ("Directorio activo", "🏢"), "cicd_builds": ("Pipeline CI", "⚙"), "alerta": ("Alerta del SIEM", "🚨")}

def _fase_evento(ev: dict) -> str:
    s, t = ev["source"], json.dumps(ev, ensure_ascii=False).lower()
    if s in ("email", "email_clicks"): return "Acceso inicial"
    if s == "vpn": return "Acceso inicial"
    if s == "idp_signins": return "Acceso inicial"
    if s == "idp_audit": return "Persistencia" if any(k in t for k in ("rule", "consent", "mfa")) else "Recogida de datos"
    if s == "edr_events":
        if "lsass" in t or "comsvcs" in t: return "Robo de credenciales"
        if "vssadmin" in t or "wbadmin" in t: return "Impacto"
        if "psexe" in t: return "Movimiento lateral"
        if any(k in t for k in ("registry_set", "service_install", "crontab")): return "Persistencia"
        if any(k in t for k in ("nltest", "adfind", "net group", "whoami")): return "Descubrimiento"
        if "sqlcmd" in t: return "Recogida de datos"
        return "Ejecución"
    if s in ("dlp", "dns"): return "Exfiltración"
    if s == "cloudtrail": return "Exfiltración" if "getobject" in t else "Persistencia" if any(k in t for k in ("createuser", "attach", "createaccesskey")) else "Descubrimiento"
    if s == "sql_audit": return "Recogida de datos"
    if s == "ad_events": return "Persistencia"
    if s in ("proxy", "firewall"): return "Mando y control"
    if s == "ecom_account": return "Impacto"
    if s == "cicd_builds": return "Acceso inicial"
    return "Ejecución"

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

def _ip_info(ip: str) -> dict | None:
    if not ip or ip.startswith(("10.", "172.16.", "192.168.")):
        return None
    i = db.intel(ip)
    geo, tip = i.get("geo") or {}, i.get("tip") or {}
    tipo = "Tor" if geo.get("is_tor") == "True" else "VPN comercial" if geo.get("is_vpn_provider") == "True" else \
           "Hosting" if geo.get("is_hosting") == "True" else "Proxy residencial" if geo.get("is_residential_proxy") == "True" else ""
    if not geo and not tip:
        return None
    return {"ip": ip, "pais": geo.get("country", ""), "org": geo.get("as_org", ""), "tipo": tipo,
            "reputacion": tip.get("reputation", ""), "familia": tip.get("malware_family", ""), "confianza": tip.get("confidence")}

def _entidades(ev: dict) -> list[dict]:
    out = []
    for k, tipo in (("user", "usuario"), ("user_upn", "usuario"), ("actor_upn", "usuario"), ("hostname", "equipo"), ("customer_id", "cliente")):
        v = ev.get(k)
        if v:
            out.append({"tipo": tipo, "valor": str(v).split("\\")[-1].split("@")[0]})
    for k in ("src_ip", "dst_ip", "sourceIPAddress", "sender_ip"):
        info = _ip_info(ev.get(k, ""))
        if info:
            out.append({"tipo": "ip", "valor": info["ip"], "info": info})
    return out

def _agrupar(pasos: list[dict]) -> list[dict]:
    """Junta eventos seguidos casi iguales (beacon cada minuto, escaneo de puertos) en un solo paso con contador."""
    out = []
    for p in pasos:
        clave = (p["fuente"], p["fase"], re.sub(r"[\d.:]+", "#", p["titulo"])) if not p["hito"] else None
        if out and clave and out[-1].get("_clave") == clave:
            out[-1]["repeticiones"] += 1; out[-1]["hasta"] = p["ts"]
            continue
        p["_clave"], p["repeticiones"], p["hasta"] = clave, 1, p["ts"]
        out.append(p)
    for p in out:
        p.pop("_clave", None)
        if p["repeticiones"] > 1:
            p["detalle"] = f"Se repite {p['repeticiones']} veces hasta las {madrid(p['hasta']).strftime('%H:%M')}"
            if p["fuente"] == "firewall":
                p["titulo"] = re.sub(r" → [\d.]+:\d+ \((\w+)\)", r" → varios equipos y puertos (escaneo)", p["titulo"])
    return out

def construir(ticket: dict, alertas: list[dict], incidente: dict | None, max_pasos: int = 60) -> dict:
    pasos = {}
    for a in alertas:      # cada alerta es un hito
        fase = TACTICA.get(a.get("mitre", {}).get("tactic", ""), "Ejecución")
        ents = [{"tipo": "equipo", "valor": h["hostname"]} for h in a.get("entities", {}).get("hosts", [])] + \
               [{"tipo": "usuario", "valor": u["upn"].split("@")[0]} for u in a.get("entities", {}).get("users", []) if "@" in u.get("upn", "")]
        pasos["A:" + a["alert_id"]] = {"ts": a["created_at"], "id": a["alert_id"], "fuente": "alerta", "fase": fase, "hito": True,
                                      "titulo": f"{a['rule_name']} ({a['rule_id']})", "detalle": a.get("description", ""),
                                      "mitre": a.get("mitre", {}).get("technique_id", ""), "severidad": a["severity"], "entidades": ents}
        for eid in a.get("related_events", []):
            pasos.setdefault(eid, {"_fase": fase})
    for e in (incidente or {}).get("timeline", []) + [{"event_id": x["event_id"]} for x in ticket.get("evidence", [])]:
        pasos.setdefault(e["event_id"], {"_mitre": e.get("mitre", "")})
    for eid in list(pasos):
        if eid.startswith("A:"):
            continue
        ev = db.get_event(eid)
        if not ev:
            del pasos[eid]; continue
        pasos[eid] = {"ts": ev["timestamp"], "id": eid, "fuente": ev["source"], "fase": pasos[eid].get("_fase") or _fase_evento(ev),
                      "hito": False, "titulo": _titulo(ev), "detalle": "", "mitre": pasos[eid].get("_mitre", ""), "entidades": _entidades(ev)}
    lista = _agrupar(sorted(pasos.values(), key=lambda p: p["ts"]))[:max_pasos]
    for p in lista:
        l = madrid(p["ts"])
        p["hora_local"] = l.strftime("%d/%m %H:%M"); p["fuera_de_horario"] = fuera_de_horario(p["ts"])
        p["fuente_nombre"], p["icono"] = FUENTE.get(p["fuente"], (p["fuente"], "•"))
    fases = [{"fase": f, "n": sum(1 for p in lista if p["fase"] == f),
              "primera": next((p["hora_local"] for p in lista if p["fase"] == f), "")} for f in FASES]
    dur = ""
    if len(lista) > 1:
        from datetime import datetime
        d = datetime.fromisoformat(lista[-1]["ts"].replace("Z", "+00:00")) - datetime.fromisoformat(lista[0]["ts"].replace("Z", "+00:00"))
        h = d.total_seconds() / 3600
        dur = f"{int(h * 60)} min" if h < 2 else f"{h:.0f} h" if h < 48 else f"{h / 24:.1f} días"
    return {"pasos": lista, "fases": fases, "duracion": dur,
            "fuera_de_horario": sum(p["fuera_de_horario"] for p in lista), "fuentes": sorted({p["fuente_nombre"] for p in lista})}
