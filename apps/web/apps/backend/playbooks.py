"""Playbooks guiados a partir de los runbooks oficiales: pasos, decisiones y qué ha comprobado ya VIGÍA en cada caso."""
import json, re
from apps.backend.config import DATA

# Qué fuente de datos o herramienta corresponde a cada pista que aparece en el texto del runbook
PISTAS = [(r"`email`|spf|dkim|dmarc|remitente", ["email"], ["get_event"]), (r"email_clicks|clic", ["email_clicks"], []),
          (r"`proxy`|descarga|beaconing|dominio", ["proxy", "dns"], ["get_intel"]), (r"edr_events|árbol de procesos|ejecución|lsass", ["edr_events"], ["get_asset"]),
          (r"idp_signins|inicio de sesión|origen|asn|dispositivo|mfa", ["idp_signins", "vpn"], ["get_intel"]), (r"idp_audit|reglas de buzón|oauth|qué hizo la sesión", ["idp_audit"], []),
          (r"sandbox|hash", [], ["get_sandbox"]), (r"\btip\b|osint|inteligencia|en ti\b", [], ["get_intel"]),
          (r"calendario_cambios|cambio aprobado|cambio|pentest|autorizado|flujo aprobado", [], ["get_changes"]),
          (r"eventos_rrhh|viajes|bajas|usuarios\.csv|usuario|rol|privilegios", [], ["get_user"]),
          (r"vulnerabilidades|vulnerable", [], ["get_cve", "get_asset"]), (r"cloudtrail|accesskeyid|getobject|bucket", ["cloudtrail"], []),
          (r"sql_audit|consultas masivas", ["sql_audit"], []), (r"ai_gateway|session_id|prompt|asistente", ["ai_gateway"], []),
          (r"dlp|datos|destino", ["dlp"], []), (r"firewall|puertos|modbus|escaneo", ["firewall"], []), (r"registry_set|persistencia", ["edr_events"], []),
          (r"cicd|build|paquete|registro", ["cicd_builds"], []), (r"`waf`|waf", ["waf"], [])]
HERR = {"get_intel": "la inteligencia (TIP y GeoIP)", "get_changes": "el calendario de cambios", "get_user": "el directorio y RRHH",
        "get_asset": "la CMDB", "get_sandbox": "la sandbox", "get_cve": "CVE (KEV y EPSS)", "get_event": "los logs"}
ICONOS = {"RB-01": "✉", "RB-02": "💻", "RB-03": "🔑", "RB-04": "📤", "RB-05": "🛒", "RB-06": "☁", "RB-07": "🤖", "RB-08": "🏭", "RB-09": "🌐", "RB-10": "📦"}

def _limpio(t):
    return re.sub(r"\*\*|`", "", t).strip()

def cargar() -> list[dict]:
    out = []
    for p in sorted((DATA / "01_contexto/runbooks").glob("RB-*.md")):
        txt = p.read_text(encoding="utf-8")
        titulo = txt.splitlines()[0].lstrip("# ").split(" ", 1)[1]
        reglas = re.findall(r"UC-[A-Z]+-\d+", txt.split("## Comprobaciones")[0])
        comp = txt.split("## Comprobaciones")[1].split("## Decisión")[0]
        pasos = []
        for n, linea in re.findall(r"^(\d+)\.\s+(.*)$", comp, re.M):
            fuentes, herr = set(), set()
            for pat, fs, hs in PISTAS:
                if re.search(pat, linea, re.I):
                    fuentes |= set(fs); herr |= set(hs)
            nombre, _, resto = _limpio(linea).partition(":")
            if len(nombre) > 45 and "." in nombre:          # "Hashes en sandbox y TIP. Un binario..." -> título corto
                nombre, _, extra = nombre.partition(".")
                resto = (extra.strip() + " " + resto).strip()
            texto = _limpio(resto or linea)
            texto = texto[:1].upper() + texto[1:]
            pasos.append({"n": int(n), "titulo": nombre if resto else _limpio(linea)[:60], "texto": texto,
                          "fuentes": sorted(fuentes), "herramientas": sorted(herr)})
        decisiones = []
        for linea in re.findall(r"^- (.*)$", txt.split("## Decisión")[1], re.M):
            cond, _, acc = _limpio(linea).partition("→")
            sev = re.findall(r"\((informational|low|medium|high|critical)(?:/(\w+))?\)", acc)
            sevs = [s for par in sev for s in par if s]
            fuerte = re.search(r"escal|aislar|revocar|desactivar|dpo|rotar|retener|deshabilitar", acc, re.I)
            color = "rojo" if any(x in ("high", "critical") for x in sevs) or fuerte else \
                    "verde" if "cerrar" in acc.lower() else "ambar"
            decisiones.append({"condicion": cond.strip(), "accion": acc.strip(), "severidades": sevs, "color": color})
        rb = p.stem
        out.append({"id": rb, "titulo": titulo, "icono": ICONOS.get(rb, "📘"), "reglas": reglas, "pasos": pasos, "decisiones": decisiones})
    return out

def aplicar(rb: dict, ticket: dict, timeline: dict | None) -> dict:
    """Marca cada paso como comprobado por VIGÍA (con su prueba) o pendiente, y elige la rama de decisión."""
    herr_usadas = {p.get("nombre") for p in ticket.get("trace", []) if p.get("tipo") == "herramienta"}
    fuentes_vistas = {}
    for p in (timeline or {}).get("pasos", []):
        if not p.get("hito"):
            fuentes_vistas.setdefault(p["fuente"], {"event_id": p["id"], "finding": p["titulo"]})
    for e in ticket.get("evidence", []):
        fuentes_vistas.setdefault(e["source"], e)
    pasos = []
    for s in rb["pasos"]:
        pruebas = [fuentes_vistas[f] for f in s["fuentes"] if f in fuentes_vistas]
        usadas = sorted(set(s["herramientas"]) & herr_usadas)
        estado = "hecho" if (pruebas or usadas) else "pendiente"
        hallazgo = (pruebas[0].get("finding", "") if pruebas else "Consultado en " + " y ".join(HERR[u] for u in usadas) if usadas else "")
        pasos.append({**s, "estado": estado, "hallazgo": str(hallazgo)[:160], "prueba": pruebas[0].get("event_id") if pruebas else ""})
    sev, ver = ticket.get("severity"), ticket.get("verdict")
    texto_caso = json.dumps(ticket.get("alertas", []), ensure_ascii=False).lower()
    # Ramas que solo aplican a un tipo concreto de caso: se descartan si el caso no lo tiene y se priorizan si lo tiene
    ESPECIFICAS = [("iban", "uc-eml-004"), ("shadow", "uc-edr-007"), ("lsass", "uc-edr-004"), ("cuenta de servicio", '"account_type": "service"'),
                   ("web shell", "uc-edr-009"), ("stuffing", "uc-web-002"), ("fuga de datos de clientes", "uc-ai-002"), ("pentest", "192.0.2.")]
    def aplica(d):
        c = d["condicion"].lower()
        return all(marca in texto_caso for kw, marca in ESPECIFICAS if kw in c)
    def especifica(d):
        c = d["condicion"].lower()
        return any(kw in c and marca in texto_caso for kw, marca in ESPECIFICAS)
    validas = [i for i, d in enumerate(rb["decisiones"]) if aplica(d)] or list(range(len(rb["decisiones"])))
    elegida = None
    if ver == "true_positive" and any(especifica(rb["decisiones"][i]) for i in validas):
        elegida = [i for i in validas if especifica(rb["decisiones"][i])][-1]      # la más grave (van en orden)
    elif ver in ("false_positive", "benign_true_positive"):
        elegida = next((i for i, d in enumerate(rb["decisiones"]) if d["color"] == "verde"), 0)
    else:
        candidatas = [i for i in validas if sev in rb["decisiones"][i]["severidades"]]
        rojas = [i for i in validas if rb["decisiones"][i]["color"] == "rojo"]
        elegida = candidatas[-1] if candidatas else (rojas[0] if rojas and sev in ("high", "critical") else
                  next((i for i, d in enumerate(rb["decisiones"]) if d["color"] == "ambar"), len(rb["decisiones"]) - 1))
    hechos = sum(p["estado"] == "hecho" for p in pasos)
    return {**rb, "pasos": pasos, "elegida": elegida, "hechos": hechos, "total": len(pasos)}
