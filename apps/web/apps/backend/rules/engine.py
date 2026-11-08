"""Motor de reglas de VIGÍA: cierra lo que se puede cerrar con una regla y calcula la severidad."""
import csv, json, ipaddress, re
from datetime import datetime, timedelta, timezone
from pathlib import Path

LEVELS = ["informational", "low", "medium", "high", "critical"]
CRIT = ["Baja", "Media", "Alta", "Crítica"]
# politica_soc.md, apartado 2: MATRIZ[severidad_regla][criticidad] -> severidad final
MATRIZ = {
    "informational": ["informational", "informational", "low", "low"],
    "low":           ["informational", "low", "low", "medium"],
    "medium":        ["low", "medium", "medium", "high"],
    "high":          ["medium", "high", "high", "critical"],
    "critical":      ["high", "critical", "critical", "critical"],
}

def madrid(ts: str) -> datetime:
    """UTC -> hora local de Madrid (CEST hasta el 25/10/2026 01:00 UTC, CET después)."""
    u = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    off = 2 if u < datetime(2026, 10, 25, 1, tzinfo=timezone.utc) else 1
    return (u + timedelta(hours=off)).replace(tzinfo=None)

def fuera_de_horario(ts: str) -> bool:
    l = madrid(ts)
    return l.weekday() >= 5 or l.hour < 8 or l.hour >= 20

class Contexto:
    def __init__(self, data: Path):
        rd = lambda p: list(csv.DictReader(open(data / p, encoding="utf-8")))
        self.assets = {a["hostname"].lower(): a for a in rd("02_inventario/activos.csv")}
        self.assets_ip = {a["ip"]: a for a in self.assets.values()}
        self.users = {u["username"].lower(): u for u in rd("02_inventario/usuarios.csv")}
        self.changes = rd("02_inventario/calendario_cambios.csv")
        self.hr = rd("02_inventario/eventos_rrhh.csv")
        # Correo: veredicto de la pasarela por message_id y dominios en los que alguien hizo clic
        self.email = {}
        for l in open(data / "04_logs/email.jsonl", encoding="utf-8"):
            e = json.loads(l); self.email[e["message_id"]] = e
        self.dominios_clic = set()
        for l in open(data / "04_logs/email_clicks.jsonl", encoding="utf-8"):
            u = json.loads(l)["url"]; self.dominios_clic.add(u.split("/")[2].lower() if "//" in u else u.lower())
        self.sandbox = {s["sha256"]: s for s in map(json.loads, open(data / "05_inteligencia/sandbox_informes.jsonl", encoding="utf-8"))}

    def cambio(self, cid):
        return next((c for c in self.changes if c["id"] == cid), None)

    def en_ventana(self, cid, ts):
        c = self.cambio(cid)
        if not c: return False
        l = madrid(ts)
        return datetime.fromisoformat(c["inicio"]) <= l <= datetime.fromisoformat(c["fin"])

    def criticidad(self, alerta) -> tuple[int, str]:
        """Criticidad (0-3) del activo o identidad más crítica de la alerta, y de quién es."""
        E, best = alerta.get("entities", {}), (-1, "")
        def sube(n, why):
            nonlocal best
            if n > best[0]: best = (n, why)
        for h in E.get("hosts", []):
            a = self.assets.get(h.get("hostname", "").lower()) or self.assets_ip.get(h.get("ip", ""))
            if a: sube(CRIT.index(a["criticality"]), f"{a['hostname']} ({a['criticality']})")
        urls = " ".join(E.get("urls", []))
        if "tarvia.example" in urls or E.get("customers"):
            sube(3, "tienda online (Crítica)")
        if E.get("cloud"):
            sube(3, "AWS tarvia-prod (Crítica)")
        return best if best[0] >= 0 else (1, "activo sin ficha en la CMDB (Media por defecto)")

    def ajustes(self, alerta) -> list[tuple[int, str]]:
        E, ev, out = alerta.get("entities", {}), alerta.get("evidence", {}), []
        for u in E.get("users", []):
            usr = self.users.get(u.get("upn", "").split("@")[0].lower())
            if usr and (usr["vip"] == "True" or usr["privileged"] == "True"):
                out.append((+1, f"identidad VIP o privilegiada: {usr['username']}")); break
        accion = str(ev.get("action", ev.get("edr_action", ""))).lower()
        if accion in ("blocked", "quarantined") and not ev.get("executed"):
            out.append((-1, f"bloqueado por el control ({accion}) sin efecto"))
        return out

def severidad(ctx: Contexto, alerta, verdict: str, extra=()) -> tuple[str, str]:
    """extra = ajustes que propone el agente, p. ej. [(+1, "pagos implicados")]. El total sigue limitado a ±1."""
    if verdict in ("benign_true_positive", "false_positive"):
        return "informational", "Actividad autorizada o falsa alarma: informational."
    n, quien = ctx.criticidad(alerta)
    base = MATRIZ[alerta["severity"]][n]
    adj = ctx.ajustes(alerta) + [(int(a), str(w)) for a, w in extra if int(a) in (-1, 1)]
    total = max(-1, min(1, sum(a for a, _ in adj)))          # máximo un nivel arriba o abajo
    final = LEVELS[max(0, min(4, LEVELS.index(base) + total))]
    txt = f"Regla {alerta['severity']} sobre {quien} = {base}"
    for a, why in adj: txt += f"; {'+' if a > 0 else '−'}1 por {why}"
    return final, txt + f". Final: {final}."

PENTEST = [ipaddress.ip_address(f"192.0.2.{i}") for i in (10, 11, 12)]
DOMINIOS_CORP = ("microsoft.com", "googleapis.com", "bmc-agent.example", "tarvia-printers.example")
DNS_SEGUROS = ("mcafee.com", "spamhaus.org", "e5.sk", "sophosxl.net")
CDNS = ("execute-api.eu-west-1.amazonaws.com", "blob.core.windows.net", "akamaized.net", "azureedge.net", "cloudfront.net", "r.cdn77.example")
PAQUETES_CONOCIDOS = ("puppeteer@", "sharp@", "esbuild@")

def decidir(ctx: Contexto, a) -> dict | None:
    """Devuelve una decisión de cierre o None (= pasa al agente). Nunca cierra un true_positive dudoso."""
    r, E, ev, ts = a["rule_id"], a.get("entities", {}), a.get("evidence", {}), a["created_at"]
    ips = [ipaddress.ip_address(i) for i in E.get("ips", []) if re.match(r"^\d+\.\d+\.\d+\.\d+$", i)]
    hosts = [h.get("hostname", "") for h in E.get("hosts", [])]
    def btp(regla, motivo): return {"verdict": "benign_true_positive", "rule": regla, "reason": motivo}
    def fp(regla, motivo):  return {"verdict": "false_positive", "rule": regla, "reason": motivo}
    def tpc(regla, motivo): return {"verdict": "true_positive", "rule": regla, "reason": motivo, "closed": True}

    if r == "UC-WEB-001":
        if any(i in PENTEST for i in ips) and ctx.en_ventana("CHG-2026-1042", ts):
            return btp("pentest", "IP del pentest autorizado CHG-2026-1042 dentro de su ventana")
        if ev.get("action") == "blocked" and "pagebuilder-lite" not in " ".join(E.get("urls", [])):
            return tpc("waf_bloqueado", "Escaneo de Internet bloqueado por el WAF, sin efecto")
    if r == "UC-EML-001" and "body_excerpt" not in ev:
        m = ctx.email.get(ev.get("message_id"), {})
        dom = ev.get("sender", "@").split("@")[1].lower()
        if m.get("verdict") in ("clean", "bulk") and m.get("spf") == m.get("dkim") == "pass":
            return fp("newsletter", f"Correo legítimo de {dom} (SPF y DKIM correctos): el usuario lo reportó por error")
        if m.get("verdict") == "spam" and not any(d.endswith(dom) for d in ctx.dominios_clic):
            return tpc("spam_sin_clic", f"Spam o phishing genérico de {dom} sin ningún clic: purgar y bloquear remitente")
    if r == "UC-NET-005" and ev.get("parent_domain") in CDNS:
        return fp("cdn", f"Subdominio aleatorio de un CDN o nube conocido ({ev.get('parent_domain')})")
    if r == "UC-EDR-002" and "CcmExec" in str(ev.get("parent", "")) and ev.get("user") == "SYSTEM":
        return btp("sccm", "Inventario de SCCM con PowerShell codificado (CHG-2026-1031)")
    if r == "UC-EDR-001" and "saplogon.exe" in str(ev.get("process_tree", "")) and ev.get("signer") == "SAP SE":
        return fp("sap", "Excel abre SAP GUI firmado por SAP SE: uso normal")
    if r == "UC-EDR-003" and ev.get("action") in ("quarantined", "blocked") and ev.get("executed") is False:
        return tpc("edr_bloqueado", "Software no deseado bloqueado antes de ejecutarse")
    if r == "UC-NET-001" and all(d.endswith(DOMINIOS_CORP) for d in E.get("domains", ["?"])):
        return fp("dominio_corporativo", "Comunicación periódica de software corporativo conocido")
    if r == "UC-NET-006" and all(d.endswith(DNS_SEGUROS) for d in E.get("domains", ["?"])):
        return fp("dns_seguridad", "Consultas largas de antivirus o listas DNSBL")
    if r == "UC-NET-003" and "NESSUS01" in hosts and madrid(ts).weekday() == 2 and 1 <= madrid(ts).hour < 5:
        return btp("nessus", "Escáner autorizado NESSUS01 en su ventana de los miércoles")
    if r == "UC-AI-001" and ev.get("action") == "flagged":
        return fp("vela_cliente", "El guardarraíl marcó una corrección normal de un cliente, sin bloqueo")
    if r == "UC-IDP-001" and "conforme" in str(ev.get("device", "")) and not ev.get("post_login_actions"):
        return fp("viaje_dispositivo", "Dispositivo corporativo conocido y conforme")
    if r == "UC-IDP-002" and ev.get("successes") == 0:
        return tpc("spray_sin_exito", "Intentos fallidos sin ningún acceso correcto")
    if r == "UC-WEB-002" and ev.get("success_count") == 0:
        return tpc("stuffing_sin_exito", "Fallos de login sin accesos correctos; rate limit activo")
    if r == "UC-CLD-003" and "terraform" in str(ev.get("source", "")):
        return btp("terraform", "Cambio hecho por el pipeline de terraform del runner CI")
    if r == "UC-DEV-001" and str(ev.get("package", "")).startswith(PAQUETES_CONOCIDOS) and set(ev.get("env_vars_read", [])) <= {"PATH", "HOME"}:
        return fp("paquete_conocido", "Paquete popular que descarga binarios por diseño; no lee secretos")
    if r == "UC-OT-001" and "ENG-WS01" in hosts:
        return btp("ot_autorizado", "ENG-WS01 es uno de los dos orígenes autorizados a OT")
    if r == "UC-OT-001" and "JUMP01" in hosts and ctx.en_ventana("CHG-2026-1063", ts):
        return btp("ot_mantenimiento", "Mantenimiento del fabricante CHG-2026-1063 vía JUMP01")
    if r == "UC-NET-004" and hosts and hosts[0] == "JUMP01" and ctx.en_ventana("CHG-2026-1057", ts):
        return btp("psexec_jump", "PsExec desde JUMP01 dentro del cambio CHG-2026-1057")
    cambio = str(ev.get("maintenance_window", ev.get("change_ticket", "")))
    if cambio.startswith("CHG-") and ctx.en_ventana(cambio, ts):
        return btp("cambio_aprobado", f"Dentro del cambio aprobado {cambio}")
    if r == "UC-DLP-001" and ev.get("personal_data_matches") == 0 and not ev.get("file_encrypted"):
        return fp("dlp_sin_datos", f"Subida a {ev.get('destination')} sin datos personales (material de trabajo)")
    if r == "UC-DLP-002" and ev.get("recipient") == "asesoria@gestoria-pons.example":
        return btp("nominas", "Envío de nóminas a la gestoría: flujo aprobado FLUJO-0007")
    return None
