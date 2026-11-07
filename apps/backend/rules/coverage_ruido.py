"""Cobertura N1 de RB-05 y RB-09, basada en el índice local de Tarvia."""
from base64 import b32decode
from binascii import Error
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address, ip_network
import re

from apps.backend.rules.engine import madrid
from apps.backend.tools import db

_STORE = "www.tarvia.example"
_WEB_FOLLOWUP_SOURCES = ("waf", "ecom_auth")
_PENTEST_SOURCES = {"192.0.2.10", "192.0.2.11", "192.0.2.12"}
_ATTACK_PATHS = {
    "930130": re.compile(r"/\.env"),
    "930120": re.compile(r"/(?:[^/?]+/)*\.\./(?:\.\./)*etc/passwd"),
    "932100": re.compile(r"/api/v1/orders/\d+/\.\./\d+"),
    "932150": re.compile(r"/cgi-bin/luci/;stok=/locale"),
    "933100": re.compile(r"/(?:[^/?]+/)*phpunit/src/Util/PHP/eval-stdin\.php"),
    "941100": re.compile(r"/[^?]+\?[^#]*<script>[^<>]+</script>", re.IGNORECASE),
    "942100": re.compile(
        r"/api/[^?]+\?[^#]*(?:\bUNION\s+SELECT\s+NULL--|'\s+OR\s+'[^']+'\s*=\s*'[^']+)", re.IGNORECASE
    ),
}
_HEARTBEATS = {
    "settings-win.data.microsoft.com": ip_network("198.18.0.11/32"),
    "teams.microsoft.com": ip_network("198.18.0.4/32"),
    "update.googleapis.com": ip_network("198.18.0.9/32"),
    "heartbeat.bmc-agent.example": ip_network("198.18.0.0/15"),
    "api.tarvia-printers.example": ip_network("198.18.0.0/15"),
}
_DNS_REPUTATION = {"dnsbl.spamhaus.org", "avqs.mcafee.com", "e5.sk", "sophosxl.net"}
_SCANS = {"CHG-2026-1049", "CHG-2026-1050", "CHG-2026-1051", "CHG-2026-1052"}
_INTERNAL = ip_network("10.0.0.0/8")
_OT = ip_network("10.40.16.0/20")
_HEX48 = re.compile(r"[0-9a-f]{48}")
_TUNNEL = re.compile(r"([a-z2-7]{32,63})\.(\d{1,8})\.t")


def _within(alert, event, minutes):
    if not isinstance(event.get("timestamp"), str):
        return False
    try:
        return abs(madrid(event["timestamp"]) - madrid(alert["created_at"])) <= timedelta(minutes=minutes)
    except ValueError:
        return False


def _change_covers(change, alert, events):
    start, end = datetime.fromisoformat(change["inicio"]), datetime.fromisoformat(change["fin"])
    timestamps = [alert["created_at"], *(event["timestamp"] for event in events)]
    return all(start <= madrid(timestamp).replace(tzinfo=None) < end for timestamp in timestamps)


def _complete(alert, direct, source):
    refs = alert.get("related_events") or []
    return (bool(direct) and {event.get("event_id") for event in direct} == set(refs)
            and all(event.get("source") == source for event in direct))


def _host_bindings(alert, analysis):
    """Comprobar coincidencia exacta del par equipo/IP entre entidad y CMDB."""
    assets = {(asset["hostname"].lower(), asset.get("ip")) for asset in analysis["context"].get("activos", [])
              if asset.get("hostname") and asset.get("zone") != "LOGISTICS-OT"}
    return {(host["hostname"].lower(), host["ip"]) for host in alert["entities"].get("hosts", [])
            if host.get("hostname") and host.get("ip")} & assets


def _direct_host(event, bindings):
    return (str(event.get("hostname", "")).lower(), event.get("src_ip")) in bindings


def _malicious(analysis, value):
    return any(item.get("indicator", "").lower() == str(value).lower()
               and (item.get("tip") or {}).get("reputation") == "malicious"
               for item in analysis["context"].get("inteligencia", []))


def _waf_blocked(event):
    return event.get("action") == "blocked" and str(event.get("status")) == "403"


def _origin_followup(alert, analysis, source_ip, direct):
    """La ventana de correlación se limita al mismo origen y a las fuentes indexadas."""
    records = db.events_for_entity(source_ip, alert["created_at"], horas=24, limit=500)
    sample_ids = {event["event_id"] for event in direct}
    complete = len(records) < 500 and sample_ids <= {event.get("event_id") for event in records}
    start = min(madrid(event["timestamp"]).astimezone(timezone.utc) for event in direct)
    end = madrid(alert["created_at"]).astimezone(timezone.utc) + timedelta(hours=24)
    missing = [source for source in _WEB_FOLLOWUP_SOURCES
               if not (bounds := db.source_bounds(source)) or bounds[0] > start or bounds[1] < end]
    related = [event for event in records if event.get("src_ip") == source_ip
               and madrid(event["timestamp"]) >= start]
    contrary = [event for event in related if (
        (event["source"] == "waf" and not _waf_blocked(event))
        or (event["source"] in {"ecom_auth", "idp_signins"} and event.get("result") == "success")
        or (event["source"] in {"proxy", "firewall"} and event.get("action") in {"allow", "allowed"})
    )]
    analysis.setdefault("trace", []).append({
        "tool": "Actividad posterior del origen", "query": f"{source_ip}, ±24 h del aviso",
        "count": len(related),
        "note": " ".join((
            f"{len(contrary)} señales posteriores contrarias.",
            "Referencias corroboradas y consulta sin truncar." if complete else "Consulta incompleta o truncada.",
            f"Ventana sin cubrir en {', '.join(missing)}." if missing else
            "Los límites del índice WAF y de acceso al comercio abarcan la ventana.",
        )),
    })
    return complete and not missing and not contrary


def _web(alert, analysis, direct, proof):
    ips = alert["entities"].get("ips") or []
    if len(ips) != 1 or not _complete(alert, direct, "waf"):
        return None
    ip = ips[0]
    if not all(event.get("src_ip") == ip and event.get("host") == _STORE and event.get("method") == "GET"
               and _within(alert, event, 30) for event in direct):
        return None
    if not all(_waf_blocked(event) for event in direct):
        return None
    exact_attack = all((pattern := _ATTACK_PATHS.get(str(event.get("rule_id"))))
                       and len(uri := str(event.get("uri", ""))) <= 512 and pattern.fullmatch(uri)
                       for event in direct)
    if exact_attack and ip in _PENTEST_SOURCES:
        change = next((entry for entry in analysis["context"].get("cambios", [])
                       if entry.get("id") == "CHG-2026-1042" and _change_covers(entry, alert, direct)), None)
        if change and all(event.get("user_agent") == "Mozilla/5.0 (compatible; pentest-auditoria-tarvia)"
                          for event in direct):
            return {**proof("benign_true_positive", direct, "El WAF bloqueó pruebas GET del pentest autorizado. "
                            "El origen, el frontal, la firma del auditor y los registros coinciden con CHG-2026-1042.",
                            basis="Prueba web autorizada dentro de la ventana y el alcance del cambio."),
                    "auto_close": True}
        return None
    scanner = all(str(event.get("rule_id")) == "913100" and event.get("uri") == "/wp-login.php"
                  for event in direct)
    if scanner:
        if not _origin_followup(alert, analysis, ip, direct):
            return proof("needs_more_info", direct, "El WAF detectó un escáner en /wp-login.php. El seguimiento "
                         "del origen tiene señales contrarias o registros incompletos.",
                         questions=("¿Los accesos posteriores pertenecen a la misma actividad?",))
        return {**proof("false_positive", direct, "El registro muestra detección y bloqueo del escáner en /wp-login.php. "
                        "La petición carece de carga de inyección y los registros correlacionados "
                        "no muestran accesos posteriores desde ese origen.",
                        basis="Detección del escáner, con HTTP 403 y seguimiento local sin accesos permitidos."),
                "auto_close": True}
    if not exact_attack:
        return None
    if alert["severity"] in {"informational", "low", "medium"} and _origin_followup(alert, analysis, ip, direct):
        return {**proof("true_positive", direct, "El WAF detectó y bloqueó una petición compatible con explotación. "
                        "El seguimiento del mismo origen no muestra accesos permitidos ni señales de continuación "
                        "en las 24 horas consultadas.",
                        basis="RB-05 permite cerrar el intento bloqueado tras la comprobación de seguimiento."),
                "resolved": True, "verified_prevention": "HTTP 403 del WAF y sin continuación del origen en la ventana verificada"}
    return proof("true_positive", direct, "La petición coincide con un intento de explotación y recibió HTTP 403.",
                 questions=("¿Hubo accesos posteriores, otra ruta o ejecución en el frontal?",))


def _pos_beacon(alert, analysis, domain, bindings, proof):
    context = analysis["context"]
    registers = {asset["hostname"].lower() for asset in context.get("activos", []) if asset.get("type") == "TPV"}
    if not registers:
        return None
    stamp = madrid(alert["created_at"])
    proxy = db.events_for_entity(domain, alert["created_at"], horas=24, source="proxy", limit=500)
    sent = [event for event in proxy if event.get("domain") == domain and _direct_host(event, bindings)
            and event.get("method") == "POST" and event.get("action") == "allowed"
            and str(event.get("status")) in {"200", "201", "204"}
            and str(event.get("bytes_out", "")).isdigit() and int(event["bytes_out"]) > 0
            and madrid(event["timestamp"]) <= stamp]
    reports, citations = {}, []
    for host in sorted(registers):
        traffic = [event for event in sent if event["hostname"].lower() == host]
        if not traffic:
            continue
        for event in db.events_for_entity(host, alert["created_at"], horas=24, source="edr_events", limit=200):
            details = event.get("details") or {}
            sha256 = event.get("sha256")
            if (event.get("hostname", "").lower() != host or event.get("event_type") != "process_access"
                    or event.get("signer") != "(sin firma)" or details.get("access") != "PROCESS_VM_READ"
                    or str(details.get("target_process", "")).lower() != "tarviapos.exe"
                    or not sha256):
                continue
            observed = madrid(event["timestamp"])
            if sha256 not in reports:
                reports[sha256] = db.sandbox(sha256)
            report = reports[sha256]
            if not report or report.get("verdict") != "malicious":
                continue
            network = report.get("network") or {}
            match = next((flow for flow in traffic if domain in network.get("domains", [])
                          and flow.get("dst_ip") in network.get("ips", [])
                          and timedelta(0) <= madrid(flow["timestamp"]) - observed <= timedelta(minutes=10)), None)
            if match:
                citations.extend((event, match))
                if report not in context.setdefault("sandbox", []):
                    context["sandbox"].append(report)
                break
    analysis.setdefault("trace", []).append({
        "tool": "Pivote de TPV", "query": "Dominio en proxy, acceso a memoria en EDR y destino en sandbox",
        "count": len(citations), "note": "Coincidencias exactas de equipo, tiempo y destino.",
    })
    if not citations:
        return None
    present = {event["event_id"] for event in analysis.get("events", [])}
    analysis.setdefault("events", []).extend(event for event in citations if event["event_id"] not in present)
    return {**proof("true_positive", citations, f"En {len(citations) // 2} TPV, un proceso sin firma leyó "
                    "memoria de la aplicación de cobro y el proxy permitió un POST al destino exacto del sandbox malicioso. "
                    "El contenido enviado y la exposición de tarjetas siguen por confirmar.",
                    actions=("Escalar a N2 y al responsable de pagos. Preservar EDR y proxy y proponer aislamiento.",)),
            "verified_impact": "memoria de la aplicación de pagos leída y tráfico al destino del sandbox",
            "escalate": ["N2", "Responsable de pagos"]}


def _beacon(alert, analysis, direct, proof):
    domains = alert["entities"].get("domains") or []
    bindings = _host_bindings(alert, analysis)
    if len(domains) != 1:
        return None
    domain = domains[0].lower()
    if not alert.get("related_events"):
        return _pos_beacon(alert, analysis, domain, bindings, proof)
    if not _complete(alert, direct, "proxy"):
        return None
    if not all(event.get("domain") == domain and _direct_host(event, bindings) and _within(alert, event, 360)
               for event in direct):
        return None
    malicious = _malicious(analysis, domain)
    if malicious and any(event.get("action") == "allowed" and event.get("method") in {"POST", "GET"}
                         for event in direct):
        return {**proof("true_positive", direct, "El proxy permitió conexiones al dominio que el TIP identifica "
                        "como malicioso. La correlación vincula el equipo y el destino. "
                        "La comunicación es compatible con C2, con origen de proceso aún por confirmar.",
                        actions=("Escalar a N2, identificar el proceso origen y preparar contención.",)),
                "escalate": ["N2"]}
    if len(direct) < 3 or domain not in _HEARTBEATS or malicious:
        return None
    url = f"https://{domain}/v1/ping"
    addresses = {event.get("dst_ip") for event in direct}
    if len(addresses) != 1:
        return None
    target = next(iter(addresses))
    try:
        if ip_address(target) not in _HEARTBEATS[domain] or _malicious(analysis, target):
            return None
    except ValueError:
        return None
    if not all(event.get("url") == url and event.get("method") == "GET" and str(event.get("status")) == "200"
               and event.get("action") == "allowed" and event.get("user_agent") == "agent"
               and event.get("category") == "Tecnología" and str(event.get("bytes_out")) == "200"
               and str(event.get("bytes_in")) == "150" for event in direct):
        return None
    return {**proof("false_positive", direct, "Las peticiones son pings del agente de telemetría en un servicio "
                    "conocido del entorno Tarvia. Coinciden destino, ruta, identidad de origen, "
                    "método y tamaño. El patrón por sí solo explica el aviso de beaconing.",
                    basis="Huella estrecha de telemetría, sin evidencia de C2 en las referencias."),
            "auto_close": True}


def _safe_internal(ip):
    try:
        address = ip_address(ip)
        return address in _INTERNAL and address not in _OT
    except ValueError:
        return False


def _scan(alert, analysis, direct, proof):
    bindings = _host_bindings(alert, analysis)
    if not _complete(alert, direct, "firewall") or len(direct) < 3:
        return None
    source_ips = {event.get("src_ip") for event in direct}
    if len(source_ips) != 1 or not source_ips <= {ip for _, ip in bindings}:
        return None
    change = next((item for item in analysis["context"].get("cambios", [])
                   if item.get("id") in _SCANS and _change_covers(item, alert, direct)), None)
    if change and all(("nessus01", event["src_ip"]) in bindings
                      and event.get("action") == "allow" and event.get("rule") == "SCANNER-ALLOW"
                      and event.get("zone_dst") != "LOGISTICS-OT"
                      and _safe_internal(event.get("dst_ip")) for event in direct):
        change_id = change["id"]
        return {**proof("benign_true_positive", direct, "La CMDB vincula el origen con NESSUS01 y el firewall "
                        f"registra escaneo permitido fuera de OT, dentro del cambio {change_id}.",
                        basis=f"Escaneo programado con origen, regla, destino y ventana verificados en {change_id}."),
                "auto_close": True}
    destinations = {event.get("dst_ip") for event in direct if event.get("dst_ip")}
    ports = {event.get("dst_port") for event in direct if event.get("dst_port")}
    if len(destinations) >= 5 and len(ports) >= 2 and all(_within(alert, event, 10) for event in direct):
        return {**proof("true_positive", direct, "El firewall registra un barrido a distintos destinos y puertos "
                        "desde un mismo activo, sin cambio y huella de escáner que lo autoricen.",
                        actions=("Cruzar el barrido con ejecución, credenciales o movimiento lateral del origen.",)),
                "escalate": ["N2"]}
    return None


def _blocklist(alert, analysis, direct, proof):
    bindings = _host_bindings(alert, analysis)
    ips = set(alert["entities"].get("ips") or [])
    source_ips = {ip for _, ip in bindings}
    for event in direct:
        target = event.get("dst_ip")
        if (event.get("source") == "firewall" and target in ips and _malicious(analysis, target)
                and event.get("src_ip") in source_ips
                and event.get("action") == "allow" and _within(alert, event, 10)):
            return {**proof("true_positive", [event], "El firewall permitió tráfico desde el equipo identificado "
                            "en CMDB hacia la IP que el TIP marca maliciosa. "
                            "La evidencia confirma la conexión, con proceso origen aún por identificar.",
                            actions=("Escalar a N2 y comprobar actividad posterior del equipo.",)),
                    "escalate": ["N2"]}
    return None


def _dns_payload(query, domain):
    suffix = "." + domain
    if not query.endswith(suffix) or not (parts := _TUNNEL.fullmatch(query[:-len(suffix)])):
        return None
    label, sequence = parts.groups()
    try:
        value = b32decode(label.upper() + "=" * (-len(label) % 8))
    except Error:
        return None
    if not value or sum(32 <= b <= 126 for b in value) / len(value) < 0.8:
        return None
    return int(sequence), label


def _dns(alert, analysis, direct, proof, tunnel):
    domains = alert["entities"].get("domains") or []
    bindings = _host_bindings(alert, analysis)
    if len(domains) != 1 or not _complete(alert, direct, "dns"):
        return None
    if not all(_direct_host(event, bindings) and _within(alert, event, 120) for event in direct):
        return None
    domain = domains[0].lower().rstrip(".")
    if not domain:
        return None
    queries = [str(event.get("query", "")).lower().rstrip(".") for event in direct]
    if not all(query == domain or query.endswith("." + domain) for query in queries):
        return None
    if _malicious(analysis, domain):
        return {**proof("true_positive", direct, "DNS registró consultas a un dominio exacto identificado "
                        "como malicioso en el TIP. La consulta no prueba que se ejecutara malware.",
                        actions=("Escalar y buscar las conexiones y el proceso que originaron la consulta.",)),
                "escalate": ["N2"]}
    if tunnel:
        suffix = "." + domain
        if (domain in _DNS_REPUTATION and len(direct) >= 3 and
                all(query.endswith(suffix) and _HEX48.fullmatch(query[:-len(suffix)]) for query in queries)
                and all(event.get("qtype") == "A" and event.get("response") == "127.0.0.2"
                        and event.get("rcode") == "NOERROR" for event in direct)):
            return {**proof("false_positive", direct, "Las consultas corresponden a la huella de reputación del "
                            "servicio conocido. Se verificaron subdominio hexadecimal, tipo A, respuesta "
                            "127.0.0.2 y origen. La longitud de etiqueta no indica un túnel por sí sola.",
                            basis="Patrón de reputación con destino y respuesta exactos."),
                    "auto_close": True}
        payloads = [_dns_payload(query, domain) for query in queries]
        if (len(direct) >= 3 and all(payloads)
                and len({row[0] for row in payloads}) >= 3 and len({row[1] for row in payloads}) >= 3
                and all(event.get("qtype") == "TXT" and event.get("rcode") == "NOERROR"
                        for event in direct)):
            return {**proof("true_positive", direct, "Un mismo origen emite consultas TXT con fragmentos "
                            "distintos codificados en Base32 y numerados. El patrón aporta evidencia de un "
                            "canal DNS. La sensibilidad y el volumen total de datos siguen por comprobar.",
                            actions=("Escalar a N2 y revisar el proceso origen y los datos transferidos.",)),
                    "escalate": ["N2"]}
    return proof("needs_more_info", direct, "El índice confirma las consultas DNS de la alerta. "
                 "La forma del nombre o el uso de un CDN compartido no acreditan generación maliciosa ni legitimidad.",
                 questions=("¿Qué proceso originó la consulta y con qué destino se comunicó después?",))


def check(alert, analysis, direct, proof):
    """Devuelve evidencia de las reglas cubiertas, con el criterio de cierre por separado."""
    rule = alert["rule_id"]
    if rule == "UC-WEB-001":
        return _web(alert, analysis, direct, proof)
    if rule == "UC-NET-001":
        return _beacon(alert, analysis, direct, proof)
    if rule == "UC-NET-002":
        return _blocklist(alert, analysis, direct, proof)
    if rule == "UC-NET-003":
        return _scan(alert, analysis, direct, proof)
    if rule in {"UC-NET-005", "UC-NET-006"}:
        return _dns(alert, analysis, direct, proof, tunnel=rule == "UC-NET-006")
    return None
