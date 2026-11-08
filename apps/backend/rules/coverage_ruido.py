"""Cobertura N1 de RB-05 y RB-09, basada en el índice local de Tarvia."""
from base64 import b32decode
from binascii import Error
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address, ip_network
import re
from urllib.parse import urlsplit

from apps.backend.rules.engine import madrid
from apps.backend.tools import db

_STORE = "www.tarvia.example"
_STORE_LOGIN = "/api/v1/auth/login"
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
_CREDENTIAL_FAILURES = {"invalid_password", "unknown_user"}
_SCANS = {"CHG-2026-1049", "CHG-2026-1050", "CHG-2026-1051", "CHG-2026-1052"}
_SCAN_ZONES = ("HQ-USERS", "MAD-USERS", "DC-SERVERS", "STORES", "LOGISTICS-IT", "LOGISTICS-OT",
               "DMZ", "DEV", "VPN-POOL", "AWS-PROD")
_HEX48 = re.compile(r"[0-9a-f]{48}")
_TUNNEL = re.compile(r"([a-z2-7]{32,63})\.(\d{1,8})\.t")


def _utc(timestamp):
    return madrid(timestamp).astimezone(timezone.utc)


def _within(alert, event, minutes):
    if not isinstance(event.get("timestamp"), str):
        return False
    try:
        return abs(_utc(event["timestamp"]) - _utc(alert["created_at"])) <= timedelta(minutes=minutes)
    except ValueError:
        return False


def _causal_events(alert, analysis, events):
    cutoff = _utc(alert["created_at"])
    prior, followup = [], []
    for event in events:
        try:
            time = _utc(event["timestamp"])
        except (AttributeError, TypeError, ValueError, KeyError):
            continue
        if time <= cutoff:
            prior.append(event)
        else:
            followup.append(event["event_id"])
    if followup:
        analysis["followup_event_ids"] = list(dict.fromkeys([*analysis.get("followup_event_ids", []), *followup]))
    return prior


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


def _http_url(value):
    if not isinstance(value, str) or any(char in value for char in "\r\n\t"):
        return None
    try:
        url = urlsplit(value)
        if (url.scheme in {"http", "https"} and url.hostname and url.username is None
                and not url.fragment and url.port != 0):
            return url
    except ValueError:
        pass
    return None


def _waf_target_matches(alert, events):
    urls = alert["entities"].get("urls") or []
    if not urls:
        return True
    expected = set()
    for value in urls:
        url = _http_url(value)
        if not url or url.port not in (None, 443 if url.scheme == "https" else 80):
            return False
        expected.add((url.hostname, url.path or "/", url.query))
    observed = {(event["host"], uri.partition("?")[0], uri.partition("?")[2])
                for event in events if isinstance(uri := event.get("uri"), str)}
    return expected == observed


def _waf_attack(event):
    rule = str(event.get("rule_id"))
    uri = str(event.get("uri", ""))
    pattern = _ATTACK_PATHS.get(rule)
    if not pattern or len(uri) > 512:
        return False
    # El ejecutor de PHPUnit se identifica por la ruta. Las reglas de inyección también usan la consulta.
    return bool(pattern.fullmatch(uri.split("?", 1)[0] if rule == "933100" else uri))


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
    direct = _causal_events(alert, analysis, direct)
    if not direct:
        return None
    ip = ips[0]
    if not all(event.get("src_ip") == ip and event.get("host") == _STORE and event.get("method") == "GET"
               and _within(alert, event, 30) for event in direct):
        return None
    if not _waf_target_matches(alert, direct):
        return proof("needs_more_info", direct, "La URL declarada no coincide con el destino y la ruta del WAF.",
                     questions=("¿Qué registro corresponde al destino indicado en el aviso?",))
    if not all(_waf_blocked(event) for event in direct):
        return None
    exact_attack = all(_waf_attack(event) for event in direct)
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


def _account_activity(login):
    stamp = _utc(login["timestamp"])
    end = stamp + timedelta(hours=1)
    account = login["customer_id"]
    records = db.events_for_entity(account, login["timestamp"], horas=1, source="ecom_account", limit=100)
    activity = [(time, event) for event in records
                if event.get("source") == "ecom_account"
                and event.get("customer_id") == account
                and event.get("event") in {"email_change", "address_change", "giftcard_purchase"}
                and stamp < (time := _utc(event["timestamp"])) <= end]
    same_origin = [(time, event) for time, event in activity if event.get("src_ip") == login["src_ip"]]
    context = [event for _, event in activity if event.get("src_ip") and event["src_ip"] != login["src_ip"]]
    changes = [(time, event) for time, event in same_origin if event["event"] != "giftcard_purchase"]
    purchases = [(time, event) for time, event in same_origin if event["event"] == "giftcard_purchase"]
    chained = {event["event_id"] for paid, event in purchases
               if any(timedelta(0) < paid - changed <= timedelta(minutes=30) for changed, _ in changes)}
    return [event for _, event in same_origin], chained, context


def _stuffing_plan(origins, customers):
    return [
        {"action": "Evaluar bloqueo acotado de IP de origen", "target": ", ".join(origins),
         "requires_approval": False,
         "justification": "RB-05 permite al operador N1 bloquear el origen corroborado tras revisar si es compartido."},
        {"action": "Reforzar CAPTCHA y limitación de frecuencia", "target": "Inicio de sesión de la tienda",
         "requires_approval": True, "approver": "Equipo de Comercio",
         "justification": "Revisar impacto en clientes y dificultar nuevos intentos distribuidos."},
        {"action": "Forzar cambio de contraseña y revocar sesiones", "target": ", ".join(customers),
         "requires_approval": True, "approver": "N2",
         "justification": "Se observaron accesos correctos asociados a la campaña en estas cuentas."},
        {"action": "Avisar a Fraude y preservar evidencias", "target": ", ".join(customers),
         "requires_approval": False,
         "justification": "Confirmar con los titulares si autorizaron la actividad y revisar las compras."},
    ]


def _device_fingerprint(event):
    value = event.get("device_fp")
    return value if isinstance(value, str) and 0 < len(value) <= 256 and value.strip() and value.isprintable() else ""


def _stuffing_scope(event, ips, customers):
    return (not ips or event.get("src_ip") in ips) and (not customers or event.get("customer_id") in customers)


def _stuffing(alert, analysis, direct, proof):
    if not _complete(alert, direct, "ecom_auth"):
        return None
    entities = alert["entities"]
    ips = set(entities.get("ips") or [])
    external = alert.get("external", False)
    customers = {row["customer_id"] for row in entities.get("customers", []) if row.get("customer_id")} if external else set()
    scoped = external and bool(ips or customers)
    stamp = _utc(alert["created_at"])
    start = stamp - timedelta(minutes=30)
    attempts = [event for event in _causal_events(alert, analysis, direct) if start <= _utc(event["timestamp"])]
    if any(not (url := _http_url(value)) or url.scheme != "https" or url.hostname != _STORE
           or url.port not in (None, 443) or url.path != _STORE_LOGIN for value in entities.get("urls", [])):
        return {**proof("needs_more_info", [], "La URL declarada no coincide con el inicio de sesión de Tarvia. "
                        "Los registros de autenticación de Tarvia quedan como contexto.",
                        questions=("¿Qué registros corresponden al destino declarado en el aviso?",)),
                "context_citations": [event["event_id"] for event in attempts]}
    success_by_device = {}
    for event in attempts:
        device = _device_fingerprint(event)
        if device and event.get("result") == "success" and event.get("src_ip") and event.get("customer_id"):
            success_by_device.setdefault(device, []).append(event)
    outside = {}
    for device, successes in success_by_device.items():
        records = db.search_logs(device, source="ecom_auth", desde=start.isoformat(), hasta=stamp.isoformat(), limit=500)
        failures, first_failure = [], {}
        for event in records:
            if (event.get("device_fp") != device or event.get("result") != "failure"
                    or event.get("failure_reason") not in _CREDENTIAL_FAILURES
                    or not event.get("src_ip") or not event.get("email")):
                continue
            time = _utc(event["timestamp"])
            if start <= time <= stamp:
                failures.append(event)
                current = first_failure.get(event["src_ip"])
                if current is None or time < current[0]:
                    first_failure[event["src_ip"]] = (time, event)
        origins = set(first_failure)
        accounts = {event["email"] for event in failures}
        if len(origins) < 3 or len(accounts) < 5 or (not external and ips and not ips & origins):
            continue
        linked = [(login, previous[1]) for login in successes
                  if (previous := first_failure.get(login["src_ip"])) and previous[0] < _utc(login["timestamp"])]
        if not linked:
            continue
        # La muestra deja en el expediente el vínculo por origen y evidencia de la campaña distribuida.
        samples = [event for _, event in first_failure.values()][:5]
        anchor = next((event for event in failures if event["src_ip"] in ips), failures[0])
        campaign = [anchor, *samples]
        if scoped:
            outside.update((login["event_id"], login) for login, _ in linked if not _stuffing_scope(login, ips, customers))
            linked = [(login, previous) for login, previous in linked if _stuffing_scope(login, ips, customers)]
            if not linked:
                continue
            campaign, off_scope = ([event for event in campaign if _stuffing_scope(event, ips, customers)],
                                   [event for event in campaign if not _stuffing_scope(event, ips, customers)])
            outside.update((event["event_id"], event) for event in off_scope)
        matched, activity, chained, context = [], {}, set(), {}
        for login, previous in linked:
            if scoped and not _stuffing_scope(previous, ips, customers):
                outside[previous["event_id"]] = previous
            else:
                matched.append(previous)
            matched.append(login)
            observed, sequences, other_origin = _account_activity(login)
            activity.update((event["event_id"], event) for event in observed)
            chained.update(sequences)
            context.update((event["event_id"], event) for event in other_origin)
        for event_id in activity:
            context.pop(event_id, None)
        evidence = list({event["event_id"]: event for event in [*campaign, *matched, *activity.values()]}.values())
        contextual = {**outside, **context}
        for event in evidence:
            contextual.pop(event["event_id"], None)
        present = {event["event_id"] for event in analysis["events"]}
        analysis["events"].extend(event for event in [*evidence, *contextual.values()] if event["event_id"] not in present)
        analysis.setdefault("trace", []).append({
            "tool": "Pivote de accesos a la tienda", "query": f"Huella {device} y orígenes en 30 min",
            "count": len(evidence),
            "note": "Muestra de fallos, accesos correctos con fallo previo del mismo origen y actividad posterior de la cuenta."
                    + (" La consulta de accesos alcanzó el límite de 500 registros." if len(records) == 500 else ""),
        })
        successes_text = f"{len(linked)} accesos correctos" if len(linked) > 1 else "un acceso correcto"
        summary = (f"El pivote general de la tienda recuperó {len(failures)} fallos en {len(accounts)} cuentas y "
                   f"{len(origins)} orígenes con la misma huella de dispositivo. "
                   f"El alcance del aviso incluye {successes_text} con un fallo previo de esa huella y origen.")
        if outside:
            summary += " Los demás registros del pivote quedan como contexto separado."
        addresses = sum(event["event"] == "address_change" for event in activity.values())
        emails = [event for event in activity.values() if event["event"] == "email_change"]
        temporary = sum((event.get("details") or {}).get("new_email_domain") == "tempmail-box.example"
                        for event in emails)
        if emails or addresses:
            summary += f" Hubo {temporary} cambios a correo temporal y {addresses} de dirección."
            if len(emails) > temporary:
                summary += f" Se observaron además {len(emails) - temporary} cambios a otros correos."
        purchases = [event for event in activity.values() if event["event"] == "giftcard_purchase"]
        if purchases:
            saved = sum((event.get("details") or {}).get("payment") == "saved_card" for event in purchases)
            summary += f" Se observaron {len(purchases)} compras de tarjeta regalo, {saved} con tarjeta guardada."
        if chained:
            summary += f" {len(chained)} compras siguieron a un cambio de la misma cuenta y origen."
        if context:
            other_purchases = sum(event["event"] == "giftcard_purchase" for event in context.values())
            summary += (" Los registros de otras IP en las mismas cuentas incluyen compras de tarjeta regalo "
                        f"({other_purchases}) y cambios de cuenta ({len(context) - other_purchases}). "
                        "Su relación con los accesos queda por comprobar.")
        affected = sorted({login["customer_id"] for login, _ in linked})
        plan = _stuffing_plan(sorted({login["src_ip"] for login, _ in linked}), affected)
        return {**proof("true_positive", evidence, summary,
                        questions=("¿Las personas titulares autorizaron estos accesos y compras?",),
                        actions=(f"{step['action']} · {step['target']}. {step['justification']}" for step in plan)),
                "affected_customers": affected, "action_plan": plan, "context_citations": list(contextual),
                "verified_impact": "accesos correctos vinculados a un patrón distribuido de fallos de credenciales",
                "escalate": ["N2", "Fraude"]}
    blocked_groups = {}
    for event in attempts:
        ip = event.get("src_ip")
        device = _device_fingerprint(event)
        if (device and ip and _stuffing_scope(event, ips, customers) and event.get("result") == "failure"
                and event.get("failure_reason") == "rate_limited" and event.get("captcha") == "challenge_failed"):
            blocked_groups.setdefault((ip, device), []).append(event)
    for blocked in blocked_groups.values():
        if len({event["email"] for event in blocked if event.get("email")}) >= 3:
            return proof("true_positive", blocked, "El comercio registró intentos contra varias cuentas desde el "
                         "mismo origen y dispositivo, frenados por CAPTCHA y limitación de frecuencia.",
                         questions=("¿Hubo accesos aceptados del mismo origen, dispositivo o campaña?",))
    if outside:
        return {**proof("needs_more_info", [], "El pivote verificó accesos en Tarvia fuera del alcance declarado. "
                        "Ningún acceso reúne las condiciones de alcance del aviso.",
                        questions=("¿Qué accesos corresponden al origen y a la cuenta declarados?",)),
                "context_citations": list(outside)}
    return None


def _proxy_target_matches(event, domain):
    url = _http_url(event.get("url"))
    return event.get("domain") == domain and url is not None and url.hostname == domain


def _proxy_url_identity(value):
    if url := _http_url(value):
        default_port = 443 if url.scheme == "https" else 80
        return url.scheme, url.hostname.removesuffix("."), url.port or default_port, url.path or "/", url.query
    return None


def _scope_proxy_urls(alert, analysis, events, proof):
    declared = alert["entities"].get("urls") or []
    if not declared:
        return events, None
    expected = {_proxy_url_identity(value) for value in declared}
    observed = [(event, _proxy_url_identity(event.get("url"))) for event in events]
    compatible = None not in expected and expected <= {identity for _, identity in observed}
    matching = [event for event, identity in observed if compatible and identity in expected]
    present = {event["event_id"] for event in analysis["events"]}
    outside = [event for event, identity in observed if not compatible or identity not in expected]
    extra = [event for event in outside if event["event_id"] not in present][:6]
    analysis["events"].extend(extra)
    context_ids = [event["event_id"] for event in outside if event["event_id"] in present]
    context_ids.extend(event["event_id"] for event in extra)
    if compatible:
        if context_ids:
            ids = analysis.get("context_event_ids", [])
            analysis["context_event_ids"] = list(dict.fromkeys([*ids, *context_ids]))
        return matching, None
    return [], {**proof("needs_more_info", [], "El destino HTTP(S) declarado no coincide con el tráfico de proxy "
                        "corroborado. Los registros recuperados quedan como contexto del aviso.",
                        questions=("¿Qué registros de proxy corresponden al destino declarado?",)),
                "context_citations": context_ids,
                "entity_verification": {"discrepancies": [{
                    "field": "urls", "declared": declared,
                    "verified": sorted({event["url"] for event, identity in observed if identity}),
                }]}}


def _positive_bytes(value):
    text = str(value)
    return text.isascii() and text.isdecimal() and text.strip("0") != ""


def _pos_beacon(alert, analysis, domain, ips, bindings, proof):
    context = analysis["context"]
    registers = {asset["hostname"].lower() for asset in context.get("activos", []) if asset.get("type") == "TPV"}
    if not registers:
        return None
    stamp = madrid(alert["created_at"])
    proxy = db.events_for_entity(domain, alert["created_at"], horas=24, source="proxy", limit=500)
    sent = [event for event in proxy if _proxy_target_matches(event, domain) and _direct_host(event, bindings)
            and event.get("method") == "POST" and event.get("action") == "allowed"
            and str(event.get("status")) in {"200", "201", "204"}
            and _positive_bytes(event.get("bytes_out"))
            and madrid(event["timestamp"]) <= stamp]
    if ips and sent:
        matching = [event for event in sent if event.get("dst_ip") in ips]
        if not matching:
            sample = sent[:6]
            present = {event["event_id"] for event in analysis["events"]}
            analysis["events"].extend(event for event in sample if event["event_id"] not in present)
            return proof("needs_more_info", sample, "El proxy muestra actividad de TPV hacia el dominio, "
                         "pero las IP de destino observadas no coinciden con las declaradas en el aviso.",
                         questions=("¿Qué registro de proxy corresponde a la IP declarada?",))
        sent = matching
    sent, mismatch = _scope_proxy_urls(alert, analysis, sent, proof)
    if mismatch:
        return mismatch
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
    ips = set(alert["entities"].get("ips") or [])
    bindings = _host_bindings(alert, analysis)
    if len(domains) != 1:
        return None
    domain = domains[0].lower()
    if not alert.get("related_events"):
        return _pos_beacon(alert, analysis, domain, ips, bindings, proof)
    if not _complete(alert, direct, "proxy"):
        return None
    prior = _causal_events(alert, analysis, direct)
    if not prior:
        return None
    if alert["entities"].get("urls"):
        candidates = [event for event in prior if _proxy_target_matches(event, domain) and _direct_host(event, bindings)
                      and _within(alert, event, 360) and (not ips or event.get("dst_ip") in ips)]
        prior, mismatch = _scope_proxy_urls(alert, analysis, candidates, proof)
        if mismatch:
            return mismatch
    if not all(_proxy_target_matches(event, domain) and _direct_host(event, bindings) and _within(alert, event, 360)
               for event in direct):
        return None
    malicious = _malicious(analysis, domain)
    if malicious:
        attempts = [event for event in prior if event.get("action") == "allowed"
                    and event.get("method") in {"POST", "GET"} and (not ips or event.get("dst_ip") in ips)]
        successful = [event for event in attempts if re.fullmatch(r"2[0-9]{2}", str(event.get("status")))
                      and _positive_bytes(event.get("bytes_out")) and _positive_bytes(event.get("bytes_in"))]
        if not successful:
            if not attempts:
                return None
            return {**proof("needs_more_info", attempts, "El proxy registró solicitudes al dominio malicioso "
                            "permitidas por política, sin confirmar una respuesta exitosa con intercambio de datos.",
                            questions=("¿Se completó alguna conexión desde ese equipo al destino?",)),
                    "escalate": ["N2"]}
        return {**proof("true_positive", successful, "El proxy registró respuestas HTTP satisfactorias y bytes "
                        "en ambos sentidos con el destino que el TIP identifica como malicioso. "
                        "La comunicación es compatible con C2, con origen de proceso aún por confirmar.",
                        actions=("Escalar a N2, identificar el proceso origen y preparar contención.",)),
                "escalate": ["N2"]}
    if len(direct) < 3 or domain not in _HEARTBEATS or malicious:
        return None
    url = f"https://{domain}/v1/ping"
    addresses = {event.get("dst_ip") for event in direct}
    if len(addresses) != 1:
        return None
    if ips and addresses != ips:
        return proof("needs_more_info", direct, "El destino registrado por el proxy no coincide con la IP declarada.",
                     questions=("¿Qué destino corresponde al aviso?",))
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
    followup = len(direct) - len(prior)
    summary = (f"Se observaron pings del agente de telemetría antes del aviso ({len(prior)}). Coinciden "
               "destino, ruta, identidad de origen, método y tamaño.")
    if followup:
        summary += f" Los pings posteriores ({followup}) corroboran el seguimiento del mismo servicio."
    return {**proof("false_positive", prior, summary,
                    basis="Huella estrecha de telemetría, sin evidencia de C2 en las referencias."),
            "auto_close": True}


def _approved_scan_target(event, networks):
    try:
        address = ip_address(event.get("dst_ip"))
    except ValueError:
        return False
    zones = {zone for zone, network in networks if address in network}
    return bool(zones and "LOGISTICS-OT" not in zones and event.get("zone_dst") in zones | {"ANY", None})


def _scan(alert, analysis, direct, proof):
    bindings = _host_bindings(alert, analysis)
    if not _complete(alert, direct, "firewall") or len(direct) < 3:
        return None
    if len(_causal_events(alert, analysis, direct)) != len(direct):
        return None
    source_ips = {event.get("src_ip") for event in direct}
    if len(source_ips) != 1 or not source_ips <= {ip for _, ip in bindings}:
        return None
    times = [_utc(event["timestamp"]) for event in direct]
    stamp = _utc(alert["created_at"])
    if max(times) - min(times) > timedelta(minutes=5):
        return None
    if alert.get("external") and stamp - min(times) > timedelta(minutes=5):
        return None
    change = next((item for item in analysis["context"].get("cambios", [])
                   if item.get("id") in _SCANS and _change_covers(item, alert, direct)), None)
    if change and ("nessus01", next(iter(source_ips))) in bindings:
        networks = [(zone, ip_network(record["cidr"])) for zone in _SCAN_ZONES for record in db.network_zones(zone)]
        if all(event.get("action") == "allow" and event.get("rule") == "SCANNER-ALLOW"
               and _approved_scan_target(event, networks) for event in direct):
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
    for event in _causal_events(alert, analysis, direct):
        target = event.get("dst_ip")
        if (event.get("source") == "firewall" and target in ips and _malicious(analysis, target)
                and event.get("src_ip") in source_ips
                and event.get("action") == "allow" and _within(alert, event, 10)):
            traffic = _positive_bytes(event.get("bytes"))
            observation = ("El registro contiene bytes de tráfico. El proceso de origen sigue por identificar."
                           if traffic else "El registro carece de bytes de tráfico positivos y no confirma una conexión establecida.")
            verdict = "true_positive" if traffic else "needs_more_info"
            return {**proof(verdict, [event], "La política del firewall permitió un intento desde el equipo "
                            "identificado en CMDB hacia la IP que el TIP marca maliciosa. " + observation,
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
    direct = _causal_events(alert, analysis, direct)
    if not direct:
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
        origins = {}
        for event, query in zip(direct, queries):
            if event.get("qtype") == "TXT" and event.get("rcode") == "NOERROR" and (payload := _dns_payload(query, domain)):
                key = (event["hostname"].lower(), event["src_ip"])
                origins.setdefault(key, []).append((event, payload))
        for rows in origins.values():
            if len({payload[0] for _, payload in rows}) >= 3 and len({payload[1] for _, payload in rows}) >= 3:
                return {**proof("true_positive", [event for event, _ in rows],
                                "Un mismo origen emite consultas TXT con fragmentos distintos codificados en "
                                "Base32 y numerados. El patrón aporta evidencia de un canal DNS. La sensibilidad "
                                "y el volumen total de datos siguen por comprobar.",
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
    if rule == "UC-WEB-002":
        return _stuffing(alert, analysis, direct, proof)
    if rule == "UC-NET-001":
        return _beacon(alert, analysis, direct, proof)
    if rule == "UC-NET-002":
        return _blocklist(alert, analysis, direct, proof)
    if rule == "UC-NET-003":
        return _scan(alert, analysis, direct, proof)
    if rule in {"UC-NET-005", "UC-NET-006"}:
        return _dns(alert, analysis, direct, proof, tunnel=rule == "UC-NET-006")
    return None
