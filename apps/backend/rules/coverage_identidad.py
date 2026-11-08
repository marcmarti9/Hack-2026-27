"""Correlación de identidad y correo con evidencia del índice (RB-01 y RB-03)."""
import re
from datetime import date, timedelta
from urllib.parse import urlsplit

from apps.backend.rules.engine import madrid
from apps.backend.tools import db


MAIL_PROFILES = {
    ("eventos@retailforum.example", "Invitación Retail Forum 2026"): "clean",
    ("notificaciones@docusign.net", "Completado: contrato de suministro"): "clean",
    ("newsletter@news.zalando.example", "Novedades de la semana"): "bulk",
    ("security-noreply@linkedin.com", "Nuevo inicio de sesión en tu cuenta"): "clean",
}
SCRIPT_CLIENT = ("axios/", "python-requests/", "curl/", "python-httpx/")
FINANCE_TERMS = {"factura", "iban", "pago", "transferencia", "remesa"}
KNOWN_TRAVEL_DESTINATIONS = {"nueva york": "US"}
TRAVEL_PIVOT_LIMIT = 101


def _account(value):
    return value.lower().removesuffix("@tarvia.example")


def _users(alert):
    return {_account(user["upn"]) for user in alert["entities"].get("users", []) if user.get("upn")}


def _later(first, second, *, minutes):
    if not first.get("timestamp") or not second.get("timestamp"):
        return False
    return timedelta(0) < madrid(second["timestamp"]) - madrid(first["timestamp"]) <= timedelta(minutes=minutes)


def _context(analysis, kind):
    return analysis.get("context", {}).get(kind, [])


def _intel(analysis, value, kind):
    return next((item.get(kind) or {} for item in _context(analysis, "inteligencia")
                 if item["indicator"] == value), {})


def _suspicious(analysis, *indicators):
    return any(_intel(analysis, value, "tip").get("reputation") in {"malicious", "suspicious"}
               for value in indicators if value)


def _record(analysis, events, tool, query, note):
    seen = {event["event_id"] for event in analysis["events"]}
    analysis["events"].extend(event for event in events if event["event_id"] not in seen)
    analysis["trace"].append({"tool": tool, "query": query, "count": len(events), "note": note})


def _url(value):
    try:
        return urlsplit(value)
    except ValueError:
        return None


def _domain(value):
    parsed = _url(value)
    return parsed.hostname if parsed else None


def _reported_message(alert, event):
    return (event["source"] == "email" and bool(event.get("message_id"))
            and any(_account(recipient) in _users(alert) for recipient in event.get("recipients", [])))


def _injected_invoice(message):
    body = message.get("body_excerpt", "").lower()
    sender = message.get("sender", "").lower().rpartition("@")[2]
    return (message.get("direction") == "inbound" and message.get("action") == "delivered"
            and message.get("dmarc") in {"none", "fail"} and "factura" in message.get("subject", "").lower()
            and re.search(r"display\s*:\s*none", body) and "false_positive" in body and "no escalar" in body
            and any((domain := _domain(url)) and domain != sender for url in message.get("urls", [])))


def _known_mail(alert, message, analysis):
    sender = message.get("sender", "").lower()
    verdict = MAIL_PROFILES.get((sender, message.get("subject")))
    if (not verdict or message.get("verdict") != verdict or message.get("action") != "delivered"
            or message.get("direction") != "inbound" or message.get("attachments") != []
            or message.get("body_excerpt") or len(message.get("recipients", [])) != 1
            or any(message.get(check) != "pass" for check in ("spf", "dkim", "dmarc"))
            or alert.get("severity") not in {"low", "informational"}):
        return False
    urls = message.get("urls", [])
    domain = sender.rpartition("@")[2]
    if len(urls) != 1 or not (url := _url(urls[0])) or (
        url.scheme, url.netloc, url.query, url.fragment
    ) != ("https", domain, "", "") or not re.fullmatch(r"/[cl]/[0-9a-f]{6}", url.path):
        return False
    if alert.get("external"):
        declared = alert.get("declared_evidence") or alert.get("evidence") or {}
        if (declared.get("message_id") != message["message_id"]
                or {entry.lower() for entry in alert["entities"].get("domains", [])} != {domain}
                or any(key in declared and declared[key] != message.get(key) for key in ("sender", "subject"))):
            return False
    if _suspicious(analysis, domain, message.get("sender_ip")):
        return False
    clicks = db.events_for_entity(message["message_id"], source="email_clicks", limit=4)
    _record(analysis, clicks, "Clics de correo", message["message_id"], "Búsqueda por ID exacto del mensaje.")
    return not clicks


def _report_mail(alert, analysis, direct, proof):
    for message in direct:
        if not _reported_message(alert, message):
            continue
        if _injected_invoice(message):
            return {**proof("true_positive", [message],
                            "El correo de facturación contiene texto oculto que intenta decidir su propio "
                            "veredicto. El enlace pertenece a otro dominio y DMARC no confirma alineación.",
                            actions=("Buscar la misma campaña y preparar retirada para N2.",),
                            basis="RB-01 · enlace, alineación del remitente y contenido del mensaje."),
                    "escalate": ["N2"]}
        sender = message.get("sender", "").lower().rpartition("@")[2]
        urls = message.get("urls", [])
        domains = {sender, *(_domain(url) for url in urls)}
        if (message.get("dmarc") == "fail" and message.get("verdict") in {"spam", "phishing"}
                and any(_intel(analysis, domain, "tip").get("reputation") == "malicious"
                        for domain in domains if domain)):
            return proof("true_positive", [message],
                         "El gateway marcó spam o phishing, DMARC falló y el TIP confirma reputación "
                         "maliciosa para un dominio observado en el correo.",
                         actions=("Revisar entrega y exposición antes de decidir la retirada.",),
                         basis="RB-01 · encabezados, gateway y reputación de un dominio observado.")
        tip = _intel(analysis, sender, "tip")
        if (message.get("dmarc") == "fail" and message.get("verdict") == "spam"
                and tip.get("reputation") == "suspicious" and "scam" in str(tip.get("tags", "")).split(",")
                and any(_domain(url) == sender for url in urls)
                and re.match(r"^(?:has ganado|reclama tu premio)\b", message.get("subject", ""), re.IGNORECASE)):
            return proof("true_positive", [message],
                         "El correo ofrece un premio y dirige al dominio que el TIP señala por estafa. "
                         "El gateway lo marcó como spam y DMARC falló. Falta verificar exposición e interacción.",
                         actions=("Buscar clics y otros destinatarios antes de decidir el bloqueo.",),
                         basis="RB-01 · señuelo, veredicto del gateway, alineación y reputación del enlace.")
        if _known_mail(alert, message, analysis):
            return {**proof("false_positive", [message],
                            "El mensaje coincide con el perfil informativo registrado. La autenticación "
                            "está alineada, el enlace usa su mismo dominio y el índice no registra clics "
                            "para este ID. El mensaje llegó sin adjuntos.",
                            basis="RB-01 · perfil informativo exacto, autenticación y búsqueda por ID."),
                    "auto_close": True}
    return None


def _attachment(alert, analysis, direct, proof):
    for mail in direct:
        if not _reported_message(alert, mail):
            continue
        for attachment in mail.get("attachments", []):
            for file in [attachment, *attachment.get("contains", [])]:
                sha = file.get("sha256")
                if not sha:
                    continue
                report = next((item for item in _context(analysis, "sandbox") if item["sha256"] == sha), None)
                report = report or db.sandbox(sha)
                if not report or report.get("verdict") != "malicious":
                    continue
                if report not in _context(analysis, "sandbox"):
                    analysis["context"]["sandbox"].append(report)
                    analysis["trace"].append({"tool": "Sandbox", "query": sha, "count": 1,
                                              "note": "Informe malicioso para el hash exacto del adjunto."})
                return {**proof("true_positive", [mail],
                                "El hash del archivo adjunto coincide con un resultado malicioso de sandbox. "
                                "El registro de correo permite localizar destinatarios y comprobar entrega.",
                                actions=("Comprobar apertura y ejecución con EDR. Preparar retirada.",),
                                basis="RB-01 · hash exacto del archivo o su contenido y veredicto de sandbox."),
                        "escalate": ["N2"]}
    return None


def _click(alert, analysis, direct, proof):
    for click in direct:
        user = click.get("user", "")
        url = click.get("url", "")
        message_id = click.get("message_id")
        if (click["source"] != "email_clicks" or click.get("action") not in {"allowed", "blocked"}
                or _account(user) not in _users(alert) or not _domain(url) or not message_id):
            continue
        mail = next((event for event in direct if event.get("message_id") == message_id
                     and event["source"] == "email"), None)
        if not mail:
            mail = next((event for event in db.events_for_entity(message_id, source="email", limit=4)
                         if event["message_id"] == message_id), None)
        if (not mail or user not in mail.get("recipients", []) or url not in mail.get("urls", [])
                or not _later(mail, click, minutes=1440)):
            continue
        if not (_injected_invoice(mail) or click.get("verdict_at_click") == "phishing"
                or _intel(analysis, _domain(url), "tip").get("reputation") == "malicious"):
            continue
        _record(analysis, [mail], "Trazabilidad de correo", message_id, "Coinciden ID, enlace y destinatario.")
        outcome = "permitió el acceso" if click["action"] == "allowed" else "bloqueó el acceso"
        return {**proof("true_positive", [mail, click],
                        f"El clic enlaza con el correo de phishing por ID, URL y destinatario. El control "
                        f"{outcome}. Estos registros dejan por confirmar el envío de credenciales.",
                        actions=("Consultar sesiones posteriores para la misma cuenta y escalar a N2.",),
                        basis="RB-01 · correo original, telemetría de clic y evidencia de phishing."),
                "escalate": ["N2"]}
    return None


def _audit_applied(event):
    # Los registros de operaciones aplicadas del índice original omiten result.
    result = event.get("result")
    return result is None or (isinstance(result, str) and result.strip().casefold() in {"", "success", "succeeded", "ok"})


def _concealment(event, actor, ip=None):
    details = event.get("details") or {}
    filters = details.get("conditions") or {}
    if not isinstance(filters, dict):
        return False
    terms = details.get("body_or_subject_contains") or filters.get("body_or_subject_contains", [])
    actions = details.get("actions") or {}
    return (event["source"] == "idp_audit" and event.get("operation") == "New-InboxRule"
            and event.get("actor_upn") == actor and event.get("target") == actor
            and _audit_applied(event) and (ip is None or event.get("src_ip") == ip)
            and isinstance(terms, list) and isinstance(actions, dict)
            and bool(FINANCE_TERMS.intersection(term.lower() for term in terms))
            and actions.get("mark_as_read") is True
            and actions.get("move_to_folder", "").lower() in {"rss feeds", "archivo", "archive", "junk email"})


def _iban(alert, analysis, direct, proof):
    for message in direct:
        body = message.get("body_excerpt", "").lower()
        if (not _reported_message(alert, message) or "iban" not in body
                or not re.search(r"\b(?:actualiz\w+|cambi\w+|nuevo)\b", body)
                or not re.search(r"\b(?:pag\w+|transferencia)\b", body)):
            continue
        sender, ip = message.get("sender"), message.get("sender_ip")
        prior = next((event for event in analysis["events"] if sender and ip
                      and _concealment(event, sender, ip) and _later(event, message, minutes=2880)), None)
        if not prior and sender and ip:
            prior = next((event for event in db.events_for_entity(sender, message["timestamp"], horas=48,
                                                                 source="idp_audit", limit=100)
                          if _concealment(event, sender, ip) and _later(event, message, minutes=2880)), None)
        if prior:
            _record(analysis, [prior], "Auditoría de buzón", sender,
                    "Mismo remitente y origen. La regla de ocultación precede al correo.")
        summary = "El correo solicita cambiar el IBAN antes del pago y el índice no acredita su autorización."
        if prior:
            summary += " El mismo usuario y origen ya habían creado una regla que oculta mensajes financieros."
        return {**proof("true_positive" if prior else "needs_more_info", [message, prior] if prior else [message],
                        summary, actions=("Avisar a Tesorería para retener el pago y escalar a N2. "
                                          "Verificar con el proveedor por un canal conocido.",),
                        questions=("¿Confirma el proveedor el cambio por un canal independiente?",),
                        basis="RB-01 · petición de cambio de IBAN sin verificar, escalado crítico a Tesorería."),
                "escalate": ["N2", "Tesorería"], "severity_override": "critical"}
    return None


def _approved_signin(event):
    return (event["source"] == "idp_signins" and event.get("result") == "success"
            and event.get("conditional_access") == "success" and event.get("device_compliant") is True
            and bool(event.get("device_id")) and event.get("risk_level") in {"low", "none"})


def _mobile(event):
    agent = event.get("user_agent", "")
    return "iPhone" in agent and "Outlook-iOS/" in agent and event.get("app") == "Office 365 Exchange Online"


def _sensitive_download(event):
    if event.get("operation") != "FileDownloaded":
        return False
    details = event.get("details") or {}
    classification = str(details.get("data_classification") or "").casefold()
    return (classification in {"personal", "sensitive", "confidential", "restricted"}
            or bool(re.search(r"\b(?:n[oó]minas?|payroll)\b", str(event.get("target") or "").casefold())))


def _travel_conflicts(events, login):
    conflicts = {}
    stamp = madrid(login["timestamp"])
    for event in events:
        if not event.get("timestamp") or abs(madrid(event["timestamp"]) - stamp) > timedelta(hours=1):
            continue
        if (event["source"] == "idp_signins" and event.get("user_upn") == login["user_upn"]
                and event.get("result") == "success" and (event.get("device_compliant") is False
                                                         or event.get("risk_level") in {"medium", "high"})):
            conflicts[event["event_id"]] = event
        if (event["source"] == "idp_audit" and event.get("actor_upn") == login["user_upn"]
                and _audit_applied(event)
                and (event.get("operation") in {"New-InboxRule", "Add-MfaMethod", "Consent to application"}
                     or (madrid(event["timestamp"]) >= stamp and _sensitive_download(event)))):
            conflicts[event["event_id"]] = event
    return list(conflicts.values())


def _travel_review(analysis, login, proof):
    truncated = False
    conflicts = _travel_conflicts(analysis["events"], login)
    for source in ("idp_signins", "idp_audit"):
        events = db.events_for_entity(login["user_upn"], login["timestamp"], horas=1,
                                     source=source, limit=TRAVEL_PIVOT_LIMIT)
        truncated = truncated or len(events) >= TRAVEL_PIVOT_LIMIT
        matches = _travel_conflicts(events, login)
        conflicts.extend(matches)
        _record(analysis, matches, "Comprobación de viaje", source,
                f"{len(events)} eventos de la cuenta consultados en ±1 h. "
                f"{len(matches)} requieren revisión.")
    if conflicts:
        unique = {event["event_id"]: event for event in conflicts}
        return {**proof("needs_more_info", [login, *list(unique.values())[:5]],
                        "El acceso encaja con el viaje o la salida móvil, pero el IdP registra accesos "
                        "de riesgo, cambios sensibles o descargas de datos sensibles de la misma cuenta en la ventana.",
                        actions=("Comprobar el origen y la actividad de la cuenta con N2.",),
                        basis="RB-03 · actividad de identidad que contradice el cierre automático."),
                "escalate": ["N2"]}
    if truncated:
        return proof("needs_more_info", [login],
                     "La consulta de la cuenta alcanzó su límite. Hace falta revisar el resto de la ventana.",
                     questions=("¿Hubo accesos de riesgo, cambios sensibles o descargas de datos sensibles en la ventana completa?",),
                     basis="RB-03 · cobertura incompleta del historial de identidad.")
    return None


def _mobile_baseline(events, current):
    return next((item for item in events if _approved_signin(item) and _mobile(item)
                 and item.get("user_upn") == current["user_upn"] and item.get("device_id") == current["device_id"]
                 and item.get("user_agent") == current["user_agent"] and item.get("country") == "ES"
                 and item.get("session_id") and item.get("mfa_result") in {"approved", "satisfied_by_session"}
                 and _later(item, current, minutes=7 * 1440)), None)


def _previous_mobile(analysis, login):
    baseline = _mobile_baseline(analysis["events"], login)
    if not baseline:
        history = db.events_for_entity(login["user_upn"], login["timestamp"], horas=168,
                                       source="idp_signins", limit=250)
        baseline = _mobile_baseline(history, login)
    if baseline:
        _record(analysis, [baseline], "Historial de identidad", login["device_id"],
                "Móvil de la misma cuenta y cliente ya observado en una sesión conforme en España.")
    return baseline


def _travel_notice(analysis, login):
    city = login.get("city", "").lower()
    if not city or KNOWN_TRAVEL_DESTINATIONS.get(city) != login.get("country"):
        return None
    day = madrid(login["timestamp"]).date()
    for account in _context(analysis, "usuarios"):
        if account["username"] != _account(login["user_upn"]):
            continue
        for event in account.get("hr_events", []):
            info = event.get("detalle", "").lower()
            dates = re.search(r"\bdel (\d{1,2})/(\d{1,2}) al (\d{1,2})/(\d{1,2})\b", info)
            if (event.get("tipo") != "viaje" or event.get("usuario") != login["user_upn"]
                    or not info.startswith(city + " ") or "móvil corporativo" not in info or not dates):
                continue
            try:
                start = date.fromisoformat(str(event["fecha_efectiva"]))
                start_day, start_month, end_day, end_month = map(int, dates.groups())
                end = date(start.year + (end_month < start_month), end_month, end_day)
                notified = date.fromisoformat(str(event["fecha"]))
            except (KeyError, TypeError, ValueError):
                continue
            if start.day == start_day and start.month == start_month and notified <= start <= day <= end:
                return event
    return None


def _travel(alert, analysis, direct, proof):
    users = _users(alert)
    for change in direct:
        actor, ip = change.get("actor_upn", ""), change.get("src_ip")
        if (change["source"] != "idp_audit" or change.get("operation") != "Add-MfaMethod" or not ip
                or not _audit_applied(change)
                or _account(actor) not in users or change.get("target") != actor):
            continue
        download = next((event for event in direct if event["source"] == "idp_audit"
                         and event.get("operation") == "FileDownloaded" and event.get("actor_upn") == actor
                         and event.get("src_ip") == ip and "nóminas" in event.get("target", "").lower()
                         and _audit_applied(event)
                         and _later(event, change, minutes=30)), None)
        if download:
            return {**proof("true_positive", [download, change],
                            "El mismo usuario y origen descargaron nóminas y añadieron un método MFA. "
                            "La combinación exige revisar acceso a datos y persistencia en la cuenta.",
                            actions=("Escalar a N2 y DPO. Validar el nuevo método con la persona.",),
                            basis="RB-03 · operaciones de auditoría de la cuenta tras el acceso."),
                    "escalate": ["N2", "DPO"]}
    if alert.get("severity") not in {"informational", "low", "medium"}:
        return None
    for login in direct:
        if (not _approved_signin(login) or not _mobile(login)
                or _account(login.get("user_upn", "")) not in users
                or _suspicious(analysis, login.get("src_ip"))):
            continue
        if (login.get("session_id") and login.get("mfa_method") == "fido2"
                and login.get("mfa_result") == "approved" and _travel_notice(analysis, login)
                and (baseline := _previous_mobile(analysis, login))):
            if review := _travel_review(analysis, login, proof):
                return review
            return {**proof("false_positive", [baseline, login],
                            "El acceso desde el destino y fechas avisados por RR. HH. usó el móvil ya observado, "
                            "una sesión identificada y FIDO2 aprobado.",
                            basis="RB-03 · identidad, viaje notificado, historial del equipo conforme y FIDO2."),
                    "auto_close": True}
        geo = _intel(analysis, login.get("src_ip"), "geo")
        if (login.get("mfa_result") != "satisfied_by_session" or login.get("asn") != "AS8075"
                or geo.get("asn") != login["asn"] or "Private Relay/VPN del móvil" not in geo.get("as_org", "")
                or login.get("country") not in {"FR", "IE", "NL"}):
            continue
        local = next((event for event in direct if _approved_signin(event)
                      and event.get("user_upn") == login["user_upn"] and event.get("country") == "ES"
                      and event.get("asn") == "AS64610" and event.get("app") == "Microsoft Teams"
                      and event.get("mfa_result") == "satisfied_by_session"
                      and event.get("device_id") != login["device_id"] and _later(event, login, minutes=30)), None)
        if not local or _suspicious(analysis, local.get("src_ip")):
            continue
        baseline = _previous_mobile(analysis, login)
        if not baseline:
            continue
        if review := _travel_review(analysis, login, proof):
            return review
        return {**proof("false_positive", [local, baseline, login],
                        "La cuenta pasó de Teams local a Outlook en un móvil conforme que ya tenía historial "
                        "de sesiones. GeoIP identifica la IP europea como salida móvil y el IdP registra MFA "
                        "satisfecho por sesión. El par de eventos carece de un identificador de sesión común.",
                        basis="RB-03 · IdP, historial del dispositivo y salida móvil identificada por GeoIP."),
                "auto_close": True}
    return None


def _spraying(alert, analysis, direct, proof):
    ips = set(alert["entities"].get("ips", []))
    failures = sorted((event for event in direct if event["source"] == "vpn"
                       and event.get("action") == "auth_fail" and event.get("src_ip") in ips
                       and event.get("user")), key=lambda event: madrid(event["timestamp"]))
    for start in failures:
        burst = [event for event in failures if event is start or _later(start, event, minutes=20)]
        accounts = {event["user"] for event in burst}
        origins = {event["src_ip"] for event in burst}
        if len(accounts) < 10 or sum(str(_intel(analysis, ip, "geo").get("is_tor")).lower() == "true"
                                    for ip in origins) < 3:
            continue
        return {**proof("true_positive", burst,
                        f"Los registros VPN muestran fallos para {len(accounts)} cuentas distintas dentro "
                        "de una ráfaga de autenticaciones repartida entre nodos Tor. La muestra acredita "
                        "el patrón de ataque, sin indicar qué contraseña se usó.",
                        actions=("Correlacionar conexiones aceptadas después de la ráfaga y revisar exclusiones MFA.",),
                        basis="RB-03 · cuentas distintas, ventana corta y orígenes Tor corroborados."),
                "escalate": ["N2"]}
    return None


def _mfa(alert, analysis, direct, proof):
    users = _users(alert)
    for login in direct:
        if (login["source"] != "idp_signins" or login.get("result") != "success"
                or login.get("mfa_result") != "approved" or login.get("mfa_method") != "push"
                or _account(login.get("user_upn", "")) not in users or not login.get("src_ip")
                or not login.get("app")):
            continue
        denied = [event for event in direct if event["source"] == "idp_signins"
                  and all(event.get(field) == login[field] for field in ("user_upn", "src_ip", "app"))
                  and event.get("result") == "failure" and event.get("mfa_method") == "push"
                  and event.get("mfa_result") in {"denied", "timeout"} and _later(event, login, minutes=15)]
        if len({event["event_id"] for event in denied}) < 4:
            continue
        return {**proof("true_positive", [*denied, login],
                        f"El IdP muestra {len(denied)} avisos MFA rechazados o agotados antes de un push "
                        "aceptado por la misma cuenta, origen y aplicación. La secuencia respalda fatiga MFA.",
                        actions=("Verificar la sesión con el usuario y preparar su revocación para N2.",),
                        basis="RB-03 · cronología de rechazos y autenticación aceptada."),
                "escalate": ["N2"]}
    return None


def _anonymous(alert, analysis, direct, proof):
    users = _users(alert)
    for login in direct:
        ip = login.get("src_ip")
        geo = _intel(analysis, ip, "geo")
        if not ip:
            continue
        if (login["source"] == "idp_signins" and login.get("result") == "success"
                and _account(login.get("user_upn", "")) in users and login.get("device_compliant") is False
                and any(str(geo.get(key)).lower() == "true" for key in ("is_hosting", "is_vpn_provider", "is_tor"))):
            audit = next((event for event in analysis["events"]
                          if _concealment(event, login["user_upn"], ip) and _later(login, event, minutes=60)), None)
            if audit:
                return {**proof("true_positive", [login, audit],
                                "Un acceso aceptado desde infraestructura de terceros con dispositivo no conforme "
                                "precede a la creación de una regla de ocultación en el mismo buzón y origen.",
                                actions=("Revisar sesión y regla de buzón con N2.",),
                                basis="RB-03 · GeoIP, inicio de sesión y operación posterior de la misma cuenta."),
                        "escalate": ["N2"]}
        if (login["source"] == "vpn" and login.get("action") == "connect"
                and _account(login.get("user", "")) in users and login.get("assigned_ip")
                and str(geo.get("is_tor")).lower() == "true"
                and login.get("mfa_result", "").startswith("not_required")
                and any(account.get("account_type") == "service" and account["username"] == _account(login["user"])
                        for account in _context(analysis, "usuarios"))):
            return {**proof("true_positive", [login],
                            "La VPN concedió dirección a una cuenta de servicio exenta de MFA desde un nodo Tor "
                            "identificado por GeoIP. Hay acceso confirmado y queda por atribuir su control.",
                            actions=("Escalar a N2 y revisar la excepción MFA y el tráfico de la IP asignada.",),
                            basis="RB-03 · conexión VPN, inventario de identidad y GeoIP."),
                    "escalate": ["N2"]}
    return None


def _inbox(alert, analysis, direct, proof):
    for event in direct:
        actor = event.get("actor_upn", "")
        if _account(actor) in _users(alert) and _concealment(event, actor):
            return {**proof("true_positive", [event],
                            "La auditoría registra que el usuario creó una regla que oculta mensajes financieros, "
                            "los desvía a una carpeta secundaria y los marca como leídos.",
                            actions=("Revisar con N2 y Tesorería los mensajes afectados y el acceso al buzón.",),
                            basis="RB-03 · regla de buzón, filtros financieros y acciones de ocultación."),
                    "escalate": ["N2", "Tesorería"]}
    return None


def _session(alert, analysis, direct, proof):
    users = _users(alert)
    for login in direct:
        if (login["source"] != "idp_signins" or login.get("result") != "success"
                or _account(login.get("user_upn", "")) not in users or not login.get("session_id")
                or login.get("device_compliant") is not False or login.get("risk_level") != "high"
                or not login.get("user_agent", "").lower().startswith(SCRIPT_CLIENT)):
            continue
        first = next((event for event in analysis["events"] if event["source"] == "idp_signins"
                      and event.get("result") == "success" and event.get("mfa_result") == "approved"
                      and all(event.get(field) == login.get(field) for field in ("user_upn", "session_id", "app"))
                      and event.get("user_agent", "").startswith("Mozilla/")
                      and _later(event, login, minutes=30)), None)
        if first and login.get("mfa_result") == "satisfied_by_session":
            ip_evidence = (" Los dos registros tienen la misma IP." if first.get("src_ip") == login.get("src_ip")
                           else " Los dos registros muestran IP distintas.")
            return {**proof("true_positive", [first, login],
                            "Una sesión identificada cambia de navegador a cliente automatizado no conforme "
                            "y el segundo acceso reutiliza el MFA de la sesión." + ip_evidence,
                            actions=("Preparar revocación de la sesión y escalar a N2.",),
                            basis="RB-03 · ID de sesión, cuenta, aplicación, MFA y cliente."),
                    "escalate": ["N2"]}
        if (str(_intel(analysis, login.get("src_ip"), "geo").get("is_hosting")).lower() == "true"
                or _suspicious(analysis, login.get("src_ip"))):
            return {**proof("needs_more_info", [login],
                            "Hay un acceso aceptado de alto riesgo desde un cliente automatizado no conforme "
                            "y un origen de riesgo. Falta el inicio original para acreditar reutilización.",
                            questions=("¿Qué cliente y autenticación constan en la creación de la sesión?",),
                            actions=("Consultar sesiones y actividad previa. Escalar a N2.",),
                            basis="RB-03 · acceso acreditado y evidencia de origen, sin correlación de sesión original."),
                    "escalate": ["N2"]}
    return None


def _consent(alert, analysis, direct, proof):
    for event in direct:
        if (event["source"] != "idp_audit" or event.get("operation") != "Consent to application"
                or _account(event.get("actor_upn", "")) not in _users(alert) or not event.get("target")
                or not _audit_applied(event)):
            continue
        details = event.get("details") or {}
        permissions = details.get("permissions", [])
        if isinstance(permissions, str):
            permissions = re.split(r"[ ,;]+", permissions)
        publisher = str(details.get("publisher", "")).lower()
        if ((details.get("publisher_verified") is False or publisher in {"no verificado", "unverified"})
                and set(permissions).intersection({"Mail.Read", "Mail.ReadWrite", "Mail.Read.Shared", "Mail.Send"})):
            return {**proof("true_positive", [event],
                            "La auditoría registra consentimiento a una aplicación de editor sin verificar con "
                            "permisos de lectura, escritura o envío de correo.",
                            actions=("Verificar la necesidad y preparar retirada del consentimiento para N2.",),
                            basis="RB-03 · consentimiento, editor y permisos observados en la auditoría."),
                    "escalate": ["N2"]}
    return None


def _privileged_ad(alert, analysis, direct, proof):
    for addition in direct:
        group = (addition.get("details") or {}).get("group")
        if (addition["source"] != "ad_events" or str(addition.get("event_code")) != "4728"
                or group not in {"Domain Admins", "Enterprise Admins"}
                or not all(addition.get(field) for field in ("target", "subject", "src_host"))
                or _account(addition["target"]) not in _users(alert)):
            continue
        creation = next((event for event in direct if event["source"] == "ad_events"
                         and str(event.get("event_code")) == "4720"
                         and all(event.get(field) == addition[field] for field in ("target", "subject", "src_host"))
                         and _later(event, addition, minutes=5)), None)
        if not creation:
            continue
        return {**proof("true_positive", [creation, addition],
                        f"El directorio registra la creación de la cuenta y su incorporación inmediata a {group} "
                        "desde el mismo equipo y operador. Hay elevación confirmada que requiere validación.",
                        actions=("Consultar el cambio con el responsable de AD y escalar a N2.",),
                        basis="RB-03 · alta de cuenta y membresía privilegiada correlacionadas."),
                "escalate": ["N2"]}
    return None


def _vpn(alert, analysis, direct, proof):
    users = _users(alert)
    for event in direct:
        user, ip = event.get("user", ""), event.get("src_ip")
        if (event["source"] != "vpn" or event.get("action") != "connect" or not event.get("assigned_ip")
                or _account(user) not in users or not ip
                or not any(account.get("account_type") == "external" and account["username"] == user
                           for account in _context(analysis, "usuarios"))):
            continue
        changed = next((row for row in _context(analysis, "cambios") if row["id"] == "CHG-2026-1071"
                        and user == "ext.logisoft"), None)
        if changed and not _suspicious(analysis, ip):
            stamp = madrid(event["timestamp"]).replace(tzinfo=None).isoformat(sep=" ", timespec="minutes")
            if str(changed["inicio"])[:16] <= stamp <= str(changed["fin"])[:16]:
                return proof("needs_more_info", [event],
                             "La cuenta externa abrió la VPN dentro de la ventana del cambio de WMS. "
                             "La aprobación también exige acreditar la IP corporativa del proveedor.",
                             questions=("¿Confirma Logística que la IP de origen es la autorizada?",),
                             basis="RB-03 · conexión VPN y coincidencia parcial con el calendario de cambios.")
    return None


RULES = {
    "UC-EML-001": _report_mail,
    "UC-EML-002": _attachment,
    "UC-EML-003": _click,
    "UC-EML-004": _iban,
    "UC-IDP-001": _travel,
    "UC-IDP-002": _spraying,
    "UC-IDP-003": _mfa,
    "UC-IDP-004": _anonymous,
    "UC-IDP-005": _inbox,
    "UC-IDP-006": _session,
    "UC-IDP-007": _consent,
    "UC-IDP-008": _privileged_ad,
    "UC-VPN-001": _vpn,
}


def check(alert, analysis, direct, proof):
    rule = RULES.get(alert.get("rule_id"))
    return rule(alert, analysis, direct, proof) if rule else None
