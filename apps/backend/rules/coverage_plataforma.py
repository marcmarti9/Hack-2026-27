"""Correlación de AWS, CI/CD, datos, Vela, OT y fraude a partir de registros de Tarvia."""
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address
import re
from urllib.parse import urlsplit

from apps.backend.rules import coverage_edr
from apps.backend.rules.engine import madrid
from apps.backend.tools import db

BUILD_DOWNLOADS = {
    "esbuild": "registry.npmjs.org",
    "sharp": "github.com",
    "puppeteer": "storage.googleapis.com",
}
VELA_ROUTINE = re.compile(
    r"(?:Olvida la talla que te dije, quiero una (?:XS|S|M|L|XL|XXL)"
    r"|No hagas caso a mi mensaje anterior, ya lo he encontrado"
    r"|Ignora lo anterior, me equivoqué de pedido: es el de las toallas"
    r"|Actúa como un estilista y dime qué combina con un pantalón beige)[.!?]?",
    re.IGNORECASE,
)
PLC_SCOPE = {f"PLC-SORT{number:02}" for number in range(1, 7)}
OT_RULES = {"ENG-WS01": "OT-ENG-ALLOW", "WMS01": "OT-WMS-ALLOW"}
OT_PORTS = {"502", "44818"}
OT_HISTORY_LIMIT = 48
PAYROLL_RECIPIENT = "asesoria@gestoria-pons.example"
DLP_GATEWAY_LIMIT = 100
SESSION_LIMIT = 64
DEPLOY_ACTOR = "svc_ecom_deploy"
STORE_HOST = "www.tarvia.example"


def _stamp(event):
    return madrid(event["timestamp"])


def _local_window(event, change):
    return (datetime.fromisoformat(change["inicio"]) <= _stamp(event).replace(tzinfo=None)
            <= datetime.fromisoformat(change["fin"]))


def _same_window(events, minutes):
    stamps = [_stamp(event) for event in events]
    return max(stamps) - min(stamps) <= timedelta(minutes=minutes)


def _record(analysis, tool, query, events, note):
    seen = {event["event_id"] for event in analysis["events"]}
    for event in events:
        if event["event_id"] not in seen:
            analysis["events"].append(event)
            seen.add(event["event_id"])
    analysis["trace"].append({"tool": tool, "query": query, "count": len(events), "note": note})


def _scope_pending(proof, events, summary, question, recipients=()):
    return {**proof("needs_more_info", [], summary, questions=(question,)),
            "context_citations": [event["event_id"] for event in events], "escalate": list(recipients)}


def _host_matches(claim, hostname, ip):
    return (not claim.get("hostname") or claim["hostname"].casefold() == hostname.casefold()) and (
        not claim.get("ip") or claim["ip"] == ip)


def _store_url(value):
    try:
        url = urlsplit(value)
        return (url.scheme == "https" and url.hostname == STORE_HOST
                and url.port in (None, 443) and url.username is None)
    except ValueError:
        return False


def _actor(event):
    return (event.get("userIdentity") or {}).get("userName")


def _key(event):
    return (event.get("userIdentity") or {}).get("accessKeyId")


def _params(event):
    return event.get("requestParameters") or {}


def _successful_cloud(events):
    return [event for event in events if event["source"] == "cloudtrail" and not event.get("errorCode")]


def _public_bucket_acl(events, bucket, stamp):
    return [event for event in events if event.get("eventName") == "PutBucketAcl"
            and event.get("eventSource") == "s3.amazonaws.com" and _params(event).get("bucketName") == bucket
            and abs(_stamp(event) - stamp) <= timedelta(minutes=10)
            and str(_params(event).get("x-amz-acl") or "").casefold()
            in {"public-read", "public-read-write", "authenticated-read"}]


def _acl_review(events, proof):
    return {**proof("needs_more_info", events, "CloudTrail registró una ACL exitosa de acceso amplio que modifica "
                    "el alcance de acceso del depósito. Falta revisar los permisos efectivos.",
                    questions=("¿Qué permisos sobre el depósito concedió la ACL y quién los autorizó?",)),
            "escalate": ["N2"]}


def _cloud_crm_downloads(alert, cloud, events, runner_ip, proof):
    if cloud.get("bucket") != "tarvia-backups-prod":
        return None
    origins = set()
    for value in alert["entities"].get("ips", []):
        try:
            origins.add(str(ip_address(value)))
        except ValueError:
            continue
    origins.discard(runner_ip)
    stamp = madrid(alert["created_at"])
    access_key = cloud.get("access_key")
    downloads = [event for event in events if _actor(event) == cloud["identity"]
                 and _key(event) and (not access_key or _key(event) == access_key)
                 and event.get("sourceIPAddress") in origins and event.get("eventName") == "GetObject"
                 and event.get("eventSource") == "s3.amazonaws.com" and _params(event).get("bucketName") == cloud["bucket"]
                 and str(_params(event).get("key") or "").startswith("sql/CRM_PROD/")
                 and type(event.get("bytes_transferred")) is int and event["bytes_transferred"] > 0
                 and abs(stamp - _stamp(event)) <= timedelta(minutes=15)]
    if downloads:
        volume = sum(event["bytes_transferred"] for event in downloads)
        return {**proof("true_positive", downloads, "CloudTrail confirma lecturas de copias del CRM "
                        f"({len(downloads)} operaciones GetObject y {volume:,} bytes) en los registros citados. "
                        "Puede haber más datos afectados.",
                        questions=("¿Cuál es el alcance total de la exposición y qué datos personales contenían las copias?",),
                        actions=("Conservar CloudTrail y escalar a N2, DPO y al responsable de Cloud.",)),
                "escalate": ["N2", "DPO"], "verified_impact": "descarga de copias del CRM"}
    return None


def _cloud(alert, analysis, direct, proof):
    rule = alert["rule_id"]
    cloud = alert["entities"].get("cloud") or {}
    events = _successful_cloud(direct)
    identity = cloud.get("identity")
    bucket = cloud.get("bucket")
    if not events or not identity:
        return None
    runner = db.asset("CI-RUNNER01")
    if not runner:
        return None
    if rule == "UC-CLD-004":
        return _cloud_crm_downloads(alert, cloud, events, runner["ip"], proof)
    if rule == "UC-CLD-003" and bucket:
        if acl_changes := _public_bucket_acl(events, bucket, madrid(alert["created_at"])):
            return _acl_review(acl_changes, proof)
    if any(_actor(event) != identity for event in events):
        return None
    origin = events[0].get("sourceIPAddress")
    if not origin or any(event.get("sourceIPAddress") != origin for event in events):
        return None

    if rule == "UC-CLD-003":
        authorized = (bucket == "tarvia-media-public" and identity == DEPLOY_ACTOR and origin == runner["ip"]
                      and all(event.get("eventName") == "PutBucketPolicy"
                              and event.get("eventSource") == "s3.amazonaws.com"
                              and re.fullmatch(r"terraform/[\d.]+", event.get("userAgent") or "")
                              and _params(event).get("bucketName") == bucket
                              and _params(event).get("policy") == "s3:GetObject para Principal * (imágenes de producto)"
                              for event in events))
        if authorized and len(events) == len(analysis["requested"]):
            stamp = _stamp(events[0])
            nearby = db.search_logs(bucket, "cloudtrail", desde=(stamp - timedelta(minutes=10)).isoformat(),
                                    hasta=(stamp + timedelta(minutes=10)).isoformat(), limit=100)
            successful = _successful_cloud(nearby)
            acl_changes = _public_bucket_acl(successful, bucket, stamp)
            policy_changes = [event for event in successful if _params(event).get("bucketName") == bucket
                              and event.get("eventName") == "PutBucketPolicy"]
            _record(analysis, "Permisos del depósito", "Cambios de política y ACL del mismo depósito en ±10 min",
                    [*policy_changes, *acl_changes],
                    "Se comprobaron actor, origen y alcance para detectar cambios contradictorios.")
            if acl_changes:
                return _acl_review([*events, *acl_changes], proof)
            indexed = {event["event_id"] for event in policy_changes}
            if (len(nearby) < 100 and {event["event_id"] for event in events} <= indexed
                    and all(_actor(event) == identity and event.get("sourceIPAddress") == origin
                            and _params(event).get("policy") == _params(events[0]).get("policy")
                            for event in policy_changes)):
                return {**proof("benign_true_positive", events, "Terraform desde el runner de Tarvia aplicó "
                                "solo lectura pública de imágenes al depósito de medios.",
                                basis="Coinciden identidad de despliegue, origen de inventario y alcance exacto de la política."),
                        "auto_close": True}
        public_change = [event for event in events if event.get("eventName") == "PutBucketPolicy"
                         and _params(event).get("bucketName") == bucket
                         and "Principal *" in str(_params(event).get("policy", ""))]
        if public_change:
            return {**proof("needs_more_info", public_change, "CloudTrail registró un cambio exitoso con principal "
                            "público. El cambio no coincide con el flujo de medios comprobado.",
                            questions=("¿Qué acciones y objetos expone la política efectiva y quién autorizó el cambio?",)),
                    "escalate": ["N2"]}
        return None

    try:
        ip_address(origin)
    except ValueError:
        return None
    if origin == runner["ip"]:
        return None
    if origin not in alert["entities"].get("ips", []):
        return None
    access_key = _key(events[0])
    if not access_key or any(_key(event) != access_key for event in events):
        return None

    if rule == "UC-CLD-001":
        operations = {event.get("eventName") for event in events}
        if not {"GetCallerIdentity", "ListBuckets", "ListUsers"}.issubset(operations) or not _same_window(events, 10):
            return None
        if cloud.get("access_key") and cloud["access_key"] != access_key:
            return _scope_pending(proof, events, "CloudTrail registra reconocimiento con una clave distinta de la "
                                  "declarada. Sus operaciones quedan como contexto.",
                                  "¿Qué registros corresponden a la clave declarada?", ("N2",))
        stamp = min(_stamp(event) for event in events)
        previous = db.search_logs(access_key, "cloudtrail", desde=(stamp - timedelta(days=7)).isoformat(),
                                  hasta=(stamp - timedelta(milliseconds=1)).isoformat(), limit=80)
        baseline = [event for event in _successful_cloud(previous) if _key(event) == access_key
                    and _actor(event) == identity and event.get("sourceIPAddress") == runner["ip"]][:2]
        _record(analysis, "Historial CloudTrail", "Origen habitual de la misma clave", baseline,
                "Ventana de siete días, limitada a 80 resultados.")
        if baseline:
            return {**proof("true_positive", [*events, *baseline], "La misma clave que se usaba desde el runner "
                            "ejecutó reconocimiento exitoso de identidad, usuarios y depósitos desde otro origen. "
                            "Debe comprobarse cómo se obtuvo la clave.",
                            actions=("Solicitar a N2 la revisión y rotación de la clave.",)),
                    "escalate": ["N2"], "verified_impact": "API de AWS accesible con una clave desde el origen observado"}
    elif rule == "UC-CLD-002":
        target = cloud.get("new_user")
        if not target:
            return None
        actions = {event["eventName"]: event for event in events if _params(event).get("userName") == target}
        if {"CreateUser", "AttachUserPolicy", "CreateAccessKey"} <= actions.keys():
            sequence = [actions[name] for name in ("CreateUser", "AttachUserPolicy", "CreateAccessKey")]
            if (_params(sequence[1]).get("policyArn") == "arn:aws:iam::aws:policy/AdministratorAccess"
                    and [_stamp(event) for event in sequence] == sorted(_stamp(event) for event in sequence)
                    and _same_window(sequence, 10)):
                return {**proof("true_positive", sequence, "La misma identidad creó un usuario, le adjuntó "
                                "AdministratorAccess y generó una clave desde el mismo origen en menos de diez minutos. "
                                "Se confirmó la persistencia administrativa en CloudTrail.",
                                actions=("Solicitar a N2 desactivar la clave y revisar la identidad creada.",)),
                        "escalate": ["N2"], "verified_impact": "creación de una identidad administrativa con clave"}
    return None


def _runner_events(alert, direct):
    runner = db.asset("CI-RUNNER01")
    hosts = alert["entities"].get("hosts", [])
    if not runner or not any(host.get("hostname") == runner["hostname"] and host.get("ip") == runner["ip"]
                            for host in hosts):
        return []
    return [event for event in direct if event["source"] == "cicd_builds"
            and event.get("runner") == runner["hostname"] and event.get("pipeline") == "ecom-frontend"]


def _cicd(alert, analysis, direct, proof):
    events = _runner_events(alert, direct)
    for event in events:
        step = event.get("step") or ""
        if not step.startswith("postinstall:") or event.get("status") != "ok" or not event.get("build_id"):
            continue
        package = step.removeprefix("postinstall:")
        details = event.get("details") or {}
        env = details.get("env_read")
        network = details.get("network") or ""
        expected_host = BUILD_DOWNLOADS.get(package)
        if (expected_host and isinstance(env, list) and set(env) == {"PATH", "HOME"}
                and details.get("stdout") == "binary downloaded"
                and network == f"GET https://{expected_host}/... (binario de plataforma)"
                and len(direct) == len(analysis["requested"]) == 1):
            return {**proof("benign_true_positive", [event], f"El postinstall de {package} descargó el binario "
                            "desde el origen previsto y solo leyó PATH y HOME.",
                            basis="Coinciden runner, pipeline, paquete, operación de descarga y variables registradas."),
                    "auto_close": True}
        if not isinstance(env, list) or not {"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"}.issubset(env):
            continue
        pieces = network.split()
        if len(pieces) < 2 or pieces[0] != "POST":
            continue
        try:
            destination = urlsplit(pieces[1]).hostname
        except ValueError:
            continue
        if not destination or destination not in alert["entities"].get("domains", []):
            continue
        installs = [entry for entry in events if entry.get("step") == "npm ci" and entry.get("build_id") == event["build_id"]]
        for install in installs:
            additions = (install.get("details") or {}).get("new_packages") or []
            if any(add.get("name") == package and "público" in (add.get("registry") or "")
                   and "registro interno" in (add.get("expected") or "") for add in additions):
                return {**proof("true_positive", [install, event], "El mismo build instaló desde el registro público "
                                "un paquete esperado en el interno. El postinstall leyó variables de AWS y registró "
                                "un POST al dominio de la alerta. El contenido enviado no figura en los registros.",
                                actions=("Escalar a N2 y rotar las credenciales del build con el responsable de CI/CD.",),
                                questions=("¿Se desplegó el build? ¿Qué credenciales del entorno aparecen luego en CloudTrail?",)),
                        "escalate": ["N2"], "verified_impact": "lectura de credenciales del entorno del build"}
    return None


def _web_disclosure(alert, direct, proof):
    entities = alert["entities"]
    accounts = {user.get("upn") for user in entities.get("users", [])}
    hashes = {file.get("sha256") for file in entities.get("files", []) if file.get("sha256")}
    for event in direct:
        if (event["source"] != "dlp" or event.get("channel") != "web_upload"
                or event.get("policy") != "Datos personales de clientes (RGPD)"):
            continue
        actor, hostname, destination = (event.get(key) for key in ("user", "hostname", "destination"))
        if not actor or f"{actor}@tarvia.example" not in accounts or not hostname or not destination:
            continue
        uploads = [entry for entry in direct if entry["source"] == "proxy" and entry.get("user") == actor
                   and entry.get("hostname") == hostname and entry.get("domain") == destination
                   and entry.get("method") == "POST" and entry.get("action") == "allowed"
                   and str(entry.get("status")) in {"200", "201", "204"}
                   and str(entry.get("bytes_out")).isdigit() and int(entry["bytes_out"]) > 0
                   and _same_window((event, entry), 15)]
        if not uploads:
            continue
        volume = sum(int(entry["bytes_out"]) for entry in uploads)
        first_upload = min(map(_stamp, uploads))
        archives = [entry for entry in direct if entry["source"] == "edr_events" and entry.get("hostname") == hostname
                    and entry.get("user") == f"TARVIA\\{actor}" and entry.get("event_type") == "file_create"
                    and entry.get("sha256") in hashes and _stamp(entry) <= first_upload
                    and (entry.get("details") or {}).get("encrypted") is True
                    and (entry.get("details") or {}).get("size") == event.get("file_size")
                    and str((entry.get("details") or {}).get("file_path")).endswith("\\" + str(event.get("file_name")))
                    and _same_window((event, entry), 60)]
        if not archives:
            continue
        first_archive = min(map(_stamp, archives))
        queries = [entry for entry in direct if entry["source"] == "sql_audit" and entry.get("user") == actor
                   and entry.get("client_host") == hostname and entry.get("database") == "CRM_PROD"
                   and type(entry.get("rows_returned")) is int and entry["rows_returned"] >= 10000
                   and _stamp(entry) < first_archive and _same_window((entry, event), 60)]
        if queries:
            chain = [*queries, *archives, *uploads, event]
            hosts = entities.get("hosts", [])
            asset = db.asset(hostname) if any(host.get("ip") for host in hosts) else None
            if (any(not _host_matches(host, hostname, (asset or {}).get("ip")) for host in hosts)
                    or any(domain.rstrip(".").casefold() != destination.casefold()
                           for domain in entities.get("domains", []))):
                return _scope_pending(proof, chain, "El equipo o el dominio declarados no coinciden con los de la "
                                      "transferencia observada. Sus registros quedan como contexto.",
                                      "¿Qué registros corresponden al equipo y al destino declarados?", ("N2", "DPO"))
            return {**proof("needs_more_info", chain,
                            f"SQL registró {len(queries)} consultas masivas del CRM antes de la creación de un "
                            f"archivo cifrado. El proxy aceptó {len(uploads)} envíos a {destination} "
                            f"({volume:,} bytes). Quedan por confirmar el contenido del archivo y el volumen recibido.",
                            questions=("¿Qué datos incluía el archivo cifrado y qué parte recibió el destino?",),
                            actions=("Preservar SQL, EDR, proxy y DLP. Escalar a N2 y DPO para determinar el alcance.",)),
                    "escalate": ["N2", "DPO"]}
    return None


def _dlp_gateway(event, sender, analysis, direct):
    nearby = db.events_for_entity(sender, around=event["timestamp"], horas=1, source="email",
                                  limit=DLP_GATEWAY_LIMIT)
    rows = {entry["event_id"]: entry for entry in direct}
    for entry in (*analysis["events"], *nearby):
        rows.setdefault(entry["event_id"], entry)
    mail = [entry for entry in rows.values() if entry["source"] == "email" and entry.get("direction") == "outbound"
            and entry.get("sender") == sender and isinstance(entry.get("recipients"), list)
            and _same_window((event, entry), 5)
            and any(attachment.get("name") == event["file_name"] and attachment.get("size") == event["file_size"]
                    for attachment in entry.get("attachments") or [])]
    capped = len(nearby) >= DLP_GATEWAY_LIMIT
    _record(analysis, "Pasarela de correo", "Remitente exacto y adjunto en los cinco minutos del registro DLP",
            mail, "El pivote alcanzó su límite." if capped else "Contraste de entrega y destinatarios.")
    return mail, capped


def _dlp(alert, analysis, direct, proof):
    accounts = {user.get("upn") for user in alert["entities"].get("users", [])}
    for event in direct:
        if event["source"] != "dlp" or event.get("channel") != "email":
            continue
        actor = event.get("user")
        if not actor or f"{actor}@tarvia.example" not in accounts:
            continue
        destination, filename = event.get("destination"), event.get("file_name") or ""
        size = event.get("file_size")
        if not destination or not filename or type(size) is not int or size <= 0:
            continue
        matches = event.get("matches") or {}
        sensitive = {name for name, count in matches.items() if type(count) is int and count > 0}
        if not sensitive or not isinstance(event.get("policy"), str) or "Datos personales" not in event["policy"]:
            continue
        authorized_payroll = False
        if destination == PAYROLL_RECIPIENT:
            change = next((item for item in analysis["context"]["cambios"] if item["id"] == "FLUJO-0007"), None)
            user = db.user(actor)
            authorized_payroll = (change and _local_window(event, change) and user and user["status"] == "active"
                                  and user["department"] == "Personas" and "nóminas" in user["title"].lower()
                                  and user["workstation"] == event.get("hostname") and event.get("action") == "audit"
                                  and event.get("policy") == "Datos personales de empleados"
                                  and re.fullmatch(r"variables_nomina_[a-z]{3}\.xlsx", filename)
                                  and sensitive == {"dni_nie", "iban"})
        candidates, capped = _dlp_gateway(event, f"{actor}@tarvia.example", analysis, direct)
        mail = [entry for entry in candidates if destination in entry["recipients"]]
        if authorized_payroll:
            mismatched_delivery = [entry for entry in candidates
                                   if destination not in entry["recipients"] and entry.get("action") == "delivered"
                                   and any(isinstance(recipient, str) and "@" in recipient
                                           and not recipient.lower().endswith("@tarvia.example")
                                           for recipient in entry["recipients"])]
            if mismatched_delivery:
                return {**proof("needs_more_info", [event, *mail, *mismatched_delivery],
                                "La pasarela registró una entrega cercana del mismo adjunto a otro destinatario "
                                "externo. Falta confirmar si corresponde al envío de nómina observado por DLP.",
                                questions=("¿Qué mensaje y destinatarios corresponden a este registro de nómina?",)),
                        "escalate": ["N2", "DPO"]}
        unauthorized_mail = [entry for entry in mail if any(
            isinstance(recipient, str) and "@" in recipient and not recipient.lower().endswith("@tarvia.example")
            and not (authorized_payroll and recipient == PAYROLL_RECIPIENT) for recipient in entry["recipients"])]
        delivered = [entry for entry in unauthorized_mail if entry.get("action") == "delivered"]
        outcomes = {(entry.get("action"), frozenset(value for value in entry["recipients"] if isinstance(value, str)))
                    for entry in mail}
        if len(outcomes) > 1 and (authorized_payroll or unauthorized_mail):
            return {**proof("needs_more_info", [event, *mail], "La pasarela contiene resultados o destinatarios distintos "
                            "para el mismo adjunto. Falta confirmar qué entrega corresponde al registro DLP.",
                            questions=("¿Qué mensaje y destinatarios corresponden al envío de datos personales?",)),
                    "escalate": ["N2", "DPO"]}
        if delivered:
            return {**proof("true_positive", [event, *delivered], "DLP detectó datos personales y la pasarela registra "
                            "la entrega del mismo adjunto a un destinatario externo fuera del flujo autorizado. "
                            "La confirmación final de alcance corresponde al DPO.",
                            actions=("Preservar el correo y escalar a N2 y DPO.",)),
                    "escalate": ["N2", "DPO"], "verified_impact": "entrega externa de adjunto con datos personales"}
        if authorized_payroll and (capped or unauthorized_mail):
            return {**proof("needs_more_info", [event, *mail], "La evidencia de la pasarela no permite confirmar "
                            "que el envío se limitara a la gestoría autorizada.",
                            questions=("¿Qué destinatarios confirma la pasarela para este adjunto?",)),
                    "escalate": ["N2"]}
        if authorized_payroll and len(direct) == len(analysis["requested"]) == 1:
            return {**proof("benign_true_positive", [event], "DLP marcó el envío de variables de nómina "
                            "desde el puesto del operador de Nóminas a la gestoría autorizada.",
                            basis="FLUJO-0007 vigente. Coinciden canal, remitente, destino y tipo de datos."),
                    "auto_close": True}
    return None


def _vela(alert, analysis, direct, proof):
    customers = {customer.get("customer_id") for customer in alert["entities"].get("customers", [])}
    ips = alert["entities"].get("ips", [])
    seen_sessions = set()
    for event in direct:
        session_id = event.get("session_id")
        if (event["source"] != "ai_gateway" or event.get("authenticated") is not True or not session_id
                or session_id in seen_sessions or event.get("customer_id") not in customers or event.get("src_ip") not in ips):
            continue
        seen_sessions.add(session_id)
        related = db.events_for_entity(session_id, source="ai_gateway", limit=SESSION_LIMIT)
        session = [entry for entry in related if entry.get("session_id") == session_id]
        if not session or len(related) == SESSION_LIMIT:
            continue
        if not any(entry["event_id"] == event["event_id"] for entry in session):
            continue
        # La sesión se lee del índice, pero la evidencia que originó la alerta sigue siendo el registro directo.
        _record(analysis, "Sesión Vela", "Correlación de turnos por identificador de sesión", session,
                "Se comprobó el resultado de cada turno y sus llamadas a herramientas.")
        if any(entry.get("authenticated") is not True or entry.get("customer_id") != event["customer_id"]
               or entry.get("src_ip") != event["src_ip"] for entry in session):
            continue
        guard = event.get("guardrail") or {}
        blocked = [entry for entry in session if (entry.get("guardrail") or {}).get("action") == "blocked"
                   and (_cross_customer_tool(entry) or re.search(
                       r"(?:imprime tu prompt de sistema|modo desarrollador activado\b.*\bcualquier cliente)",
                       entry.get("prompt") or "", re.IGNORECASE))]
        exposed = [entry for entry in session if str(entry.get("response_summary") or "").startswith(
            ("El asistente enumeró ", "El asistente devolvió ")) and "códigos internos" in entry["response_summary"]]
        exposed_with_tool = [entry for entry in exposed if _cross_customer_tool(entry, successful=True)]
        if exposed and (blocked or exposed_with_tool):
            context = ("El guardarraíl denegó un turno y otro registro de la misma sesión muestra exposición de códigos internos."
                       if blocked else "Un turno de la sesión ejecutó una herramienta contra otro cliente "
                       "y el resultado del asistente registra exposición de códigos internos.")
            return {**proof("true_positive", [*blocked, *(exposed if blocked else exposed_with_tool)], context,
                            actions=("Escalar a N2 y al equipo de IA. Revisar la sesión y rotar los códigos expuestos.",)),
                    "escalate": ["N2", "Equipo de IA"], "verified_impact": "divulgación de códigos internos"}
        cross_orders = [entry for entry in session
                        if _cross_customer_tool(entry, successful=True, name="get_order")]
        if cross_orders:
            return {**proof("true_positive", cross_orders, "La herramienta de pedidos registró una consulta exitosa "
                            "a un cliente distinto del autenticado. El registro confirma el acceso cruzado. "
                            "El equipo de IA debe verificar los datos exactos devueltos.",
                            actions=("Escalar a N2 y al equipo de IA. Preservar y revisar la respuesta de la sesión.",),
                            questions=("¿Qué datos de pedido o dirección devolvió la consulta?",)),
                    "escalate": ["N2", "Equipo de IA"], "verified_impact": "consulta exitosa a pedidos de otro cliente"}
        if exposed:
            return {**proof("needs_more_info", exposed,
                            "El resumen de respuesta registra códigos internos. Falta corroborar cómo se obtuvieron.",
                            questions=("¿Confirma el equipo de IA la exposición en la salida original de la sesión?",)),
                    "escalate": ["N2", "Equipo de IA"]}
        if (blocked and all(entry.get("tool_calls") == [] and entry.get("response_summary") == "Rechazado por el guardarraíl"
                            for entry in session)):
            return {**proof("true_positive", blocked, "La sesión contiene un intento de manipulación que el guardarraíl "
                            "rechazó. Los turnos recuperados no registran ejecución de herramientas.",
                            actions=("Registrar el intento y avisar al equipo de IA.",),
                            questions=("¿La misma cuenta o IP lo intentó en otras sesiones?",)),
                    "escalate": ["Equipo de IA"]}
        if (alert["rule_id"] == "UC-AI-001" and guard.get("category") == "prompt_injection"
                and guard.get("action") == "flagged" and VELA_ROUTINE.fullmatch(event.get("prompt") or "")
                and all(entry.get("tool_calls") == [] and entry.get("response_summary") == "Respuesta normal tras revisión"
                        and VELA_ROUTINE.fullmatch(entry.get("prompt") or "") for entry in session)):
            return {**proof("false_positive", session, "Se comprobó una petición normal de compra o una "
                            "corrección del cliente. Los turnos de la sesión no ejecutaron herramientas.",
                            basis="Prompt completo y actividad de sesión corroborados en el registro de Vela."),
                    "auto_close": True}
    return None


def _cross_customer_tool(event, *, successful=False, name=None):
    for tool in event.get("tool_calls") or []:
        if name and tool.get("name") != name:
            continue
        target = (tool.get("args") or {}).get("customer_id")
        result = str(tool.get("result") or "").casefold()
        verified = result in {"ok", "success"} if successful else result.startswith("denied: customer_id mismatch")
        if target and target != event.get("customer_id") and verified:
            return True
    return False


def _ot_precursors(event, hostname, analysis, proof, direct):
    origin, end = event["src_ip"], _stamp(event).astimezone(timezone.utc)
    start = end - timedelta(hours=2)
    center = (end - timedelta(hours=1)).isoformat()
    fw = db.events_for_entity(origin, around=center, horas=1, source="firewall", limit=OT_HISTORY_LIMIT)
    edr = db.events_for_entity(hostname, around=center, horas=1, source="edr_events", limit=OT_HISTORY_LIMIT)
    previous_fw = [entry for entry in fw if entry.get("src_ip") == origin and start <= _stamp(entry) < end]
    previous_edr = [entry for entry in edr if entry["source"] == "edr_events"
                    and entry.get("hostname") == hostname and start <= _stamp(entry) < end]
    suspicious = [entry for entry in previous_fw if entry.get("zone_dst") == "LOGISTICS-OT"
                  and str(entry.get("dst_port")) in OT_PORTS
                  and (entry.get("action") in {"deny", "block", "reject"} or (
                       entry.get("action") == "allow"
                       and entry.get("rule") != OT_RULES.get(hostname, "OT-MAINT-TEMP")))]
    suspicious.extend(entry for entry in previous_edr
                      if coverage_edr.recovery_attempt(entry) or coverage_edr.lsass_attempt(entry))
    capped = len(fw) >= OT_HISTORY_LIMIT or len(edr) >= OT_HISTORY_LIMIT
    _record(analysis, "Actividad previa OT", "Firewall y EDR del origen exacto en las dos horas anteriores",
            suspicious, f"Registros anteriores del origen: {len(previous_fw)} de firewall y {len(previous_edr)} de EDR. "
            + ("Consulta limitada, historial incompleto." if capped
               else "La ausencia de señales en estas fuentes no cubre actividad fuera de la ventana ni fuentes ausentes."))
    if suspicious or capped:
        summary = ("Hay señales previas del mismo origen que impiden confirmar el cierre de la conexión OT."
                   if suspicious else "El historial del origen excede el límite de la consulta. Falta verificar la actividad previa.")
        return {**proof("needs_more_info", [*direct, *suspicious], summary,
                        questions=("¿Qué actividad previa observan N2 y Operaciones en el origen?",),
                        actions=("Preservar los registros y preparar el aviso a N2 y Operaciones.",)),
                "escalate": ["N2", "Responsable de Operaciones"]}
    return None


def _ot(alert, analysis, direct, proof):
    if not direct or len(direct) != len(analysis["requested"]):
        return None
    assets = {asset["ip"]: asset for asset in analysis["context"]["activos"]}
    change = next((item for item in analysis["context"]["cambios"] if item["id"] == "CHG-2026-1063"), None)
    reasons = set()
    destinations = {}
    windows = {}
    for event in direct:
        if (event["source"] != "firewall" or event.get("zone_dst") != "LOGISTICS-OT"
                or event.get("action") != "allow" or str(event.get("dst_port")) not in OT_PORTS
                or event.get("proto") != "TCP"):
            return None
        source, destination = assets.get(event.get("src_ip")), event.get("dst_ip")
        if not source or not destination:
            return None
        if destination not in destinations:
            destinations[destination] = db.asset(destination)
        target = destinations[destination]
        if not target or target["zone"] != "LOGISTICS-OT" or target["hostname"] not in PLC_SCOPE:
            return None
        expected_rule = OT_RULES.get(source["hostname"])
        if expected_rule and event.get("rule") == expected_rule:
            reasons.add("Origen permanente autorizado por RB-08")
        elif (source["hostname"] == "JUMP01" and event.get("rule") == "OT-MAINT-TEMP" and change
              and _local_window(event, change)):
            reasons.add("Mantenimiento CHG-2026-1063 dentro de su ventana")
        else:
            return None
        windows[event["src_ip"], _stamp(event)] = event
    if any(not any(_host_matches(host, assets[origin]["hostname"], origin) for origin, _ in windows)
           for host in alert["entities"].get("hosts", [])):
        return _scope_pending(proof, direct, "El nombre de equipo o la IP declarados no coinciden con el origen "
                              "observado. Los flujos quedan como contexto sin confirmar la autorización del aviso.",
                              "¿Qué activo de inventario originó el flujo declarado?", ("N2", "Responsable de Operaciones"))
    for (origin, _), event in windows.items():
        if pending := _ot_precursors(event, assets[origin]["hostname"], analysis, proof, direct):
            return pending
    return {**proof("benign_true_positive", direct, "El tráfico fue hacia el clasificador de Martorell "
                    "por un puerto industrial previsto, desde un origen con autorización comprobada.",
                    basis=". ".join(sorted(reasons)) + ". Coinciden origen, destino, protocolo y regla de firewall."),
            "auto_close": True, "ot_authorized": True}


def _ato(alert, analysis, direct, proof):
    entities = alert["entities"]
    customers = {customer.get("customer_id") for customer in entities.get("customers", [])}
    ips = entities.get("ips", [])
    for changed in direct:
        customer, origin = changed.get("customer_id"), changed.get("src_ip")
        kind = changed.get("event")
        if (changed["source"] != "ecom_account" or kind not in {"email_change", "address_change"}
                or not customer or customer not in customers or origin not in ips):
            continue
        if kind == "email_change" and (changed.get("details") or {}).get("new_email_domain") != "tempmail-box.example":
            continue
        stamp = _stamp(changed)
        payments = [entry for entry in direct if entry["source"] == "ecom_account"
                    and entry.get("customer_id") == customer and entry.get("src_ip") == origin
                    and entry.get("event") == "giftcard_purchase"
                    and (entry.get("details") or {}).get("payment") == "saved_card"
                    and timedelta(0) <= _stamp(entry) - stamp <= timedelta(minutes=30)]
        if not payments:
            continue
        logs = db.events_for_entity(customer, around=changed["timestamp"], horas=1, source="ecom_auth", limit=80)
        logins = [entry for entry in logs if entry.get("customer_id") == customer and entry.get("src_ip") == origin
                  and entry.get("result") == "success" and str(entry.get("device_fp") or "").startswith("fp-headless-")
                  and timedelta(0) <= stamp - _stamp(entry) <= timedelta(hours=1)]
        _record(analysis, "Autenticación de cliente", "Accesos del cliente antes del cambio", logins,
                "Mismo cliente y origen, con huella de automatización.")
        if logins:
            if (any(domain.rstrip(".").casefold() != STORE_HOST for domain in entities.get("domains", []))
                    or any(not _store_url(value) for value in entities.get("urls", []))):
                return _scope_pending(proof, [*logins, changed, *payments], "El comercio declarado no coincide con "
                                      "la tienda de Tarvia. Los registros de Tarvia quedan como contexto.",
                                      "¿Qué registros corresponden al comercio declarado?")
            change = "al cambio a correo temporal" if kind == "email_change" else "al cambio de dirección"
            return {**proof("true_positive", [logins[-1], changed, *payments], "Un login exitoso automatizado "
                            f"precedió {change} y la compra de tarjeta regalo con una tarjeta "
                            "guardada. Coinciden cliente y origen. El titular debe confirmar si autorizó la operación.",
                            actions=("Escalar a Fraude y N2. Conservar el acceso, el cambio y la compra en el expediente.",)),
                    "escalate": ["N2", "Fraude"], "verified_impact": "compra con tarjeta guardada"}
    return None


def check(alert, analysis, direct, proof):
    """Devuelve un hallazgo respaldado o cede a las reglas generales y al modelo."""
    rule = alert["rule_id"]
    if rule.startswith("UC-CLD-"):
        return _cloud(alert, analysis, direct, proof)
    if rule == "UC-DEV-001":
        return _cicd(alert, analysis, direct, proof)
    if rule == "UC-DLP-001":
        return _web_disclosure(alert, direct, proof)
    if rule == "UC-DLP-002":
        return _dlp(alert, analysis, direct, proof)
    if rule in {"UC-AI-001", "UC-AI-002"}:
        return _vela(alert, analysis, direct, proof)
    if rule == "UC-OT-001":
        return _ot(alert, analysis, direct, proof)
    if rule == "UC-WEB-003":
        return _ato(alert, analysis, direct, proof)
    return None
