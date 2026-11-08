"""Clasificación EDR y pivotes de preransomware sobre registros originales."""

import re
from base64 import b64decode
from binascii import Error as Base64Error
from datetime import datetime, timedelta
from pathlib import PureWindowsPath
from urllib.parse import urlsplit

from apps.backend.rules.engine import madrid
from apps.backend.tools import db

SAP_GUI_SHA256 = "84bd19b4b49dbf3c466d6c0907b317e7299d6fe18b90c7756d9ba7044e4978cf"
SAP_GUI_PATH = r"c:\program files\sap\frontend\sapgui\saplogon.exe"
SAP_GUI_COMMAND = r'saplogon.exe /ini_file="\\fs01\sap\saplogon.ini"'
CHAIN_RULES = {"UC-EDR-001", "UC-EDR-004", "UC-EDR-007", "UC-EDR-008", "UC-EDR-011", "UC-NET-004"}
CHAIN_PIVOTS = {"UC-EML-002", "UC-NET-001", "UC-IDP-008"}
DISCOVERY = {"whoami.exe", "net.exe", "nltest.exe", "adf.exe", "adfind.exe", "net1.exe"}


def _windows_image(basename):
    return rf'(?:"(?:[^"\r\n]+\\)?{basename}"|(?:[^\s"]+\\)?{basename})'


RECOVERY_COMMANDS = {
    "vssadmin.exe": re.compile(_windows_image(r"vssadmin(?:\.exe)?") + r"[ \t]+delete[ \t]+shadows(?=$|[ \t])", re.I),
    "wbadmin.exe": re.compile(_windows_image(r"wbadmin(?:\.exe)?") + r"[ \t]+delete[ \t]+catalog(?=$|[ \t])", re.I),
    "wmic.exe": re.compile(
        _windows_image(r"wmic(?:\.exe)?")
        + r'[ \t]+(?:shadowcopy|path[ \t]+(?:win32_shadowcopy|"win32_shadowcopy"))[ \t]+delete'
          r"(?:[ \t]+/nointeractive)?[ \t]*$", re.I,
    ),
}
LSASS_TARGET = re.compile(r"lsass\.exe(?:[ \t]+\(pid[ \t]+([0-9]+)\))?", re.I)
LSASS_DUMP = re.compile(
    _windows_image(r"rundll32(?:\.exe)?") + r"[ \t]+" + _windows_image(r"comsvcs\.dll")
    + r"(?:[ \t]*,[ \t]*|[ \t]+)minidump[ \t]+([0-9]+)[ \t]+\S", re.I,
)
SHADOW_PIPELINE = re.compile(
    r"""(?:get-ciminstance|get-wmiobject)[ \t]+(?:-classname[ \t]+)?(["']?)win32_shadowcopy\1[ \t]*"""
    r"\|[ \t]*(?:remove-(?:ciminstance|wmiobject)(?:[ \t]+-confirm:\$false)?"
    r"|foreach-object[ \t]*\{[ \t]*\$_\.delete\([ \t]*\)[ \t]*\})",
    re.I,
)
PS_PREFIX = (
    r'^\s*(?:powershell(?:\.exe)?|"[^"\r\n]+\\powershell\.exe"|[^\s"]+\\powershell\.exe)'
    r'(?:[ \t]+-(?:noprofile|noninteractive|nologo|executionpolicy[ \t]+\w+))*[ \t]+'
)
PS_COMMAND = re.compile(PS_PREFIX + r"-(?:command|c)[ \t]+(.+)", re.I)
EDR_STOP = re.compile(
    _windows_image(r"sc(?:\.exe)?") + r'[ \t]+stop[ \t]+(?:edragentsvc|"edragentsvc")(?=$|[ \t])', re.I,
)
WEB_SHELL_COMMAND = re.compile(r"(?:/dev/tcp/|\bbase64\b[^|]*\|\s*(?:bash|sh)\b|\bnc\s+-e\b|\b-encodedcommand\s+\S+)", re.I)
ENCODED_PS = re.compile(PS_PREFIX + r'-(?:encodedcommand|enc)[ \t]+("?)([a-z0-9+/=]{12,8192})\1[ \t]*$', re.I)


def _lower(value):
    return value.strip().lower() if isinstance(value, str) else ""


def _account(value):
    # Los registros AD y proxy usan el nombre corto del mismo usuario de Tarvia.
    raw = _lower(value)
    if "\\" in raw:
        domain, _, username = raw.rpartition("\\")
        return username if domain == "tarvia" else raw
    if "@" in raw:
        username, _, domain = raw.rpartition("@")
        return username if domain == "tarvia.example" else f"{domain}\\{username}"
    return raw


def _details(event):
    value = event.get("details")
    return value if isinstance(value, dict) else {}


def _ts(event):
    return madrid(event["timestamp"])


def _near(first, second, minutes=10):
    return abs(_ts(first) - _ts(second)) <= timedelta(minutes=minutes)


def _covers_edr_window(event, *, before=0, after):
    bounds = db.source_bounds("edr_events")
    if not bounds:
        return False
    stamp = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
    first, last = bounds
    return first <= stamp - timedelta(hours=before) and stamp + timedelta(hours=after) <= last


def _pid_reassigned(process, event, observations):
    start, end = _ts(process), _ts(event)
    return any(candidate.get("event_type") == "process_start"
               and candidate.get("hostname") == process.get("hostname") and candidate.get("pid") == process.get("pid")
               and start < _ts(candidate) <= end for candidate in observations)


def _same_process(child, parent, minutes=30, *, observations=()):
    return (
        child.get("hostname") == parent.get("hostname") and bool(parent.get("pid"))
        and child.get("parent_pid") == parent["pid"]
        and _lower(child.get("parent_name")) == _lower(parent.get("process_name"))
        and timedelta(0) <= _ts(child) - _ts(parent) <= timedelta(minutes=minutes)
        and not _pid_reassigned(parent, child, observations)
    )


def _scope(alert, direct):
    assets = set()
    for row in alert.get("entities", {}).get("hosts", []):
        if hostname := _lower(row.get("hostname")):
            assets.add(hostname)
        elif row.get("ip") and (asset := db.asset(row["ip"])):
            assets.add(_lower(asset["hostname"]))
    stamp = madrid(alert["created_at"])
    return [
        event for event in direct if event.get("source") == "edr_events"
        and _lower(event.get("hostname")) in assets
        and abs(_ts(event) - stamp) <= timedelta(hours=24)
    ]


def _verify_entities(alert, analysis, events):
    declared = alert.get("entities", {})
    inventory = {_lower(asset["hostname"]): asset for asset in analysis["context"]["activos"]}
    hosts, users, processes = {}, {}, {}
    for event in events:
        host = event["hostname"]
        if _lower(host) not in hosts:
            asset = inventory.get(_lower(host)) or db.asset(host) or {}
            hosts[_lower(host)] = {"hostname": host, **({"ip": asset["ip"]} if asset.get("ip") else {})}
        if account := _account(event.get("user")):
            raw = event["user"]
            tarvia = _lower(raw) in {f"tarvia\\{account}", f"{account}@tarvia.example"}
            users[account] = {"upn": f"{account}@tarvia.example" if tarvia else raw}
        if name := event.get("process_name"):
            pid = event.get("pid")
            processes[(host, _lower(name), pid)] = {
                "hostname": host, "name": name, **({"pid": pid} if pid else {}),
            }

    discrepancies = []
    for row in declared.get("hosts", []):
        verified = hosts.get(_lower(row.get("hostname"))) or {}
        if row.get("ip") and verified.get("ip") and row["ip"] != verified["ip"]:
            discrepancies.append({"field": "hosts.ip", "declared": row, "verified": [verified]})
    for row in declared.get("users", []):
        if row.get("upn") and users and _account(row["upn"]) not in users:
            discrepancies.append({"field": "users.upn", "declared": row, "verified": list(users.values())})
    for row in declared.get("processes", []):
        if not row.get("pid"):
            continue
        matches = [process for process in processes.values()
                   if _lower(process["name"]) == _lower(row.get("name")) and process.get("pid")
                   and (not row.get("hostname") or _lower(process["hostname"]) == _lower(row["hostname"]))]
        if matches and all(str(row["pid"]) != str(process["pid"]) for process in matches):
            discrepancies.append({"field": "processes.pid", "declared": row, "verified": matches})
    return {"verified": {"hosts": list(hosts.values()), "users": list(users.values()),
                         "processes": list(processes.values())}, "discrepancies": discrepancies}


def _keep(analysis, events):
    """Mantiene recuperables todas las pruebas citadas por el expediente."""
    known = {event["event_id"] for event in analysis["events"]}
    for event in events:
        if event["event_id"] not in known:
            analysis["events"].append(event)
            known.add(event["event_id"])


def _trace(analysis, tool, query, events, note):
    analysis.setdefault("trace", []).append({
        "tool": tool, "query": query, "count": len(events), "note": note,
    })


def _sandbox(analysis, sha256):
    context = analysis.get("context")
    if not sha256 or context is None:
        return None
    reports = context.setdefault("sandbox", [])
    for report in reports:
        if _lower(report.get("sha256")) == _lower(sha256):
            return report
    report = db.sandbox(sha256)
    if report:
        reports.append(report)
    return report


def _sap(alert, analysis, edr, proof):
    if len(edr) != 1 or len(alert.get("related_events", [])) != 1:
        return None
    event = edr[0]
    if not (
        event.get("event_type") == "process_start"
        and _lower(event.get("process_path")) == SAP_GUI_PATH
        and _lower(event.get("command_line")) == SAP_GUI_COMMAND
        and _lower(event.get("signer")) == "sap se"
        and _lower(event.get("parent_name")) == "excel.exe"
        and _lower(event.get("sha256")) == SAP_GUI_SHA256
        and abs(_ts(event) - madrid(alert["created_at"])) <= timedelta(minutes=10)
    ):
        return None
    if not _covers_edr_window(event, after=0.5):
        return None
    nearby = db.events_for_entity(event["hostname"], event["timestamp"], horas=1, source="edr_events", limit=500)
    if len(nearby) == 500 or any(
        _same_process(candidate, event, observations=(*nearby, *analysis["events"]))
        and _lower(candidate.get("process_name")) in {"cmd.exe", "powershell.exe", "wscript.exe", "mshta.exe"}
        for candidate in (*nearby, *analysis["events"])
    ):
        return None
    return {
        **proof("false_positive", [event],
                "Excel abrió el cliente SAP GUI con la firma, el hash, la ruta y el INI corporativo "
                "esperados. En los eventos recuperados no hay un intérprete hijo vinculado al proceso.",
                basis="Perfil exacto de SAP GUI firmado y configuración corporativa."),
        "auto_close": True,
    }


def _antivirus(alert, analysis, direct, edr, proof):
    detections = [event for event in edr if event.get("event_type") == "detection" and _details(event).get("detection")]
    if not detections:
        return None
    execution_types = {"process_start", "process_access", "network_connect", "registry_set", "service_install"}
    detection_ids = {event["event_id"] for event in detections}
    incomplete = any(event.get("source") == "edr_events" and event.get("event_type") == "detection"
                     and event["event_id"] not in detection_ids for event in direct)
    executions, unblocked = {}, {}
    uncovered = truncated = False
    for event in detections:
        action = _lower(_details(event).get("action"))
        if action == "detected_only":
            unblocked[event["event_id"]] = event
        incomplete |= action not in {"blocked", "quarantined"}
        sha256 = _lower(event.get("sha256"))
        if not re.fullmatch(r"[0-9a-f]{64}", sha256):
            incomplete = True
            continue
        observations = db.events_for_entity(sha256, event["timestamp"], horas=24,
                                            source="edr_events", limit=500)
        matched = {candidate["event_id"]: candidate for candidate in (*observations, *analysis["events"], *edr)
                   if candidate.get("source") == "edr_events" and candidate.get("hostname") == event["hostname"]
                   and _lower(candidate.get("sha256")) == sha256
                   and _near(candidate, event, 24 * 60)}
        _trace(analysis, "Búsqueda EDR por hash", sha256, matched,
               "Mismo equipo dentro de ±24 horas. Límite de recuperación 500.")
        executions.update((key, row) for key, row in matched.items() if row.get("event_type") in execution_types)
        unblocked.update((key, row) for key, row in matched.items() if row.get("event_type") == "detection"
                         and _lower(_details(row).get("action")) == "detected_only")
        uncovered |= not _covers_edr_window(event, before=24, after=24)
        truncated |= len(observations) >= 500
    evidence = {event["event_id"]: event for event in detections} | unblocked | executions
    _keep(analysis, evidence.values())
    if executions:
        return {**proof("true_positive", evidence.values(),
                        "El antivirus registró una detección y el EDR vinculó un hash detectado con actividad "
                        "en el mismo equipo. Hay que investigar el alcance.",
                        actions=("Revisar el equipo y solicitar contención a N2 si procede.",)),
                "escalate": ["N2"], "verified_impact": "actividad del mismo binario observada en EDR"}
    if unblocked:
        return {**proof("true_positive", evidence.values(),
                        "El antivirus registró una detección sin bloqueo. Hace falta comprobar su ejecución.",
                        actions=("Revisar ejecución, telemetría y posible contención con N2.",)),
                "escalate": ["N2"]}
    metadata = alert.get("evidence", {})
    reported = isinstance(metadata, dict) and metadata.get("executed") is False
    verified = reported and not alert.get("external") and not (incomplete or uncovered or truncated)
    limit = (" El índice EDR no abarca toda la ventana de 24 h a cada lado." if uncovered
             else " La consulta alcanzó el límite de 500 eventos." if truncated else "")
    summary = ("Se necesita corroborar la acción o el hash de todas las detecciones." if incomplete else
               "El antivirus registró bloqueo o cuarentena y la búsqueda acotada no recuperó ejecución "
               "para los mismos hashes y equipos.")
    result = proof("true_positive", evidence.values(), summary + limit,
                   actions=("Revisar la cuarentena y programar un escaneo completo del equipo.",),
                   questions=() if verified else ("¿Confirma el EDR que todas las acciones precedieron a la ejecución?",))
    if verified:
        result.update(resolved=True, verified_prevention="acción del EDR y ausencia de ejecución de los hashes en sus equipos")
    return result


def _decode_powershell(command):
    encoded = ENCODED_PS.search(command)
    if not encoded:
        return ""
    try:
        return b64decode(encoded[2], validate=True).decode("utf-16-le")
    except (Base64Error, UnicodeError):
        return ""


def recovery_attempt(event):
    """Reconoce el lanzamiento de un comando contra las copias en la telemetría."""
    if event.get("event_type") != "process_start":
        return False
    process = _lower(event.get("process_name"))
    command = event.get("command_line") or ""
    if process == "powershell.exe":
        payload = _decode_powershell(command)
        if not payload and (plain := PS_COMMAND.fullmatch(command)):
            payload = plain[1].strip()
            if len(payload) >= 2 and payload[0] == payload[-1] == '"':
                payload = payload[1:-1]
        return bool(SHADOW_PIPELINE.fullmatch(payload.strip()))
    pattern = RECOVERY_COMMANDS.get(process)
    return bool(pattern and pattern.match(command.lstrip()))


def _encoded_powershell(edr, proof):
    for event in edr:
        if event.get("event_type") != "process_start" or _lower(event.get("process_name")) != "powershell.exe":
            continue
        payload = _decode_powershell(event.get("command_line") or "")
        if not payload:
            continue
        shadow = SHADOW_PIPELINE.fullmatch(payload.strip())
        fetch_and_run = re.search(r"\b(?:iex|invoke-expression)\b", payload, re.I) and re.search(
            r"\b(?:downloadstring|invoke-webrequest|downloadfile)\s*[( ]", payload, re.I,
        )
        if shadow or fetch_and_run:
            purpose = "inhibición de recuperación" if shadow else "descarga y ejecución de código"
            finding = {**proof("true_positive", [event], f"El EDR registró el inicio de PowerShell. "
                               f"El comando codificado contiene una operación de {purpose}. El efecto queda por verificar.",
                               actions=("Escalar a N2 y verificar el resultado y el origen del comando.",)),
                       "escalate": ["N2"]}
            if shadow:
                finding["severity_override"] = "critical"
            return finding
    return None


def lsass_attempt(event):
    """Identifica acceso a memoria de LSASS o el lanzamiento de su volcado."""
    details = _details(event)
    target = LSASS_TARGET.fullmatch(_lower(details.get("target_process")))
    if not target:
        return False
    if event.get("event_type") == "process_access":
        return bool(re.search(r"\bprocess_vm_read\b", _lower(details.get("access"))))
    if event.get("event_type") != "process_start" or _lower(event.get("process_name")) != "rundll32.exe":
        return False
    command = LSASS_DUMP.match(_lower(event.get("command_line")))
    return bool(command and (not target[1] or command[1] == target[1]))


def _malicious_process(event, analysis):
    if event.get("event_type") != "process_start":
        return None
    report = _sandbox(analysis, event.get("sha256"))
    return report if report and report.get("verdict") == "malicious" else None


def _loader_path(events, analysis):
    """Instalador hijo de un script que crea y ejecuta una DLL maliciosa conocida."""
    starts = [event for event in events if event.get("event_type") == "process_start"]
    files = [event for event in events if event.get("event_type") == "file_create"]
    for artifact in files:
        path = _lower(_details(artifact).get("file_path"))
        if not path.endswith(".dll"):
            continue
        for parent in starts:
            if (_lower(parent.get("process_name")) != "msiexec.exe" or not parent.get("pid")
                    or parent.get("pid") != artifact.get("pid") or parent.get("hostname") != artifact.get("hostname")
                    or not timedelta(0) <= _ts(artifact) - _ts(parent) <= timedelta(minutes=10)
                    or _pid_reassigned(parent, artifact, starts)):
                continue
            for launch in starts:
                if (_lower(launch.get("process_name")) == "rundll32.exe" and path in _lower(launch.get("command_line"))
                        and _same_process(launch, parent, observations=starts) and _ts(launch) >= _ts(artifact)):
                    report = _sandbox(analysis, artifact.get("sha256"))
                    if not report or report.get("verdict") != "malicious":
                        continue
                    script = next((candidate for candidate in starts
                                   if _lower(candidate.get("process_name")) in {"wscript.exe", "cscript.exe"}
                                   and _same_process(parent, candidate, observations=starts)), None)
                    if script:
                        return script, parent, artifact, launch, report
    return None


def _anydesk(edr, proof):
    for session in edr:
        details = _details(session)
        if (session.get("event_type") != "network_connect" or _lower(session.get("process_name")) != "anydesk.exe"
                or "incoming" not in _lower(details.get("session")) or "control remoto" not in _lower(details.get("session"))):
            continue
        children = [event for event in edr if _same_process(event, session, observations=edr)
                    and _lower(event.get("process_name")) in {"powershell.exe", "cmd.exe"}
                    and "\\\\" in (event.get("command_line") or "")]
        if children:
            return {**proof("true_positive", [session, *children],
                            "AnyDesk registró control remoto entrante y lanzó un intérprete que recorrió "
                            "un recurso compartido. La firma del programa no autoriza la sesión.",
                            actions=("Solicitar a N2 revisión de la sesión y del acceso a recursos compartidos.",)),
                    "escalate": ["N2"]}
    return None


def _point_of_sale(edr, proof):
    for event in edr:
        details = _details(event)
        if (event.get("event_type") == "process_access" and _lower(details.get("target_process")) == "tarviapos.exe"
                and "process_vm_read" in _lower(details.get("access"))
                and _lower(event.get("signer")) in {"", "(sin firma)"}):
            return {**proof("true_positive", [event],
                            "Un proceso sin firma accedió a la memoria del proceso de cobro. "
                            "La evidencia no identifica los datos que leyó ni una transferencia.",
                            actions=("Escalar a N2 y Negocio, preservar evidencias y revisar el alcance PCI.",),
                            questions=("¿Qué datos quedaron expuestos y existe una salida de red relacionada?",)),
                    "escalate": ["N2", "Negocio"], "verified_impact": "acceso a memoria de la aplicación de cobro"}
    return None


def _edr_stopped(event):
    return (event.get("event_type") == "agent_status" and _lower(event.get("process_name")) == "edragentsvc"
            and _lower(_details(event).get("status")) == "stopped")


def _edr_stop(event):
    return (event.get("source") == "edr_events" and event.get("event_type") == "process_start"
            and _lower(event.get("process_name")) == "sc.exe" and EDR_STOP.match(_lower(event.get("command_line"))))


def _stop_precedes_status(command, status):
    return (command.get("hostname") == status.get("hostname")
            and timedelta(0) <= _ts(status) - _ts(command) <= timedelta(minutes=5))


def _status(edr, analysis, proof):
    stopped = [event for event in edr if _edr_stopped(event)]
    observations = {event["event_id"]: event for event in (*analysis["events"], *edr)}
    for event in stopped:
        commands = [candidate for candidate in observations.values()
                    if _edr_stop(candidate) and _stop_precedes_status(candidate, event)]
        if not commands:
            start = (_ts(event) - timedelta(minutes=5)).isoformat()
            candidates = db.search_logs("edragentsvc", source="edr_events", desde=start,
                                        hasta=event["timestamp"], limit=500)
            commands = [candidate for candidate in candidates
                        if candidate["event_id"] not in observations and _edr_stop(candidate)
                        and _stop_precedes_status(candidate, event)]
        command = max(commands, key=_ts, default=None)
        if command:
            _keep(analysis, [command])
            return {**proof("true_positive", [command, event],
                            "El proceso lanzó la orden de detener el servicio EDR y el evento de estado "
                            "confirmó que quedó detenido.",
                            actions=("Escalar inmediatamente y restaurar la visibilidad del equipo con N2.",)),
                    "escalate": ["N2"], "verified_impact": "pérdida de telemetría EDR comprobada"}
    if not stopped or {event["event_id"] for event in stopped} != set(analysis["requested"]):
        return None
    for event in stopped:
        details = _details(event)
        if not (_lower(details.get("reason")) == "upgrade 7.14 -> 7.15"
                and type(details.get("restarted_after_s")) is int and 0 < details["restarted_after_s"] <= 180
                and _in_change(analysis, "CHG-2026-1080", event)
                and any(asset.get("hostname") == event["hostname"] and "windows server" in
                        _lower((db.asset(event["hostname"]) or {}).get("os"))
                        for asset in analysis["context"]["activos"])):
            return None
    return {**proof("benign_true_positive", stopped, "La detención, la versión y la recuperación del "
                    "agente EDR coinciden con el mantenimiento programado de servidores.",
                    basis="Ventana CHG-2026-1080 y recuperación del agente registradas."),
            "authorized_change": True}


def _in_change(analysis, change_id, event):
    stamp = _ts(event).replace(tzinfo=None)
    return any(
        row["id"] == change_id and datetime.fromisoformat(row["inicio"]) <= stamp <= datetime.fromisoformat(row["fin"])
        for row in analysis["context"]["cambios"]
    )


def _smb_precedes(flow, service, source_ip, target_ip):
    return (
        flow.get("source") == "firewall" and flow.get("src_ip") == source_ip and flow.get("dst_ip") == target_ip
        and _lower(flow.get("proto")) == "tcp" and str(flow.get("dst_port")) in {"445", "139"}
        and flow.get("action") == "allow" and timedelta(0) <= _ts(service) - _ts(flow) <= timedelta(minutes=3)
    )


def _approved_lateral(service, edr, analysis, proof):
    target = service["hostname"]
    nearby = db.events_for_entity(target, service["timestamp"], horas=1, source="edr_events", limit=500)
    observations = {event["event_id"]: event for event in (*nearby, *analysis["events"], *edr)}
    children = [
        event for event in observations.values() if event.get("source") == "edr_events"
        and event.get("event_type") == "process_start" and event.get("hostname") == target
        and _lower(event.get("parent_name")) == "psexesvc.exe"
        and timedelta(0) <= _ts(event) - _ts(service) <= timedelta(minutes=30)
    ]
    _keep(analysis, children)
    _trace(analysis, "Procesos de PsExec", target, children,
           "Procesos bajo PSEXESVC en los 30 minutos posteriores a la instalación.")
    recoveries = [event for event in children if recovery_attempt(event)]
    if recoveries:
        return {**proof("true_positive", [service, *recoveries],
                        "En la ventana del mantenimiento se lanzaron comandos contra las copias bajo PSEXESVC. "
                        "El cambio no cubre esos comandos y su efecto queda por verificar.",
                        actions=("Escalar a N2 y verificar el estado de las copias.",)),
                "escalate": ["N2"], "severity_override": "critical"}
    malicious = [(event, report) for event in children if (report := _malicious_process(event, analysis))]
    if malicious:
        return {**proof("true_positive", [service, *(event for event, _ in malicious)],
                        "En la ventana del mantenimiento se ejecutó un proceso bajo PSEXESVC cuyo hash "
                        "está identificado como malicioso en sandbox.",
                        actions=("Escalar a N2 y revisar el proceso observado en el servidor.",)),
                "escalate": ["N2"], "verified_impact": "ejecución de un binario malicioso durante el mantenimiento",
                "sandbox_refs": list(dict.fromkeys(report["sha256"] for _, report in malicious))}
    if children or len(nearby) == 500 or not _covers_edr_window(service, after=0.5):
        return {**proof("needs_more_info", [service, *children],
                        "La instalación coincide con el cambio. Falta verificar el alcance de los procesos "
                        "bajo PSEXESVC o completar la ventana de telemetría.",
                        questions=("¿Las ejecuciones del servidor corresponden al paquete del cambio?",)),
                "escalate": ["N2"]}
    return {**proof("benign_true_positive", [service], "PsExec ejecutó la instalación de monitorización "
                    "desde el bastión y en un servidor incluido en la ventana autorizada.",
                    basis="Origen, destino, paquete y ventana compatibles con CHG-2026-1057."),
            "auto_close": True}


def _lateral(edr, direct, analysis, proof):
    assets = {asset["hostname"]: asset for asset in analysis["context"]["activos"]}
    scoped = {event["event_id"] for event in edr}
    findings, unverified = [], []
    for service in direct:
        details = _details(service)
        if (service.get("source") != "edr_events" or service.get("event_type") != "service_install"
                or _lower(details.get("service_name")) != "psexesvc"):
            continue
        origin, target = details.get("remote_host"), service.get("hostname")
        if (service["event_id"] not in scoped or origin not in assets or target not in assets
                or not _account(service.get("user")).startswith("adm.")):
            unverified.append(service)
            continue
        scope = {"ERP-APP01", "HR-APP01", "PRINT01", "CRM-APP01"}
        if (origin == "JUMP01" and target in scope and _in_change(analysis, "CHG-2026-1057", service)
                and details.get("payload") == "Instalación agente de monitorización 3.4"):
            findings.append(_approved_lateral(service, edr, analysis, proof))
            continue
        flow = next((event for event in direct
                     if _smb_precedes(event, service, assets[origin]["ip"], assets[target]["ip"])), None)
        if origin != "JUMP01" and flow:
            findings.append({**proof("true_positive", [flow, service], "El firewall y la instalación de PSEXESVC "
                                      "coinciden en origen, destino y tiempo. La cuenta privilegiada se utilizó "
                                      "desde fuera del bastión permitido.",
                                      actions=("Escalar a N2 y revisar la cuenta y el proceso hijo en el destino.",)),
                             "escalate": ["N2"], "verified_impact": "sesión administrativa y servicio remoto observados"})
        else:
            unverified.append(service)
    if not findings:
        return None
    priority = {"true_positive": 2, "needs_more_info": 1, "benign_true_positive": 0}
    finding = max(findings, key=lambda row: (priority[row["verdict"]], row.get("severity_override") == "critical"))
    if finding["verdict"] == "benign_true_positive" and unverified:
        return {**proof("needs_more_info", unverified, "Se verificó parte del mantenimiento, pero faltan pruebas "
                        "para atribuir todas las instalaciones de PsExec al cambio."),
                "escalate": ["N2"]}
    finding["citations"] = list(dict.fromkeys(event_id for row in findings for event_id in row["citations"]))
    return finding


def _mining(edr, direct, analysis, proof):
    assets = {asset["hostname"]: asset for asset in analysis["context"]["activos"]}
    for process in edr:
        cpu = _details(process).get("cpu_pct_avg")
        if type(cpu) not in {int, float} or cpu < 80:
            continue
        report = _malicious_process(process, analysis)
        if not report or "xmr" not in _lower(report.get("malware_family")):
            continue
        destinations = (report.get("network") or {}).get("ips") or []
        host_ip = assets.get(process["hostname"], {}).get("ip")
        flow = next((event for event in direct if event.get("source") == "firewall" and host_ip
                     and event.get("src_ip") == host_ip and event.get("dst_ip") in destinations
                     and event.get("action") == "allow" and str(event.get("dst_port")) == "3333"
                     and _near(event, process)), None)
        if flow:
            vulnerable = any(row.get("id") == "CVE-2024-23897" and _lower(row.get("estado")) == "abierta"
                             for row in assets.get(process["hostname"], {}).get("vulnerabilities", []))
            return {**proof("true_positive", [process, flow],
                            "El proceso se ejecutó con uso alto de CPU. El hash está identificado como "
                            "minero en sandbox y el firewall confirma conexión a su pool."
                            + (" El inventario registra CVE-2024-23897 en el servidor. Falta confirmar el acceso inicial."
                               if vulnerable else ""),
                            actions=("Escalar a N2, revisar el acceso inicial y solicitar contención.",)),
                    "escalate": ["N2"], "verified_impact": "ejecución y conexión del minero",
                    "sandbox_refs": [report["sha256"]]}
    return None


def _web_shell(edr, analysis, proof):
    assets = {asset["hostname"]: asset for asset in analysis["context"]["activos"]}
    generic = []
    for event in edr:
        parent = _lower(event.get("parent_name"))
        child = _lower(event.get("process_name"))
        asset = assets.get(event["hostname"], {})
        if (event.get("event_type") != "process_start"
                or not (parent.startswith(("php-fpm", "nginx", "httpd", "apache")) or parent in {"w3wp.exe", "java"})
                or child not in {"sh", "bash", "cmd.exe", "powershell.exe"}
                or not any(word in _lower(asset.get("type")) for word in ("web", "servidor", "server"))
                or not event.get("command_line")):
            continue
        if WEB_SHELL_COMMAND.search(event["command_line"]):
            cves = [row["id"] for row in asset.get("vulnerabilities", []) if row.get("id")]
            return {**proof("true_positive", [event],
                            "El servicio web lanzó un intérprete de comandos con un patrón de shell remota "
                            "o ejecución codificada en el nodo."
                            + (f" El inventario asocia al activo {', '.join(cves[:4])}. No prueba cuál se explotó."
                               if cves else ""),
                            actions=("Escalar a N2. Revisar el acceso inicial y proponer aislamiento del nodo.",)),
                    "escalate": ["N2"], "verified_impact": "ejecución del intérprete en el servidor"}
        generic.append(event)
    if generic:
        return {**proof("needs_more_info", generic, "El servicio web lanzó un intérprete. "
                        "La línea de comandos por sí sola no permite atribuirlo a una web shell.",
                        questions=("¿Qué solicitud web originó el proceso y qué archivo ejecutó el servidor?",),
                        actions=("Preservar telemetría web y EDR para revisión de N2.",)), "escalate": ["N2"]}
    return None


def _browser_credentials(edr, analysis, proof):
    unverified = []
    for event in edr:
        details = _details(event)
        targets = [_lower(details.get(key)) for key in ("target_path", "file_path", "target_file")]
        if (event.get("event_type") in {"file_read", "file_access", "file_open", "file_copy"}
                and any(path.endswith("\\login data") and ("\\google\\chrome\\user data\\" in path
                                                            or "\\microsoft\\edge\\user data\\" in path)
                        for path in targets)
                and _lower(event.get("process_name")) not in {"", "chrome.exe", "msedge.exe"}):
            report = _sandbox(analysis, event.get("sha256"))
            if not report or report.get("verdict") != "malicious":
                unverified.append(event)
                continue
            return {**proof("true_positive", [event],
                            "Un binario malicioso consultó la base de credenciales del navegador. "
                            "El registro no demuestra que las credenciales se descifraran o salieran del equipo.",
                            actions=("Escalar a N2 y revisar el alcance antes de rotar credenciales.",)),
                    "escalate": ["N2"], "verified_impact": "acceso al almacén de credenciales",
                    "sandbox_refs": [report["sha256"]]}
    if unverified:
        return proof("needs_more_info", unverified, "Un proceso ajeno al navegador accedió a su base "
                     "de credenciales. Falta verificar el origen y la autorización del binario.",
                     questions=("¿El proceso tiene un hash o firma verificados y acceso autorizado?",))
    return None


def _direct_finding(alert, analysis, direct, edr, proof):
    rule = alert["rule_id"]
    if rule == "UC-EDR-001":
        sap = _sap(alert, analysis, edr, proof)
        if sap:
            return sap
        loader = _loader_path(edr, analysis)
        if loader:
            return {**proof("true_positive", loader[:4], "Un script lanzó msiexec. Ese proceso creó una DLL "
                            "identificada en sandbox y rundll32 la ejecutó.",
                            actions=("Solicitar contención del equipo a N2 y revisar otros usos del hash.",)),
                    "escalate": ["N2"], "verified_impact": "ejecución de DLL maliciosa",
                    "sandbox_refs": [loader[4]["sha256"]]}
    if rule == "UC-EDR-002":
        return _encoded_powershell(edr, proof)
    if rule == "UC-EDR-003":
        return _antivirus(alert, analysis, direct, edr, proof)
    if rule == "UC-EDR-004":
        lsass = [event for event in edr if lsass_attempt(event)]
        if lsass:
            return {**proof("true_positive", lsass, "EDR registra el acceso o intento de volcado de LSASS. "
                            "No se ha comprobado la extracción de credenciales.",
                            actions=("Escalar a N2 y preservar el volcado y las sesiones relacionadas.",)),
                    "escalate": ["N2"], "verified_impact": "ejecución de proceso dirigido a LSASS"}
    if rule == "UC-EDR-005":
        return _anydesk(edr, proof)
    if rule == "UC-EDR-006":
        return _mining(edr, direct, analysis, proof)
    if rule == "UC-EDR-007":
        recovery = [event for event in edr if recovery_attempt(event)]
        if recovery:
            blocked = _lower((alert.get("evidence") or {}).get("edr_action")) == "blocked"
            return {**proof("true_positive", recovery, "Se lanzaron comandos de inhibición de recuperación."
                            + (" La alerta reporta bloqueo. El log de proceso no confirma el efecto de los comandos."
                               if blocked else " Los registros no confirman el resultado de los comandos.")
                            + " Es una señal de preransomware. No se ha observado cifrado.",
                            actions=("Escalado inmediato a N2. Preservar el host y verificar copias, volúmenes y otros equipos.",),
                            questions=("¿Se eliminó alguna instantánea o se observaron escrituras de cifrado?",)),
                    "escalate": ["N2"], "verified_impact": "lanzamiento de comandos contra la recuperación",
                    "severity_override": "critical"}
    if rule == "UC-EDR-008":
        for anchor in edr:
            if not anchor.get("parent_pid"):
                continue
            group = [event for event in edr if event.get("event_type") == "process_start"
                     and _lower(event.get("process_name")) in DISCOVERY and event.get("hostname") == anchor["hostname"]
                     and event.get("parent_pid") == anchor.get("parent_pid") and _near(anchor, event, 3)
                     and _lower(event.get("parent_name")) == "rundll32.exe"]
            if len({_lower(event["process_name"]) for event in group}) >= 3:
                return {**proof("true_positive", group, "La misma instancia de rundll32 lanzó varios comandos "
                                "de enumeración de cuentas y equipos en pocos minutos.",
                                actions=("Escalar a N2 y buscar el proceso que inició la enumeración.",)),
                        "escalate": ["N2"]}
    if rule == "UC-EDR-009":
        return _web_shell(edr, analysis, proof)
    if rule == "UC-EDR-010":
        return _browser_credentials(edr, analysis, proof)
    if rule == "UC-EDR-011":
        return _status(edr, analysis, proof)
    if rule == "UC-EDR-012":
        return _point_of_sale(edr, proof)
    if rule == "UC-NET-004":
        return _lateral(edr, direct, analysis, proof)
    return None


def check(alert, analysis, direct, proof):
    """Emite un hallazgo solo después de comprobar los eventos originales."""
    rule = alert.get("rule_id", "")
    if "context" not in analysis or not (rule.startswith("UC-EDR-") or rule == "UC-NET-004"):
        return None
    edr = _scope(alert, direct)
    finding = _direct_finding(alert, analysis, direct, edr, proof)
    if finding:
        cited = set(finding["citations"])
        anchors = [event for event in edr if event["event_id"] in cited]
        if rule == "UC-EDR-011" and finding["verdict"] == "true_positive":
            # El hallazgo ya comprobó host, servicio, orden y ventana de la pareja.
            anchors.extend(event for event in analysis["events"] if event["event_id"] in cited
                           and event not in anchors and _edr_stop(event))
        if alert.get("external") and anchors:
            finding["entity_verification"] = _verify_entities(alert, analysis, anchors)
        if finding["verdict"] == "true_positive" and rule in CHAIN_RULES:
            _attach_incident(alert, analysis, finding, anchors)
    return finding


def _attach_incident(alert, analysis, finding, anchors):
    if incident := _preransomware(alert, analysis, anchors):
        finding["incident"] = incident
        finding["severity_override"] = "critical"
        finding["citations"] = list(dict.fromkeys(finding["citations"] + incident["evidence_ids"]))


def link_incident(alert, analysis, finding):
    """Amplía hallazgos positivos con pruebas directas de la misma cadena."""
    if not finding or finding["verdict"] != "true_positive" or alert["rule_id"] not in CHAIN_PIVOTS:
        return finding
    direct_ids = set(finding["citations"]).intersection(analysis["requested"])
    stamp = madrid(alert["created_at"])
    anchors = [event for event in analysis["events"] if event["event_id"] in direct_ids
               and abs(_ts(event) - stamp) <= timedelta(hours=24)]
    _attach_incident(alert, analysis, finding, anchors)
    return finding


def _lateral_edge(service, events, analysis):
    origin = _details(service).get("remote_host")
    target = service["hostname"]
    actor = _account(service.get("user"))
    if not origin or origin in {target, "JUMP01"} or not actor.startswith("adm."):
        return None
    child = next((event for event in events if _lower(event.get("parent_name")) == "psexesvc.exe"
                  and _account(event.get("user")) == actor and timedelta(0) <=
                  _ts(event) - _ts(service) <= timedelta(minutes=2)
                  and _malicious_process(event, analysis)), None)
    if not child:
        return None
    source_asset, target_asset = db.asset(origin), db.asset(target)
    if not source_asset or not target_asset:
        return None
    flow = next((event for event in db.events_for_entity(source_asset["ip"], service["timestamp"], horas=1,
                                                         source="firewall", limit=500)
                 if _smb_precedes(event, service, source_asset["ip"], target_asset["ip"])), None)
    return (flow, service, child) if flow else None


def _payload_peers(payload):
    return [
        event for event in db.events_for_entity(payload["sha256"], payload["timestamp"], horas=2,
                                               source="edr_events", limit=100)
        if event.get("event_type") == "process_start" and _lower(event.get("parent_name")) == "psexesvc.exe"
        and _account(event.get("user")) == _account(payload.get("user"))
        and _lower(event.get("sha256")) == _lower(payload.get("sha256")) and event.get("hostname") != payload["hostname"]
    ]


def _delivery(script, analysis):
    command = script.get("command_line") or ""
    file_path = re.search(r'"([^"]+\.(?:js|jse|vbs|vbe))"', command, re.I)
    if not file_path:
        return None
    filename = PureWindowsPath(file_path.group(1)).name
    for mail in db.search_logs(filename, source="email", desde=(_ts(script) - timedelta(days=1)).isoformat(),
                               hasta=script["timestamp"], limit=100):
        if (mail.get("direction") != "inbound" or mail.get("action") != "delivered"
                or _account(script.get("user")) not in {_account(address) for address in mail.get("recipients", [])}):
            continue
        for attachment in mail.get("attachments", []):
            for candidate in (attachment, *attachment.get("contains", [])):
                if _lower(candidate.get("name")) != _lower(filename):
                    continue
                report = _sandbox(analysis, candidate.get("sha256"))
                if report and report.get("verdict") == "malicious":
                    return mail
    return None


def _beacon(installer, launch):
    url = re.search(r'https?://[^"\s]+', installer.get("command_line") or "")
    if not url:
        return []
    domain = urlsplit(url.group()).hostname
    if not domain:
        return []
    candidates = db.events_for_entity(domain, launch["timestamp"], horas=48, source="proxy", limit=500)
    # Repetición periódica al mismo destino del instalador, desde la misma sesión lógica.
    flows = [event for event in candidates if _lower(event.get("domain")) == _lower(domain)
             and event.get("hostname") == launch["hostname"]
             and _account(event.get("user")) == _account(launch.get("user"))
             and event.get("method") == "POST" and event.get("action") == "allowed"
             and str(event.get("status")) == "200" and _ts(event) >= _ts(launch)]
    for index, start in enumerate(flows[:-2]):
        group = flows[index:index + 3]
        intervals = [(_ts(right) - _ts(left)).total_seconds() for left, right in zip(group, group[1:])]
        if all(35 <= seconds <= 90 for seconds in intervals) and len({event.get("url") for event in group}) == 1:
            return group
    return []


def _privilege_pair(stop, actor):
    events = [event for event in db.events_for_entity(stop["hostname"], stop["timestamp"], horas=2,
                                                     source="ad_events", limit=100)
              if event.get("src_host") == stop["hostname"] and _account(event.get("subject")) == actor
              and timedelta(0) <= _ts(stop) - _ts(event) <= timedelta(minutes=30)]
    for membership in events:
        if (str(membership.get("event_code")) != "4728"
                or _lower(_details(membership).get("group")) != "domain admins"):
            continue
        created = next((event for event in events if str(event.get("event_code")) == "4720"
                        and event.get("target") == membership.get("target") and event.get("target")
                        and timedelta(0) <= _ts(membership) - _ts(event) <= timedelta(minutes=15)), None)
        if created:
            return [created, membership]
    return []


def _mail_script_hosts(mail, alert):
    if mail.get("direction") != "inbound" or mail.get("action") != "delivered":
        return set()
    recipients = {_account(address) for address in mail.get("recipients", [])}
    subjects = {_account(row.get("upn")) for row in alert.get("entities", {}).get("users", [])}
    hosts = set()
    for recipient in sorted((recipients & subjects) - {""})[:8]:
        candidates = db.events_for_entity(recipient, mail["timestamp"], horas=24, source="edr_events", limit=500)
        hosts.update(event["hostname"] for event in candidates if event.get("hostname")
                     and _account(event.get("user")) == recipient and event.get("event_type") == "process_start"
                     and _lower(event.get("process_name")) in {"wscript.exe", "cscript.exe"}
                     and timedelta(0) <= _ts(event) - _ts(mail) <= timedelta(days=1))
    return hosts


def _preransomware(alert, analysis, anchors):
    """Exige movimiento lateral, acciones contra las copias y una prueba común con la alerta."""
    if not anchors:
        return None
    stamp = madrid(alert["created_at"])
    start, end = stamp - timedelta(days=10), stamp + timedelta(days=10)
    by_host = {}

    def host_edr(host):
        if host not in by_host:
            by_host[host] = [event for event in db.events_for_entity(host, alert["created_at"], horas=240,
                                                                   source="edr_events", limit=500)
                            if event.get("hostname") == host]
        return by_host[host]

    seed_hosts = set()
    for event in anchors:
        source = event["source"]
        if source == "edr_events" and event.get("hostname"):
            seed_hosts.add(event["hostname"])
        elif (source == "proxy" and event.get("hostname") and event.get("method") == "POST"
              and event.get("action") == "allowed"):
            seed_hosts.add(event["hostname"])
        elif source == "email":
            seed_hosts.update(_mail_script_hosts(event, alert))
        elif source == "ad_events" and event.get("src_host"):
            seed_hosts.add(event["src_host"])
    if not seed_hosts:
        return None

    seed_events = {event["event_id"] for event in anchors}
    bridge_hosts = set(seed_hosts)
    # Solo la misma muestra maliciosa, identidad y servicio permite partir del host del día 18.
    if alert["rule_id"] in {"UC-EDR-011", "UC-IDP-008"}:
        for host in sorted(seed_hosts):
            observations = host_edr(host)
            for payload in observations:
                if _lower(payload.get("parent_name")) != "psexesvc.exe":
                    continue
                linked = any(
                    (anchor["source"] == "edr_events"
                     and _same_process(anchor, payload, 10 * 24 * 60, observations=observations))
                    or (anchor["source"] == "ad_events" and anchor.get("src_host") == host
                        and _account(anchor.get("subject")) == _account(payload.get("user"))
                        and timedelta(0) <= _ts(anchor) - _ts(payload) <= timedelta(days=10))
                    for anchor in anchors
                )
                if linked and _malicious_process(payload, analysis):
                    bridge_hosts.update(peer["hostname"] for peer in _payload_peers(payload))

    services = [
        event for event in db.search_logs("PSEXESVC", source="edr_events", desde=start.isoformat(),
                                          hasta=end.isoformat(), limit=500)
        if event.get("event_type") == "service_install" and _lower(_details(event).get("service_name")) == "psexesvc"
        and (event.get("hostname") in bridge_hosts or _details(event).get("remote_host") in seed_hosts)
    ]
    for service in services:
        target = service["hostname"]
        observations = host_edr(target)
        edge = _lateral_edge(service, observations, analysis)
        if not edge:
            continue
        flow, service, payload = edge
        origin = _details(service)["remote_host"]
        recoveries = [event for event in observations if recovery_attempt(event)
                      and _same_process(event, payload, 120, observations=observations)
                      and _account(event.get("user")) == _account(payload.get("user"))]
        if not recoveries:
            continue
        incident, evidence = _render_incident(analysis, host_edr, origin, target, flow, service, payload, recoveries)
        if seed_events.intersection(incident["evidence_ids"]):
            _keep(analysis, evidence)
            _trace(analysis, "Pivote preransomware", "EDR, firewall, correo, proxy y AD con relaciones verificadas",
                   evidence, "Ventana de ±10 días. Se cruzaron padre y PID, cuenta, host y hash.")
            return incident
    return None


def _render_incident(analysis, host_edr, origin, target, flow, service, payload, recoveries):
    entries, evidence = [], []
    affected = [origin, target]

    def stage(label, host, events, finding):
        evidence.extend(events)
        first = min(events, key=_ts)
        entries.append({"timestamp": first["timestamp"], "event_id": first["event_id"],
                        "evidence_ids": [event["event_id"] for event in events], "source": first["source"],
                        "host": host, "stage": label, "finding": finding})

    origin_events = [event for event in host_edr(origin)
                     if timedelta(0) <= _ts(service) - _ts(event) <= timedelta(hours=36)]
    loader = _loader_path(origin_events, analysis)
    if loader:
        script, installer, artifact, launch, report = loader
        if mail := _delivery(script, analysis):
            stage("Correo de entrada", origin, [mail],
                  "Correo entregado a la usuaria antes de ejecutar un script con el mismo nombre. "
                  "El hash del adjunto está clasificado como malicioso en sandbox.")
        filename = PureWindowsPath(_details(artifact)["file_path"]).name
        family = report.get("malware_family") or "identificada por sandbox"
        stage("Ejecución", origin, [script, installer, artifact, launch],
              f"El script lanzó el instalador. Este creó {filename} ({family}) y su hijo rundll32 ejecutó esa DLL.")
        persistence = [
            event for event in origin_events if event.get("event_type") == "registry_set"
            and event.get("pid") == launch["pid"] and _lower(event.get("process_name")) == "rundll32.exe"
            and "\\currentversion\\run\\" in _lower(_details(event).get("key"))
            and timedelta(0) <= _ts(event) - _ts(launch) <= timedelta(minutes=2)
            and not _pid_reassigned(launch, event, origin_events)
            and _lower(_details(artifact)["file_path"]) in _lower(_details(event).get("value"))
        ]
        if persistence:
            stage("Persistencia", origin, persistence, "La misma instancia creó una entrada Run para la DLL.")
        if beacon := _beacon(installer, launch):
            stage("Comunicación periódica", origin, beacon,
                  "El proxy aceptó POST repetidos al dominio del instalador desde el mismo equipo y cuenta. "
                  "El patrón es compatible con C2. El contenido de las solicitudes no está disponible.")
        recon = [event for event in origin_events if event.get("event_type") == "process_start"
                 and _lower(event.get("process_name")) in DISCOVERY
                 and _same_process(event, launch, 24 * 60, observations=origin_events)]
        if len({_lower(event["process_name"]) for event in recon}) >= 3:
            stage("Reconocimiento", origin, recon, "Comandos de enumeración de cuentas, grupos y equipos "
                  "registrados bajo el mismo PID padre de rundll32 en una ventana de 24 horas.")
        lsass = [event for event in origin_events if lsass_attempt(event)
                 and _same_process(event, launch, 24 * 60, observations=origin_events)]
        if lsass:
            stage("Acceso a credenciales", origin, lsass,
                  "rundll32 lanzó un intento de volcado de LSASS. La creación del volcado no está confirmada.")

    stage("Movimiento lateral", target, [flow, service, payload],
          f"El firewall permitió SMB desde {origin}. El destino registró PSEXESVC desde ese origen y "
          "segundos después un proceso hijo malicioso con la misma cuenta privilegiada.")
    stage("Inhibición de recuperación", target, recoveries,
          "El binario malicioso lanzó comandos contra las copias de recuperación. "
          "EDR registra el arranque de los procesos. El resultado de los comandos y el cifrado quedan sin verificar.")

    for peer in _payload_peers(payload):
        host = peer["hostname"]
        if host in affected or len(affected) >= 4:
            continue
        affected.append(host)
        stage("Reaparición de la muestra", host, [peer],
              "Se ejecutó un binario con el mismo SHA-256, cuenta y servicio padre que en el servidor. "
              "El origen de esta segunda ejecución queda por determinar.")
        events = host_edr(host)
        stop = next((event for event in events if _edr_stop(event)
                     and _same_process(event, peer, 10 * 24 * 60, observations=events)), None)
        if not stop:
            continue
        status = next((event for event in events if _edr_stopped(event) and _stop_precedes_status(stop, event)), None)
        if privileges := _privilege_pair(stop, _account(peer.get("user"))):
            stage("Privilegios persistentes", host, privileges,
                  "La misma cuenta privilegiada creó otra cuenta y la incorporó a Domain Admins minutos después.")
        if status:
            stage("Defensa desactivada", host, [stop, status],
                  "El agente EDR quedó detenido tras la orden. El nombre y el PID padre coinciden "
                  "con la ejecución previa en este host. La separación temporal impide confirmar continuidad del proceso.")

    return {
        "title": "Cadena de preransomware",
        "timeline": sorted(entries, key=lambda item: madrid(item["timestamp"])),
        "affected": affected,
        "scope": ("Actividad maliciosa vinculada por telemetría de proceso, identidad, red y hash. "
                  "Hay evidencia de ejecución, movimiento lateral e inhibición de recuperación."),
        "limits": ["No se ha observado cifrado ni se ha confirmado el resultado de los comandos contra las copias.",
                   "El hash repetido en otro equipo no demuestra la ruta seguida.",
                   "La telemetría no prueba que el intento contra LSASS permitiera el uso posterior de la cuenta privilegiada."],
        "evidence_ids": list(dict.fromkeys(event["event_id"] for event in evidence)),
    }, evidence
