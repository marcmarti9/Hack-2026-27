"""Criterio verificable y enrutamiento N1 sobre los datos del reto."""
from base64 import b64encode
from datetime import datetime, time, timedelta, timezone

from apps.backend.rules import coverage_edr, coverage_identidad, coverage_plataforma, coverage_ruido
from apps.backend.rules.approvals import is_ot
from apps.backend.rules.engine import Severity, madrid, severidad
from apps.backend.tools import db

SCCM_CHANGE = "CHG-2026-1031"
SCCM_SCRIPT = ("$inv = Get-CimInstance Win32_Product | Select Name,Version | ConvertTo-Json | "
               r"Out-File C:\Windows\CCM\Inventory\sw.json")
WINDOWS_POWERSHELL = r"c:\windows\system32\windowspowershell\v1.0\powershell.exe"
SCCM_COMMAND = ("powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand "
                + b64encode("$inv = Get-CimInstance Win32_Product".encode("utf-16-le")).decode("ascii"))
EXTERNAL_ROUTINE_RULES = {
    ("UC-EDR-002", "EDR", "RB-02"),
    ("UC-EML-001", "EMAIL_GW", "RB-01"),
    ("UC-NET-006", "DNS", "RB-09"),
    ("UC-WEB-001", "WAF", "RB-05"),
}


def _proof(verdict, events, summary, *, actions=(), questions=(), basis=""):
    return {"verdict": verdict, "citations": [event["event_id"] for event in events], "summary": summary,
            "questions": list(questions), "actions": list(actions), "confidence": None, "basis": basis}


def _same_host(event, hosts):
    return event.get("hostname", "").lower() in hosts


def _phishing_session(alert, direct, events):
    users = {row.get("upn", "") for row in alert["entities"].get("users", [])}
    domains = set(alert["entities"].get("domains", []))
    for post in direct:
        user = str(post.get("user", "")).split("@", 1)[0] + "@tarvia.example"
        if (post["source"] != "proxy" or post.get("method") != "POST" or post.get("action") != "allowed"
                or user not in users or post.get("domain") not in domains or not post.get("dst_ip")):
            continue
        stamp = madrid(post["timestamp"])
        for login in events:
            if (login["source"] == "idp_signins" and login.get("user_upn") == user
                    and login.get("src_ip") == post["dst_ip"] and login.get("result") == "success"
                    and login.get("device_compliant") is False
                    and timedelta(0) <= madrid(login["timestamp"]) - stamp <= timedelta(minutes=5)):
                return {**_proof("true_positive", [post, login],
                                 "Tras un POST al sitio señalado por phishing, la misma cuenta inició sesión "
                                 "desde la IP del sitio con un dispositivo no conforme. La secuencia respalda un "
                                 "posible robo de sesión. Los logs no contienen la contraseña enviada.",
                                 actions=("Verificar la sesión y preparar su revocación para N2.",)),
                        "escalate": ["N2"]}
    return None


def _vendor_access(alert, direct, context):
    account = next((user for user in context["usuarios"] if user["username"] == "ext.logisoft"
                    and user["account_type"] == "external"), None)
    if not account or any(change["id"] == "CHG-2026-1071" for change in context["cambios"]):
        return None
    origins = set(alert["entities"].get("ips", [])) if alert.get("external") else set()
    for vpn in direct:
        if vpn["source"] != "vpn" or vpn.get("user") != account["username"] or vpn.get("action") != "connect":
            continue
        if origins and vpn.get("src_ip") not in origins:
            continue
        stamp = madrid(vpn["timestamp"])
        if stamp.weekday() < 5 and time(8) <= stamp.time() < time(18):
            continue
        target = db.asset("WMS01")
        if not target:
            continue
        for log in direct:
            if (log["source"] == "firewall" and vpn.get("assigned_ip") and log.get("src_ip") == vpn["assigned_ip"]
                    and log.get("dst_ip") == target["ip"] and str(log.get("dst_port")) == "3389"
                    and log.get("action") == "allow"
                    and timedelta(0) <= madrid(log["timestamp"]) - stamp <= timedelta(minutes=15)):
                return {**_proof("true_positive", [vpn, log], "El proveedor abrió la VPN y el firewall permitió "
                                 "RDP hacia WMS01 fuera de la ventana contractual y del cambio aprobado. "
                                 "El acceso a la VPN está probado. Queda por comprobar quién controlaba la cuenta "
                                 "y si hubo una sesión RDP en WMS01.",
                                 actions=("Escalar a N2 y Logística. Revisar la sesión del proveedor.",)),
                        "escalate": ["N2", "Logística"],
                        "verified_impact": "acceso a la VPN fuera de la ventana contractual"}
    return None


def _miner(direct, analysis):
    suspicious = {entry["indicator"] for entry in analysis["context"]["inteligencia"]
                  if (entry.get("tip") or {}).get("reputation") == "malicious"
                  and "xmr" in (entry["tip"].get("malware_family") or "").lower()}
    sources = {asset["ip"]: asset["hostname"].lower() for asset in analysis["context"]["activos"]}
    for flow in direct:
        if (flow["source"] != "firewall" or flow.get("dst_ip") not in suspicious
                or flow.get("action") != "allow" or str(flow.get("dst_port")) != "3333"):
            continue
        if not (hostname := sources.get(flow.get("src_ip"))):
            continue
        stamp = madrid(flow["timestamp"])
        for process in analysis["events"]:
            if (process["source"] != "edr_events" or process.get("event_type") != "process_start"
                    or process.get("hostname", "").lower() != hostname or ":3333" not in process.get("command_line", "")
                    or not process.get("sha256") or abs(madrid(process["timestamp"]) - stamp) > timedelta(minutes=10)):
                continue
            report = db.sandbox(process["sha256"])
            if (not report or report.get("verdict") != "malicious"
                    or flow["dst_ip"] not in (report.get("network") or {}).get("ips", [])):
                continue
            if report not in analysis["context"]["sandbox"]:
                analysis["context"]["sandbox"].append(report)
            analysis["trace"].append({"tool": "Sandbox del proceso", "query": process["sha256"],
                                      "count": 1, "note": "Coincide el destino de red del informe."})
            persistence = [event for event in analysis["events"] if event["source"] == "edr_events"
                           and event.get("hostname") == process["hostname"]
                           and process.get("process_path") and process["process_path"] in
                           str((event.get("details") or {}).get("persistence", ""))]
            return {**_proof("true_positive", [flow, process, *persistence],
                             "EDR registra la ejecución del proceso. El destino permitido del firewall coincide "
                             "con el pool del informe de sandbox y el TIP." +
                             (" Otro registro muestra la persistencia del mismo ejecutable." if persistence else ""),
                             actions=("Preparar investigación de persistencia y escalado a N2.",)),
                    "sandbox_refs": [report["sha256"]], "escalate": ["N2"]}
    return None


def _sccm_match(alert, direct, context, hosts):
    change = next((row for row in context["cambios"] if row["id"] == SCCM_CHANGE), None)
    if not change or not hosts or not context["activos"]:
        return None
    if {row["hostname"].lower() for row in context["activos"]} != hosts:
        return None
    if any(row["type"] not in {"Portátil", "Sobremesa"} or row["zone"] == "LOGISTICS-OT"
           for row in context["activos"]):
        return None
    stamp = madrid(alert["created_at"])
    if not datetime.fromisoformat(change["inicio"]) <= stamp.replace(tzinfo=None) <= datetime.fromisoformat(change["fin"]):
        return None
    if not time(8) <= stamp.time() < time(10):
        return None
    if len(direct) != 1 or len(alert.get("related_events", [])) != 1:
        return None
    event = direct[0]
    details = event.get("details") or {}
    if alert.get("external"):
        asset_ips = {row["hostname"].lower(): row["ip"] for row in context["activos"]}
        if hosts != {event.get("hostname", "").lower()} or any(
            host.get("ip") and host["ip"] != asset_ips.get(host.get("hostname", "").lower())
            for host in alert["entities"].get("hosts", [])
        ):
            return None
        process_fields = (("name", "process_name"), ("parent", "parent_name"), ("command_line", "command_line"))
        if any(str(process[key]).lower() != str(event.get(field, "")).lower()
               for process in alert["entities"].get("processes", [])
               for key, field in process_fields if key in process):
            return None
    if (_same_host(event, hosts) and event["source"] == "edr_events" and event.get("event_type") == "process_start"
            and event.get("process_path", "").lower() == WINDOWS_POWERSHELL
            and event.get("parent_name", "").lower() == "ccmexec.exe"
            and event.get("user") == r"NT AUTHORITY\SYSTEM" and event.get("signer") == "Microsoft Windows"
            and details.get("decoded") == SCCM_SCRIPT and event.get("command_line") == SCCM_COMMAND
            and abs((madrid(event["timestamp"]) - stamp).total_seconds()) <= 300
            and time(8) <= madrid(event["timestamp"]).time() < time(10)):
        return event


def local_finding(alert, analysis):
    """Pruebas estrechas sobre observaciones del índice. Un resultado vacío no permite cerrar."""
    direct = [event for event in analysis["events"] if event["event_id"] in analysis["requested"]]
    if alert.get("external"):
        stamp = madrid(alert["created_at"]).astimezone(timezone.utc)
        contemporary = [event for event in direct
                        if stamp - timedelta(hours=24) <= madrid(event["timestamp"]).astimezone(timezone.utc) <= stamp]
        if len(contemporary) < len(direct):
            current_ids = {event["event_id"] for event in contemporary}
            analysis["context_event_ids"] = [event["event_id"] for event in direct if event["event_id"] not in current_ids]
            analysis["trace"].append({
                "tool": "Ventana de referencias externas", "query": "Referencias directas en las 24 h hasta el aviso",
                "count": len(contemporary),
                "note": "Los registros fuera de ventana se conservan como contexto, sin confirmar este aviso.",
            })
        direct = contemporary
    hosts = {host["hostname"].lower() for host in alert.get("entities", {}).get("hosts", [])
             if host.get("hostname")}
    if alert["rule_id"] == "UC-EML-003":
        if finding := _phishing_session(alert, direct, analysis["events"]):
            return finding
    if alert["rule_id"] == "UC-VPN-001":
        if finding := _vendor_access(alert, direct, analysis["context"]):
            return finding
    if alert["rule_id"] == "UC-NET-002":
        if finding := _miner(direct, analysis):
            return finding
    if "context" in analysis:
        for coverage in (coverage_edr, coverage_identidad, coverage_plataforma, coverage_ruido):
            if finding := coverage.check(alert, analysis, direct, _proof):
                return coverage_edr.link_incident(alert, analysis, finding)
    if alert["rule_id"] == "UC-IDP-008":
        change = next((row for row in analysis["context"]["cambios"] if row["id"] == "CHG-2026-1078"), None)
        admins = {user["username"] for user in analysis["context"]["usuarios"] if user["privileged"] == "True"}
        for event in direct:
            if (not change or event["source"] != "ad_events" or event.get("src_host") != "JUMP01"
                    or event.get("subject") not in admins or str(event.get("event_code")) != "4728"
                    or (event.get("details") or {}).get("group") != "Backup Operators"):
                continue
            stamp = madrid(event["timestamp"]).replace(tzinfo=None)
            if datetime.fromisoformat(change["inicio"]) <= stamp <= datetime.fromisoformat(change["fin"]):
                return _proof("needs_more_info", [event], "El alta desde JUMP01 coincide con el grupo y la ventana "
                              "del cambio CHG-2026-1078. El cambio no identifica al usuario añadido.",
                              questions=("¿Es el usuario añadido el operador incluido en la autorización?",))
    if alert["rule_id"] == "UC-EDR-002":
        event = _sccm_match(alert, direct, analysis["context"], hosts)
        if event:
            return _proof("benign_true_positive", [event],
                          f"{event['event_id']} registra el inventario de SCCM en un puesto incluido en {SCCM_CHANGE}. "
                          "Coinciden proceso, firma, comando y ventana.", basis=f"Actividad autorizada verificada contra {SCCM_CHANGE}.")
    if alert["rule_id"] == "UC-EDR-004" and "context" not in analysis:
        for event in direct:
            details = event.get("details") or {}
            command = event.get("command_line", "").lower()
            if (_same_host(event, hosts) and event["source"] == "edr_events"
                    and event.get("event_type") == "process_start"
                    and event.get("process_name", "").lower() == "rundll32.exe"
                    and abs(madrid(event["timestamp"]) - madrid(alert["created_at"])) <= timedelta(minutes=15)
                    and "comsvcs.dll" in command and "minidump " in command
                    and details.get("target_process", "").lower().startswith("lsass.exe (pid ")):
                return _proof(
                    "true_positive", [event],
                    f"{event['event_id']} registra rundll32 con comsvcs.dll y MiniDump dirigido a LSASS. "
                    "El proceso se inició. El registro no confirma la extracción de credenciales.",
                    questions=("¿Se creó o transfirió el volcado?", "¿Hay uso posterior de credenciales?"),
                    actions=("Revisar el aislamiento del puesto con N2. Verificar conexiones y credenciales expuestas.",),
                )
    if alert["rule_id"] == "UC-IDP-002":
        ips = set(alert["entities"].get("ips", []))
        failures = [event for event in direct if event["source"] == "idp_signins" and event.get("src_ip") in ips
                    and event.get("user_agent") == "BAV2ROPC" and event.get("result") == "failure"
                    and event.get("failure_reason") == "blocked_by_smart_lockout"]
        for ip in sorted(ips):
            attempts = [event for event in failures if event["src_ip"] == ip and event.get("user_upn")]
            users = {event["user_upn"] for event in attempts}
            if len(users) >= 3:
                return _proof("true_positive", attempts, f"Un mismo origen intentó autenticación heredada contra "
                              f"{len(users)} cuentas distintas y el IdP bloqueó esos intentos. "
                              "El patrón es compatible con password spraying. No confirma acceso.",
                              questions=("¿Hubo un acceso correcto desde el mismo origen en otro servicio?",))
    if alert["rule_id"] != "UC-OT-001":
        for report in analysis.get("context", {}).get("sandbox", []):
            if report.get("verdict") == "malicious" and report.get("sha256"):
                return {**_proof("true_positive", [], "El SHA-256 de la alerta coincide con un informe de sandbox "
                                 "que clasifica el archivo como malicioso. Falta confirmar exposición y ejecución en Tarvia.",
                                 questions=("¿Dónde apareció el archivo y se llegó a ejecutar?",),
                                 actions=("Buscar el hash en correo y EDR. Preservar el expediente para N2.",)),
                        "sandbox_refs": [report["sha256"]], "escalate": ["N2"]}
    return None


def missing_references(analysis):
    return set(analysis["requested"]) - {event["event_id"] for event in analysis["events"]}


def effective_priority(alert, analysis, finding, verdict):
    """Aplica el runbook y las pruebas locales antes de elegir el contraste."""
    base = Severity(analysis["severity"], analysis["severity_rationale"], analysis["sla"])
    verified = bool(finding and (finding.get("citations") or finding.get("sandbox_refs")))
    if verified and finding.get("severity_override") == "critical":
        return Severity("critical", f"{base.rationale} Regla de escalado del runbook aplicable.", "15 min")
    if alert["severity"] == "critical":
        if (verified and verdict == finding["verdict"] == "benign_true_positive"
                and finding.get("authorized_change") and not missing_references(analysis)):
            return Severity("informational", f"{base.rationale} Cambio autorizado verificado. "
                            "El cierre requiere decisión humana por la prioridad de origen.", "Revisión diaria")
        return (base if base.level == "critical" else
                Severity("critical", f"{base.rationale} Se conserva la prioridad crítica de origen.", "15 min"))
    if verified and verdict == finding["verdict"]:
        if verdict in {"benign_true_positive", "false_positive"}:
            if base.level != "critical" or (finding.get("auto_close") and not finding.get("escalate")):
                priority = severidad(alert, verdict)
                return Severity(priority.level, f"{base.rationale} Tras comprobar el caso: {priority.rationale}",
                                priority.sla)
        elif base.level != "critical" and (finding.get("verified_impact") or finding.get("verified_prevention")):
            return severidad(alert, verdict, verified_impact=finding.get("verified_impact", ""),
                             verified_prevention=finding.get("verified_prevention", ""))
    return base


def route(alert, analysis, mode, finding):
    """La autorización y la cobertura no dependen de lo que redacte el modelo."""
    initial_severity = analysis["severity"]
    verdict = analysis["verdict"]
    matched = bool(finding and verdict == finding["verdict"] and
                   (finding.get("citations") or finding.get("sandbox_refs")))
    priority = effective_priority(alert, analysis, finding, verdict)
    severity = priority.level
    critical = severity == "critical"
    analysis.update(severity=severity, severity_rationale=priority.rationale, sla=priority.sla)
    local = (analysis["provider"] == "Reglas locales" and not alert.get("external")
             and alert["severity"] != "critical")
    current_refs = set(analysis["requested"]) - set(analysis.get("context_event_ids", []))
    # A pasted alert cannot grant itself permission. Every reference must be
    # current and covered by the deterministic finding before it can close.
    external_routine = (
        alert.get("external") and matched and severity in {"informational", "low"}
        and (alert["rule_id"], alert.get("source_product"), alert.get("runbook")) in EXTERNAL_ROUTINE_RULES
        and (alert["rule_id"] != "UC-WEB-001" or alert["entities"].get("urls"))
        and alert["severity"] in {"informational", "low", "medium"}
        and initial_severity in {"informational", "low", "medium"}
        and current_refs and current_refs == set(analysis["requested"])
        and current_refs <= set(finding["citations"])
        and not missing_references(analysis)
        and not any(asset["zone"] == "LOGISTICS-OT" for asset in analysis["context"]["activos"])
        and (analysis["provider"] == "Reglas locales" or (analysis["confidence"] or 0) >= 80)
    )
    result = {"mode": mode, "recommendation": "review", "recipients": [], "automatic": False,
              "reason": "Revisión pendiente. Hace falta evidencia suficiente o una decisión humana."}
    if critical:
        result.update(recommendation="escalate", recipients=["N2 de guardia (teléfono)", "Responsable SOC", "CISO"],
                      reason="Crítica. Preparar el aviso y el expediente para revisión humana inmediata. SLA de 15 min.")
    elif severity == "high":
        result.update(recommendation="escalate", recipients=["N2", "Responsable SOC"],
                      reason=("Verdadero positivo de severidad alta. Revisar con N2 en la misma jornada."
                              if verdict == "true_positive" else
                              "Severidad alta. N2 debe revisar el expediente en la misma jornada."))
    elif finding and finding["verdict"] == "true_positive" and alert["rule_id"] == "UC-EDR-004":
        result.update(recommendation="escalate", recipients=["N2"],
                      reason="Señal de acceso a credenciales. Confirmar alcance y decidir la respuesta con N2.")
    elif matched and verdict in {"benign_true_positive", "false_positive"}:
        result.update(recommendation="close", reason=finding.get("basis") or finding["summary"])
        old_rule = (alert["rule_id"] == "UC-EDR-002"
                    and alert["severity"] in {"informational", "low", "medium"} and initial_severity != "high")
        result["automatic"] = bool((local or external_routine) and (finding.get("auto_close") or old_rule))
    elif (matched and verdict == "true_positive" and finding.get("resolved")
          and finding.get("verified_prevention") and severity in {"informational", "low"}):
        result.update(recommendation="close", automatic=bool(local or external_routine),
                      reason=finding["verified_prevention"])
    if result["recommendation"] == "close" and missing_references(analysis):
        result.update(recommendation="review", automatic=False,
                      reason="Faltan referencias directas. Revisar la cobertura antes de cerrar.")
    assets = analysis["context"]["activos"]
    if alert.get("external") and matched and finding.get("citations"):
        checked = set(finding["citations"])
        hosts = {event[field] for event in analysis["events"] if event["event_id"] in checked
                 for field in ("hostname", "src_host") if event.get(field)}
        assets = [asset for asset in assets if asset["hostname"] in hosts]
        current_refs &= checked
    ot_asset = any(asset["zone"] == "LOGISTICS-OT" for asset in assets)
    direct_flows = [event for event in analysis["events"]
                    if event.get("source") == "firewall" and event["event_id"] in current_refs]
    ot_alert = alert["rule_id"] == "UC-OT-001" or any(
        "LOGISTICS-OT" in {flow.get("zone_src"), flow.get("zone_dst")} for flow in direct_flows
    )
    if direct_flows and not (ot_asset or ot_alert):
        endpoints = {flow[key] for flow in direct_flows for key in ("src_ip", "dst_ip") if flow.get(key)}
        with db.read_session():
            ot_alert = any(is_ot(endpoint) for endpoint in sorted(endpoints))
    result["ot"] = ot_asset or ot_alert
    ot_authorized = (local and alert["rule_id"] == "UC-OT-001" and matched
                     and verdict == "benign_true_positive" and finding.get("ot_authorized"))
    if result["ot"] and not ot_authorized:
        result["recommendation"] = "escalate"
        result["automatic"] = False
        result["recipients"] = list(dict.fromkeys([*result["recipients"], "N2", "Responsable de Operaciones"]))
        result["reason"] = "La alerta afecta a OT. Preparar el escalado a Operaciones y N2."
    if finding and finding.get("escalate"):
        result["recommendation"] = "escalate"
        result["automatic"] = False
        result["recipients"] = list(dict.fromkeys([*result["recipients"], *finding["escalate"]]))
        if not critical and not result["ot"]:
            result["reason"] = "La evidencia justifica preparar el aviso y preservar los datos para revisión."
    minutes = {"critical": 15, "high": 30, "medium": 240, "low": 1440}
    deadline = 15 if critical else minutes.get(analysis["severity"])
    if deadline is not None:
        stamp = datetime.fromisoformat(alert["created_at"].replace("Z", "+00:00"))
        result["deadline_at"] = (stamp + timedelta(minutes=deadline)).isoformat()
    return result
