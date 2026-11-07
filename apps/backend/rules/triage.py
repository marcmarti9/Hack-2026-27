"""Criterio verificable y enrutamiento N1 sobre los datos del reto."""
from base64 import b64encode
from datetime import datetime, time, timedelta
import re

from apps.backend.rules.engine import madrid, severidad

SCCM_CHANGE = "CHG-2026-1031"
SCCM_SCRIPT = ("$inv = Get-CimInstance Win32_Product | Select Name,Version | ConvertTo-Json | "
               r"Out-File C:\Windows\CCM\Inventory\sw.json")
WINDOWS_POWERSHELL = r"c:\windows\system32\windowspowershell\v1.0\powershell.exe"
SCCM_COMMAND = ("powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand "
                + b64encode("$inv = Get-CimInstance Win32_Product".encode("utf-16-le")).decode("ascii"))
VELA_SIZE_CORRECTION = re.compile(r"Olvida la talla que te dije, quiero una (?:XS|S|M|L|XL|XXL)[.!]?", re.IGNORECASE)


def _proof(verdict, events, summary, *, actions=(), questions=(), basis=""):
    return {"verdict": verdict, "citations": [event["event_id"] for event in events], "summary": summary,
            "questions": list(questions), "actions": list(actions), "confidence": None, "basis": basis}


def _possible_disclosure(direct):
    for event in direct:
        if event["source"] != "dlp" or "Datos personales" not in event.get("policy", ""):
            continue
        transfers = [log for log in direct if log["source"] == "proxy" and log.get("method") == "POST"
                     and log.get("action") == "allowed" and str(log.get("status")) in {"200", "201", "204"}
                     and log.get("hostname") == event.get("hostname") and log.get("user") == event.get("user")
                     and log.get("domain") == event.get("destination")
                     and str(log.get("bytes_out", "")).isdigit() and int(log["bytes_out"]) > 0]
        if not transfers:
            continue
        total = sum(int(log["bytes_out"]) for log in transfers)
        return {**_proof("needs_more_info", [event, *transfers],
                         f"DLP marcó posible información personal y el proxy registró {len(transfers)} "
                         f"envíos aceptados al mismo destino ({total:,} bytes). "
                         "Los registros no confirman el contenido ni la transferencia completa.",
                         questions=("¿Qué datos contenía el archivo y qué parte llegó al destino?",),
                         actions=("Preservar registros y pedir a N2 y DPO que determinen alcance y notificación.",)),
                "escalate": ["N2", "DPO"]}
    return None


def _same_host(event, hosts):
    return event.get("hostname", "").lower() in hosts


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
    hosts = {host["hostname"].lower() for host in alert.get("entities", {}).get("hosts", [])
             if host.get("hostname")}
    if alert["rule_id"] == "UC-EDR-002":
        event = _sccm_match(alert, direct, analysis["context"], hosts)
        if event:
            return _proof("benign_true_positive", [event],
                          f"{event['event_id']} registra el inventario de SCCM en un puesto incluido en {SCCM_CHANGE}. "
                          "Coinciden proceso, firma, comando y ventana.", basis=f"Actividad autorizada verificada contra {SCCM_CHANGE}.")
    if alert["rule_id"] == "UC-EDR-004":
        for event in direct:
            details = event.get("details") or {}
            command = event.get("command_line", "").lower()
            if (_same_host(event, hosts) and event["source"] == "edr_events"
                    and event.get("event_type") == "process_start"
                    and event.get("process_name", "").lower() == "rundll32.exe"
                    and "comsvcs.dll" in command and "minidump " in command
                    and details.get("target_process", "").lower().startswith("lsass.exe (pid ")):
                return _proof(
                    "true_positive", [event],
                    f"{event['event_id']} registra rundll32 con comsvcs.dll y MiniDump dirigido a LSASS. "
                    "El proceso se inició. El registro no confirma la extracción de credenciales.",
                    questions=("¿Se creó o transfirió el volcado?", "¿Hay uso posterior de credenciales?"),
                    actions=("Revisar el aislamiento del puesto con N2. Verificar conexiones y credenciales expuestas.",),
                )
    if alert["rule_id"] == "UC-WEB-001":
        ips = set(alert["entities"].get("ips", []))
        for event in direct:
            if (event["source"] == "waf" and event.get("src_ip") in ips
                    and event["src_ip"] not in {"192.0.2.10", "192.0.2.11", "192.0.2.12"}
                    and event.get("host") == "www.tarvia.example" and str(event.get("status")) == "403"
                    and event.get("action") == "blocked"
                    and event.get("uri", "").split("?", 1)[0].endswith("/phpunit/src/Util/PHP/eval-stdin.php")):
                return _proof("true_positive", [event], f"{event['event_id']} registra una petición al ejecutor de PHPUnit "
                              "bloqueada con HTTP 403. El registro confirma el intento y el bloqueo, sin evidencia de ejecución.",
                              questions=("¿Hay solicitudes posteriores permitidas desde el mismo origen?",),
                              actions=("Verificar tráfico posterior antes de cerrar o atribuir compromiso.",))
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
    if alert["rule_id"] == "UC-AI-001":
        entities = alert["entities"]
        customers = {row["customer_id"] for row in entities.get("customers", [])}
        for event in direct:
            guard = event.get("guardrail") or {}
            if (event["source"] == "ai_gateway" and event.get("authenticated") is True
                    and event.get("customer_id") in customers and event.get("src_ip") in entities.get("ips", [])
                    and guard.get("action") == "flagged" and guard.get("category") == "prompt_injection"
                    and event.get("tool_calls") == [] and event.get("response_summary") == "Respuesta normal tras revisión"
                    and VELA_SIZE_CORRECTION.fullmatch(event.get("prompt", ""))):
                return _proof("false_positive", [event], "El registro contiene una corrección de talla completa. "
                              "Vela marcó el mensaje pero el registro no muestra llamadas a herramientas.",
                              basis="Corrección de talla acotada, validada con el registro del asistente.")
    if alert["rule_id"] == "UC-AI-002":
        for event in direct:
            if event["source"] != "ai_gateway" or not event.get("session_id"):
                continue
            response = event.get("response_summary", "")
            if response.startswith("El asistente enumeró ") and "códigos internos" in response:
                denials = [log for log in direct if log["source"] == "ai_gateway"
                           and log.get("session_id") == event["session_id"]
                           and (log.get("guardrail") or {}).get("category") == "authz_mismatch"
                           and (log.get("guardrail") or {}).get("action") == "blocked"]
                if denials:
                    return {**_proof("true_positive", [*denials, event],
                                     "Una consulta entre clientes fue denegada. En la misma sesión, "
                                     "el registro indica exposición de códigos internos en otra respuesta. "
                                     "El bloqueo de la primera consulta no acredita que toda la sesión fuera segura.",
                                     actions=("Escalar a N2 y al equipo de IA. Revisar los códigos expuestos.",)),
                            "escalate": ["N2", "Equipo de IA"]}
    if alert["rule_id"] in {"UC-DLP-001", "UC-DLP-002"} and (disclosure := _possible_disclosure(direct)):
        return disclosure
    if alert["rule_id"] == "UC-OT-001":
        for asset in analysis["context"]["activos"]:
            if asset["hostname"] != "ENG-WS01":
                continue
            for event in direct:
                if (event["source"] == "firewall" and event.get("src_ip") == asset["ip"]
                        and event.get("zone_dst") == "LOGISTICS-OT" and event.get("rule") == "OT-ENG-ALLOW"
                        and event.get("action") == "allow" and str(event.get("dst_port")) in {"502", "44818"}):
                    return _proof("benign_true_positive", [event], "La CMDB identifica el puesto de ingeniería "
                                  "y el firewall registra una conexión permitida a OT por un puerto previsto en RB-08.",
                                  basis="Origen de ingeniería, puerto y regla de red autorizados en RB-08.")
    if alert["rule_id"] != "UC-OT-001":
        for report in analysis.get("context", {}).get("sandbox", []):
            if report.get("verdict") == "malicious" and report.get("sha256"):
                return {**_proof("true_positive", [], "El SHA-256 de la alerta coincide con un informe de sandbox "
                                 "que clasifica el archivo como malicioso. Falta confirmar exposición y ejecución en Tarvia.",
                                 questions=("¿Dónde apareció el archivo y se llegó a ejecutar?",),
                                 actions=("Buscar el hash en correo y EDR. Preservar el expediente para N2.",)),
                        "sandbox_refs": [report["sha256"]], "escalate": ["N2"]}
    return None


def route(alert, analysis, mode, finding):
    """La autorización y la cobertura no dependen de lo que redacte el modelo."""
    severity = analysis["severity"]
    verdict = analysis["verdict"]
    result = {"mode": mode, "recommendation": "review", "recipients": [], "automatic": False,
              "reason": "Revisión pendiente. Hace falta evidencia suficiente o una decisión humana."}
    if severity == "critical" or alert["severity"] == "critical":
        result.update(recommendation="escalate", recipients=["N2 de guardia (teléfono)", "Responsable SOC", "CISO"],
                      reason="Crítica. Preparar el aviso y el expediente para revisión humana inmediata. SLA de 15 min.")
    elif severity == "high" and verdict == "true_positive":
        result.update(recommendation="escalate", recipients=["N2", "Responsable SOC"],
                      reason="Verdadero positivo de severidad alta. Revisar con N2 en la misma jornada.")
    elif finding and finding["verdict"] == "true_positive" and alert["rule_id"] == "UC-EDR-004":
        result.update(recommendation="escalate", recipients=["N2"],
                      reason="Señal de acceso a credenciales. Confirmar alcance y decidir la respuesta con N2.")
    elif finding and verdict in {"benign_true_positive", "false_positive"}:
        result.update(recommendation="close", reason=finding["basis"])
        priority = severidad(alert, verdict)
        analysis.update(severity=priority.level,
                        severity_rationale=f"{analysis['severity_rationale']} Tras comprobar el caso: {priority.rationale}",
                        sla=priority.sla)
        if (analysis["provider"] == "Reglas locales" and not alert.get("external")
                and alert["rule_id"] in {"UC-EDR-002", "UC-AI-001"}
                and alert["severity"] in {"informational", "low", "medium"} and severity != "high"):
            result["automatic"] = True
    ot_asset = any(asset["zone"] == "LOGISTICS-OT" for asset in analysis["context"]["activos"])
    ot_alert = alert["rule_id"] == "UC-OT-001" or any(
        event.get("source") == "firewall" and "LOGISTICS-OT" in {event.get("zone_src"), event.get("zone_dst")}
        and event["event_id"] in analysis["requested"] for event in analysis["events"]
    )
    ot_authorized = alert["rule_id"] == "UC-OT-001" and finding and finding["verdict"] == "benign_true_positive"
    if ot_asset or (ot_alert and not ot_authorized):
        result["recommendation"] = "escalate"
        result["automatic"] = False
        result["recipients"] = list(dict.fromkeys([*result["recipients"], "N2", "Responsable de Operaciones"]))
        result["reason"] = "La alerta afecta a OT. Preparar el escalado a Operaciones y N2."
    elif finding and finding.get("escalate"):
        result["recommendation"] = "escalate"
        result["automatic"] = False
        result["recipients"] = list(dict.fromkeys([*result["recipients"], *finding["escalate"]]))
        if severity != "critical":
            result["reason"] = "La evidencia justifica preparar el aviso y preservar los datos para revisión."
    minutes = {"critical": 15, "high": 30, "medium": 240, "low": 1440}
    deadline = 15 if alert["severity"] == "critical" else minutes.get(analysis["severity"])
    if deadline is not None:
        stamp = datetime.fromisoformat(alert["created_at"].replace("Z", "+00:00"))
        result["deadline_at"] = (stamp + timedelta(minutes=deadline)).isoformat()
    return result
