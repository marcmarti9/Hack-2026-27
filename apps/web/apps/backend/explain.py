"""Por qué se descarta cada grupo de alertas: criterio exacto, respaldo y recomendación para el equipo de detección."""
import collections, json
from apps.backend.rules.engine import madrid

MOTIVOS = {
    "waf_bloqueado": {"titulo": "Escaneos de Internet bloqueados por el WAF", "icono": "🛡", "tipo": "Ataque sin efecto",
        "por_que": "Bots de Internet prueban rutas conocidas (phpunit, .env, wp-login). El WAF devolvió 403 en todas y la tienda no usa esas rutas, así que no hubo efecto.",
        "criterio": "Regla UC-WEB-001 · acción del WAF = blocked · la URL no toca el plugin vulnerable pagebuilder-lite de WEB-ECOM03",
        "respaldo": "Runbook RB-05: 'Escaneo bloqueado o pentest autorizado → cerrar'",
        "recomendacion": "Agrupar los bloqueos por IP en una sola alerta diaria: ahorra unas 120 alertas al día.", "campos": ["rule_msg", "hits", "action"]},
    "newsletter": {"titulo": "Newsletters legítimas reportadas como phishing", "icono": "✉", "tipo": "Falsa alarma",
        "por_que": "Empleados pulsaron 'Reportar phishing' en boletines de remitentes conocidos (Retail Forum, LinkedIn, DocuSign...). La pasarela los dio por limpios y el remitente pasa SPF y DKIM.",
        "criterio": "Regla UC-EML-001 · veredicto de la pasarela = clean o bulk · SPF = pass y DKIM = pass · sin texto sospechoso en el cuerpo",
        "respaldo": "Runbook RB-01, comprobación 1 (remitente, SPF, DKIM y DMARC)",
        "recomendacion": "Responder al usuario automáticamente 'gracias, es legítimo' y añadir esos remitentes a una lista de confianza.", "campos": ["sender", "subject"]},
    "sccm": {"titulo": "Inventario de software de SCCM", "icono": "⚙", "tipo": "Actividad autorizada",
        "por_que": "El agente de SCCM lanza cada mañana un PowerShell codificado para hacer inventario. Está aprobado como cambio permanente.",
        "criterio": "Regla UC-EDR-002 · proceso padre CcmExec.exe · usuario SYSTEM",
        "respaldo": "Cambio aprobado CHG-2026-1031 (svc_sccm, diario de 08:00 a 10:00)",
        "recomendacion": "Excluir en la regla el padre CcmExec.exe con usuario SYSTEM: son 1.349 alertas menos al mes.", "campos": ["parent", "user", "decoded_preview"]},
    "viaje_dispositivo": {"titulo": "Viajes con dispositivo corporativo conocido", "icono": "✈", "tipo": "Falsa alarma",
        "por_que": "La regla de viaje imposible saltó por inicios de sesión desde otra ciudad, pero desde un móvil o portátil corporativo conocido y conforme, sin ninguna acción rara después.",
        "criterio": "Regla UC-IDP-001 · dispositivo 'conocido y conforme' · sin acciones posteriores sospechosas",
        "respaldo": "Runbook RB-03: 'Viaje notificado o dispositivo conocido → cerrar'",
        "recomendacion": "Usar el ID del dispositivo conforme en la regla para no alertar en estos casos.", "campos": ["previous_login", "current_login", "device"]},
    "dominio_corporativo": {"titulo": "Software corporativo que se comunica a menudo", "icono": "🌐", "tipo": "Falsa alarma",
        "por_que": "Windows Update, Teams, Google Update, el agente BMC y las impresoras se conectan periódicamente. Es normal: es su forma de funcionar.",
        "criterio": "Regla UC-NET-001 · todos los dominios pertenecen a servicios corporativos conocidos",
        "respaldo": "Inventario de software de Tarvia",
        "recomendacion": "Lista de exclusión de dominios corporativos en la regla de beaconing.", "campos": []},
    "spam_sin_clic": {"titulo": "Spam y phishing genérico sin ningún clic", "icono": "🗑", "tipo": "Ataque sin efecto",
        "por_que": "Campañas genéricas (facturas falsas de Microsoft, sorteos) que nadie abrió. Se purgan de todos los buzones y se bloquea el remitente.",
        "criterio": "Regla UC-EML-001 · veredicto de la pasarela = spam · ningún clic en ese dominio en email_clicks",
        "respaldo": "Runbook RB-01: 'Sin interacción y sin entrega masiva → purgar, bloquear remitente, cerrar'",
        "recomendacion": "Purga y bloqueo automáticos (el N1 puede ejecutarlos sin aprobación).", "campos": ["sender", "subject"]},
    "cdn": {"titulo": "Subdominios aleatorios de CDN y nube", "icono": "🧭", "tipo": "Falsa alarma",
        "por_que": "Akamai, CloudFront, Azure y AWS usan nombres de subdominio aleatorios que parecen generados por malware, pero son su funcionamiento normal.",
        "criterio": "Regla UC-NET-005 · dominio padre en la lista de CDN y nube conocidos",
        "respaldo": "Runbook RB-09: 'Software conocido → cerrar y proponer exclusión'",
        "recomendacion": "Excluir estos dominios padre de la regla DGA.", "campos": ["query", "entropy"]},
    "sap": {"titulo": "Excel abriendo SAP GUI", "icono": "📊", "tipo": "Falsa alarma",
        "por_que": "Los usuarios de finanzas abren SAP desde Excel con un complemento. El proceso hijo está firmado por SAP SE.",
        "criterio": "Regla UC-EDR-001 · árbol EXCEL.EXE > saplogon.exe · firmante SAP SE",
        "respaldo": "Runbook RB-02, comprobación 1 (firma y software aprobado)",
        "recomendacion": "Excluir saplogon.exe firmado por SAP SE como hijo de Excel: 531 alertas menos.", "campos": ["process_tree", "signer"]},
    "vela_cliente": {"titulo": "Clientes de Vela corrigiendo su pedido", "icono": "🤖", "tipo": "Falsa alarma",
        "por_que": "Frases como 'olvida la talla que te dije' activan el detector de prompt injection, pero son clientes corrigiéndose. El guardarraíl solo las marcó y no las bloqueó.",
        "criterio": "Regla UC-AI-001 · acción del guardarraíl = flagged (no blocked)",
        "respaldo": "Runbook RB-07: 'Un cliente corrigiéndose no es un ataque'",
        "recomendacion": "Afinar el guardarraíl de Vela: solo alertar si bloquea o si hay llamada a herramientas con datos de otro cliente.", "campos": ["prompt_excerpt", "action"]},
    "edr_bloqueado": {"titulo": "Software no deseado bloqueado por el EDR", "icono": "🧹", "tipo": "Ataque sin efecto",
        "por_que": "Cracks, activadores y adware que el antivirus puso en cuarentena antes de que se ejecutaran.",
        "criterio": "Regla UC-EDR-003 · acción = quarantined o blocked · executed = false",
        "respaldo": "Runbook RB-02: 'Bloqueado antes de ejecutar y sin actividad posterior → cerrar'",
        "recomendacion": "Recordatorio automático al usuario sobre el uso de software no autorizado.", "campos": ["detection_name", "action"]},
    "dns_seguridad": {"titulo": "Consultas de antivirus y listas DNSBL", "icono": "🧭", "tipo": "Falsa alarma",
        "por_que": "McAfee, Sophos y Spamhaus consultan su reputación con subdominios muy largos. Parece un túnel DNS, pero es su funcionamiento normal.",
        "criterio": "Regla UC-NET-006 · todos los dominios son de antivirus o DNSBL conocidos",
        "respaldo": "Runbook RB-09", "recomendacion": "Excluir estos dominios de la regla de túnel DNS (sin tocar el de WMS01, que es real).", "campos": ["queries_1h"]},
    "stuffing_sin_exito": {"titulo": "Credential stuffing sin ningún acceso correcto", "icono": "🛒", "tipo": "Ataque sin efecto",
        "por_que": "Intentos de login masivos contra la tienda con 0 accesos correctos y el rate limit activado.",
        "criterio": "Regla UC-WEB-002 · success_count = 0", "respaldo": "Runbook RB-05, comprobación 2 ('sobre todo, cuántos accesos correctos')",
        "recomendacion": "Activar captcha también en la API de la app.", "campos": ["failed_logins_15min", "success_count"]},
    "spray_sin_exito": {"titulo": "Password spraying sin ningún acceso correcto", "icono": "🔑", "tipo": "Ataque sin efecto",
        "por_que": "Intentos contra cuentas con autenticación heredada, bloqueada por política, sin ningún éxito.",
        "criterio": "Regla UC-IDP-002 · successes = 0", "respaldo": "Runbook RB-03", "recomendacion": "Mantener bloqueada la autenticación heredada.", "campos": ["failed_attempts", "protocol"]},
    "terraform": {"titulo": "Cambios de terraform desde el CI", "icono": "☁", "tipo": "Actividad autorizada",
        "por_que": "El pipeline de infraestructura aplica la política del bucket de recursos estáticos.", "criterio": "Regla UC-CLD-003 · origen = terraform desde el runner CI interno",
        "respaldo": "Runbook RB-06: 'Pipeline conocido → cerrar'", "recomendacion": "Etiquetar los cambios de terraform con el ID del PR para no alertar.", "campos": ["change", "source"]},
    "pentest": {"titulo": "Pentest contratado de la tienda online", "icono": "🎯", "tipo": "Actividad autorizada",
        "por_que": "Ataques web desde las IPs de la auditora externa, dentro de las fechas del pentest.", "criterio": "Regla UC-WEB-001 · IP en 192.0.2.10-12 · entre el 8/10 08:00 y el 10/10 18:00",
        "respaldo": "Cambio aprobado CHG-2026-1042", "recomendacion": "Cargar las ventanas de pentest en el SIEM para suprimir estas alertas automáticamente.", "campos": ["rule_msg", "hits"]},
    "nessus": {"titulo": "Escáner de vulnerabilidades NESSUS01", "icono": "🔍", "tipo": "Actividad autorizada",
        "por_que": "El escaneo semanal toca cientos de equipos en minutos, en su ventana de los miércoles de 01:00 a 05:00.", "criterio": "Regla UC-NET-003 · origen NESSUS01 · miércoles entre 01:00 y 05:00",
        "respaldo": "Cambios CHG-2026-1049 a 1052", "recomendacion": "Excluir NESSUS01 en su ventana.", "campos": ["distinct_dst_hosts"]},
    "paquete_conocido": {"titulo": "Paquetes npm conocidos que descargan binarios", "icono": "📦", "tipo": "Falsa alarma",
        "por_que": "puppeteer, sharp y esbuild descargan binarios al instalarse por diseño y no leen secretos.", "criterio": "Regla UC-DEV-001 · paquete conocido · solo lee PATH y HOME",
        "respaldo": "Runbook RB-10: 'Paquete conocido sin acceso a secretos → cerrar y excluir'", "recomendacion": "Lista de paquetes permitidos en el pipeline.", "campos": ["package", "network"]},
    "ot_autorizado": {"titulo": "ENG-WS01 hablando con la red OT", "icono": "🏭", "tipo": "Actividad autorizada",
        "por_que": "La estación de ingeniería es uno de los dos equipos autorizados a hablar con los PLC del clasificador.", "criterio": "Regla UC-OT-001 · origen = ENG-WS01",
        "respaldo": "Reglas de la casa: solo ENG-WS01 y WMS01 pueden hablar con OT", "recomendacion": "Excluir ENG-WS01 de la regla.", "campos": ["ports"]},
    "cambio_aprobado": {"titulo": "Dentro de un cambio aprobado", "icono": "📅", "tipo": "Actividad autorizada",
        "por_que": "La alerta coincide en origen y fecha con un cambio del calendario (paradas del EDR, altas en grupos o el proveedor fuera de horario).",
        "criterio": "La alerta cita un CHG que existe en el calendario y está dentro de su ventana", "respaldo": "CHG-2026-1071, 1078 y 1080",
        "recomendacion": "Integrar el calendario de cambios con el SIEM.", "campos": ["change_ticket", "maintenance_window"]},
    "psexec_jump": {"titulo": "PsExec desde el servidor de salto", "icono": "🛠", "tipo": "Actividad autorizada",
        "por_que": "Despliegue del agente de monitorización desde JUMP01 con cuenta adm, como dice el cambio.", "criterio": "Regla UC-NET-004 · origen JUMP01 · dentro del CHG-2026-1057",
        "respaldo": "Cambio CHG-2026-1057", "recomendacion": "—", "campos": ["method", "account"]},
    "nominas": {"titulo": "Nóminas a la gestoría", "icono": "💼", "tipo": "Actividad autorizada",
        "por_que": "Envío mensual de variables de nómina al encargado del tratamiento, con contrato vigente.", "criterio": "Regla UC-DLP-002 · destinatario = asesoria@gestoria-pons.example",
        "respaldo": "Flujo aprobado FLUJO-0007", "recomendacion": "Excluir el flujo de la regla DLP.", "campos": ["recipient", "matches"]},
    "ot_mantenimiento": {"titulo": "Mantenimiento del clasificador", "icono": "🏭", "tipo": "Actividad autorizada",
        "por_que": "El fabricante entra a los PLC vía JUMP01 con una regla temporal.", "criterio": "Regla UC-OT-001 · origen JUMP01 · dentro del CHG-2026-1063",
        "respaldo": "Cambio CHG-2026-1063", "recomendacion": "—", "campos": ["firewall_rule"]},
    "dlp_sin_datos": {"titulo": "Subidas de material de trabajo sin datos personales", "icono": "📤", "tipo": "Falsa alarma",
        "por_que": "Ficheros grandes de campaña (fotos, vídeos) enviados por WeTransfer sin ningún dato personal.", "criterio": "Regla UC-DLP-001 · 0 coincidencias de datos personales · fichero no cifrado",
        "respaldo": "Runbook RB-04: 'Sin datos sensibles → cerrar'", "recomendacion": "Subir el umbral de tamaño para material de marketing.", "campos": ["destination", "file", "personal_data_matches"]},
}

def descartado(cerradas: list[dict], alertas: dict, total: int) -> dict:
    por = collections.defaultdict(list)
    for c in cerradas:
        por[c["rule"]].append(c)
    grupos = []
    for k, xs in sorted(por.items(), key=lambda kv: -len(kv[1])):
        m = MOTIVOS.get(k, {"titulo": k, "icono": "•", "tipo": "", "por_que": xs[0]["reason"], "criterio": "", "respaldo": "", "recomendacion": "", "campos": []})
        reglas = collections.Counter(x["rule_id"] for x in xs)
        fuera = sum(1 for x in xs if (lambda l: l.weekday() >= 5 or l.hour < 8 or l.hour >= 20)(madrid(x["created_at"])))
        ejemplos = []
        for x in xs[:: max(1, len(xs) // 5)][:5]:
            a = alertas.get(x["alert_id"], {})
            ev = a.get("evidence", {})
            datos = {c: ev[c] for c in m["campos"] if c in ev}
            ents = a.get("entities", {})
            quien = ([h["hostname"] for h in ents.get("hosts", [])] + [u.get("upn", "").split("@")[0] for u in ents.get("users", [])] + ents.get("ips", []))[:2]
            ejemplos.append({"alert_id": x["alert_id"], "cuando": madrid(x["created_at"]).strftime("%d/%m %H:%M"), "regla": x["rule_id"],
                             "quien": ", ".join(quien), "datos": {k2: (json.dumps(v, ensure_ascii=False) if not isinstance(v, str) else v)[:90] for k2, v in datos.items()}})
        grupos.append({"clave": k, **{c: m[c] for c in ("titulo", "icono", "tipo", "por_que", "criterio", "respaldo", "recomendacion")},
                       "n": len(xs), "pct": round(100 * len(xs) / total, 1), "horas": round(len(xs) * 15 / 60),
                       "fuera_de_horario": fuera, "reglas": [{"rule_id": r, "n": n, "nombre": alertas_nombre(alertas, r)} for r, n in reglas.most_common()],
                       "ejemplos": ejemplos})
    tipos = collections.Counter()
    for g in grupos:
        tipos[g["tipo"]] += g["n"]
    return {"total": total, "cerradas": len(cerradas), "tipos": tipos.most_common(), "grupos": grupos}

_NOMBRES = {}
def alertas_nombre(alertas, rule_id):
    if not _NOMBRES:
        for a in alertas.values():
            _NOMBRES.setdefault(a["rule_id"], a["rule_name"])
    return _NOMBRES.get(rule_id, rule_id)
