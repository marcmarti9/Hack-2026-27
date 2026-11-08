"""Backend de VIGÍA para la web. Uso: uvicorn apps.backend.main:app --port 8100"""
import csv, hashlib, ipaddress, json, threading, time, uuid
from datetime import datetime, timedelta
import requests
from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from apps.backend.config import DATA, OUT, ROOT, SOC_API, MOCK
from apps.backend.tools import db
from apps.backend.rules.engine import madrid, fuera_de_horario
from apps.backend.rules.approvals import aprobacion
from apps.backend import timeline as tl, explain, playbooks as pb

app = FastAPI(title="VIGÍA")
ALERTAS = {}
for _l in open(DATA / "03_alertas/alertas.jsonl", encoding="utf-8"):
    if _l.strip():
        _a = json.loads(_l); ALERTAS[_a["alert_id"]] = _a
ZONAS = [(z["zona"], ipaddress.ip_network(z["cidr"]), z["descripcion"])
         for z in csv.DictReader(open(DATA / "02_inventario/zonas_red.csv", encoding="utf-8"))]
POR_FUENTE = {"WAF": "DMZ", "ECOM": "DMZ", "AI_GATEWAY": "DMZ", "CLOUD": "AWS-PROD", "CICD": "AWS-PROD", "VPN": "VPN-POOL",
              "IDP": "IDENTIDAD", "EMAIL_GW": "CORREO", "DLP": "HQ-USERS", "AD": "DC-SERVERS"}
DIAS = ["lunes", "martes", "miércoles", "jueves", "viernes", "sábado", "domingo"]
CONTENCIONES = {"isolate_host", "disable_user", "revoke_sessions", "reset_password", "block_ioc", "purge_email", "disable_access_key"}

def leer(nombre, defecto):
    p = OUT / nombre
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else defecto

def _dir(nombre):
    d = OUT / nombre
    return [json.loads(p.read_text(encoding="utf-8")) for p in sorted(d.glob("*.json"))] if d.exists() else []

def tickets():
    return _dir("tickets")

def incidentes_todos():
    return _dir("incidents")

def zona_de(a: dict) -> str:
    for h in a.get("entities", {}).get("hosts", []):
        try:
            ip = ipaddress.ip_address(h.get("ip", ""))
            for nombre, red, _ in ZONAS:
                if ip in red:
                    return nombre
        except ValueError:
            pass
    return POR_FUENTE.get(a.get("source_product", ""), "OTROS")

def siguiente_apertura(ts: str) -> datetime:
    """Primera hora con SOC abierto (L-V 8:00-20:00, hora de Madrid) a partir de ts."""
    l = madrid(ts)
    while l.weekday() >= 5 or l.hour < 8 or l.hour >= 20:
        l = (l + timedelta(hours=1)).replace(minute=0, second=0, microsecond=0)
    return l

@app.get("/api/estado")
def estado():
    from apps.backend.config import MODEL_AGENT
    return {"modo_demo": MOCK, "modelo": MODEL_AGENT, "tickets": len(tickets()), "incidentes": len(incidentes_todos())}

@app.get("/api/resumen")
def resumen():
    return leer("resumen.json", {})

@app.get("/api/tickets")
def lista_tickets():
    orden = ["critical", "high", "medium", "low", "informational"]
    ts = [{k: t.get(k) for k in ("ticket_id", "title", "verdict", "severity", "confidence", "alert_ids", "out_of_hours",
                                 "human_review", "escalation", "manipulation_detected", "summary")} for t in tickets()]
    for t in ts:
        t["primera"] = min((ALERTAS[a]["created_at"] for a in t["alert_ids"] if a in ALERTAS), default="")
    return sorted(ts, key=lambda t: (orden.index(t["severity"]), t["primera"]))

@app.get("/api/tickets/{tid}")
def ticket(tid: str):
    t = next((t for t in tickets() if t["ticket_id"] == tid), None)
    if not t:
        raise HTTPException(404)
    t["alertas"] = [ALERTAS[a] for a in t["alert_ids"] if a in ALERTAS]
    t["incidente"] = next((i for i in incidentes_todos() if set(i.get("alert_ids", [])) & set(t["alert_ids"])), None)
    t["linea"] = tl.construir(t, t["alertas"], t["incidente"])
    rbs = sorted({a["runbook"] for a in t["alertas"]}, key=lambda r: -sum(a["runbook"] == r for a in t["alertas"]))
    t["playbooks"] = [pb.aplicar(next(p for p in PLAYBOOKS if p["id"] == r), t, t["linea"]) for r in rbs if any(p["id"] == r for p in PLAYBOOKS)]
    return t

PLAYBOOKS = pb.cargar()

@app.get("/api/playbooks")
def lista_playbooks():
    por_rb = {}
    for a in ALERTAS.values():
        por_rb[a["runbook"]] = por_rb.get(a["runbook"], 0) + 1
    casos = {}
    for t in tickets():
        for r in {ALERTAS[x]["runbook"] for x in t["alert_ids"] if x in ALERTAS}:
            casos.setdefault(r, []).append({"ticket_id": t["ticket_id"], "title": t["title"], "severity": t["severity"]})
    return [{**p, "alertas": por_rb.get(p["id"], 0), "casos": casos.get(p["id"], [])} for p in PLAYBOOKS]

@app.get("/api/descartado")
def descartado():
    return explain.descartado(leer("cerradas.json", []), ALERTAS, len(ALERTAS))

@app.get("/api/incidentes")
def incidentes():
    return incidentes_todos()

@app.get("/api/cerradas")
def cerradas(rule: str = "", limit: int = 200):
    return [c for c in leer("cerradas.json", []) if not rule or c["rule"] == rule][:limit]

@app.get("/api/caza")
def caza():
    return leer("caza.json", [])

@app.get("/api/evento/{event_id}")
def evento(event_id: str):
    e = db.get_event(event_id)
    if not e:
        raise HTTPException(404)
    return e

@app.get("/api/rgpd")
def rgpd():
    """Reloj de 72 h para cada posible brecha de datos personales (RGPD art. 33)."""
    out = []
    for t in tickets():
        als = [ALERTAS[a] for a in t["alert_ids"] if a in ALERTAS]
        fugas = [a for a in als if a["rule_id"] in ("UC-DLP-001", "UC-CLD-004")
                 or (a["rule_id"] == "UC-DLP-002" and "gestoria-pons" not in json.dumps(a))
                 or (a["rule_id"] == "UC-NET-006" and any(h.get("hostname") == "WMS01" for h in a["entities"].get("hosts", [])))]
        if not fugas or t["verdict"] != "true_positive":
            continue
        ini = min(a["created_at"] for a in fugas)
        t0 = datetime.fromisoformat(ini.replace("Z", "+00:00"))
        apertura = siguiente_apertura(ini)
        perdidas = (apertura - madrid(ini)).total_seconds() / 3600
        out.append({"ticket_id": t["ticket_id"], "title": t["title"], "inicio": ini, "inicio_local": madrid(ini).isoformat(),
                    "limite": (t0 + timedelta(hours=72)).isoformat(), "triage_seconds": t.get("triage_seconds", 0),
                    "horas_sin_vigia": round(perdidas, 1),
                    "apertura_soc": f"{DIAS[apertura.weekday()]} {apertura:%d/%m a las %H:%M}",
                    "notificar": ["DPO", "AEPD (España) y CNPD (Portugal) en 72 h", "Afectados si hay alto riesgo"]})
    return sorted(out, key=lambda x: x["inicio"])

def _pos(clave: str) -> tuple[float, float]:
    """Posición fija (0-1, 0-1) de un equipo dentro de su zona: siempre la misma para el mismo nombre."""
    d = hashlib.md5(clave.encode()).digest()
    return d[0] / 255, d[1] / 255

@app.get("/api/mapa")
def mapa():
    """Zonas, puntos de alerta en el tiempo (posición fija por equipo) y saltos entre equipos de cada ticket."""
    estado_a = {c["alert_id"]: "cerrada" for c in leer("cerradas.json", [])}
    for t in tickets():
        for a in t["alert_ids"]:
            estado_a[a] = "escalada" if t["verdict"] == "true_positive" else "cerrada"
    puntos = []
    for a in ALERTAS.values():
        hosts = a.get("entities", {}).get("hosts", [])
        clave = hosts[0]["hostname"] if hosts else (a.get("entities", {}).get("ips") or [a["alert_id"]])[0]
        px, py = _pos(clave)
        puntos.append({"alert_id": a["alert_id"], "ts": a["created_at"], "zona": zona_de(a), "px": px, "py": py,
                       "severidad": a["severity"], "estado": estado_a.get(a["alert_id"], "pendiente")})
    saltos = []
    for t in tickets():
        camino = []
        for a in sorted((ALERTAS[x] for x in t["alert_ids"] if x in ALERTAS), key=lambda a: a["created_at"]):
            for h in a.get("entities", {}).get("hosts", []):
                z = zona_de({"entities": {"hosts": [h]}})
                if not camino or camino[-1]["zona"] != z:
                    camino.append({"host": h["hostname"], "ts": a["created_at"], "zona": z})
        if len(camino) > 1:
            saltos.append({"ticket_id": t["ticket_id"], "title": t["title"], "camino": camino})
    zonas = [{"zona": n, "cidr": str(r), "descripcion": d} for n, r, d in ZONAS] + \
            [{"zona": z, "cidr": "", "descripcion": d} for z, d in
             (("IDENTIDAD", "Inicios de sesión y cuentas"), ("CORREO", "Correo y colaboración"), ("OTROS", "Sin zona"))]
    return {"zonas": zonas, "puntos": puntos, "saltos": saltos}

class Aprobar(BaseModel):
    ticket_id: str
    action: str
    target: str
    approver: str
    rol: str = "N2"
    reason: str = ""

@app.post("/api/aprobar")
def aprobar(p: Aprobar):
    if p.action not in CONTENCIONES:
        raise HTTPException(400, f"'{p.action}' no es una contención: es un escalado y lo gestiona una persona")
    regla = aprobacion(p.action, p.target, db.asset(p.target))
    if not regla["permitido"]:
        raise HTTPException(403, regla["nota"])
    if regla["requiere"] and p.rol == "N1":
        raise HTTPException(403, f"El N1 no puede aprobarlo: requiere {' + '.join(regla['requiere'])}")
    body = {"target": p.target, "justification": p.reason or f"Ticket {p.ticket_id}", "ticket_id": p.ticket_id}
    try:
        if regla["requiere"]:
            tok = requests.post(f"{SOC_API}/approvals", json={"action": p.action, "target": p.target,
                                "approver": p.approver, "reason": p.reason}, timeout=10).json()["approval_token"]
            body["approval_token"] = tok
        r = requests.post(f"{SOC_API}/containment/{p.action}", json=body, timeout=10)
    except requests.ConnectionError:
        raise HTTPException(503, "La API simulada de Deloitte no está arrancada (puerto 8000)")
    if r.status_code != 200:
        raise HTTPException(r.status_code, r.text)
    ruta = OUT / "tickets" / f"{p.ticket_id}.json"
    if ruta.exists():
        t = json.loads(ruta.read_text(encoding="utf-8"))
        t.setdefault("executed_actions", []).append({**r.json(), "approver": p.approver, "rol": p.rol, "requiere": regla["requiere"]})
        ruta.write_text(json.dumps(t, ensure_ascii=False, indent=1), encoding="utf-8")
    return {"ok": True, "requiere": regla["requiere"], "resultado": r.json()}

# ---------- Análisis en directo: pegar alertas nuevas (las del jurado) y ver al agente trabajar paso a paso ----------
CATALOGO = {r["rule_id"]: r for r in csv.DictReader(open(DATA / "01_contexto/catalogo_casos_de_uso.csv", encoding="utf-8"))}
VIVO = OUT / "alertas_vivo.jsonl"
if VIVO.exists():
    for _l in open(VIVO, encoding="utf-8"):
        if _l.strip():
            _a = json.loads(_l); ALERTAS[_a["alert_id"]] = _a
TRABAJOS = {}

def _normalizar(a: dict) -> dict:
    """Completa una alerta mínima con los datos del catálogo de reglas."""
    for k in ("alert_id", "created_at", "rule_id"):
        if not a.get(k):
            raise ValueError(f"A una alerta le falta '{k}'")
    c = CATALOGO.get(a["rule_id"], {})
    a.setdefault("severity", c.get("severidad_base", "medium")); a.setdefault("status", "new")
    a.setdefault("rule_name", c.get("nombre", a["rule_id"])); a.setdefault("runbook", c.get("runbook", "RB-02"))
    a.setdefault("source_product", c.get("fuente", "")); a.setdefault("description", c.get("logica", ""))
    a.setdefault("mitre", {"tactic": c.get("tactica", ""), "technique_id": c.get("tecnica_id", ""), "technique": c.get("tecnica", "")})
    a.setdefault("entities", {}); a.setdefault("evidence", {}); a.setdefault("related_events", [])
    return a

def _leer_alertas(texto: str) -> list[dict]:
    texto = texto.strip()
    if not texto:
        raise ValueError("No has pegado ninguna alerta")
    try:
        d = json.loads(texto)
        lista = d if isinstance(d, list) else d.get("items", [d]) if isinstance(d, dict) else []
    except json.JSONDecodeError:
        lista = [json.loads(l) for l in texto.splitlines() if l.strip()]
    return [_normalizar(a) for a in lista]

def _trabajo(jid: str, alertas: list[dict], saltar_motor: bool = False):
    from apps.backend.agents import n1, fiscal
    from apps.backend.hunt import shield, group
    from apps.backend.rules.engine import decidir, LEVELS
    J = TRABAJOS[jid]
    try:
        cambios = {c["id"] for c in csv.DictReader(open(DATA / "02_inventario/calendario_cambios.csv", encoding="utf-8"))}
        resto = []
        for a in alertas:
            d = None if saltar_motor else decidir(n1.CTX, a)
            if d:
                J["cerradas"].append({"alert_id": a["alert_id"], "rule_id": a["rule_id"], **d})
                J["pasos"].append({"tipo": "motor", "texto": f"{a['alert_id']}: cerrada por el motor de reglas · {d['reason']}"})
            else:
                a["_escudo_vigia"] = shield.analizar(a, cambios)
                if a["_escudo_vigia"]:
                    J["pasos"].append({"tipo": "escudo", "texto": f"{a['alert_id']}: el escudo detecta un intento de manipulación ({a['_escudo_vigia'][0]['tipo']})"})
                resto.append(a)
        grupos = group.agrupar(resto, list(ALERTAS.values())) if resto else []
        for i, g in enumerate(grupos, 1):
            J["estado"] = f"Investigando el caso {i} de {len(grupos)} ({len(g)} alerta(s))"
            J["pasos"].append({"tipo": "caso", "texto": J["estado"]})
            t = n1.investigar(g, on_step=lambda p: J["pasos"].append(p))
            if LEVELS.index(t["severity"]) >= 2:
                J["estado"] = "La IA revisora (fiscal) intenta tumbar el veredicto"
                J["pasos"].append({"tipo": "fiscal", "texto": J["estado"]})
                t = fiscal.aplicar(t, fiscal.revisar(t, g))
            (OUT / "tickets").mkdir(parents=True, exist_ok=True)
            (OUT / "tickets" / f"{t['ticket_id']}.json").write_text(json.dumps(t, ensure_ascii=False, indent=1, default=str), encoding="utf-8")
            J["tickets"].append({"ticket_id": t["ticket_id"], "title": t["title"], "verdict": t["verdict"], "severity": t["severity"],
                                 "confidence": t["confidence"], "triage_seconds": t["triage_seconds"]})
        J["estado"] = "terminado"
    except Exception as e:
        J["estado"], J["error"] = "error", f"{type(e).__name__}: {e}"
    J["fin"] = time.time()

def _lanzar(alertas, saltar_motor=False):
    jid = uuid.uuid4().hex[:10]
    TRABAJOS[jid] = {"id": jid, "estado": "en cola", "pasos": [], "cerradas": [], "tickets": [], "error": "", "inicio": time.time(), "fin": None,
                     "alertas": len(alertas), "modo_demo": MOCK}
    threading.Thread(target=_trabajo, args=(jid, alertas, saltar_motor), daemon=True).start()
    return {"trabajo": jid}

class Entrada(BaseModel):
    texto: str

@app.post("/api/analizar")
def analizar(e: Entrada):
    try:
        alertas = _leer_alertas(e.texto)
    except (ValueError, json.JSONDecodeError) as err:
        raise HTTPException(400, f"No entiendo las alertas: {err}")
    with open(VIVO, "a", encoding="utf-8") as f:
        for a in alertas:
            ALERTAS[a["alert_id"]] = a
            f.write(json.dumps({k: v for k, v in a.items() if not k.startswith("_")}, ensure_ascii=False) + "\n")
    return _lanzar(alertas)

@app.post("/api/reinvestigar/{tid}")
def reinvestigar(tid: str):
    t = next((t for t in tickets() if t["ticket_id"] == tid), None)
    if not t:
        raise HTTPException(404)
    return _lanzar([dict(ALERTAS[a]) for a in t["alert_ids"] if a in ALERTAS], saltar_motor=True)

@app.get("/api/trabajo/{jid}")
def trabajo(jid: str, desde: int = 0):
    J = TRABAJOS.get(jid)
    if not J:
        raise HTTPException(404)
    return {**{k: v for k, v in J.items() if k != "pasos"}, "pasos": J["pasos"][desde:], "total_pasos": len(J["pasos"]),
            "segundos": round((J["fin"] or time.time()) - J["inicio"], 1)}

@app.get("/api/ejemplos_directo")
def ejemplos_directo():
    from scripts.alertas_directo import ALERTAS as EJ
    return EJ

class Pregunta(BaseModel):
    pregunta: str

@app.post("/api/chat")
def chat(p: Pregunta):
    from apps.backend.agents import chat as ch
    return ch.responder(p.pregunta)

app.mount("/", StaticFiles(directory=str(ROOT / "apps" / "frontend"), html=True), name="web")
