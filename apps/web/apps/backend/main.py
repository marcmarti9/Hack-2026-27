"""Backend y frontend de Vigía. Arranque desde la raíz con servir.sh."""
import csv
import hashlib
import ipaddress
import json
from datetime import datetime, timedelta, timezone
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from apps.backend.config import DATA
from apps.backend.rules.engine import madrid, fuera_de_horario
from apps.backend.tools import db, threat_intel

from .config import OUT, ROOT
from . import defensa, timeline as tl, playbooks as pb

app = FastAPI(title="VIGÍA")
app.include_router(defensa.router)


@app.middleware("http")
async def browser_boundary(request: Request, call_next):
    if request.method in {"POST", "PUT", "DELETE"}:
        origin = request.headers.get("origin")
        if origin and origin != f"{request.url.scheme}://{request.url.netloc}":
            return JSONResponse({"detail": "Origen de la solicitud no permitido."}, status_code=403)
        if request.headers.get("sec-fetch-site") == "cross-site":
            return JSONResponse({"detail": "Origen de la solicitud no permitido."}, status_code=403)
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


ALERTAS = {}
for _l in open(DATA / "03_alertas/alertas.jsonl", encoding="utf-8"):
    if _l.strip():
        _a = json.loads(_l); ALERTAS[_a["alert_id"]] = _a
ZONAS = [(z["zona"], ipaddress.ip_network(z["cidr"]), z["descripcion"])
         for z in csv.DictReader(open(DATA / "02_inventario/zonas_red.csv", encoding="utf-8"))]
POR_FUENTE = {"WAF": "DMZ", "ECOM": "DMZ", "AI_GATEWAY": "DMZ", "CLOUD": "AWS-PROD", "CICD": "AWS-PROD", "VPN": "VPN-POOL",
              "IDP": "IDENTIDAD", "EMAIL_GW": "CORREO", "DLP": "HQ-USERS", "AD": "DC-SERVERS"}
DIAS = ["lunes", "martes", "miércoles", "jueves", "viernes", "sábado", "domingo"]

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
    model = defensa.model()
    return {"modo_demo": not bool(model), "modelo": model or "Motor local",
            "openai_disponible": bool(model), "tickets": len(defensa.reviews.all()),
            "incidentes": len(incidentes_todos())}


@app.get("/api/resumen")
def resumen():
    result = defensa.overview(len(ALERTAS), AFTER_HOURS)
    return {**result, "manipulaciones": None, "hallazgos_caza": len(leer("caza.json", []))}


@app.get("/api/inteligencia")
def inteligencia():
    snapshot = threat_intel.current_snapshot()
    now = datetime.now(timezone.utc)
    return {"fuentes": [
        {"id": name, "url": source["url"], "registros": len(source["records"]),
         "consultada": source["checked_at"], "actualizada": source["fetched_at"],
         "publicada": source["published_at"],
         "estado": "sin datos" if not source["fetched_at"] else
         "copia anterior" if source["error"] or now - datetime.fromisoformat(source["fetched_at"]) >
         timedelta(seconds=2 * threat_intel.INTERVAL) else "actualizada"}
        for name, source in snapshot.get("sources", {}).items()
    ]}


@app.get("/api/tickets")
def lista_tickets(q: str = Query("", max_length=80), offset: int = Query(0, ge=0), limit: int = Query(60, ge=1, le=120)):
    with db.read_session():
        return defensa.cards(q.strip(), offset, limit)


@app.get("/api/tickets/{tid}")
def ticket(tid: str):
    with db.read_session():
        aid = defensa.alert_from_ticket(tid)
        t = defensa.ticket_view(aid) if aid else None
        if t:
            t["incidente"] = t.get("incident")
            known = set(x["event_id"] for x in t.get("evidence", []))
            analysed = {alert["alert_id"]: alert for alert in t["alertas"]}
            alerts = []
            for key in t["alert_ids"]:
                if key in analysed:
                    alerts.append(analysed[key])
                elif row := ALERTAS.get(key):
                    alerts.append({**row, "related_events": [ev for ev in row.get("related_events", []) if ev in known]})
            t["alertas"] = alerts
        else:
            t = next((row for row in tickets() if row["ticket_id"] == tid), None)
            if not t:
                raise HTTPException(404, "No hay expediente para esa alerta. Analízala desde el directo.")
            t["alertas"] = [ALERTAS[key] for key in t["alert_ids"] if key in ALERTAS]
            t["incidente"] = next((row for row in incidentes_todos()
                                    if set(row.get("alert_ids", [])) & set(t["alert_ids"])), None)
        t["linea"] = tl.construir(t, t["alertas"], t["incidente"], database=db)
        runbooks = {a["runbook"] for a in t["alertas"]}
        t["playbooks"] = [pb.aplicar(p, t, t["linea"]) for p in PLAYBOOKS if p["id"] in runbooks]
        return t


PLAYBOOKS = pb.cargar(DATA)
AFTER_HOURS = sum(fuera_de_horario(a["created_at"]) for a in ALERTAS.values())

@app.get("/api/playbooks")
def lista_playbooks():
    por_rb = {}
    for a in ALERTAS.values():
        por_rb[a["runbook"]] = por_rb.get(a["runbook"], 0) + 1
    casos = {}
    with db.read_session():
        cards = defensa.cards(limit=120)
    for t in cards:
        for r in {ALERTAS[x]["runbook"] for x in t["alert_ids"] if x in ALERTAS}:
            casos.setdefault(r, []).append({"ticket_id": t["ticket_id"], "title": t["title"], "severity": t["severity"]})
    return [{**p, "alertas": por_rb.get(p["id"], 0), "casos": casos.get(p["id"], [])} for p in PLAYBOOKS]

@app.get("/api/descartado")
def descartado():
    return defensa.closure_groups(ALERTAS)

@app.get("/api/incidentes")
def incidentes():
    return incidentes_todos()

@app.get("/api/cerradas")
def cerradas(rule: str = "", limit: int = Query(200, ge=1, le=500)):
    return [c for c in defensa._catalog()[1] if not rule or c["rule"] == rule][:limit]

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
    with db.read_session():
        cards = defensa.cards(limit=120)
    for t in cards:
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
    index, closes, _ = defensa._catalog()
    estado_a = {c["alert_id"]: "cerrada" for c in closes}
    estado_a.update({aid: "escalada" for aid, (_, route, _) in index.items() if route == "escalate"})
    with db.read_session():
        cards = defensa.cards(limit=120)
    for t in cards:
        if t["escalation"]["escalate"]:
            estado_a[t["alert_id"]] = "escalada"
    puntos = []
    for a in ALERTAS.values():
        hosts = a.get("entities", {}).get("hosts", [])
        clave = hosts[0]["hostname"] if hosts else (a.get("entities", {}).get("ips") or [a["alert_id"]])[0]
        px, py = _pos(clave)
        puntos.append({"alert_id": a["alert_id"], "ts": a["created_at"], "zona": zona_de(a), "px": px, "py": py,
                       "severidad": a["severity"], "estado": estado_a.get(a["alert_id"], "pendiente")})
    saltos = []
    for t in cards:
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

@app.post("/api/reinvestigar/{tid}")
def reinvestigar(tid: str):
    aid = defensa.alert_from_ticket(tid)
    ids = [aid] if aid else next((t["alert_ids"] for t in tickets() if t["ticket_id"] == tid), [])
    if not ids:
        raise HTTPException(404, "No se encontró el expediente.")
    return defensa.launch(defensa._input(json.dumps(ids)), "guardia", False)


@app.get("/api/ejemplos_directo")
def ejemplos_directo():
    return [json.loads(line) for line in defensa.sample_path.read_text(encoding="utf-8").splitlines()
            if line.startswith("{")]


app.mount("/", StaticFiles(directory=ROOT / "apps" / "frontend", html=True), name="web")
