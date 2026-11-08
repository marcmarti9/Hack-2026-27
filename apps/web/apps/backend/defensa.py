"""Servicio web para el triaje canónico, los expedientes y las decisiones."""
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache
from pathlib import Path
from threading import Lock
from time import time
from typing import Literal
from uuid import uuid4
import json
import logging
import os

from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from apps.backend.config import ROOT as REPO
from apps.backend.rules.engine import fuera_de_horario, madrid
from apps.backend.tools import db
from apps.desktop import assistant, sim_response
from apps.desktop.defense import ALERT_ID, MAX_ALERTS, MAX_BYTES, _object, parse_alerts
from apps.desktop.demo import DEMO_USER
from apps.desktop.review import Reviews, investigate, reviewed_proposal
from apps.desktop.session import Account

from .config import OUT

router = APIRouter(prefix="/api")
state = Path(os.getenv("VIGIA_WEB_OUT") or OUT).resolve()
state.mkdir(parents=True, exist_ok=True)
reviews = Reviews(state)
pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="triaje-web")
lock = Lock()
jobs = {}
corpus_path = Path(os.getenv("VIGIA_WEB_CORPUS") or state / "corpus.jsonl")
sample_path = REPO / "eval" / "lote-presentacion-091.jsonl"
showcase = ("ALR-20261010-011795", "ALR-20261011-011800", "ALR-20261014-011817",
            "ALR-20261005-000301", "ALR-20261005-000099")
log = logging.getLogger(__name__)


def model():
    return "" if os.getenv("VIGIA_WEB_LOCAL_ONLY") == "1" else assistant.available_model()


def web_id(alert_id):
    return f"VIG-{alert_id}"


def alert_from_ticket(ticket_id):
    key = ticket_id.removeprefix("VIG-")
    return key if ALERT_ID.fullmatch(key) else None


def _batch_text(text):
    if len(text.encode("utf-8")) > MAX_BYTES:
        raise ValueError("El lote supera 1 MB.")
    text = text.strip().removeprefix("\ufeff")
    if not text:
        raise ValueError("Pega una alerta o un ID del índice.")
    try:
        payload = json.loads(text, object_pairs_hook=_object)
    except json.JSONDecodeError:
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        if all(ALERT_ID.fullmatch(line) for line in lines):
            return parse_alerts("\n".join(json.dumps(line) for line in lines).encode())
        return parse_alerts(text.encode())
    if isinstance(payload, dict) and "items" in payload and "alert_id" not in payload:
        payload = payload["items"]
        if not isinstance(payload, list):
            raise ValueError("El campo items debe ser una lista de alertas.")
    if not isinstance(payload, list):
        payload = [payload]
    if len(payload) > MAX_ALERTS:
        raise ValueError(f"El lote admite hasta {MAX_ALERTS} alertas.")
    return parse_alerts("\n".join(json.dumps(item, ensure_ascii=False) for item in payload).encode("utf-8"))


def _input(text):
    try:
        return _batch_text(text)
    except UnicodeError:
        raise ValueError("El texto debe usar UTF-8.") from None


def _catalog():
    try:
        info = corpus_path.stat()
    except FileNotFoundError:
        return {}, [], {}
    return _scan(corpus_path, info.st_ino, info.st_size, info.st_mtime_ns)


@lru_cache(maxsize=1)
def _scan(path, inode, size, mtime):
    index, closes, times = {}, [], []
    counts = Counter()
    with path.open("rb") as handle:
        while True:
            offset = handle.tell()
            line = handle.readline()
            if not line:
                break
            report = json.loads(line)
            aid = report.get("alert_id")
            if report.get("estado") == "error" or not aid:
                counts["errores"] += 1
                continue
            route = report["routing"]
            counts["investigadas"] += 1
            counts["escaladas"] += route["recommendation"] == "escalate"
            counts["abstenciones"] += report["verdict"] == "needs_more_info"
            counts["fuera_de_horario"] += fuera_de_horario(report["created_at"])
            times.append(report.get("timing_ms") or 0)
            index[aid] = (offset, route["recommendation"], report.get("ticket_id"))
            if route["automatic"]:
                basis = report.get("criterio_verificado") or {}
                closes.append({"alert_id": aid, "rule_id": report["rule_id"], "rule": report["runbook"],
                               "created_at": report["created_at"], "reason": report["summary"],
                               "citations": basis.get("citations", []), "verdict": report["verdict"]})
    times.sort()
    stats = dict(counts)
    if times:
        stats["p50_ms"] = times[len(times) // 2]
        stats["p95_ms"] = times[int(len(times) * .95)]
    return index, closes, stats


def corpus_report(aid):
    index, _, _ = _catalog()
    if aid not in index:
        return None
    with corpus_path.open("rb") as handle:
        handle.seek(index[aid][0])
        report = json.loads(handle.readline())
    return report if report.get("alert_id") == aid else None


@lru_cache(maxsize=len(showcase))
def _preview(aid):
    alert = db.get_alert(aid)
    if alert is None:
        return None
    return investigate(alert, triage=True, mode="guardia" if fuera_de_horario(alert["created_at"]) else "diurno")["report"]


def record(aid, rows=None):
    stored = (reviews.all() if rows is None else rows).get(aid) or {}
    analysis = stored.get("analysis") or {}
    alert = analysis.get("input_alert") or db.get_alert(aid)
    report = analysis.get("report") or corpus_report(aid)
    if report is None and aid in showcase:
        report = _preview(aid)
    if not alert or not report:
        return None
    return alert, analysis, report, stored


def _decision(row):
    if not row.get("decision"):
        return None
    return {key: row.get(key) for key in ("decision", "verdict", "reviewer", "reviewed_at")}


def _disposition(report, stored):
    return {"automatic": "Cierre automático", "accepted": "Aceptada", "corrected": "Corregida"}.get(
        stored.get("decision"),
        {"close": "Cierre propuesto", "review": "Revisión", "escalate": "Escalar"}[report["routing"]["recommendation"]])


def _summary(alert, report, stored):
    aid = alert["alert_id"]
    route = report["routing"]
    decision = _decision(stored)
    return {
        "alert_id": aid, "ticket_id": web_id(aid), "incident_id": report.get("ticket_id"),
        "title": alert["rule_name"], "verdict": stored.get("verdict") or report["verdict"],
        "severity": report["severity"], "confidence": report["confidence"],
        "alert_ids": report["alert_ids"], "primera": alert["created_at"],
        "out_of_hours": fuera_de_horario(alert["created_at"]),
        "human_review": not decision and route["recommendation"] in {"review", "escalate"},
        "escalation": report["escalation"], "summary": report["summary"],
        "triage_seconds": report["triage_seconds"], "disposition": _disposition(report, stored),
        "responsables": route.get("recipients", []), "plazo": route.get("deadline_at"),
    }


def cards(query="", offset=0, limit=60):
    rows = reviews.all()
    index, _, _ = _catalog()
    keys = dict.fromkeys((*rows, *showcase, *(aid for aid, (_, route, _) in index.items() if route == "escalate")))
    if query:
        query = query.casefold()
        keys = dict.fromkeys(aid for aid in (*keys, *index) if query in aid.casefold())
    results = []
    incidents = set()
    for aid in keys:
        if data := record(aid, rows):
            alert, _, report, stored = data
            incident = report.get("ticket_id")
            if not query and incident and incident in incidents and aid not in rows:
                continue
            incidents.add(incident)
            results.append(_summary(alert, report, stored))
    ranks = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
    return sorted(results, key=lambda row: (ranks.get(row["severity"], 5), row["primera"]))[offset:offset + limit]


def overview(total, after_hours):
    index, closes, stats = _catalog()
    rows = reviews.all()
    live = {aid: row["analysis"]["report"] for aid, row in rows.items() if (row.get("analysis") or {}).get("report")}
    complete = stats.get("investigadas") == total and not stats.get("errores")
    investigated = stats.get("investigadas", 0) + sum(aid not in index for aid in live)
    pending = stats.get("abstenciones", sum(r["verdict"] == "needs_more_info" for r in live.values()))
    escalations = stats.get("escaladas", sum(r["routing"]["recommendation"] == "escalate" for r in live.values()))
    groups = {ticket for _, route, ticket in index.values() if route == "escalate" and ticket}
    return {
        "alertas": total, "cerradas_por_reglas": len(closes), "al_agente": investigated,
        "grupos": len(groups) if index else escalations, "investigadas": investigated,
        "escaladas": escalations, "abstenciones": pending,
        "cierres_ejecutados": sum(row.get("decision") == "automatic" for row in rows.values()),
        "corpus_completo": complete, "benchmark": {k: stats[k] for k in ("p50_ms", "p95_ms") if k in stats},
        "fuera_de_horario_al_agente": round(100 * stats.get("fuera_de_horario", 0) / max(1, stats.get("investigadas", 0)), 1),
        "fuera_de_horario_total": round(100 * after_hours / max(1, total), 1),
    }


def closure_groups(alerts):
    _, closes, _ = _catalog()
    groups = []
    labels = {"false_positive": "Falsa alarma", "benign_true_positive": "Actividad autorizada",
              "true_positive": "Ataque sin efecto"}
    grouped = {}
    for row in closes:
        grouped.setdefault((row["rule_id"], row["verdict"]), []).append(row)
    for (rule, verdict), group in sorted(grouped.items(), key=lambda item: -len(item[1])):
        first = group[0]
        label = alerts.get(first["alert_id"], {}).get("rule_name", rule)
        examples = [
            {"alert_id": row["alert_id"], "cuando": madrid(row["created_at"]).strftime("%d/%m %H:%M"),
             "quien": row["rule_id"], "datos": {"Motivo": row["reason"], "Citas": ", ".join(row["citations"])}}
            for row in group[::max(1, len(group) // 5)][:5]
        ]
        groups.append({"clave": rule, "titulo": label, "icono": "•", "tipo": labels.get(verdict, "Falsa alarma"),
                       "por_que": first["reason"], "criterio": "Se exige un hallazgo local corroborado.",
                       "respaldo": f"{first['rule']} · abre el expediente para comprobar los registros.",
                       "recomendacion": "", "n": len(group), "pct": round(100 * len(group) / max(1, len(alerts)), 1),
                       "horas": round(len(group) * 15 / 60), "reglas": [{"rule_id": rule, "nombre": label, "n": len(group)}],
                       "ejemplos": examples})
    types = Counter()
    for group in groups:
        types[group["tipo"]] += group["n"]
    return {"total": len(alerts), "cerradas": len(closes), "tipos": types.most_common(), "grupos": groups}


def _history(aid):
    return [{"kind": row["kind"], "actor": row["actor"], "created_at": row["created_at"],
             "reason": row["data"].get("reason") or row["data"].get("result") or ""}
            for row in reviews.history(aid, limit=80)]


def ticket_view(aid):
    if not (data := record(aid)):
        return None
    alert, analysis, report, stored = data
    decision = _decision(stored)
    report = {**report, "decision_actual": decision, "review_provider": analysis.get("review_provider"),
              "review_reason": analysis.get("review_reason"), "tiempos_ms": analysis.get("timing", {}),
              "revisiones_guia": analysis.get("guidance", {})}
    if decision:
        report["veredicto_triaje"] = report["verdict"]
        report["verdict"] = decision["verdict"]
    simulated = sim_response.isolation_records(reviews, aid, analysis) if analysis else []
    proposal = sim_response.isolation_proposal(aid, practice=bool(os.getenv("VIGIA_WEB_N2_PASSWORD")))
    if proposal and not simulated and stored.get("verdict") in (None, "true_positive"):
        report["isolation_proposal"] = proposal
    report["executed_actions"] = simulated
    challenge = report.get("contraste") or {}
    route = report["routing"]
    trace = [{"tipo": "evidencia", "texto": line} if isinstance(line, str) else line
             for line in report.get("consultas", [])]
    return {
        **report, **_summary(alert, report, stored), "expediente": report, "alertas": [alert],
        "fiscal": {"agrees": challenge["verdict"] == (report.get("propuesta") or {}).get("verdict"),
                   "comment": challenge.get("summary", ""), "objections": challenge.get("questions", [])}
        if challenge else None,
        "trace": trace, "historial": _history(aid), "decision_actual": decision,
        "puede_aceptar": bool(analysis and not decision and reviewed_proposal(analysis)),
        "routing": route, "provider": report.get("provider"), "provider_errors": report.get("provider_errors", {}),
    }


def _stage(job, kind, text):
    with lock:
        job["estado"] = text
        job["pasos"].append({"tipo": kind, "texto": text})


def _run(job, alerts, mode, remote):
    try:
        results, errors = {}, {}
        for alert in alerts:
            aid = alert["alert_id"]
            _stage(job, "caso", f"{aid} · recuperando registros, inventario y contexto.")
            try:
                reviews.validate_alert_input(alert)
                guidance = reviews.guidance(alert["runbook"]) if remote else None
                results[aid] = investigate(alert, remote, guidance, triage=True, mode=mode,
                                           on_stage=lambda kind, text: _stage(job, kind, f"{aid} · {text}"))
            except ValueError as error:
                errors[aid] = str(error)
            except Exception:
                log.exception("Falló el triaje del expediente %s", aid)
                errors[aid] = "No se pudo investigar esta alerta. Comprueba el índice."
        _stage(job, "guardado", "Contrastando identidades y guardando los expedientes del lote.")
        for aid, (_, error) in reviews.save_batch(results).items():
            if error:
                errors[aid] = error
        rows = reviews.all()
        cards_out = []
        for alert in alerts:
            aid = alert["alert_id"]
            if aid in errors:
                _stage(job, "error", f"{aid} · {errors[aid]}")
                continue
            report = results[aid]["report"]
            item = _summary(alert, report, rows.get(aid) or {})
            if report.get("provider_errors"):
                _stage(job, "aviso", f"{aid} · {next(iter(report['provider_errors'].values()))} Se conserva la decisión verificable.")
            elif remote and not results[aid].get("review_provider"):
                _stage(job, "local", f"{aid} · se aplicó la política local de cierre o falta evidencia para el contraste.")
            cards_out.append(item)
        with lock:
            job.update(estado="terminado" if cards_out else "error", fin=time(), tickets=cards_out,
                       error="; ".join(f"{aid}: {value}" for aid, value in errors.items()))
    except Exception:
        log.exception("Falló el guardado del lote web")
        with lock:
            job.update(estado="error", fin=time(), error="No se pudo guardar el lote de análisis.")


def launch(alerts, mode, remote):
    if remote and not model():
        raise HTTPException(409, "Configura OPENAI_API_KEY en el servidor para usar OpenAI.")
    with lock:
        if any(not job["fin"] for job in jobs.values()):
            raise HTTPException(409, "Ya hay un lote en curso. Espera a que termine.")
        if len(jobs) >= 32:
            jobs.pop(next(iter(jobs)))
        jid = uuid4().hex
        job = jobs[jid] = {"id": jid, "estado": "en cola", "pasos": [], "cerradas": [], "tickets": [],
                           "error": "", "inicio": time(), "fin": None, "alertas": len(alerts), "modo_demo": not remote}
    pool.submit(_run, job, alerts, mode, remote)
    return {"trabajo": jid}


class Entrada(BaseModel):
    texto: str = Field(min_length=1, max_length=MAX_BYTES)
    modo: Literal["diurno", "guardia"] = "guardia"
    remoto: bool = False


@router.post("/analizar")
def analyze(entry: Entrada):
    try:
        alerts = _input(entry.texto)
    except RecursionError:
        raise HTTPException(400, "El lote tiene demasiados niveles de anidación.") from None
    except ValueError as error:
        raise HTTPException(400, f"Lote inválido: {error}") from None
    return launch(alerts, entry.modo, entry.remoto)


@router.get("/trabajo/{jid}")
def job_state(jid: str, desde: int = 0):
    with lock:
        if not (job := jobs.get(jid)):
            raise HTTPException(404, "No se encontró el análisis.")
        return {**job, "pasos": job["pasos"][max(0, desde):], "total_pasos": len(job["pasos"]),
                "segundos": round((job["fin"] or time()) - job["inicio"], 1)}


@router.get("/lote_ensayo")
def sample(una: bool = False):
    content = sample_path.read_text(encoding="utf-8")
    if una:
        content = next(line for line in content.splitlines() if line.startswith("{"))
    return {"texto": content}


@router.get("/expediente/{aid}")
def export(aid: str):
    if not ALERT_ID.fullmatch(aid) or not (view := ticket_view(aid)):
        raise HTTPException(404, "Expediente no disponible.")
    return JSONResponse({"alerta": view["alert_id"], "informe": view["expediente"], "historial": view["historial"]},
                        headers={"Content-Disposition": f'attachment; filename="Vigia-{aid}.json"'})


class Decision(BaseModel):
    decision: Literal["accepted", "corrected"]
    verdict: Literal["true_positive", "benign_true_positive", "false_positive", "false_negative", "true_negative"]
    reason: str = Field(default="", max_length=1000)
    rol: Literal["N1", "N2", "Responsable"] = "N1"


@router.post("/decision/{aid}")
def decide(aid: str, entry: Decision):
    if not ALERT_ID.fullmatch(aid) or not (data := record(aid)):
        raise HTTPException(404, "Expediente no disponible.")
    alert, analysis, report, _ = data
    if report["routing"]["recommendation"] == "escalate" and entry.rol == "N1":
        raise HTTPException(403, "El escalado requiere revisión N2.")
    if entry.decision == "corrected" and not entry.reason.strip():
        raise HTTPException(400, "Indica el motivo de la corrección.")
    try:
        applied = reviews.decide(aid, entry.verdict, entry.decision, f"analista.{entry.rol.lower()}",
                                 expected=analysis, reason=entry.reason, alert=alert)
    except ValueError as error:
        raise HTTPException(400, str(error)) from None
    if not applied:
        raise HTTPException(409, "El expediente ya tiene una decisión vigente.")
    return {"ok": True}


class Document(BaseModel):
    revision: int = Field(ge=0)
    texto: str = Field(min_length=1, max_length=16000)
    rol: Literal["N1", "N2", "Responsable"] = "N1"


@router.get("/documentos/{name}")
def document(name: str):
    try:
        revision, text = reviews.document(name)
    except ValueError:
        raise HTTPException(404, "Documento desconocido.") from None
    return {"revision": revision, "texto": text}


@router.put("/documentos/{name}")
def save_document(name: str, entry: Document):
    if entry.rol == "N1":
        raise HTTPException(403, "La edición requiere rol N2.")
    try:
        revision = reviews.save_document(name, entry.texto, entry.revision, f"analista.{entry.rol.lower()}")
    except ValueError as error:
        raise HTTPException(409, str(error)) from None
    return {"revision": revision, "texto": entry.texto}


@router.get("/relevo")
def handover():
    rows = reviews.all()
    cases = []
    count = closes = pending = 0
    for aid, row in rows.items():
        analysis = row.get("analysis") or {}
        if analysis.get("routing", {}).get("mode") != "guardia":
            continue
        count += 1
        closes += row.get("decision") == "automatic"
        if analysis["routing"]["recommendation"] == "escalate":
            if data := record(aid, rows):
                alert, _, report, stored = data
                cases.append(_summary(alert, report, stored))
        elif not row.get("decision"):
            pending += 1
    cases.sort(key=lambda case: (case["severity"] != "critical", case["plazo"] or ""))
    return {"modo": "guardia", "casos": cases, "investigadas": count, "cierres": closes, "pendientes": pending}


class Question(BaseModel):
    pregunta: str = Field(min_length=1, max_length=2000)
    remoto: bool = False


@router.post("/chat")
def ask(entry: Question):
    question = entry.pregunta.strip()
    with db.read_session():
        alert, events = assistant.context_for(question, None)
        if not events:
            for word in question.replace("?", " ").replace("¿", " ").split():
                if "." in word or "-" in word or word.isupper():
                    events = db.events_for_entity(word.strip(".,;!"), limit=6)
                    if events:
                        break
    try:
        answer = (assistant.openai_answer(question, alert, events)
                  if entry.remoto and events and model() else assistant.local_answer(alert, events))
    except ValueError as error:
        answer = f"{error}\n\n{assistant.local_answer(alert, events)}"
    return {"respuesta": answer, "pasos": [{"herramienta": "Registro recuperado", "entrada": item["event_id"]}
                                         for item in events]}


class Isolation(BaseModel):
    target: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=1, max_length=200)
    reason: str = Field(min_length=1, max_length=500)
    confirmed: bool


@router.post("/aislar/{aid}")
def isolate(aid: str, entry: Isolation):
    password = os.getenv("VIGIA_WEB_N2_PASSWORD")
    if not password or not ALERT_ID.fullmatch(aid):
        raise HTTPException(403, "Aislamiento de práctica deshabilitado.")
    if not (data := record(aid)) or data[3].get("verdict") in {"false_positive", "true_negative", "benign_true_positive"}:
        raise HTTPException(409, "No hay una propuesta activa para el expediente.")
    with lock:
        account = Account(state)
        if account.name() is None:
            account.create(DEMO_USER, password)
    try:
        return sim_response.execute_isolation(reviews, account, aid, practice=True, target=entry.target,
                                              confirmed=entry.confirmed, password=entry.password,
                                              justification=entry.reason)
    except ValueError as error:
        raise HTTPException(400, str(error)) from None
