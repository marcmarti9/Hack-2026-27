"""API del sistema. Arranque:  uvicorn backend.main:app --reload"""
from __future__ import annotations

from pathlib import Path
from threading import Lock
from typing import Annotated, Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field, StrictBool, StringConstraints

from backend.config import DATA, get_settings
from backend.factory import build_client, build_judge
from backend.models.enums import Action, HumanAction, Status, TrafficLight, Verdict
from backend.policies.containment import ApprovalError, ApprovalService, fingerprint
from backend.review import apply_decision, current_verdict
from backend.storage import Storage
from backend.triage.engine import TriageEngine

settings = get_settings()
client = build_client(settings)
judge = build_judge(settings)
engine = TriageEngine(client, judge, settings)
approvals = ApprovalService(settings.approval_secret)
store = Storage(settings.db_path)
mutations = Lock()  # La instalación local ejecuta un solo proceso de API.

app = FastAPI(title="Agentic SOC · Triaje asistido por IA", version="0.1.0")


Reviewer = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=120)]


class DecisionIn(BaseModel):
    reviewer: Reviewer
    action: HumanAction
    final_verdict: Optional[Verdict] = None
    comment: Optional[str] = Field(default=None, max_length=2000)


class ContainmentIn(BaseModel):
    reviewer: Reviewer
    confirm: StrictBool = False


def _demo_ids() -> list[str]:
    f = Path(DATA / "demo_alerts.txt")
    ids = [x.strip() for x in f.read_text(encoding="utf-8").splitlines() if x.strip()] if f.exists() else []
    return ids or client.list_alert_ids()


@app.get("/health")
def health():
    return {"status": "ok", "soc_mode": settings.soc_mode, "judge": judge.name}


@app.get("/alerts")
def list_alerts():
    stored = {r.alert_id: r for r in store.list_results()}
    rows = []
    for aid in dict.fromkeys([*_demo_ids(), *stored]):
        r = stored.get(aid)
        rows.append({
            "alert_id": aid, "processed": r is not None,
            "light": r.light.value if r else None, "verdict": r.verdict.value if r else None,
            "severity": r.severity if r else None, "status": r.status.value if r else "not_processed",
        })
    return rows


@app.post("/alerts/{alert_id}/triage")
def run_triage(alert_id: str):
    existing = store.get_result(alert_id)
    if existing is not None:
        return existing.model_dump(mode="json")
    result = engine.run(alert_id)
    with mutations:
        existing = store.get_result(alert_id)
        if existing is not None:
            return existing.model_dump(mode="json")
        store.save_result(result, "triage", f"light={result.light.value} judge={judge.name} t={result.processing_seconds}s")
    return result.model_dump(mode="json")


@app.get("/alerts/{alert_id}")
def get_alert(alert_id: str):
    r = store.get_result(alert_id)
    if r is None:
        raise HTTPException(404, "Alerta no procesada todavía")
    body = r.model_dump(mode="json")
    body["final_verdict"] = current_verdict(r).value
    return body


@app.post("/alerts/{alert_id}/decision")
def decide(alert_id: str, body: DecisionIn):
    with mutations:
        r = store.get_result(alert_id)
        if r is None:
            raise HTTPException(404, "Alerta no procesada todavía")
        try:
            updated = apply_decision(r, reviewer=body.reviewer, action=body.action,
                                     final_verdict=body.final_verdict, comment=body.comment)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        store.save_result(updated, "human_decision", f"{body.reviewer}: {body.action.value} {body.final_verdict or ''}")
    return updated.model_dump(mode="json")


@app.post("/alerts/{alert_id}/containment")
def approve_and_execute_containment(alert_id: str, body: ContainmentIn):
    """Solo con aprobación humana explícita. Emite un token firmado de un solo uso y ejecuta la contención SIMULADA."""
    if settings.soc_mode != "fixture":
        raise HTTPException(409, "La contención solo está habilitada con datos de ejemplo locales")
    with mutations:
        return _simulate_containment(alert_id, body)


def _simulate_containment(alert_id: str, body: ContainmentIn):
    r = store.get_result(alert_id)
    if r is None or r.containment is None:
        raise HTTPException(404, "No hay contención propuesta para esta alerta")
    if r.light != TrafficLight.RED or r.recommended_action != Action.REQUEST_CONTAINMENT:
        raise HTTPException(409, "Solo se puede contener una alerta roja con contención propuesta")
    if r.containment.approved:
        raise HTTPException(409, "La contención ya fue aprobada")
    if current_verdict(r) != Verdict.TRUE_POSITIVE:
        raise HTTPException(409, "El veredicto vigente no permite contener la alerta")
    if not body.confirm:
        raise HTTPException(422, "Falta confirmación humana explícita (confirm=true)")
    c = r.containment
    try:
        token = approvals.issue(alert_id=alert_id, target=c.target, operation=c.operation, approver=body.reviewer)
        approvals.verify(token, alert_id=alert_id, target=c.target, operation=c.operation)
        outcome = client.request_containment(target=c.target, operation=c.operation, approval_token=token)
    except (ApprovalError, ValueError) as exc:
        raise HTTPException(403, str(exc)) from exc
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(502, f"La API del SOC rechazó o falló la contención: {exc}") from exc
    data = r.model_dump()
    data["containment"] = {**data["containment"], "approved": True, "approval_token": fingerprint(token)}
    updated = r.model_validate(data)
    store.save_result(updated, "containment_executed", f"{body.reviewer}: {c.operation} {c.target} -> {outcome}")
    return {"result": updated.model_dump(mode="json"), "soc_response": outcome}


@app.get("/alerts/{alert_id}/audit")
def audit(alert_id: str):
    return store.audit(alert_id)


@app.get("/metrics")
def metrics():
    results = store.list_results()
    times = [r.processing_seconds for r in results if r.processing_seconds is not None]
    by = lambda key: {k: sum(1 for r in results if key(r) == k) for k in {key(r) for r in results}}  # noqa: E731
    return {
        "processed": len(results),
        "by_light": by(lambda r: r.light.value),
        "by_status": by(lambda r: r.status.value),
        "avg_processing_seconds": round(sum(times) / len(times), 3) if times else None,
        "human_corrections": sum(1 for r in results for d in r.human_decisions if d.changed_ai_verdict),
        "pending_human_review": sum(1 for r in results if r.status == Status.PENDING_HUMAN_REVIEW),
        "note": "Tiempos = ejecución del agente en esta máquina. No es una comparación con el triaje manual.",
    }
