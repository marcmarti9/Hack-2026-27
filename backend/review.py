"""Decisiones humanas sobre un resultado de triaje. El resultado de la IA no se modifica: la decisión se añade."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from backend.models.enums import Action, HumanAction, Status, TrafficLight, Verdict
from backend.models.triage_result import HumanDecision, TriageResult


def current_verdict(result: TriageResult) -> Verdict:
    for d in reversed(result.human_decisions):
        if d.final_verdict:
            return d.final_verdict
    return result.verdict


def apply_decision(result: TriageResult, *, reviewer: str, action: HumanAction,
                   final_verdict: Optional[Verdict] = None, comment: Optional[str] = None) -> TriageResult:
    if result.status != Status.PENDING_HUMAN_REVIEW:
        raise ValueError("Esta alerta ya tiene una decisión humana registrada")
    if action == HumanAction.ACCEPT and result.light == TrafficLight.YELLOW:
        raise ValueError("Una alerta amarilla no se acepta tal cual: clasifícala (corregir) o escálala")
    if action == HumanAction.CORRECT and final_verdict in (None, Verdict.UNDETERMINED):
        raise ValueError("Corregir exige indicar el veredicto final (TP, BTP o FP)")
    if action != HumanAction.CORRECT and final_verdict is not None:
        raise ValueError("Solo se puede indicar el veredicto final al corregir")

    reference = result.verdict if result.light != TrafficLight.YELLOW else result.ai_suggested_verdict
    changed = action == HumanAction.CORRECT and reference is not None and final_verdict != reference

    if action == HumanAction.ACCEPT:
        status = Status.CLOSED if result.recommended_action == Action.CLOSE else Status.ACCEPTED
    elif action == HumanAction.CORRECT:
        status = Status.CORRECTED
    else:
        status = Status.ESCALATED

    decision = HumanDecision(reviewer=reviewer, action=action, final_verdict=final_verdict, comment=comment,
                             at=datetime.now(timezone.utc), changed_ai_verdict=changed)
    data = result.model_dump()
    data["human_decisions"] = [*data["human_decisions"], decision.model_dump()]
    data["status"] = status
    return TriageResult.model_validate(data)  # vuelve a pasar todas las validaciones
