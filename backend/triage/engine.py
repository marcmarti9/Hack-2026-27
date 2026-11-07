"""Convierte una Investigation (lógica pura) en un TriageResult validado por pydantic.

Si algo falla (o el resultado no supera las validaciones) se devuelve un AMARILLO visible con el motivo,
nunca un cierre automático.
"""
from __future__ import annotations

from backend.config import Settings
from backend.integrations.soc_client import SOCClient
from backend.models.enums import Action, TrafficLight, Verdict, YellowReason
from backend.models.triage_result import ContainmentRequest, Evidence, ToolCall, TriageResult
from backend.triage.investigation import Investigation, investigate
from backend.triage.llm import Judge


def to_result(inv: Investigation) -> TriageResult:
    d = inv.decision
    containment = None
    if d.light == TrafficLight.RED:
        if inv.containment_proposal:
            containment = ContainmentRequest(**inv.containment_proposal)
            action = Action.REQUEST_CONTAINMENT
        else:
            action = Action.ESCALATE
    elif d.light == TrafficLight.GREEN:
        action = Action.CLOSE
    else:
        action = Action.REQUEST_REVIEW

    out = inv.judge_output
    suggested = out.verdict if (d.light == TrafficLight.YELLOW and out.verdict != Verdict.UNDETERMINED) else None
    return TriageResult(
        alert_id=inv.alert_id, verdict=d.verdict, ai_suggested_verdict=suggested, light=d.light,
        confidence=out.confidence, severity=inv.severity, sla=inv.sla, summary=inv.summary,
        affected_entities=inv.entities,
        evidence=[Evidence(source=e.source, reference=e.reference, finding=e.finding, supports=e.supports)
                  for e in inv.evidence],
        tool_trace=[ToolCall(step=c.step, tool=c.tool, params=c.params, outcome=c.outcome, error=c.error,
                             duration_ms=c.duration_ms, at=c.at) for c in inv.trace],
        yellow_reasons=d.reasons, missing_information=d.missing, warnings=inv.warnings,
        recommended_action=action, containment=containment, processing_seconds=round(inv.elapsed, 3),
    )


def fallback_result(alert_id: str, exc: Exception) -> TriageResult:
    return TriageResult(
        alert_id=alert_id, verdict=Verdict.UNDETERMINED, light=TrafficLight.YELLOW, confidence=0.0,
        summary="Error interno durante el triaje automático; requiere revisión humana.",
        yellow_reasons=[YellowReason.TOOL_FAILED],
        missing_information=[f"Error interno: {type(exc).__name__}: {exc}"],
        recommended_action=Action.REQUEST_REVIEW,
    )


class TriageEngine:
    def __init__(self, client: SOCClient, judge: Judge, settings: Settings):
        self.client, self.judge, self.settings = client, judge, settings

    def run(self, alert_id: str) -> TriageResult:
        try:
            return to_result(investigate(self.client, self.judge, self.settings, alert_id))
        except Exception as exc:  # noqa: BLE001
            return fallback_result(alert_id, exc)
