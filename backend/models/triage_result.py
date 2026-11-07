"""Contrato de salida del motor de triaje (propuesta del equipo, NO esquema oficial de Deloitte).

Las validaciones impiden que el sistema emita combinaciones incoherentes aunque el modelo se equivoque.
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field, model_validator

from backend.config import get_settings
from backend.models.enums import (
    Action,
    HumanAction,
    Status,
    TrafficLight,
    Verdict,
    YellowReason,
)


class Evidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source: str = Field(description="Herramienta que recuperó el dato (soc_alert, threat_intel...)")
    reference: str = Field(min_length=1, description="ID real del registro recuperado")
    finding: str = Field(min_length=1)
    supports: Optional[Verdict] = None


class ToolCall(BaseModel):
    """Traza de cada consulta: alimenta la línea de tiempo del dashboard y los tiempos medidos."""

    model_config = ConfigDict(extra="forbid")

    step: int = Field(ge=1, le=7)
    tool: str
    params: dict
    outcome: str = Field(pattern="^(ok|empty|error)$")
    error: Optional[str] = None
    duration_ms: Optional[int] = None
    at: datetime


class HumanDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reviewer: str = Field(min_length=1)
    action: HumanAction
    final_verdict: Optional[Verdict] = None
    comment: Optional[str] = None
    at: datetime
    changed_ai_verdict: bool = False


class ContainmentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target: str
    operation: str
    approved: bool = False
    approval_token: Optional[str] = None  # se guarda solo una huella, nunca el token completo

    @model_validator(mode="after")
    def _needs_token_if_approved(self) -> "ContainmentRequest":
        if self.approved and not self.approval_token:
            raise ValueError("Contención aprobada sin token de aprobación")
        return self


class TriageResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    alert_id: str
    verdict: Verdict
    ai_suggested_verdict: Optional[Verdict] = None  # hacia dónde se inclinaba la IA en un amarillo
    light: TrafficLight
    confidence: float = Field(ge=0, le=1)
    severity: Optional[str] = None  # calculada por código con la matriz oficial
    sla: Optional[str] = None
    summary: str
    affected_entities: list[str] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    tool_trace: list[ToolCall] = Field(default_factory=list)
    yellow_reasons: list[YellowReason] = Field(default_factory=list)
    missing_information: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    recommended_action: Action
    containment: Optional[ContainmentRequest] = None
    requires_human_approval: bool = True
    status: Status = Status.PENDING_HUMAN_REVIEW
    human_decisions: list[HumanDecision] = Field(default_factory=list)
    processing_seconds: Optional[float] = None

    @model_validator(mode="after")
    def _consistency(self) -> "TriageResult":
        min_red = get_settings().min_evidences_red

        if self.light == TrafficLight.YELLOW:
            if self.verdict != Verdict.UNDETERMINED:
                raise ValueError("Amarillo exige verdict=undetermined")
            if not self.yellow_reasons:
                raise ValueError("Amarillo exige al menos un motivo")
            if not self.missing_information:
                raise ValueError("Amarillo exige explicar qué información falta")
        else:
            if self.verdict == Verdict.UNDETERMINED:
                raise ValueError("verdict=undetermined solo puede ser amarillo")
            if self.yellow_reasons:
                raise ValueError("yellow_reasons solo es válido en amarillo")

        if self.light == TrafficLight.RED and self.verdict != Verdict.TRUE_POSITIVE:
            raise ValueError("Rojo exige true_positive")
        if self.light == TrafficLight.GREEN and self.verdict not in (
            Verdict.FALSE_POSITIVE,
            Verdict.BENIGN_TRUE_POSITIVE,
        ):
            raise ValueError("Verde exige false_positive o benign_true_positive")

        if self.light != TrafficLight.YELLOW and not self.evidence:
            raise ValueError("Un veredicto firme exige evidencias con referencia")
        if self.light == TrafficLight.RED and len(self.evidence) < min_red:
            raise ValueError(f"Rojo exige al menos {min_red} evidencias")

        if self.tool_trace:
            sources = {c.tool for c in self.tool_trace}
            for ev in self.evidence:
                if ev.source not in sources:
                    raise ValueError(f"Evidencia de fuente no consultada: {ev.source}")

        if not self.requires_human_approval:
            raise ValueError("requires_human_approval debe ser True en este MVP")
        if self.recommended_action == Action.REQUEST_CONTAINMENT:
            if self.containment is None:
                raise ValueError("request_containment exige el objeto containment")
            if self.light != TrafficLight.RED:
                raise ValueError("Solo se solicita contención en rojo")
        if self.status != Status.PENDING_HUMAN_REVIEW and not self.human_decisions:
            raise ValueError("Un estado final exige una decisión humana registrada")
        return self
