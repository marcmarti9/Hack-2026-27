"""Política del semáforo. Lógica determinista: el color NO lo decide el modelo.

Orden: primero se evalúan las condiciones de amarillo (la duda tiene prioridad).
Los umbrales son propuestas del equipo; las reglas de negocio oficiales las entrega Deloitte.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from backend.models.enums import TrafficLight, Verdict
from backend.models.enums import YellowReason as R


@dataclass
class Assessment:
    verdict: Verdict
    confidence: float
    evidence_count: int = 0
    unsupported_claims: bool = False
    tool_failures: list[str] = field(default_factory=list)
    empty_required: list[str] = field(default_factory=list)
    contradictory: bool = False
    asset_criticality: Optional[str] = None
    injection_detected: bool = False
    runbook_found: bool = True
    has_legitimacy_evidence: bool = False
    authorized_change: bool = False
    reviewer_disagrees: bool = False
    missing_information: list[str] = field(default_factory=list)


@dataclass
class LightDecision:
    light: TrafficLight
    verdict: Verdict
    reasons: list[R]
    missing: list[str]


def decide(
    a: Assessment,
    *,
    confidence_threshold: float = 0.7,
    critical_confidence: float = 0.9,
    min_evidences_red: int = 2,
) -> LightDecision:
    reasons: list[R] = []
    missing = list(a.missing_information)

    def add(reason: R, msg: Optional[str] = None) -> None:
        if reason not in reasons:
            reasons.append(reason)
        if msg:
            missing.append(msg)

    for tool in a.tool_failures:
        add(R.TOOL_FAILED, f"Falló la consulta '{tool}': repetirla o investigarla manualmente.")
    for tool in a.empty_required:
        add(R.EMPTY_RESULT, f"La consulta obligatoria '{tool}' no devolvió datos.")
    if a.contradictory or (a.verdict == Verdict.TRUE_POSITIVE and a.authorized_change):
        add(R.CONTRADICTORY_EVIDENCE, "Hay evidencias contradictorias (p. ej. indicadores maliciosos y un cambio autorizado).")
    if a.unsupported_claims:
        add(R.UNSUPPORTED_CLAIM, "Alguna afirmación del análisis no tiene una evidencia verificable detrás.")
    if a.verdict != Verdict.UNDETERMINED and a.confidence < confidence_threshold:
        add(R.LOW_CONFIDENCE, f"Confianza {a.confidence:.2f} inferior al umbral {confidence_threshold:.2f}.")
    if (
        a.asset_criticality == "critical"
        and a.verdict in (Verdict.FALSE_POSITIVE, Verdict.BENIGN_TRUE_POSITIVE)
        and a.confidence < critical_confidence
    ):
        add(R.CRITICAL_ASSET_AMBIGUOUS, "Activo crítico: descartar la alerta exige más certeza.")
    if a.injection_detected:
        add(R.POSSIBLE_PROMPT_INJECTION, "Los datos contienen texto que parece una instrucción dirigida a la IA.")
    if not a.runbook_found:
        add(R.NO_RUNBOOK, "La regla no tiene un runbook asociado.")
    if a.reviewer_disagrees:
        add(R.REVIEWER_DISAGREES, "La segunda revisión discrepa del veredicto.")

    if a.verdict == Verdict.UNDETERMINED and not reasons:
        add(R.LOW_CONFIDENCE, "El análisis no alcanzó un veredicto con las evidencias disponibles.")

    if not reasons:
        if a.verdict == Verdict.TRUE_POSITIVE:
            if a.evidence_count >= min_evidences_red:
                return LightDecision(TrafficLight.RED, Verdict.TRUE_POSITIVE, [], [])
            add(R.UNSUPPORTED_CLAIM, f"Rojo exige al menos {min_evidences_red} evidencias verificables.")
        elif a.verdict in (Verdict.FALSE_POSITIVE, Verdict.BENIGN_TRUE_POSITIVE):
            if a.has_legitimacy_evidence and a.evidence_count >= 1:
                return LightDecision(TrafficLight.GREEN, a.verdict, [], [])
            add(R.UNSUPPORTED_CLAIM, "Falta evidencia POSITIVA de legitimidad: no encontrar nada malo no basta.")

    if not missing:
        missing.append("Revisión humana necesaria: " + ", ".join(r.value for r in reasons))
    return LightDecision(TrafficLight.YELLOW, Verdict.UNDETERMINED, reasons, missing)
