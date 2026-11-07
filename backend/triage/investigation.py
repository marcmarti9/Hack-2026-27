"""Orquestador de los 7 pasos del triaje (lógica pura: no depende de pydantic).

1 Entender · 2 Contextualizar · 3 Enriquecer · 4 Correlacionar · 5 Decidir · 6 Priorizar · 7 Actuar
Las consultas y reglas son código determinista; el modelo solo interviene en el paso 5.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from backend.config import Settings
from backend.integrations.soc_client import SOCClient
from backend.models.enums import TrafficLight, Verdict
from backend.policies import severity as severity_policy
from backend.policies import traffic_light
from backend.policies.runbooks import get_runbook
from backend.triage.injection import scan
from backend.triage.llm import Judge
from backend.triage.records import EvidenceRecord, JudgeOutput, ToolCallRecord
from backend.triage.tools import Investigator

ENTITY_FIELDS = ("host", "user", "src_ip", "dest_ip", "domain")


@dataclass
class Investigation:
    alert_id: str
    alert: Optional[dict]
    trace: list[ToolCallRecord]
    evidence: list[EvidenceRecord]
    judge_output: JudgeOutput
    decision: traffic_light.LightDecision
    severity: Optional[str] = None
    sla: Optional[str] = None
    asset_criticality: Optional[str] = None
    containment_proposal: Optional[dict] = None
    entities: list[str] = field(default_factory=list)
    summary: str = ""
    warnings: list[str] = field(default_factory=list)
    elapsed: float = 0.0


def parse_ts(value) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def is_authorized(change: dict, alert_ts) -> bool:
    """Cambio aprobado cuya ventana contiene el instante de la alerta. Si no se puede comprobar, NO es válido."""
    ts, start, end = parse_ts(alert_ts), parse_ts(change.get("start")), parse_ts(change.get("end"))
    if not (ts and start and end) or str(change.get("status", "")).lower() != "approved":
        return False
    try:
        return start <= ts <= end
    except TypeError:  # mezcla de fechas con/sin zona horaria
        return False


def _undetermined(summary: str, missing: list[str]) -> JudgeOutput:
    return JudgeOutput(Verdict.UNDETERMINED, 0.0, summary, [], missing)


def investigate(client: SOCClient, judge: Judge, settings: Settings, alert_id: str) -> Investigation:
    t0 = time.perf_counter()
    inv = Investigator(client)
    warnings: list[str] = []
    thresholds = dict(confidence_threshold=settings.confidence_threshold,
                      critical_confidence=settings.critical_confidence,
                      min_evidences_red=settings.min_evidences_red)

    # 1. Entender
    alert = inv.alert(alert_id)
    if alert is None:
        failures = [c.tool for c in inv.trace if c.outcome == "error"]
        empties = [c.tool for c in inv.trace if c.outcome == "empty"]
        out = _undetermined("No se pudo recuperar la alerta; no hay base para investigar.",
                            ["No se pudo recuperar la alerta original."])
        decision = traffic_light.decide(
            traffic_light.Assessment(Verdict.UNDETERMINED, 0.0, tool_failures=failures, empty_required=empties,
                                     missing_information=out.missing_information), **thresholds)
        return Investigation(alert_id, None, inv.trace, [], out, decision, summary=out.summary,
                             elapsed=time.perf_counter() - t0)

    entities = {k: alert.get(k) for k in ENTITY_FIELDS}
    runbook = get_runbook(alert.get("rule_id"))

    # 2. Contextualizar
    asset = inv.asset(entities["host"]) if entities["host"] else None
    identity = inv.identity(entities["user"]) if entities["user"] else None
    changes = inv.changes(entities["host"], entities["user"]) if (entities["host"] or entities["user"]) else None
    authorized = [c for c in (changes or []) if is_authorized(c, alert.get("timestamp"))]

    # 3. Enriquecer
    indicators = [x for x in dict.fromkeys([entities["src_ip"], entities["dest_ip"], entities["domain"]]) if x]
    reputation = {i: inv.reputation(i) for i in indicators}

    # 4. Correlacionar
    events = inv.events(entities) or []
    related = inv.related(entities, alert_id) or []

    # 5. Decidir
    context = {
        "alert": alert, "asset": asset, "identity": identity, "changes": changes or [],
        "authorized_changes": authorized, "reputation": reputation, "events": events, "related_alerts": related,
    }
    try:
        out = judge.judge(context, set(inv.refs))
    except Exception as exc:  # noqa: BLE001
        out = _undetermined("El análisis automático falló; revisión manual necesaria.",
                            ["El modelo no devolvió una respuesta válida."])
        warnings.append(f"Fallo del juez ({type(exc).__name__}): {exc}")

    evidence: list[EvidenceRecord] = []
    dropped = 0
    for e in out.evidence:
        if e.reference in inv.refs:  # solo se aceptan referencias realmente recuperadas
            evidence.append(EvidenceRecord(inv.refs[e.reference], e.reference, e.finding, e.supports))
        else:
            dropped += 1
    if dropped:
        warnings.append(f"Se descartaron {dropped} evidencia(s) con referencias no recuperadas del entorno.")

    supports = {e.supports for e in evidence if e.supports}
    contradictory = Verdict.TRUE_POSITIVE in supports and bool(
        supports & {Verdict.FALSE_POSITIVE, Verdict.BENIGN_TRUE_POSITIVE})
    legit = out.verdict in (Verdict.FALSE_POSITIVE, Verdict.BENIGN_TRUE_POSITIVE) and any(
        e.supports in (Verdict.FALSE_POSITIVE, Verdict.BENIGN_TRUE_POSITIVE) for e in evidence)
    required = runbook.required_tools if runbook else ["soc_alert"]
    criticality = severity_policy.normalize_level(asset.get("criticality")) if asset else None
    injection = scan(inv.texts)
    if injection:
        warnings.append(f"Posible inyección de instrucciones en los datos: {injection}")

    assessment = traffic_light.Assessment(
        verdict=out.verdict, confidence=out.confidence, evidence_count=len(evidence),
        unsupported_claims=dropped > 0 or (out.verdict != Verdict.UNDETERMINED and not evidence),
        tool_failures=[c.tool for c in inv.trace if c.outcome == "error"],
        empty_required=[c.tool for c in inv.trace if c.outcome == "empty" and c.tool in required],
        contradictory=contradictory, asset_criticality=criticality, injection_detected=bool(injection),
        runbook_found=runbook is not None, has_legitimacy_evidence=legit, authorized_change=bool(authorized),
        missing_information=list(out.missing_information))
    decision = traffic_light.decide(assessment, **thresholds)

    # 6. Priorizar (código + matriz; solo si hay algo que atender)
    sev, sla = None, None
    if decision.light != TrafficLight.GREEN:
        res = severity_policy.compute(criticality, alert.get("severity"))
        sev, sla = res.severity, res.sla
        if res.placeholder:
            warnings.append("La matriz de severidad/SLA es un PLACEHOLDER, no la oficial de Deloitte.")
        if res.note:
            warnings.append(res.note)

    # 7. Actuar: solo se PROPONE; ejecutar exige aprobación humana
    proposal = None
    if decision.light == TrafficLight.RED and runbook and runbook.containment:
        target = alert.get(runbook.containment["target_field"])
        if target:
            proposal = {"target": str(target), "operation": runbook.containment["operation"]}

    return Investigation(
        alert_id=alert_id, alert=alert, trace=inv.trace, evidence=evidence, judge_output=out, decision=decision,
        severity=sev, sla=sla, asset_criticality=criticality, containment_proposal=proposal,
        entities=[str(v) for v in entities.values() if v], summary=out.summary or "Sin resumen.",
        warnings=warnings, elapsed=time.perf_counter() - t0)
