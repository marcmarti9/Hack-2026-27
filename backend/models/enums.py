"""Enums del dominio (sin dependencias externas: se pueden usar y probar sin pydantic)."""
from enum import Enum


class Verdict(str, Enum):
    TRUE_POSITIVE = "true_positive"
    BENIGN_TRUE_POSITIVE = "benign_true_positive"
    FALSE_POSITIVE = "false_positive"
    UNDETERMINED = "undetermined"  # pruebas insuficientes: no se inventa clasificación


class TrafficLight(str, Enum):
    RED = "red"        # ataque real (TP)
    YELLOW = "yellow"  # duda: decide siempre un humano
    GREEN = "green"    # FP o BTP con evidencia de legitimidad


class Action(str, Enum):
    ESCALATE = "escalate"
    CLOSE = "close"
    REQUEST_REVIEW = "request_review"
    REQUEST_CONTAINMENT = "request_containment"


class HumanAction(str, Enum):
    ACCEPT = "accept"
    CORRECT = "correct"
    ESCALATE = "escalate"


class Status(str, Enum):
    PENDING_HUMAN_REVIEW = "pending_human_review"
    ACCEPTED = "accepted"
    CORRECTED = "corrected"
    ESCALATED = "escalated"
    CLOSED = "closed"


class YellowReason(str, Enum):
    TOOL_FAILED = "A1_tool_failed"
    EMPTY_RESULT = "A2_empty_required_result"
    CONTRADICTORY_EVIDENCE = "A3_contradictory_evidence"
    UNSUPPORTED_CLAIM = "A4_unsupported_claim"
    LOW_CONFIDENCE = "A5_low_confidence"
    CRITICAL_ASSET_AMBIGUOUS = "A6_critical_asset_ambiguous"
    POSSIBLE_PROMPT_INJECTION = "A7_possible_prompt_injection"
    NO_RUNBOOK = "A8_no_runbook"
    REVIEWER_DISAGREES = "A9_reviewer_disagrees"
