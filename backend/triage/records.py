"""Registros internos de la investigación (dataclasses puras, sin dependencias externas)."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from backend.models.enums import Verdict


@dataclass
class ToolCallRecord:
    step: int
    tool: str
    params: dict
    outcome: str  # ok | empty | error
    error: Optional[str]
    duration_ms: int
    at: datetime


@dataclass
class EvidenceRecord:
    source: str
    reference: str
    finding: str
    supports: Optional[Verdict] = None


@dataclass
class JudgeEvidence:
    reference: str
    finding: str
    supports: Optional[Verdict] = None


@dataclass
class JudgeOutput:
    verdict: Verdict
    confidence: float
    summary: str
    evidence: list[JudgeEvidence] = field(default_factory=list)
    missing_information: list[str] = field(default_factory=list)
