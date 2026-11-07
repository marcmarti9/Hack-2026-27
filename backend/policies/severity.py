"""Prioridad = f(criticidad del activo, severidad SIEM) y SLA, leídos de data/policies/severity_matrix.json.

Se aplica la matriz base, sin los ajustes posteriores por contexto.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Optional

from backend.config import DATA

_ALIASES = {
    "crítica": "critical", "critica": "critical", "critical": "critical",
    "alta": "high", "high": "high",
    "media": "medium", "medium": "medium",
    "baja": "low", "low": "low",
}


def normalize_level(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    return _ALIASES.get(str(value).strip().lower())


@dataclass
class SeverityResult:
    severity: Optional[str]
    sla: Optional[str]
    placeholder: bool
    note: Optional[str] = None


def load_matrix(path=None) -> dict:
    with open(path or (DATA / "policies" / "severity_matrix.json"), encoding="utf-8") as fh:
        return json.load(fh)


def compute(asset_criticality: Optional[str], siem_severity: Optional[str], matrix: Optional[dict] = None) -> SeverityResult:
    matrix = matrix or load_matrix()
    placeholder = bool(matrix.get("_placeholder"))
    crit = normalize_level(asset_criticality)
    sev = "informational" if siem_severity == "informational" else normalize_level(siem_severity)
    if crit is None or sev is None:
        return SeverityResult(None, None, placeholder, "Falta criticidad del activo o severidad SIEM: no se calcula prioridad.")
    result = matrix["priority"].get(crit, {}).get(sev)
    if result is None:
        return SeverityResult(None, None, placeholder, f"La matriz no cubre ({crit}, {sev}).")
    return SeverityResult(result, matrix["sla"].get(result), placeholder)
