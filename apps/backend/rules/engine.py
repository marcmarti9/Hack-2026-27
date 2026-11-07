"""Severidad base y ajustes verificados según la política del SOC de Tarvia."""
from dataclasses import dataclass
from datetime import datetime
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo

from apps.backend.tools import db

LEVELS = ("informational", "low", "medium", "high", "critical")
CRITICALITY = {"baja": 0, "media": 1, "alta": 2, "crítica": 3}
MATRIX = {
    "informational": ("informational", "informational", "low", "low"),
    "low": ("informational", "low", "low", "medium"),
    "medium": ("low", "medium", "medium", "high"),
    "high": ("medium", "high", "high", "critical"),
    "critical": ("high", "critical", "critical", "critical"),
}
SLA = dict(zip(LEVELS, ("Revisión diaria", "24 h", "4 h", "30 min", "15 min")))
MADRID = ZoneInfo("Europe/Madrid")


@dataclass(frozen=True)
class Severity:
    level: str
    rationale: str
    sla: str


def madrid(timestamp: str) -> datetime:
    date = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    if date.utcoffset() is None:
        raise ValueError("La fecha de alerta debe tener zona horaria.")
    return date.astimezone(MADRID)


def fuera_de_horario(timestamp: str) -> bool:
    local = madrid(timestamp)
    return local.weekday() >= 5 or not 8 <= local.hour < 20


def _ecommerce(entities: dict) -> bool:
    if entities.get("customers"):
        return True
    for url in entities.get("urls", []):
        try:
            host = urlsplit(url).hostname
        except ValueError:
            continue
        if host == "www.tarvia.example":
            return True
    return False


def _criticality(entities: dict) -> tuple[int, str]:
    candidates = []
    for host in entities.get("hosts", []):
        record = db.asset(host.get("hostname") or host.get("ip") or "")
        if record and (level := CRITICALITY.get(record["criticality"].lower())) is not None:
            candidates.append((level, f"{record['hostname']} ({record['criticality']})"))
    if _ecommerce(entities):
        candidates.append((3, "tienda online (Crítica)"))
    if entities.get("cloud"):
        candidates.append((3, "entorno AWS de Tarvia (Crítica)"))
    return max(candidates, key=lambda candidate: candidate[0],
               default=(1, "criticidad desconocida (Media provisional)"))


def severidad(alerta: dict, verdict: str, *, verified_impact: str = "",
              verified_prevention: str = "") -> Severity:
    """Los ajustes recibidos deben estar respaldados por evidencia validada."""
    if verdict in {"benign_true_positive", "false_positive"}:
        return Severity("informational", "Actividad autorizada o falsa alarma.", SLA["informational"])
    entities = alerta.get("entities", {})
    criticality, affected = _criticality(entities)
    initial = alerta["severity"]
    base = MATRIX[initial][criticality]
    impact = [verified_impact] if verified_impact else []
    for account in entities.get("users", []):
        record = db.user(account.get("upn", ""))
        if record and (record["vip"] == "True" or record["privileged"] == "True"):
            impact.append(f"identidad VIP o privilegiada ({record['username']})")
    prevention = verified_prevention if not verified_impact else ""
    adjustment = bool(impact) - bool(prevention)
    result = LEVELS[max(0, min(len(LEVELS) - 1, LEVELS.index(base) + adjustment))]
    reason = f"Regla {initial} sobre {affected} = {base}"
    if impact:
        reason += f". +1 por {', '.join(impact)}"
    if prevention:
        reason += f". −1 por {prevention}"
    return Severity(result, f"{reason}. Final: {result}.", SLA[result])
