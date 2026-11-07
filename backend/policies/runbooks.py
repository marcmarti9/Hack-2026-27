"""Runbooks de ejemplo por regla, desde data/policies/runbooks.json."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Optional

from backend.config import DATA


@dataclass
class Runbook:
    name: str
    required_tools: list[str] = field(default_factory=list)
    containment: Optional[dict] = None  # {"operation": "...", "target_field": "host|user"}


def load_runbooks(path=None) -> dict:
    with open(path or (DATA / "policies" / "runbooks.json"), encoding="utf-8") as fh:
        return json.load(fh)


def get_runbook(rule_id: Optional[str], data: Optional[dict] = None) -> Optional[Runbook]:
    data = data or load_runbooks()
    entry = data.get("by_rule", {}).get(rule_id or "")
    if entry is None and data.get("allow_default"):
        entry = data.get("default")
    if entry is None:
        return None
    return Runbook(
        name=entry.get("name", "default"),
        required_tools=list(entry.get("required_tools", [])),
        containment=entry.get("containment"),
    )
