"""Herramientas de investigación: consultas tipadas, de solo lectura, con traza y registro de referencias.

El modelo NUNCA inventa datos: solo puede citar referencias (IDs) que hayan devuelto estas herramientas.
"""
from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any, Callable, Iterator, Optional

from backend.integrations.soc_client import SOCClient
from backend.triage.records import ToolCallRecord

TOOL_ALERT = "soc_alert"
TOOL_EVENTS = "soc_events"
TOOL_RELATED = "soc_related_alerts"
TOOL_ASSET = "cmdb_asset"
TOOL_IDENTITY = "directory_identity"
TOOL_CHANGES = "change_calendar"
TOOL_INTEL = "threat_intel"


def _strings(obj: Any) -> Iterator[str]:
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from _strings(v)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            yield from _strings(v)


class Investigator:
    def __init__(self, client: SOCClient):
        self.client = client
        self.trace: list[ToolCallRecord] = []
        self.refs: dict[str, str] = {}   # referencia -> herramienta que la devolvió
        self.texts: list[str] = []       # todo el texto recuperado (para detectar inyección)

    def _register(self, tool: str, data: Any) -> None:
        for item in data if isinstance(data, list) else [data]:
            if isinstance(item, dict):
                rid = item.get("id")
                if rid:
                    self.refs[str(rid)] = tool
                self.texts.extend(_strings(item))

    def _run(self, step: int, tool: str, params: dict, fn: Callable[[], Any]) -> Any:
        at = datetime.now(timezone.utc)
        t0 = time.perf_counter()
        error: Optional[str] = None
        data: Any = None
        try:
            data = fn()
        except Exception as exc:  # noqa: BLE001 - cualquier fallo debe quedar visible, no romper el triaje
            error = f"{type(exc).__name__}: {exc}"
        ms = int((time.perf_counter() - t0) * 1000)
        if error:
            outcome = "error"
        elif data is None or data == [] or data == {}:
            outcome = "empty"
        else:
            outcome = "ok"
            self._register(tool, data)
        self.trace.append(ToolCallRecord(step, tool, params, outcome, error, ms, at))
        return None if error else data

    # Paso 1
    def alert(self, alert_id: str):
        return self._run(1, TOOL_ALERT, {"alert_id": alert_id}, lambda: self.client.get_alert(alert_id))

    # Paso 2
    def asset(self, host: str):
        return self._run(2, TOOL_ASSET, {"host": host}, lambda: self.client.get_asset(host))

    def identity(self, user: str):
        return self._run(2, TOOL_IDENTITY, {"user": user}, lambda: self.client.get_identity(user))

    def changes(self, host: Optional[str], user: Optional[str]):
        return self._run(2, TOOL_CHANGES, {"host": host, "user": user},
                         lambda: self.client.get_changes(host=host, user=user))

    # Paso 3
    def reputation(self, indicator: str):
        return self._run(3, TOOL_INTEL, {"indicator": indicator}, lambda: self.client.ioc_reputation(indicator))

    # Paso 4
    def events(self, e: dict, limit: int = 50):
        params = {"host": e.get("host"), "user": e.get("user"), "ip": e.get("src_ip"), "domain": e.get("domain")}
        return self._run(4, TOOL_EVENTS, params, lambda: self.client.search_events(limit=limit, **params))

    def related(self, e: dict, exclude_id: str):
        params = {"host": e.get("host"), "user": e.get("user"), "ip": e.get("src_ip"), "domain": e.get("domain")}
        return self._run(4, TOOL_RELATED, params,
                         lambda: self.client.related_alerts(exclude_id=exclude_id, **params))
