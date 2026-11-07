"""Conector con el SOC.

- FixtureSOCClient: lee data/fixtures (desarrollo y tests; datos inventados).
- HttpSOCClient: PLANTILLA para la API real de Deloitte. Los endpoints, la autenticación y los formatos
  están SIN VERIFICAR: ajustar ENDPOINTS y los mapeos al recibir la documentación técnica.
"""
from __future__ import annotations

import json
import time
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Optional

from backend.config import DATA


class SOCError(Exception):
    pass


# Un único sitio donde adaptar los nombres de campo de la API real a los canónicos del sistema.
ALERT_FIELD_ALIASES = {
    "id": ["id", "alert_id", "alertId", "AlertId"],
    "rule_id": ["rule_id", "ruleId", "rule", "detection_id"],
    "rule_name": ["rule_name", "ruleName", "name", "title"],
    "severity": ["severity", "siem_severity", "priority"],
    "timestamp": ["timestamp", "time", "@timestamp", "created_at"],
    "host": ["host", "hostname", "asset", "device"],
    "user": ["user", "username", "account", "identity"],
    "src_ip": ["src_ip", "source_ip", "srcIp"],
    "dest_ip": ["dest_ip", "destination_ip", "dst_ip"],
    "domain": ["domain", "fqdn"],
    "description": ["description", "summary", "message"],
}


def normalize_alert(raw: dict) -> dict:
    out: dict[str, Any] = {}
    for canon, aliases in ALERT_FIELD_ALIASES.items():
        out[canon] = next((raw[a] for a in aliases if raw.get(a) not in (None, "")), None)
    if out["id"] is not None:
        out["id"] = str(out["id"])
    if isinstance(out.get("severity"), str):
        out["severity"] = out["severity"].lower()
    return out


class SOCClient(ABC):
    @abstractmethod
    def get_alert(self, alert_id: str) -> Optional[dict]: ...

    @abstractmethod
    def search_events(self, *, host=None, user=None, ip=None, domain=None, limit: int = 50) -> list[dict]: ...

    @abstractmethod
    def related_alerts(self, *, host=None, user=None, ip=None, domain=None, exclude_id: str = "") -> list[dict]: ...

    @abstractmethod
    def get_asset(self, host: str) -> Optional[dict]: ...

    @abstractmethod
    def get_identity(self, user: str) -> Optional[dict]: ...

    @abstractmethod
    def get_changes(self, *, host=None, user=None) -> list[dict]: ...

    @abstractmethod
    def ioc_reputation(self, indicator: str) -> Optional[dict]: ...

    @abstractmethod
    def request_containment(self, *, target: str, operation: str, approval_token: str) -> dict: ...

    def list_alert_ids(self) -> list[str]:
        return []


def _load(path: Path) -> list[dict]:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


class FixtureSOCClient(SOCClient):
    def __init__(self, base: Optional[Path] = None):
        base = base or (DATA / "fixtures")
        self._alerts = {a["id"]: a for a in _load(base / "alerts.json")}
        self._events = _load(base / "events.json")
        self._assets = {a["hostname"]: a for a in _load(base / "assets.json")}
        self._identities = {i["username"]: i for i in _load(base / "identities.json")}
        self._changes = _load(base / "changes.json")
        self._reputation = {r["indicator"]: r for r in _load(base / "reputation.json")}
        self.containment_log: list[dict] = []

    def list_alert_ids(self) -> list[str]:
        return list(self._alerts)

    def get_alert(self, alert_id):
        raw = self._alerts.get(alert_id)
        return normalize_alert(raw) if raw else None

    @staticmethod
    def _matches(rec: dict, host, user, ip, domain) -> bool:
        return any([
            host and rec.get("host") == host,
            user and rec.get("user") == user,
            ip and rec.get("src_ip") == ip,
            domain and rec.get("domain") == domain,
        ])

    def search_events(self, *, host=None, user=None, ip=None, domain=None, limit=50):
        return [e for e in self._events if self._matches(e, host, user, ip, domain)][:limit]

    def related_alerts(self, *, host=None, user=None, ip=None, domain=None, exclude_id=""):
        return [a for a in self._alerts.values()
                if a["id"] != exclude_id and self._matches(a, host, user, ip, domain)]

    def get_asset(self, host):
        return self._assets.get(host)

    def get_identity(self, user):
        return self._identities.get(user)

    def get_changes(self, *, host=None, user=None):
        return [c for c in self._changes if (host and host in c.get("hosts", [])) or (user and user in c.get("users", []))]

    def ioc_reputation(self, indicator):
        return self._reputation.get(indicator)

    def request_containment(self, *, target, operation, approval_token):
        if not approval_token:
            raise SOCError("Contención rechazada: falta token de aprobación")
        entry = {"status": "simulated", "target": target, "operation": operation}
        self.containment_log.append(entry)
        return entry


class HttpSOCClient(SOCClient):
    """PLANTILLA. TODO al recibir la documentación de Deloitte:
    1) rellenar ENDPOINTS, 2) confirmar autenticación (cabecera/esquema), 3) paginación y límites,
    4) formato de la petición de contención y su token, 5) asegurar que cada registro tenga un 'id'.
    """

    ENDPOINTS = {  # TODO: valores de ejemplo SIN VERIFICAR
        "alert": "/alerts/{id}",
        "events": "/events",
        "alerts": "/alerts",
        "asset": "/assets/{id}",
        "identity": "/identities/{id}",
        "changes": "/changes",
        "ioc": "/intel/{id}",
        "containment": "/containment",
    }

    def __init__(self, base_url: str, token: str, timeout: float = 15.0, retries: int = 3):
        if not base_url:
            raise SOCError("SOC_API_BASE_URL no configurada")
        self.base_url, self.token, self.timeout, self.retries = base_url.rstrip("/"), token, timeout, retries

    def _request(self, method: str, path: str, **kwargs) -> Any:
        import httpx  # import perezoso: el modo fixture no lo necesita

        headers = {"Authorization": f"Bearer {self.token}"}  # TODO: confirmar esquema de autenticación
        last: Optional[Exception] = None
        for attempt in range(self.retries):
            try:
                resp = httpx.request(method, self.base_url + path, headers=headers, timeout=self.timeout, **kwargs)
                if resp.status_code == 404:
                    return None
                if resp.status_code in (429, 500, 502, 503, 504):
                    raise SOCError(f"HTTP {resp.status_code}")
                resp.raise_for_status()
                return resp.json()
            except Exception as exc:  # noqa: BLE001
                last = exc
                time.sleep(0.5 * (2 ** attempt))
        raise SOCError(f"Fallo tras {self.retries} intentos: {last}")

    @staticmethod
    def _items(data) -> list[dict]:
        if data is None:
            return []
        if isinstance(data, list):
            return data
        for key in ("items", "results", "data"):
            if isinstance(data.get(key), list):
                return data[key]
        return [data]

    def get_alert(self, alert_id):
        data = self._request("GET", self.ENDPOINTS["alert"].format(id=alert_id))
        return normalize_alert(data) if data else None

    def search_events(self, *, host=None, user=None, ip=None, domain=None, limit=50):
        params = {k: v for k, v in {"host": host, "user": user, "ip": ip, "domain": domain, "limit": limit}.items() if v}
        return self._items(self._request("GET", self.ENDPOINTS["events"], params=params))

    def related_alerts(self, *, host=None, user=None, ip=None, domain=None, exclude_id=""):
        params = {k: v for k, v in {"host": host, "user": user, "ip": ip, "domain": domain}.items() if v}
        return [a for a in self._items(self._request("GET", self.ENDPOINTS["alerts"], params=params))
                if str(a.get("id", a.get("alert_id"))) != exclude_id]

    def get_asset(self, host):
        return self._request("GET", self.ENDPOINTS["asset"].format(id=host))

    def get_identity(self, user):
        return self._request("GET", self.ENDPOINTS["identity"].format(id=user))

    def get_changes(self, *, host=None, user=None):
        params = {k: v for k, v in {"host": host, "user": user}.items() if v}
        return self._items(self._request("GET", self.ENDPOINTS["changes"], params=params))

    def ioc_reputation(self, indicator):
        return self._request("GET", self.ENDPOINTS["ioc"].format(id=indicator))

    def request_containment(self, *, target, operation, approval_token):
        # TODO: formato real de la petición y del token de aprobación de Deloitte
        return self._request("POST", self.ENDPOINTS["containment"],
                             json={"target": target, "operation": operation, "approval_token": approval_token})
