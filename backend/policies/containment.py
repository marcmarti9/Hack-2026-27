"""Aprobación humana de contención mediante token firmado (HMAC), de un solo uso, con caducidad.

Este token es el control LOCAL del sistema. El mecanismo real de Deloitte (formato, endpoint, token)
debe verificarse con su documentación y conectarse en integrations/soc_client.py.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import time
from typing import Optional


class ApprovalError(Exception):
    pass


class ApprovalService:
    def __init__(self, secret: str, ttl_seconds: int = 900):
        self._secret = secret.encode()
        self._ttl = ttl_seconds
        self._used: set[str] = set()

    def _sign(self, body: str) -> str:
        return hmac.new(self._secret, body.encode(), hashlib.sha256).hexdigest()

    def issue(self, *, alert_id: str, target: str, operation: str, approver: str, now: Optional[float] = None) -> str:
        parts = (alert_id, target, operation, approver)
        if any("|" in p for p in parts) or not all(parts):
            raise ValueError("Campos de aprobación vacíos o con caracteres no permitidos")
        exp = int((now if now is not None else time.time()) + self._ttl)
        body = "|".join([*parts, str(exp), secrets.token_hex(8)])
        return base64.urlsafe_b64encode(body.encode()).decode() + "." + self._sign(body)

    def verify(self, token: str, *, alert_id: str, target: str, operation: str,
               now: Optional[float] = None, consume: bool = True) -> dict:
        try:
            b64, sig = token.rsplit(".", 1)
            body = base64.urlsafe_b64decode(b64.encode()).decode()
            a, t, o, approver, exp, nonce = body.split("|")
        except Exception as exc:
            raise ApprovalError("Token mal formado") from exc
        if not hmac.compare_digest(sig, self._sign(body)):
            raise ApprovalError("Firma del token inválida")
        if (a, t, o) != (alert_id, target, operation):
            raise ApprovalError("El token no corresponde a esta acción")
        if (now if now is not None else time.time()) > int(exp):
            raise ApprovalError("Token caducado")
        if nonce in self._used:
            raise ApprovalError("Token ya utilizado")
        if consume:
            self._used.add(nonce)
        return {"approver": approver, "expires": int(exp)}


def fingerprint(token: str) -> str:
    """Huella para guardar en BD/logs sin exponer el token."""
    return "sha256:" + hashlib.sha256(token.encode()).hexdigest()[:16]
