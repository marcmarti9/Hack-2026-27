"""Todas las llamadas a la IA (OpenAI o Claude) pasan por aquí: caché del prompt de sistema, reintentos y plan B si se rechaza un parámetro.
Lleva la cuenta de tokens para controlar el gasto (USO)."""
import copy, time
from apps.backend.config import MOCK, PROVEEDOR

USO = {"llamadas": 0, "entrada": 0, "salida": 0, "cache_leida": 0}

def _sin_strict(tools):
    out = copy.deepcopy(tools or [])
    for t in out:
        t.pop("strict", None)
    return out

def crear(client, **kw):
    """Igual que client.messages.create(**kw), pero robusto para una demo en directo."""
    if not MOCK and PROVEEDOR == "claude" and isinstance(kw.get("system"), str):  # caché (OpenAI la hace sola): el prompt de sistema (política + runbooks) se repite en cada turno
        kw["system"] = [{"type": "text", "text": kw["system"], "cache_control": {"type": "ephemeral"}}]
    intentos, espera = 0, 3
    while True:
        try:
            r = client.messages.create(**kw)
            u = getattr(r, "usage", None)
            if u is not None:
                USO["llamadas"] += 1
                USO["entrada"] += getattr(u, "input_tokens", 0) or 0
                USO["salida"] += getattr(u, "output_tokens", 0) or 0
                USO["cache_leida"] += getattr(u, "cache_read_input_tokens", 0) or 0
            return r
        except Exception as e:                                  # anthropic.* sin importar el paquete en modo demo
            nombre, texto = type(e).__name__, str(e).lower()
            if nombre == "BadRequestError" and "strict" in texto and any(t.get("strict") for t in kw.get("tools", [])):
                kw["tools"] = _sin_strict(kw["tools"]); continue                       # plan B: sin strict (valida jsonschema)
            if nombre == "BadRequestError" and "cache_control" in texto and isinstance(kw.get("system"), list):
                kw["system"] = kw["system"][0]["text"]; continue                       # plan B: sin caché
            if nombre in ("RateLimitError", "InternalServerError", "APIConnectionError", "APITimeoutError", "OverloadedError") \
                    or "rate limit" in texto or "overloaded" in texto or "529" in texto:
                intentos += 1
                if intentos > 5:
                    raise
                time.sleep(espera); espera = min(espera * 2, 30); continue
            raise

def resumen_uso() -> str:
    return (f"{USO['llamadas']} llamadas · {USO['entrada']:,} tokens de entrada ({USO['cache_leida']:,} desde caché) · "
            f"{USO['salida']:,} de salida").replace(",", ".")
