"""Detección básica de intentos de inyección de instrucciones en datos no confiables (logs, alertas...).

Es una capa de aviso, no una garantía: por eso, ante un hallazgo, la alerta pasa SIEMPRE a amarillo
y el modelo recibe los datos delimitados como "no confiables".
"""
from __future__ import annotations

import re
from typing import Iterable

_PATTERNS = [
    r"ignor(a|e|ar)\s+(tus|las|todas)\s+(las\s+)?instrucciones",
    r"ignore\s+(all\s+|your\s+|any\s+|previous\s+|prior\s+)+instructions",
    r"disregard\b.{0,40}\binstructions",
    r"cierra\s+(esta\s+)?alerta",
    r"marc(a|ar)\s+(esta\s+)?(alerta\s+)?como\s+(un\s+)?falso\s+positivo",
    r"clasif[ií]ca(la)?\s+como\s+(benign|falso|btp|fp)",
    r"close\s+this\s+alert",
    r"system\s+prompt",
    r"you\s+are\s+now\b",
    r"act[uú]a\s+como\b",
]
_COMPILED = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in _PATTERNS]


def scan(texts: Iterable[str]) -> list[str]:
    """Devuelve fragmentos sospechosos encontrados (máx. 5, sin duplicados)."""
    found: list[str] = []
    for text in texts:
        if not isinstance(text, str):
            continue
        for rx in _COMPILED:
            m = rx.search(text)
            if m and m.group(0) not in found:
                found.append(m.group(0))
                if len(found) >= 5:
                    return found
    return found
