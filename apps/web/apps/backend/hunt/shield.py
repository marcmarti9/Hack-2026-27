"""Escudo anti-manipulación: detecta texto escrito para engañar a la IA o al analista."""
import json, re

PATRONES = [
    (r"display\s*:\s*none|font-size\s*:\s*0|color\s*:\s*#?fff", "HTML oculto"),
    (r"sistema automatizado|clasificador|clasificaci[oó]n de seguridad|modelo de lenguaje|\bIA\b|asistente", "texto dirigido a un sistema automático"),
    (r"(ignora|olvida) (todas )?(tus|las) instrucciones|instrucciones (anteriores|previas)|prompt de sistema|system override|modo desarrollador", "intento de dar órdenes al modelo"),
    (r"(ha sido|fue) (revisado|aprobado)|no requiere revisi[oó]n|marcar como (seguro|leg[ií]timo)|falso positivo|whitelist", "afirmación de seguridad o autorización"),
]
TICKET = re.compile(r"\b(?:SEC|CHG|INC|FLUJO)-\d{3,5}(?:-\d{3,5})?\b")

def analizar(alerta: dict, cambios_ids: set[str]) -> list[dict]:
    """Devuelve los indicios encontrados en los campos que puede controlar el atacante."""
    texto = json.dumps(alerta.get("evidence", alerta), ensure_ascii=False)
    out = []
    for pat, tipo in PATRONES:
        m = re.search(pat, texto, re.I)
        if m:
            out.append({"tipo": tipo, "fragmento": texto[max(0, m.start() - 40): m.end() + 40]})
    for t in TICKET.finditer(texto):
        if t.group(0) not in cambios_ids and not t.group(0).startswith("INC"):
            out.append({"tipo": "autorización que no existe en el calendario", "fragmento": t.group(0)})
    return out
