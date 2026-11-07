"""Resumen operativo y carga de alertas para reproducción."""
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from apps.backend.rules.engine import LEVELS

MAX_REPORT = 5_000_000


def read_report(path: Path) -> list[dict]:
    with path.open("rb") as stream:
        payload = stream.read(MAX_REPORT + 1)
    if len(payload) > MAX_REPORT:
        raise ValueError("El archivo supera el límite de 5 MB.")
    text = payload.decode("utf-8-sig")
    data = json.loads(text) if path.suffix.lower() == ".json" else [
        json.loads(line) for line in text.splitlines() if line.strip()
    ]
    if not isinstance(data, list) or not data:
        raise ValueError("El informe necesita una lista de alertas JSON o JSONL.")
    seen = set()
    result = []
    for row in data:
        try:
            identifier, stamp, severity = row["alert_id"], row["created_at"], row["severity"]
            date = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
            if not isinstance(identifier, str) or not identifier or identifier in seen:
                raise ValueError
            if date.utcoffset() is None or severity not in LEVELS:
                raise ValueError
        except (KeyError, TypeError, ValueError, AttributeError):
            raise ValueError("Cada alerta debe tener un ID único, fecha con zona y severidad válida.") from None
        seen.add(identifier)
        result.append({"alert_id": identifier, "time": date.astimezone(timezone.utc), "severity": severity,
                       "source": str(row.get("source_product") or "Sin fuente")[:100],
                       "title": str(row.get("rule_name") or identifier)[:160]})
    return sorted(result, key=lambda item: item["time"])


def imported_summary(rows: list[dict], day: str) -> tuple[list[dict], list[dict]]:
    active = [row for row in rows if row["time"].date().isoformat() == day]
    totals = Counter((row["severity"], row["source"]) for row in active)
    timeline = Counter(row["time"].hour for row in active)
    signals = {}
    for row in active:
        signals.setdefault(row["time"].hour, set()).add(f"{row['source']} · {row['title']}")
    return (
        [{"severity": severity, "source": source, "total": count}
         for (severity, source), count in totals.most_common()],
        [{"hour": hour, "total": count, "signals": sorted(signals[hour])[:3]}
         for hour, count in sorted(timeline.items())],
    )
