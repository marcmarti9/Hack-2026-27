"""Mide la cobertura local sobre el corpus oficial, sin consultar el archivo ni OpenAI."""
import json
from collections import Counter
from time import monotonic

from apps.backend.config import DATA
from apps.backend.rules.engine import fuera_de_horario
from apps.engine.review import investigate

def main():
    started = monotonic()
    counts = Counter()
    timings = []
    with (DATA / "03_alertas" / "alertas.jsonl").open(encoding="utf-8") as source:
        for number, line in enumerate(source, 1):
            alert = json.loads(line)
            mode = "guardia" if fuera_de_horario(alert["created_at"]) else "diurno"
            try:
                result = investigate(alert, triage=True, mode=mode)
                routing = result["routing"]
                if result["severity"] == "critical" or alert["severity"] == "critical":
                    assert routing["recommendation"] == "escalate" and not routing["automatic"]
                counts[(mode, result["verdict"])] += 1
                counts[("disposition", "automatic" if routing["automatic"] else routing["recommendation"])] += 1
                timings.append(result["timing"]["total_ms"])
            except Exception as error:
                counts[("error", type(error).__name__)] += 1
                if sum(n for (key, _), n in counts.items() if key == "error") <= 5:
                    print(number, alert["alert_id"], repr(error), flush=True)
            if number % 1000 == 0:
                print("Procesadas", number, "en", round(monotonic() - started), "s", flush=True)
    assert number == 11061
    assert len(timings) == number, counts
    values = sorted(timings)
    print(json.dumps({"cases": number, "outcomes": {f"{k[0]}:{k[1]}": n for k,n in counts.items()},
                      "p50_ms": values[len(values)//2], "p95_ms": values[int(len(values)*.95)],
                      "elapsed_seconds": round(monotonic() - started, 2)}, ensure_ascii=False))


if __name__ == "__main__":
    main()
