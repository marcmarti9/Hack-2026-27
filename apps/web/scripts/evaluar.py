"""Métricas honestas: compara los veredictos de VIGÍA con nuestras etiquetas a mano (eval/etiquetas.csv)."""
import csv, json, collections
from apps.backend.config import ROOT, OUT

etq = {r["alert_id"]: r for r in csv.DictReader(open(ROOT / "eval" / "etiquetas.csv", encoding="utf-8"))}
pred = {c["alert_id"]: c["verdict"] for c in json.loads((OUT / "cerradas.json").read_text(encoding="utf-8"))}
for p in (OUT / "tickets").glob("*.json") if (OUT / "tickets").exists() else []:
    t = json.loads(p.read_text(encoding="utf-8"))
    for a in t["alert_ids"]:
        pred[a] = t["verdict"]
mat = collections.Counter((e["verdict"], pred.get(a, "sin_procesar")) for a, e in etq.items())
tp = sum(v for (r, p), v in mat.items() if r == p == "true_positive")
fn = sum(v for (r, p), v in mat.items() if r == "true_positive" and p != "true_positive")
fp = sum(v for (r, p), v in mat.items() if r != "true_positive" and p == "true_positive")
ok = sum(v for (r, p), v in mat.items() if r == p)
print(f"Etiquetadas: {len(etq)} | aciertos: {ok} ({100 * ok / max(1, len(etq)):.0f}%)")
print(f"Ataques reales detectados (recall): {tp}/{tp + fn} | falsas alarmas marcadas como ataque: {fp}")
for (r, p), v in sorted(mat.items()):
    if r != p:
        print(f"  FALLO real={r:22s} vigía={p:22s} x{v}")
