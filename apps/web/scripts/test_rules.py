"""Comprueba el motor de reglas: debe imprimir 'cerradas 10974' y 'al agente 87'."""
import json, collections
from apps.backend.config import DATA
from apps.backend.rules.engine import Contexto, decidir, severidad

ctx = Contexto(DATA)
A = [json.loads(l) for l in open(DATA / "03_alertas/alertas.jsonl", encoding="utf-8")]
cerradas, resto = collections.Counter(), collections.Counter()
for a in A:
    d = decidir(ctx, a)
    (cerradas if d else resto)[d["rule"] if d else a["rule_id"]] += 1
print("cerradas", sum(cerradas.values()), cerradas.most_common())
print("al agente", sum(resto.values()), resto.most_common())
a = next(x for x in A if x["alert_id"] == "ALR-20261005-000172")
print(severidad(ctx, a, "true_positive"))
