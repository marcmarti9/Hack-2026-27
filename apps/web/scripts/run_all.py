"""Orquestador: reglas -> escudo -> grupos -> agente N1 -> fiscal -> caza -> N2. Guarda todo en out/.
Uso:  python -m scripts.run_all --solo-reglas        (sin API: motor, grupos y caza)
      python -m scripts.run_all --max 5              (los 5 grupos más graves con IA)
      python -m scripts.run_all                      (todo)"""
import argparse, csv, json, collections
from pathlib import Path
from apps.backend.config import DATA, OUT
from apps.backend.rules.engine import Contexto, decidir, severidad, fuera_de_horario, LEVELS
from apps.backend.hunt import shield, group, hunt

SALIDA = OUT
def guardar(nombre, obj):
    (SALIDA / nombre).parent.mkdir(parents=True, exist_ok=True)
    (SALIDA / nombre).write_text(json.dumps(obj, ensure_ascii=False, indent=1, default=str), encoding="utf-8")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--solo-reglas", action="store_true"); ap.add_argument("--max", type=int, default=999)
    ap.add_argument("--n2", action="store_true", help="informe N2 de los true_positive high/critical")
    ap.add_argument("--fichero", default=str(DATA / "03_alertas/alertas.jsonl"))
    ap.add_argument("--salida", default=str(OUT), help="carpeta de resultados (para el directo: out/directo)")
    args = ap.parse_args()
    global SALIDA
    SALIDA = Path(args.salida)
    if not args.solo_reglas:                       # limpia resultados de pasadas anteriores
        for sub in ("tickets", "incidents"):
            for f in (SALIDA / sub).glob("*.json"):
                f.unlink()
    ctx = Contexto(DATA)
    cambios = {c["id"] for c in csv.DictReader(open(DATA / "02_inventario/calendario_cambios.csv", encoding="utf-8"))}
    todas = [json.loads(l) for l in open(args.fichero, encoding="utf-8") if l.strip()]

    # 1. Motor de reglas
    cerradas, resto = [], []
    for a in todas:
        d = decidir(ctx, a)
        if d:
            sev, why = severidad(ctx, a, d["verdict"]) if d["verdict"] == "true_positive" else ("informational", d["reason"])
            cerradas.append({"alert_id": a["alert_id"], "created_at": a["created_at"], "rule_id": a["rule_id"], **d,
                             "severity": "low" if sev not in ("informational", "low") else sev})
        else:
            a["_escudo_vigia"] = shield.analizar(a, cambios)       # 2. escudo
            resto.append(a)
    guardar("cerradas.json", cerradas)

    # 3. Grupos, ordenados por gravedad
    grupos = group.agrupar(resto, todas)
    grupos.sort(key=lambda g: -max(LEVELS.index(a["severity"]) for a in g))
    guardar("grupos.json", [[a["alert_id"] for a in g] for g in grupos])

    # 4. Caza
    cazas = hunt.cazar()
    guardar("caza.json", cazas)

    # 5. Agente N1 + fiscal
    tickets = []
    if not args.solo_reglas:
        from apps.backend.agents import n1, fiscal
        for g in grupos[: args.max]:
            t = n1.investigar(g)
            if LEVELS.index(t["severity"]) >= 2:
                t = fiscal.aplicar(t, fiscal.revisar(t, g))
            guardar(f"tickets/{t['ticket_id']}.json", t)
            tickets.append(t)
            print(f"{t['ticket_id']} {t['verdict']:22s} {t['severity']:9s} {t['title'][:70]}")

    # 6. N2: informe de incidente con los hallazgos de caza que tocan sus equipos o usuarios
    if args.n2 and tickets:
        from apps.backend.agents import n2
        for t in tickets:
            if t["verdict"] != "true_positive" or LEVELS.index(t["severity"]) < 3:
                continue
            ents = {x.lower() for x in (t.get("affected", {}).get("hosts", []) + t.get("affected", {}).get("users", []))}
            relacionadas = [c for c in cazas if any(e and e in json.dumps(c["ejemplos"]).lower() for e in ents)]
            inc = n2.informe([t], relacionadas)
            guardar(f"incidents/{inc['incident_id']}.json", inc)
            print("  N2:", inc["incident_id"], inc.get("title", "")[:70])

    # 7. Resumen para la web y la presentación
    resumen = {"alertas": len(todas), "cerradas_por_reglas": len(cerradas), "al_agente": len(resto), "grupos": len(grupos),
               "tickets": len(tickets), "por_regla": collections.Counter(c["rule"] for c in cerradas).most_common(),
               "fuera_de_horario_total": round(100 * sum(fuera_de_horario(a["created_at"]) for a in todas) / len(todas), 1),
               "fuera_de_horario_al_agente": round(100 * sum(fuera_de_horario(a["created_at"]) for a in resto) / max(1, len(resto)), 1),
               "manipulaciones": sum(1 for a in resto if a["_escudo_vigia"]), "hallazgos_caza": len(cazas)}
    guardar("resumen.json", resumen)
    print(json.dumps({k: v for k, v in resumen.items() if k != "por_regla"}, ensure_ascii=False))
    if not args.solo_reglas:
        from apps.backend.agents import llm
        print("Uso de Claude:", llm.resumen_uso())

if __name__ == "__main__":
    main()
