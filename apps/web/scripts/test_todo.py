"""Comprueba TODO el proyecto (sin gastar API). Uso: python -m scripts.test_todo
Imprime OK o FALLO por cada comprobación y termina con código 1 si algo falla."""
import json, os, subprocess, sys
from pathlib import Path
from apps.backend.config import DATA, ROOT

RES, ENV_MOCK = [], {**os.environ, "VIGIA_MOCK": "1", "PYTHONUTF8": "1"}
def check(nombre, cond, detalle=""):
    RES.append(bool(cond)); print(f"{'OK   ' if cond else 'FALLO'} {nombre}" + (f"  ({detalle})" if detalle else ""))

def py(*args, env=None):
    r = subprocess.run([sys.executable, "-m", *args], cwd=ROOT, capture_output=True, text=True, env=env or ENV_MOCK, encoding="utf-8")
    return r.returncode, r.stdout + r.stderr

def main():
    from apps.backend.tools import db
    n = lambda t: db._rows(f"SELECT count(*) n FROM {t}")[0]["n"]
    check("1. ingesta: 814.471 eventos, 2.467.451 entidades, 11.061 alertas",
          (n("events"), n("event_entities"), n("alerts")) == (814471, 2467451, 11061), f"{n('events')}, {n('event_entities')}, {n('alerts')}")
    check("2. consultas DuckDB", db.asset("JENKINS-DEV01")["vulnerabilities"][0]["id"] == "CVE-2024-23897"
          and len(db.events_for_entity("WS-BCN-1770", "2026-10-10T00:23:00Z", 24)) == 100
          and db.intel("203.0.113.88")["tip"]["malware_family"] == "Latrodectus")

    from apps.backend.rules.engine import Contexto, decidir, severidad
    ctx = Contexto(DATA)
    A = [json.loads(l) for l in open(DATA / "03_alertas/alertas.jsonl", encoding="utf-8")]
    resto = [a for a in A if not decidir(ctx, a)]
    check("3. motor de reglas: 10.974 cerradas, 87 al agente", (len(A) - len(resto), len(resto)) == (10974, 87), f"{len(A) - len(resto)} / {len(resto)}")
    a = next(x for x in A if x["alert_id"] == "ALR-20261005-000172")
    check("4. matriz de severidad (ALR-20261005-000172 = low)", severidad(ctx, a, "true_positive")[0] == "low")

    code, out = py("scripts.test_n1_fake", env={**os.environ, "VIGIA_MOCK": "0", "PYTHONUTF8": "1", "ANTHROPIC_API_KEY": os.getenv("ANTHROPIC_API_KEY", "sin-clave")})
    check("5. agente N1 con cliente falso: schema, critical, N2 de guardia, prueba inventada descartada",
          code == 0 and "OK schema | critical | N2 de guardia" in out and "no existen" in out, out.strip()[-160:])

    import csv
    from apps.backend.hunt import shield, group, hunt
    ids = {c["id"] for c in csv.DictReader(open(DATA / "02_inventario/calendario_cambios.csv", encoding="utf-8"))}
    marcadas = [x["alert_id"] for x in A if shield.analizar(x, ids)]
    check("6. escudo: 18 alertas, todas de escenarios reales", len(marcadas) == 18 and all(int(i[-6:]) >= 11785 for i in marcadas), str(len(marcadas)))
    check("7. agrupación: 87 alertas en 17 grupos", len(group.agrupar(resto, A)) == 17)
    cz = hunt.cazar()
    check("8. caza: primer hallazgo servicio_sin_firma con EDR-0123433", cz and cz[0]["caza"] == "servicio_sin_firma" and cz[0]["event_ids"][0] == "EDR-0123433")

    code, out = py("scripts.run_all", "--solo-reglas", "--salida", "out/_test")
    r = json.loads((ROOT / "out/_test/resumen.json").read_text(encoding="utf-8")) if code == 0 else {}
    esperado = {"alertas": 11061, "cerradas_por_reglas": 10974, "al_agente": 87, "grupos": 17, "fuera_de_horario_total": 31.7,
                "fuera_de_horario_al_agente": 62.1, "manipulaciones": 18, "hallazgos_caza": 5}
    check("9. orquestador --solo-reglas con los números esperados", all(r.get(k) == v for k, v in esperado.items()), json.dumps({k: r.get(k) for k in esperado}))

    code, out = py("scripts.run_all", "--n2", "--salida", "out/_test")
    import jsonschema
    TS = json.load(open(DATA / "01_contexto/ticket_salida.schema.json", encoding="utf-8"))
    IS = json.load(open(DATA / "01_contexto/informe_incidente.schema.json", encoding="utf-8"))
    tks = list((ROOT / "out/_test/tickets").glob("*.json")); incs = list((ROOT / "out/_test/incidents").glob("*.json"))
    ok = code == 0 and len(tks) == 17 and len(incs) > 0
    try:
        for p in tks: jsonschema.validate(json.loads(p.read_text(encoding="utf-8")), TS)
        for p in incs: jsonschema.validate(json.loads(p.read_text(encoding="utf-8")), IS)
    except jsonschema.ValidationError as e:
        ok = False; out = str(e)[:200]
    check("10. modo demo completo: 17 tickets y los informes N2 cumplen los schemas de Deloitte", ok, f"{len(tks)} tickets, {len(incs)} informes")

    code, out = py("scripts.alertas_directo")
    code2, out2 = py("scripts.run_all", "--fichero", "out/alertas_directo.jsonl", "--salida", "out/_test_directo", "--n2")
    check("11. alertas del directo: las 3 llegan al agente y salen como ticket", code == 0 and code2 == 0 and
          len(list((ROOT / "out/_test_directo/tickets").glob("*.json"))) == 3)

    from fastapi.testclient import TestClient
    from apps.backend.main import app
    c = TestClient(app)
    rutas = ["estado", "resumen", "tickets", "rgpd", "mapa", "caza", "incidentes", "cerradas?rule=pentest", "evento/EDR-0123433",
             "descartado", "playbooks"]
    estados = {p: c.get("/api/" + p).status_code for p in rutas}
    t0 = c.get("/api/tickets").json()
    det = c.get("/api/tickets/" + t0[0]["ticket_id"]) if t0 else None
    estados["ticket"] = det.status_code if det else 0
    estados["historia_y_playbook"] = 200 if det and det.json()["linea"]["pasos"] and det.json()["playbooks"] else 0
    estados["10_playbooks"] = 200 if len(c.get("/api/playbooks").json()) == 10 else 0
    estados["web"] = c.get("/").status_code
    check("12. backend y web responden", all(v == 200 for v in estados.values()), json.dumps(estados))
    n1_bloq = c.post("/api/aprobar", json={"ticket_id": "x", "action": "isolate_host", "target": "FS01", "approver": "a", "rol": "N1"}).status_code
    ot = c.post("/api/aprobar", json={"ticket_id": "x", "action": "isolate_host", "target": "PLC-SORT01", "approver": "a", "rol": "N2"}).status_code
    check("13. aprobaciones: el N1 no puede aislar un servidor y nadie actúa sobre OT", n1_bloq == 403 and ot == 403)

    print(f"\n{sum(RES)}/{len(RES)} comprobaciones correctas")
    sys.exit(0 if all(RES) else 1)

if __name__ == "__main__":
    main()
