"""Comprueba que la clave de Claude funciona antes de gastar en la pasada completa.
Uso:  python -m scripts.probar_claude            (2 llamadas mínimas: Sonnet y Haiku)
      python -m scripts.probar_claude --caso     (además investiga de verdad el caso del fraude de IBAN)"""
import json, os, sys, time
from apps.backend.config import DATA, MODEL_AGENT, MODEL_FAST, MOCK, ROOT

def main():
    if MOCK:
        sys.exit("Estás en modo demo (VIGIA_MOCK=1). Pon VIGIA_MOCK=0 en .env para probar Claude de verdad.")
    clave = os.getenv("ANTHROPIC_API_KEY", "")
    if not clave.startswith("sk-ant-") or clave.endswith("..."):
        sys.exit(f"No hay una clave válida en {ROOT / '.env'} (ANTHROPIC_API_KEY=sk-ant-...).")
    import anthropic
    from apps.backend.agents import llm
    c = anthropic.Anthropic(max_retries=2, timeout=60)
    for modelo in (MODEL_AGENT, MODEL_FAST):
        t0 = time.time()
        try:
            r = llm.crear(c, model=modelo, max_tokens=20, messages=[{"role": "user", "content": "Responde solo: VIGÍA lista"}])
            print(f"OK   {modelo:20s} {time.time() - t0:4.1f}s  ->  {r.content[0].text.strip()}")
        except Exception as e:
            print(f"FALLO {modelo}: {type(e).__name__}: {str(e)[:300]}")
            if "not_found" in str(e).lower() or "model" in str(e).lower():
                print("      Cambia MODEL_AGENT / MODEL_FAST en apps/backend/config.py por un modelo disponible en tu cuenta.")
            sys.exit(1)
    if "--caso" in sys.argv:
        from apps.backend.agents import n1
        A = [json.loads(l) for l in open(DATA / "03_alertas/alertas.jsonl", encoding="utf-8")]
        grupo = [a for a in A if a["alert_id"] in ("ALR-20261007-011785", "ALR-20261007-011786", "ALR-20261007-011787",
                                                   "ALR-20261007-011788", "ALR-20261008-011789")]
        print("\nInvestigando el fraude de IBAN con Claude (1-2 minutos)...")
        t = n1.investigar(grupo, on_step=lambda p: print("  ·", p.get("nombre") or p.get("texto", "")[:100]))
        print(f"\n{t['title']}\n{t['verdict']} · {t['severity']} · confianza {t['confidence']} · {len(t['evidence'])} pruebas · {t['triage_seconds']} s")
        print(t["summary"])
    print("\nUso:", llm.resumen_uso())

if __name__ == "__main__":
    main()
