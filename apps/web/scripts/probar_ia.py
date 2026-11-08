"""Comprueba que la clave de la IA funciona antes de lanzar la pasada completa.
Uso:  python -m scripts.probar_ia            (una llamada mínima a cada modelo: agentes, fiscal y chat)
      python -m scripts.probar_ia --caso     (además investiga de verdad el caso del fraude de IBAN)
      python -m scripts.probar_ia --solo-config  (comprueba configuración sin llamadas de red)"""
import json, sys, time
from apps.backend import config
from apps.backend.config import DATA, MOCK, PROVEEDOR

def main():
    if MOCK:
        sys.exit("Estás en modo demo (VIGIA_MOCK=1). Pon VIGIA_MOCK=0 en .env para probar la IA de verdad.")
    nombre, prefijo = ("OPENAI_API_KEY", "sk-") if PROVEEDOR == "openai" else ("ANTHROPIC_API_KEY", "sk-ant-")
    if not config._clave(nombre, prefijo):
        sys.exit(f"Falta configurar {nombre} en el entorno o en {config.USER_CONFIG}.")
    if "--solo-config" in sys.argv:
        print(f"Proveedor {PROVEEDOR}. Se ha cargado {nombre}. Comprobación local, sin llamar a la API.")
        return
    from apps.backend.agents import llm
    c = config.llm_client()
    print(f"Proveedor: {PROVEEDOR}")
    for papel, modelo in (("agentes", config.MODEL_AGENT), ("fiscal", config.MODEL_REVIEW), ("chat", config.MODEL_FAST)):
        t0 = time.time()
        try:
            r = llm.crear(c, model=modelo, max_tokens=50, messages=[{"role": "user", "content": "Responde solo: VIGÍA lista"}])
            texto = "".join(b.text for b in r.content if b.type == "text").strip()
            print(f"OK    {papel:8s} {modelo:20s} {time.time() - t0:4.1f}s  ->  {texto[:60]}")
        except Exception as e:
            print(f"FALLO {papel} {modelo}: {type(e).__name__}: {str(e)[:400]}")
            if PROVEEDOR == "openai":
                print("      Si el modelo no existe en tu cuenta, cambia OPENAI_MODEL / OPENAI_REVIEW_MODEL en .env.")
            sys.exit(1)
    if "--caso" in sys.argv:
        from apps.backend.agents import n1
        A = [json.loads(l) for l in open(DATA / "03_alertas/alertas.jsonl", encoding="utf-8")]
        grupo = [a for a in A if a["alert_id"] in ("ALR-20261007-011785", "ALR-20261007-011786", "ALR-20261007-011787",
                                                   "ALR-20261007-011788", "ALR-20261008-011789")]
        print(f"\nInvestigando el fraude de IBAN con {config.MODEL_AGENT} (1-3 minutos)...")
        t = n1.investigar(grupo, on_step=lambda p: print("  ·", p.get("nombre") or p.get("texto", "")[:100]))
        print(f"\n{t['title']}\n{t['verdict']} · {t['severity']} · confianza {t['confidence']} · {len(t['evidence'])} pruebas · {t['triage_seconds']} s")
        print(t["summary"])
    print("\nUso:", llm.resumen_uso())

if __name__ == "__main__":
    main()
