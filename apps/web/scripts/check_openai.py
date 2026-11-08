"""Comprueba el adaptador de OpenAI sin gastar ni conectarse a internet.

python -m scripts.check_openai          traducción de mensajes y herramientas, reintentos y plan B (sin base de datos)
python -m scripts.check_openai --e2e    además, un caso completo N1 + fiscal + N2 + chat con la base de datos real:
                                        un transporte falso hace de OpenAI devolviendo lo que respondería el modo demo,
                                        así cada turno pasa por la traducción de ida y vuelta."""
import json, os, sys
from types import SimpleNamespace

os.environ["VIGIA_MOCK"] = "0"
os.environ["VIGIA_PROVEEDOR"] = "openai"
os.environ.setdefault("OPENAI_API_KEY", "sk-prueba-sin-red")

from apps.backend.agents import llm, openai_client as oc   # noqa: E402

FALLOS = []
def check(nombre, ok, detalle=""):
    print(("OK    " if ok else "FALLO ") + nombre + (f"  ({detalle})" if detalle and not ok else ""))
    if not ok:
        FALLOS.append(nombre)


def a_mensajes_claude(payload):
    """Inverso del adaptador: items de la Responses API -> mensajes de Claude (para reutilizar el modo demo)."""
    msgs = []
    def poner(rol, bloque):
        if msgs and msgs[-1]["role"] == rol and isinstance(msgs[-1]["content"], list):
            msgs[-1]["content"].append(bloque)
        else:
            msgs.append({"role": rol, "content": [bloque]})
    for it in payload["input"]:
        t = it.get("type")
        if t == "function_call":
            poner("assistant", {"type": "tool_use", "id": it["call_id"], "name": it["name"], "input": json.loads(it["arguments"])})
        elif t == "function_call_output":
            poner("user", {"type": "tool_result", "tool_use_id": it["call_id"], "content": it["output"]})
        elif t == "reasoning":
            poner("assistant", {"type": "reasoning"})
        else:
            msgs.append({"role": it["role"], "content": it["content"]})
    return msgs


def a_respuesta_openai(r):
    out = [{"type": "reasoning", "id": "rs_1", "summary": [], "encrypted_content": "cifrado"}]
    for b in r.content:
        if b.type == "text":
            out.append({"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": b.text}]})
        elif b.type == "tool_use":
            out.append({"type": "function_call", "call_id": "call_" + b.id, "name": b.name, "arguments": json.dumps(b.input)})
    return {"status": "completed", "output": out, "usage": {"input_tokens": 100, "output_tokens": 10,
                                                             "input_tokens_details": {"cached_tokens": 40}}}


def unitarias():
    vistos = []
    respuestas = [
        {"status": "completed", "output": [
            {"type": "reasoning", "id": "rs_a", "summary": [], "encrypted_content": "x"},
            {"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": "Miro el evento."}]},
            {"type": "function_call", "call_id": "call_1", "name": "get_event", "arguments": "{\"event_id\": \"EDR-1\"}"}],
         "usage": {"input_tokens": 50, "output_tokens": 5}},
        {"status": "completed", "output": [
            {"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": "Hecho."}]}],
         "usage": {"input_tokens": 60, "output_tokens": 3, "input_tokens_details": {"cached_tokens": 30}}},
    ]
    def transporte(p):
        vistos.append(json.loads(json.dumps(p)))
        return respuestas[len(vistos) - 1]
    c = oc.OpenAIClient(transporte=transporte, esfuerzo="low")
    tools = [{"name": "get_event", "description": "d", "strict": True,
              "input_schema": {"type": "object", "properties": {"event_id": {"type": "string"}}, "required": ["event_id"]}}]
    msgs = [{"role": "user", "content": "Investiga"}]
    r = llm.crear(c, model="gpt-6-luna", max_tokens=1000, system="Eres N1", tools=tools, tool_choice={"type": "auto"}, messages=msgs)
    p = vistos[0]
    check("instrucciones y modelo", p["instructions"] == "Eres N1" and p["model"] == "gpt-6-luna")
    check("herramientas como function sin strict", p["tools"][0] == {"type": "function", "name": "get_event", "description": "d",
          "parameters": tools[0]["input_schema"], "strict": False} and p["tool_choice"] == "auto")
    check("mínimo de tokens de salida para el razonamiento", p["max_output_tokens"] >= 4000)
    check("respuesta como bloques text + tool_use", [b.type for b in r.content] == ["reasoning", "text", "tool_use"]
          and r.content[2].input == {"event_id": "EDR-1"} and r.content[2].id == "call_1" and r.stop_reason == "tool_use")
    msgs += [{"role": "assistant", "content": r.content},
             {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "call_1", "content": "{\"ok\": 1}"}]}]
    r2 = llm.crear(c, model="gpt-6-luna", max_tokens=1000, system="Eres N1", tools=tools, tool_choice={"type": "auto"}, messages=msgs)
    tipos = [i.get("type", i.get("role")) for i in vistos[1]["input"]]
    check("segundo turno: razonamiento, texto, llamada y resultado en orden", tipos == ["user", "reasoning", "assistant", "function_call",
          "function_call_output"], tipos)
    check("resultado enlazado por call_id", vistos[1]["input"][-1] == {"type": "function_call_output", "call_id": "call_1", "output": "{\"ok\": 1}"})
    check("fin de turno sin herramientas", r2.stop_reason == "end_turn" and r2.content[0].text == "Hecho.")
    check("cuenta de uso y caché", llm.USO["llamadas"] >= 2 and llm.USO["cache_leida"] >= 30)
    check("forzar una herramienta", oc.traducir_eleccion({"type": "tool", "name": "x"}) == {"type": "function", "name": "x"})

    # plan B: si la cuenta no acepta el razonamiento cifrado, se repite sin él
    llamadas = []
    def rechaza(p):
        llamadas.append(p)
        if "include" in p:
            raise oc.BadRequestError("HTTP 400: reasoning.encrypted_content not supported")
        return respuestas[1]
    c2 = oc.OpenAIClient(transporte=rechaza, esfuerzo="low")
    c2.messages.create(model="m", messages=[{"role": "user", "content": "hola"}], max_tokens=10)
    check("plan B sin razonamiento cifrado", len(llamadas) == 2 and "include" not in llamadas[1] and not c2.con_razonamiento)

    # reintento ante límite de peticiones (sin esperar de verdad)
    import time
    dormir, time.sleep = time.sleep, lambda s: None
    try:
        n = []
        def limita(p):
            n.append(1)
            if len(n) < 3:
                raise oc.RateLimitError("HTTP 429: rate limit")
            return respuestas[1]
        r3 = llm.crear(oc.OpenAIClient(transporte=limita), model="m", max_tokens=10, messages=[{"role": "user", "content": "hola"}])
        check("reintenta tras HTTP 429", len(n) == 3 and r3.content[0].text == "Hecho.")
    finally:
        time.sleep = dormir

    sin = oc.OpenAIClient(api_key="")
    try:
        sin._http({}); ok = False
    except oc.AuthenticationError:
        ok = True
    check("sin clave avisa claramente", ok)


def extremo_a_extremo():
    from apps.backend.agents.mock_llm import MockClient
    from apps.backend.agents import n1, fiscal, n2, chat
    from apps.backend.config import DATA
    demo = MockClient()
    turnos = []
    def transporte(p):
        msgs = a_mensajes_claude(p)
        tools = [{"name": t["name"], "input_schema": t["parameters"]} for t in p.get("tools", [])]
        turnos.append(p["model"])
        return a_respuesta_openai(demo.messages.create(model=p["model"], messages=msgs, tools=tools, system=p.get("instructions")))
    falso = oc.OpenAIClient(transporte=transporte)
    n1.client = falso
    fiscal.client = falso
    A = [json.loads(l) for l in open(DATA / "03_alertas/alertas.jsonl", encoding="utf-8")]
    grupo = [a for a in A if a["alert_id"] in ("ALR-20261007-011785", "ALR-20261007-011786", "ALR-20261007-011787",
                                               "ALR-20261007-011788", "ALR-20261008-011789")]
    t = n1.investigar(grupo)
    check("N1 por OpenAI: ticket con pruebas reales", t["verdict"] == "true_positive" and len(t["evidence"]) > 0
          and not any("no existen" in q for q in t.get("open_questions", [])), f"{t['verdict']} {len(t['evidence'])}")
    rev = fiscal.revisar(t, grupo)
    check("fiscal por OpenAI con su propio modelo", rev is not None and "gpt-6.1-sol" in turnos, str(turnos[-3:]))
    rep = n2.informe([t])
    check("informe N2 por OpenAI", bool(rep), "sin informe")
    res = chat.responder("qué hizo marta puig")
    check("chat por OpenAI", bool(res and res.get("respuesta")), str(res)[:200])


if __name__ == "__main__":
    unitarias()
    if "--e2e" in sys.argv:
        extremo_a_extremo()
    print(f"\n{'Todo correcto' if not FALLOS else str(len(FALLOS)) + ' fallo(s)'}")
    sys.exit(1 if FALLOS else 0)
