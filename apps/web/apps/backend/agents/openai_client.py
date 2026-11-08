"""Cliente de OpenAI con la misma forma que el de Claude: client.messages.create(**kw) -> respuesta con .content y .usage.

Los agentes (N1, fiscal, N2 y chat) están escritos con el formato de mensajes y herramientas de Claude. Este adaptador
lo traduce a la Responses API de OpenAI y devuelve bloques text / tool_use, así los agentes no cambian.
Sin dependencias nuevas: usa urllib, como el asistente de escritorio."""
import json, os
from http.client import HTTPException
from types import SimpleNamespace
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

URL = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1").rstrip("/") + "/responses"


class OpenAIError(Exception):
    pass

# Mismos nombres que las excepciones de anthropic, para que llm.crear reintente igual con los dos proveedores.
class BadRequestError(OpenAIError): pass
class AuthenticationError(OpenAIError): pass
class NotFoundError(OpenAIError): pass
class RateLimitError(OpenAIError): pass
class InternalServerError(OpenAIError): pass
class APIConnectionError(OpenAIError): pass

_POR_CODIGO = {400: BadRequestError, 401: AuthenticationError, 403: AuthenticationError, 404: NotFoundError,
               429: RateLimitError}


def _texto(contenido) -> str:
    """Contenido de Claude (str o lista de bloques) a texto plano."""
    if isinstance(contenido, str):
        return contenido
    partes = []
    for b in contenido or []:
        t = b.get("type") if isinstance(b, dict) else getattr(b, "type", "")
        if t == "text":
            partes.append(b["text"] if isinstance(b, dict) else b.text)
    return "\n".join(partes)


def _campo(b, nombre, defecto=None):
    return b.get(nombre, defecto) if isinstance(b, dict) else getattr(b, nombre, defecto)


def traducir_mensajes(messages, con_razonamiento=True) -> list:
    """Mensajes de Claude a items de entrada de la Responses API."""
    items = []
    for m in messages:
        rol, contenido = m["role"], m["content"]
        if isinstance(contenido, str):
            items.append({"role": rol, "content": contenido})
            continue
        texto = []
        for b in contenido:
            tipo = _campo(b, "type")
            if tipo == "text" and _campo(b, "text", "").strip():
                texto.append(_campo(b, "text"))
            elif tipo == "tool_use":
                if texto:
                    items.append({"role": rol, "content": "\n".join(texto)}); texto = []
                items.append({"type": "function_call", "call_id": _campo(b, "id"), "name": _campo(b, "name"),
                              "arguments": json.dumps(_campo(b, "input") or {}, ensure_ascii=False)})
            elif tipo == "tool_result":
                salida = _campo(b, "content")
                items.append({"type": "function_call_output", "call_id": _campo(b, "tool_use_id"),
                              "output": salida if isinstance(salida, str) else _texto(salida)})
            elif tipo == "reasoning" and con_razonamiento and _campo(b, "raw"):
                items.append(_campo(b, "raw"))
        if texto:
            items.append({"role": rol, "content": "\n".join(texto)})
    return items


def traducir_herramientas(tools) -> list:
    # strict=False: los esquemas están escritos para Claude y el modo estricto de OpenAI exige que todo campo sea obligatorio.
    # Lo que importa se valida después (pruebas contra los logs, schema de Deloitte).
    return [{"type": "function", "name": t["name"], "description": t.get("description", ""),
             "parameters": t.get("input_schema") or {"type": "object", "properties": {}}, "strict": False} for t in tools or []]


def traducir_eleccion(tool_choice):
    tipo = (tool_choice or {}).get("type", "auto")
    if tipo == "tool":
        return {"type": "function", "name": tool_choice["name"]}
    return {"any": "required", "none": "none"}.get(tipo, "auto")


def traducir_respuesta(data: dict) -> SimpleNamespace:
    bloques = []
    for item in data.get("output") or []:
        tipo = item.get("type")
        if tipo == "message":
            for c in item.get("content") or []:
                if c.get("type") == "output_text" and c.get("text"):
                    bloques.append(SimpleNamespace(type="text", text=c["text"]))
        elif tipo == "function_call":
            try:
                entrada = json.loads(item.get("arguments") or "{}")
            except json.JSONDecodeError:
                entrada = {"_argumentos_ilegibles": item.get("arguments", "")[:500]}
            bloques.append(SimpleNamespace(type="tool_use", id=item.get("call_id") or item.get("id"),
                                           name=item.get("name"), input=entrada))
        elif tipo == "reasoning":
            bloques.append(SimpleNamespace(type="reasoning", raw=item))   # se devuelve tal cual en el turno siguiente
    u = data.get("usage") or {}
    uso = SimpleNamespace(input_tokens=u.get("input_tokens", 0), output_tokens=u.get("output_tokens", 0),
                          cache_read_input_tokens=(u.get("input_tokens_details") or {}).get("cached_tokens", 0))
    parada = "tool_use" if any(b.type == "tool_use" for b in bloques) else (
        "max_tokens" if data.get("status") == "incomplete" else "end_turn")
    return SimpleNamespace(content=bloques, usage=uso, stop_reason=parada, model=data.get("model"))


class _Mensajes:
    def __init__(self, cliente):
        self.c = cliente

    def create(self, *, model, messages, max_tokens=4096, system=None, tools=None, tool_choice=None, **_):
        return self.c.responder(model=model, messages=messages, max_tokens=max_tokens, system=system,
                                tools=tools, tool_choice=tool_choice)


class OpenAIClient:
    """Se usa como anthropic.Anthropic(): client.messages.create(...)."""

    def __init__(self, api_key=None, timeout=180, esfuerzo=None, transporte=None):
        self.api_key = os.getenv("OPENAI_API_KEY", "") if api_key is None else api_key
        self.timeout = timeout
        self.esfuerzo = esfuerzo or os.getenv("VIGIA_RAZONAMIENTO", "low")
        self.transporte = transporte or self._http      # las pruebas inyectan uno falso
        self.con_razonamiento = True
        self.messages = _Mensajes(self)

    def payload(self, *, model, messages, max_tokens, system, tools, tool_choice):
        p = {"model": model, "input": traducir_mensajes(messages, self.con_razonamiento),
             "max_output_tokens": max(int(max_tokens), 4000),    # el razonamiento también cuenta como salida
             "store": False}
        instr = _texto(system) if system else ""
        if instr:
            p["instructions"] = instr
        if tools:
            p["tools"] = traducir_herramientas(tools)
            p["tool_choice"] = traducir_eleccion(tool_choice)
            p["parallel_tool_calls"] = True
        if self.esfuerzo and self.esfuerzo != "none":
            p["reasoning"] = {"effort": self.esfuerzo}
            if self.con_razonamiento:
                p["include"] = ["reasoning.encrypted_content"]
        return p

    def responder(self, **kw):
        p = self.payload(**kw)
        try:
            data = self.transporte(p)
        except BadRequestError as e:
            if self.con_razonamiento and ("reasoning" in str(e).lower() or "encrypted" in str(e).lower()):
                self.con_razonamiento = False               # plan B: sin devolver el razonamiento entre turnos
                data = self.transporte(self.payload(**kw))
            else:
                raise
        if data.get("status") == "failed":
            raise InternalServerError(str(data.get("error"))[:300])
        return traducir_respuesta(data)

    def _http(self, payload: dict) -> dict:
        if not self.api_key:
            raise AuthenticationError("Falta OPENAI_API_KEY en .env")
        req = Request(URL, json.dumps(payload, ensure_ascii=False).encode("utf-8"),
                      headers={"Authorization": "Bearer " + self.api_key, "Content-Type": "application/json"})
        try:
            with urlopen(req, timeout=self.timeout) as r:
                return json.loads(r.read().decode("utf-8"))
        except HTTPError as e:
            cuerpo = e.read().decode("utf-8", "replace")[:600]
            clase = _POR_CODIGO.get(e.code, InternalServerError if e.code >= 500 else OpenAIError)
            raise clase(f"HTTP {e.code}: {cuerpo}") from None
        except (URLError, HTTPException, TimeoutError, OSError) as e:
            raise APIConnectionError(f"No se pudo conectar con OpenAI: {e}") from None
