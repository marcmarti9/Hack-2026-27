"""Único sitio con rutas, modelos y modo de ejecución."""
import os
from pathlib import Path
from dotenv import dotenv_values, load_dotenv

ROOT = Path(__file__).resolve().parents[2]
USER_CONFIG = Path(os.getenv("XDG_CONFIG_HOME") or Path.home() / ".config") / "vigia" / ".env"
CONFIG_FILES = (USER_CONFIG, ROOT.parent.parent / ".env", ROOT / ".env")


def _valida(valor, prefijo):
    valor = (valor or "").strip()
    return valor.startswith(prefijo) and len(valor) > len(prefijo) and not valor.endswith("...")


def _clave(nombre, prefijo):
    return _valida(os.getenv(nombre), prefijo)


for path in CONFIG_FILES:
    load_dotenv(path)

# Un valor vacío o de ejemplo no debe ocultar la clave de otro archivo.
if not _clave("OPENAI_API_KEY", "sk-"):
    for path in CONFIG_FILES:
        key = dotenv_values(path).get("OPENAI_API_KEY")
        if _valida(key, "sk-"):
            os.environ["OPENAI_API_KEY"] = key.strip()
            break
    else:
        os.environ.pop("OPENAI_API_KEY", None)

DATA = Path(os.getenv("VIGIA_DATA", ROOT / "data" / "dataset"))
OUT = Path(os.getenv("VIGIA_OUT", ROOT / "out"))
DB = Path(os.getenv("VIGIA_DB", OUT / "tarvia.duckdb"))
SOC_API = os.getenv("VIGIA_SOC_API", "http://127.0.0.1:8000")     # API simulada de Deloitte
MOCK = os.getenv("VIGIA_MOCK", "0") == "1"                          # modo demo sin API

# Proveedor de los agentes: openai (por defecto si hay clave de OpenAI) o claude. VIGIA_PROVEEDOR lo fuerza.
PROVEEDOR = os.getenv("VIGIA_PROVEEDOR") or ("openai" if _clave("OPENAI_API_KEY", "sk-") or not _clave("ANTHROPIC_API_KEY", "sk-ant-")
                                             else "claude")
if PROVEEDOR == "openai":     # los mismos modelos que usa la app de escritorio del equipo
    MODEL_AGENT = os.getenv("OPENAI_MODEL", "gpt-6-luna")             # investigador N1, informe N2
    MODEL_REVIEW = os.getenv("OPENAI_REVIEW_MODEL", "gpt-6.1-sol")    # fiscal: un modelo distinto intenta refutar
    MODEL_FAST = os.getenv("OPENAI_CHAT_MODEL", MODEL_AGENT)          # chat
else:
    MODEL_AGENT = "claude-sonnet-5-5"
    MODEL_REVIEW = MODEL_AGENT
    MODEL_FAST = "claude-haiku-5-5"

def llm_client():
    """Cliente de OpenAI o de Claude o, en modo demo, el simulado. Los tres tienen los mismos métodos."""
    if MOCK:
        from apps.backend.agents.mock_llm import MockClient
        return MockClient()
    if PROVEEDOR == "openai":
        from apps.backend.agents.openai_client import OpenAIClient
        return OpenAIClient(timeout=180)
    import anthropic
    return anthropic.Anthropic(max_retries=4, timeout=180)
