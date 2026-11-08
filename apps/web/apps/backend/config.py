"""Único sitio con rutas, modelos y modo de ejecución."""
import os
from pathlib import Path
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[2]
load_dotenv(ROOT / ".env")
DATA = Path(os.getenv("VIGIA_DATA", ROOT / "data" / "dataset"))
OUT = Path(os.getenv("VIGIA_OUT", ROOT / "out"))
DB = Path(os.getenv("VIGIA_DB", OUT / "tarvia.duckdb"))
SOC_API = os.getenv("VIGIA_SOC_API", "http://127.0.0.1:8000")     # API simulada de Deloitte
MODEL_AGENT = "claude-sonnet-5-5"
MODEL_FAST = "claude-haiku-5-5"
MOCK = os.getenv("VIGIA_MOCK", "0") == "1"                          # modo demo sin API

def llm_client():
    """Cliente de Claude o, en modo demo, el simulado (mismos métodos)."""
    if MOCK:
        from apps.backend.agents.mock_llm import MockClient
        return MockClient()
    import anthropic
    return anthropic.Anthropic(max_retries=4, timeout=180)
