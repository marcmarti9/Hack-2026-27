"""Configuración centralizada. Todo sale de variables de entorno (.env); nunca se hardcodean secretos."""
from __future__ import annotations

import os
import secrets
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

try:  # python-dotenv es opcional
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:  # pragma: no cover
    pass

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"


@dataclass(frozen=True)
class Settings:
    soc_mode: str
    soc_base_url: str
    soc_token: str
    llm_mode: str
    anthropic_api_key: str
    anthropic_model: str
    approval_secret: str
    confidence_threshold: float
    critical_confidence: float
    min_evidences_red: int
    db_path: str


@lru_cache
def get_settings() -> Settings:
    return Settings(
        soc_mode=os.getenv("SOC_CLIENT_MODE", "fixture"),
        soc_base_url=os.getenv("SOC_API_BASE_URL", ""),
        soc_token=os.getenv("SOC_API_TOKEN", ""),
        llm_mode=os.getenv("LLM_MODE", "heuristic"),
        anthropic_api_key=os.getenv("ANTHROPIC_API_KEY", ""),
        anthropic_model=os.getenv("ANTHROPIC_MODEL", ""),
        approval_secret=os.getenv("APPROVAL_SECRET") or secrets.token_urlsafe(32),
        confidence_threshold=float(os.getenv("CONFIDENCE_THRESHOLD", "0.7")),
        critical_confidence=float(os.getenv("CRITICAL_CONFIDENCE", "0.9")),
        min_evidences_red=int(os.getenv("MIN_EVIDENCES_RED", "2")),
        db_path=os.getenv("DB_PATH", str(DATA / "triage.db")),
    )
