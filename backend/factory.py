"""Construcción de componentes según la configuración (.env)."""
from __future__ import annotations

from backend.config import Settings
from backend.integrations.soc_client import FixtureSOCClient, HttpSOCClient, SOCClient
from backend.triage.llm import AnthropicJudge, HeuristicJudge, Judge


def build_client(s: Settings) -> SOCClient:
    if s.soc_mode == "http":
        return HttpSOCClient(s.soc_base_url, s.soc_token)
    if s.soc_mode != "fixture":
        raise ValueError("SOC_CLIENT_MODE debe ser fixture o http")
    return FixtureSOCClient()


def build_judge(s: Settings) -> Judge:
    if s.llm_mode == "anthropic":
        return AnthropicJudge(s.anthropic_api_key, s.anthropic_model)
    if s.llm_mode != "heuristic":
        raise ValueError("LLM_MODE debe ser heuristic o anthropic")
    return HeuristicJudge()
