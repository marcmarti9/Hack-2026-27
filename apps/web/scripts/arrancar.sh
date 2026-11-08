#!/usr/bin/env bash
# VIGÍA - arranque en Linux/macOS.  Uso: bash scripts/arrancar.sh [--demo] [--rehacer]
set -e
cd "$(dirname "$0")/.."
RAIZ=$(pwd); export PYTHONUTF8=1
[ -x .venv/bin/python ] || python3 -m venv .venv
PY=$RAIZ/.venv/bin/python
$PY -m pip install --quiet --upgrade pip && $PY -m pip install --quiet -r requirements.txt
[ -f .env ] || cp .env.example .env
if [[ " $* " == *" --demo "* ]] || ! grep -qE '^(OPENAI_API_KEY=sk-|ANTHROPIC_API_KEY=sk-ant-)[^.]' .env; then
  export VIGIA_MOCK=1; echo "MODO DEMO: agentes simulados."
else export VIGIA_MOCK=0; fi
[ -d data/dataset/04_logs ] || { echo "Falta el dataset en data/dataset"; exit 1; }
[ -f out/tarvia.duckdb ] || $PY -m apps.backend.ingest
if [[ " $* " == *" --rehacer "* ]] || [ ! -f out/resumen.json ]; then $PY -m scripts.run_all --n2; fi
(cd data/dataset/06_herramientas && $PY -m uvicorn mock_soc_api:app --port 8000) &
MOCK_PID=$!
trap "kill $MOCK_PID 2>/dev/null" EXIT
(sleep 4 && (xdg-open http://127.0.0.1:8100 2>/dev/null || open http://127.0.0.1:8100 2>/dev/null || true)) &
$PY -m uvicorn apps.backend.main:app --port 8100
