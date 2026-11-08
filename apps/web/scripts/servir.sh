#!/bin/sh
set -eu
cd "$(dirname "$0")/../../.."
if [ "$#" -eq 0 ]; then
    set -- --host 127.0.0.1
fi
export VIGIA_DATA_DIR="${VIGIA_DATA_DIR:-${VIGIA_DATA:-$PWD/data/dataset}}"
export VIGIA_OUT_DIR="${VIGIA_OUT_DIR:-$PWD/out/web-index}"
export VIGIA_WEB_OUT="${VIGIA_WEB_OUT:-$PWD/out/web}"
test -f "$VIGIA_DATA_DIR/03_alertas/alertas.jsonl" || {
    echo "Indica la carpeta del dataset oficial en VIGIA_DATA_DIR." >&2
    exit 1
}
if [ "${VIGIA_REBUILD_INDEX:-0}" = 1 ] || [ ! -s "$VIGIA_OUT_DIR/tarvia.duckdb" ]; then
    python -m apps.backend.ingest
fi
exec python -m uvicorn apps.web.apps.backend.main:app --port 8100 "$@"
