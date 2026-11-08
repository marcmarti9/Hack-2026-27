#!/usr/bin/env bash
# Arranca la mesa web desde cualquier carpeta.
set -euo pipefail
cd "$(dirname "$0")/../../.."
for option in "$@"; do
    case "$option" in
        --demo) export VIGIA_WEB_LOCAL_ONLY=1 ;;
        --rehacer) export VIGIA_REBUILD_INDEX=1 ;;
        *) echo "Opción desconocida: $option" >&2; exit 2 ;;
    esac
done
[ -x .venv/bin/python ] || python3 -m venv .venv
. .venv/bin/activate
python -m pip install --quiet -r apps/web/requirements.lock
exec sh apps/web/scripts/servir.sh
