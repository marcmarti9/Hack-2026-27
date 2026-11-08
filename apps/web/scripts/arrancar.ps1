# Arranca la mesa web desde cualquier carpeta.
param([switch]$Demo, [switch]$Rehacer)
$ErrorActionPreference = "Stop"
$Raiz = (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")).Path
Set-Location $Raiz
$env:PYTHONUTF8 = "1"
if ($Demo) { $env:VIGIA_WEB_LOCAL_ONLY = "1" }
if (-not $env:VIGIA_DATA_DIR) {
    if ($env:VIGIA_DATA) { $env:VIGIA_DATA_DIR = $env:VIGIA_DATA }
    else { $env:VIGIA_DATA_DIR = Join-Path $Raiz "data\dataset" }
}
if (-not $env:VIGIA_OUT_DIR) { $env:VIGIA_OUT_DIR = Join-Path $Raiz "out\web-index" }
if (-not $env:VIGIA_WEB_OUT) { $env:VIGIA_WEB_OUT = Join-Path $Raiz "out\web" }
if (-not (Test-Path (Join-Path $env:VIGIA_DATA_DIR "03_alertas\alertas.jsonl"))) {
    throw "Indica la carpeta del dataset oficial en VIGIA_DATA_DIR."
}
$Py = Join-Path $Raiz ".venv\Scripts\python.exe"
if (-not (Test-Path $Py)) {
    if (Get-Command py -ErrorAction SilentlyContinue) { & py -3 -m venv .venv }
    else { & python -m venv .venv }
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
& $Py -m pip install --quiet -r requirements.txt -r apps/web/requirements.txt
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
if ($Rehacer -or -not (Test-Path (Join-Path $env:VIGIA_OUT_DIR "tarvia.duckdb"))) {
    & $Py -m apps.backend.ingest
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
& $Py -m uvicorn apps.web.apps.backend.main:app --host 127.0.0.1 --port 8100
exit $LASTEXITCODE
