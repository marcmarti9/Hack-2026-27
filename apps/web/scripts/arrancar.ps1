# VIGÍA - arranque en Windows.
# Uso (desde la carpeta vigia):  powershell -ExecutionPolicy Bypass -File scripts\arrancar.ps1 [-Demo] [-Rehacer]
#   -Demo     agentes simulados con datos reales (sin clave de API)
#   -Rehacer  vuelve a ejecutar el orquestador aunque ya haya resultados
param([switch]$Demo, [switch]$Rehacer)
$ErrorActionPreference = "Stop"
$Raiz = Split-Path $PSScriptRoot -Parent
Set-Location $Raiz
$env:PYTHONUTF8 = "1"

# 1. Entorno virtual de Python
if (-not (Test-Path ".venv\Scripts\python.exe")) {
    Write-Host "Creando el entorno de Python (.venv)..." -ForegroundColor Cyan
    if (Get-Command py -ErrorAction SilentlyContinue) { & py -3 -m venv .venv } else { & python -m venv .venv }
}
$Py = Join-Path $Raiz ".venv\Scripts\python.exe"
Write-Host "Instalando dependencias..." -ForegroundColor Cyan
& $Py -m pip install --quiet --upgrade pip
& $Py -m pip install --quiet -r requirements.txt

# 2. Configuración: .env y modo demo automático si no hay clave
if (-not (Test-Path ".env")) { Copy-Item ".env.example" ".env" }
$HayClave = Select-String -Path ".env" -Pattern '^ANTHROPIC_API_KEY=sk-ant-(?!\.\.\.)' -Quiet
if ($Demo -or -not $HayClave) {
    $env:VIGIA_MOCK = "1"
    Write-Host "MODO DEMO: agentes simulados (no hay clave de API o has usado -Demo)." -ForegroundColor Yellow
} else { $env:VIGIA_MOCK = "0" }

# 3. Base de datos y resultados
if (-not (Test-Path "data\dataset\04_logs")) { throw "Falta el dataset en data\dataset (carpetas 01_contexto ... 06_herramientas)." }
if (-not (Test-Path "out\tarvia.duckdb")) {
    Write-Host "Cargando el dataset en DuckDB (unos 30 segundos)..." -ForegroundColor Cyan
    & $Py -m apps.backend.ingest
}
if ($Rehacer -or -not (Test-Path "out\resumen.json")) {
    Write-Host "Ejecutando VIGÍA sobre las 11.061 alertas..." -ForegroundColor Cyan
    & $Py -m scripts.run_all --n2
}

# 4. Cierra un VIGÍA anterior que siga ocupando los puertos (si no, seguiría sirviendo el código viejo)
foreach ($puerto in 8000, 8100) {
    Get-NetTCPConnection -LocalPort $puerto -State Listen -ErrorAction SilentlyContinue | ForEach-Object {
        Write-Host "Cerrando el proceso anterior del puerto $puerto..." -ForegroundColor Yellow
        Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue
    }
}
Start-Sleep -Seconds 1

# 5. API simulada de Deloitte (puerto 8000) y backend de VIGÍA (puerto 8100), cada uno en su ventana
$Mock = $env:VIGIA_MOCK
Start-Process powershell -ArgumentList "-NoExit", "-Command", "`$host.UI.RawUI.WindowTitle='API Deloitte (8000)'; Set-Location '$Raiz\data\dataset\06_herramientas'; & '$Py' -m uvicorn mock_soc_api:app --port 8000"
Start-Process powershell -ArgumentList "-NoExit", "-Command", "`$host.UI.RawUI.WindowTitle='VIGIA (8100)'; `$env:VIGIA_MOCK='$Mock'; `$env:PYTHONUTF8='1'; Set-Location '$Raiz'; & '$Py' -m uvicorn apps.backend.main:app --port 8100"
Start-Sleep -Seconds 6
Start-Process "http://127.0.0.1:8100"
Write-Host "VIGÍA en http://127.0.0.1:8100 . Cierra las dos ventanas para pararlo." -ForegroundColor Green
