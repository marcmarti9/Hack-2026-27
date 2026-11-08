# Vigía web

Mesa de triaje de Tarvia en el navegador. Usa el índice, las reglas y los expedientes del motor que comparte con Vigía escritorio. En **Analizar en directo** puedes pegar IDs del índice, alertas completas en JSON o un lote JSONL de hasta diez alertas. La pantalla va mostrando la recuperación de registros, las llamadas de propuesta y contraste cuando corresponden, y el guardado del expediente.

## Arranque local

Desde la raíz del repositorio, con Python 3.11 o superior y el dataset oficial en `data/dataset`:

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt -r apps/web/requirements.txt
sh apps/web/scripts/servir.sh
```

Abre [Vigía web](http://127.0.0.1:8100/). Si usas otra ubicación del dataset, exporta `VIGIA_DATA_DIR` antes de arrancar. El script crea el índice DuckDB en `out/web-index` si hace falta. Puedes reutilizar el del escritorio con `VIGIA_OUT_DIR`. La web guarda sus expedientes, decisiones y revisiones de guías en `out/web/review.sqlite`.

En Windows puedes ejecutar `powershell -File apps/web/scripts/arrancar.ps1` desde la raíz. En Linux y macOS también puedes usar `bash apps/web/scripts/arrancar.sh` para crear el entorno virtual y arrancar la web.

## Docker

Desde la raíz:

```bash
docker build -f apps/web/Dockerfile -t vigia-web .
docker run --rm -p 127.0.0.1:8100:8100 \
  -v "$PWD/data/dataset:/dataset:ro" \
  -v vigia-web-index:/index -v vigia-web-state:/state \
  vigia-web
```

Para cargar OpenAI en Docker, añade `--env-file` con el archivo local de configuración al comando `docker run`. El archivo de configuración se queda fuera del repositorio y de la imagen. Esta mesa está preparada para ejecutarse en el equipo de la demo con los datos ficticios de Tarvia. El selector de rol reproduce los perfiles del ejercicio.

## OpenAI en directo

Configura `OPENAI_API_KEY` en `~/.config/vigia/.env` o en el `.env` de la raíz y reinicia el servidor. La clave la usa el backend. **Analizar en directo → Alerta nueva de ensayo** prepara una alerta sintética con un registro de Tarvia que el índice puede recuperar. Elige **Guardia**, deja activado **Contrastar con OpenAI** y pulsa **Analizar alertas**.

Vigía usa Luna para proponer y Sol para el contraste cuando hay severidad alta, dudas o discrepancias. El veredicto se coteja con las citas y la evidencia local. Un fallo del proveedor queda en el expediente y el escalado de seguridad sigue la política del SOC. Los cierres elegibles por regla se resuelven localmente. [Modelos en OpenAI Docs](https://developers.openai.com/api/docs/guides/latest-model)

## Datos de presentación

Para mostrar los resultados del barrido completo, usa un `corpus.jsonl` generado con el mismo índice. Desde la raíz y con las mismas variables de dataset e índice que la web:

```bash
python -m scripts.run_corpus "${VIGIA_DATA_DIR:-data/dataset}/03_alertas/alertas.jsonl" \
  --output out/web/corpus.jsonl --jobs 4
```

También puedes indicar su ruta con `VIGIA_WEB_CORPUS`. La web distingue los cierres elegibles del barrido y los cierres registrados en la mesa. Desde **Casos** puedes buscar por ID. **Lo descartado** enlaza a expedientes del barrido. Los runbooks y la guía del agente admiten revisiones versionadas para el contraste.

Para enseñar el aislamiento, arranca el simulador oficial en el mismo entorno de red del backend, configura `VIGIA_SIM_PORT` y una clave de práctica de 10 a 128 caracteres en `VIGIA_WEB_N2_PASSWORD`. Vigía muestra la opción solo si el expediente y el puesto cumplen la política. La acción requiere confirmación, justificación y reautenticación N2.

[Guion de la defensa web](../../docs/defensa-web.md) · [EPIC](../../EPIC.md). Los scripts de agentes del prototipo previo siguen disponibles para experimentos independientes desde `apps/web`. El recorrido de presentación se inicia con `servir.sh`.
