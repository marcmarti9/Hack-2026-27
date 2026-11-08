# VIGÍA · el SOC que no se apaga

Analista SOC N1 con IA para Tarvia (reto de Deloitte, UAB THE HACK! 2026). VIGÍA trabaja las 24 horas: cierra el ruido
con reglas explicables, investiga lo demás con agentes de IA, une las alertas en casos, caza lo que no generó alerta y deja
al humano solo la decisión. **La IA investiga, la persona decide.**

## Resultados medidos sobre el dataset

| Medida | Valor |
| --- | --- |
| Alertas del SIEM | 11.061 |
| Cerradas por el motor de reglas, cada una con su motivo | 10.974 |
| Investigadas por la IA | 87 |
| Casos para el humano | 17 |
| De lo que llega a la IA, fuera de horario | 62,1 % (frente al 31,7 % del total) |
| Intentos de engañar a la IA detectados | 18 (todos en ataques reales, 0 falsas alarmas) |
| Hallazgos de caza sin alerta | 5 (entre ellos el implante de WMS01) |

`python -m scripts.test_todo` comprueba todo esto en un minuto (13 comprobaciones).

## Instalación en Windows (primera vez)

1. Instala **Python 3.11 o superior** desde python.org marcando "Add python.exe to PATH".
2. Copia el dataset de Deloitte dentro de `data\dataset\` (carpetas `01_contexto` ... `06_herramientas`). Ya está copiado en este equipo.
3. Copia `.env.example` como `.env` y pon tu clave de OpenAI (`OPENAI_API_KEY=sk-...`) o, si lo preferís, la de Anthropic con `VIGIA_PROVEEDOR=claude`. Sin clave, VIGÍA arranca en **modo demo**.
4. Desde la carpeta `vigia`:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\arrancar.ps1
```

El script crea el entorno, instala las dependencias, carga los datos en DuckDB (unos 30 s), ejecuta VIGÍA sobre las
alertas, arranca la API de Deloitte (puerto 8000) y la web (puerto 8100) y abre el navegador en http://127.0.0.1:8100.

Opciones: `-Demo` fuerza el modo demo aunque haya clave; `-Rehacer` vuelve a ejecutar el orquestador.

## Modos de ejecución (con el entorno activado: `.\.venv\Scripts\Activate.ps1`)

| Comando | Qué hace | Gasta API |
| --- | --- | --- |
| `python -m apps.backend.ingest` | Carga el dataset en `out\tarvia.duckdb` | No |
| `python -m scripts.run_all --solo-reglas` | Motor de reglas, escudo, grupos y caza | No |
| `$env:VIGIA_MOCK="1"; python -m scripts.run_all --n2` | Todo con agentes simulados (datos reales) | No |
| `python -m scripts.run_all --max 3` | Los 3 casos más graves con la IA real | Sí |
| `python -m scripts.run_all --n2` | Todo con la IA real: 17 casos + informes N2 | Sí |
| `python -m scripts.alertas_directo` y `python -m scripts.run_all --fichero out\alertas_directo.jsonl --salida out\directo --n2` | Ensayo de alertas del directo | Sí |
| `python -m scripts.evaluar` | Métricas contra `eval\etiquetas.csv` | No |
| `python -m scripts.test_todo` | Las 13 comprobaciones | No |
| `uvicorn apps.backend.main:app --port 8100` | Solo la web | Solo el chat |

## Arquitectura

```
alertas.jsonl ─► motor de reglas (sin IA) ─► cerradas con explicación (10.974)
                       │ lo dudoso (87)
                       ▼
                escudo anti-manipulación ─► agrupación (17 casos)
                       ▼
            agente N1 (OpenAI o Claude + 10 herramientas sobre DuckDB y CVE)
                       ▼
     validador de pruebas + severidad por matriz ─► fiscal (IA revisora)
                       ▼
            caza sin alerta ─► agente N2 (informe de incidente)
                       ▼
       web: parte de guardia · casos · mapa · descartado · chat
                       ▼
     el humano aprueba ─► API de Deloitte (token) ─► contención
```

| Carpeta | Contenido |
| --- | --- |
| `apps/backend/ingest.py` | Carga a DuckDB (814.471 eventos, 2,4 M entidades) |
| `apps/backend/tools/` | Consultas (`db.py`) y CVE con CISA KEV y EPSS (`cve.py`) |
| `apps/backend/rules/` | Reglas de la casa, matriz de severidad y tabla de aprobaciones |
| `apps/backend/agents/` | N1, fiscal, N2, chat y `mock_llm.py` (modo demo) |
| `apps/backend/hunt/` | Escudo, agrupación y caza |
| `apps/backend/main.py` | API de la web (puerto 8100) |
| `apps/frontend/` | La web: HTML, CSS y JS sin compilación |
| `scripts/` | Orquestador, pruebas, alertas del directo, métricas y arranque |

## Reglas de diseño

- La severidad la calcula la matriz de `politica_soc.md`, no la IA. El agente solo propone ajustes de ±1 con motivo.
- Toda prueba citada se comprueba en los logs. Si no existe, se descarta y baja la confianza.
- Lo que escribe el atacante entra como `<datos_no_confiables>` y nunca como instrucción.
- Las contenciones siguen la tabla de aprobaciones. El rol N1 no puede aprobar lo que requiere N2. Nunca se actúa sobre OT.
- El motor solo cierra casos 100 % claros; ante la duda, la alerta va al agente.

## Modo demo (VIGIA_MOCK=1)

Imita al modelo real con el mismo interfaz: consulta las herramientas de verdad, cita solo eventos que existen y aplica
heurísticas por regla. Sirve para enseñar la web sin clave o si falla la conexión. Los tickets llevan la marca
"[modo demo]" y la web muestra la etiqueta MODO DEMO. **No sustituye al razonamiento del modelo real.**

## Límites conocidos

- Las reglas del motor se han ajustado mirando este dataset; con datos nuevos, lo que no encaje exactamente pasa al agente.
- El camino con la IA real está probado con un transporte simulado (`python -m scripts.check_openai --e2e`); hay que validarlo con la clave (`python -m scripts.probar_ia --caso`, primer caso: fraude de IBAN).
- La descarga de CISA KEV y EPSS (`python -m apps.backend.tools.cve`) necesita Internet una vez; sin caché, VIGÍA dice "sin datos externos".
- El grafo de entidades carga Cytoscape desde Internet; sin conexión se indica y el resto funciona.
- Algunas CVE del dataset parecen inventadas y no tienen datos externos.

## Datos y secretos

El dataset de Deloitte, `out/` y `.env` están en `.gitignore` y **no se suben a Git**. No se visita ni descarga ningún
indicador del dataset: solo se consultan el TIP y la sandbox locales.

## Proveedor de IA

Los agentes están escritos una sola vez y funcionan con OpenAI o con Claude:

- **OpenAI (por defecto)**: `apps/backend/agents/openai_client.py` traduce los mensajes y herramientas a la Responses API. `gpt-6-luna` investiga, redacta el informe N2 y responde el chat; `gpt-6.1-sol` hace de fiscal, así quien revisa es un modelo distinto del que investiga. Se cambian con `OPENAI_MODEL`, `OPENAI_REVIEW_MODEL` y `VIGIA_RAZONAMIENTO` en `.env`.
- **Claude**: `VIGIA_PROVEEDOR=claude` y `ANTHROPIC_API_KEY`.
- La clave de la API se factura aparte de la suscripción de ChatGPT. Para ensayar sin gastar está el modo demo.

Comprobaciones: `python -m scripts.check_openai` (sin red ni gasto), `python -m scripts.probar_ia` (una llamada por modelo) y `python -m scripts.probar_ia --caso`.
