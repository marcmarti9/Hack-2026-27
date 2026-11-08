# Vigía web

Mesa de triaje de Tarvia en el navegador. **Triaje** recibe lotes y muestra el progreso y el informe de cada alerta. **Casos** y **Panel** permiten consultar el histórico. La API usa `apps/engine` para investigar y `apps/backend` para consultar el índice y aplicar la política.

## Arranque con Docker Compose

Con Git y Docker Compose instalados, ejecuta estos comandos desde la raíz del repositorio:

```bash
git clone https://github.com/dttdfr/DTT-UAB-The-Hack.git data/dataset
git -C data/dataset checkout --detach ea61e70a3c066ff7663c613475f180597d56bd06
docker compose up -d --build
docker compose logs -f vigia
```

El primer arranque construye el índice. Con los volúmenes vacíos, la prueba local indexó 814.471 eventos y 11.061 alertas en unos 6 min 44 s. Cuando el log indique que Uvicorn ha arrancado, abre [Vigía web](http://127.0.0.1:8100/#directo). Los volúmenes conservan el índice y el estado de la mesa entre arranques. [Dataset oficial, revisión fijada](https://github.com/dttdfr/DTT-UAB-The-Hack/tree/ea61e70a3c066ff7663c613475f180597d56bd06)

Si ya tienes el dataset, usa esa misma revisión y define `VIGIA_DATASET_PATH` con su ruta. Puedes ponerla en el `.env` local de la raíz junto con `VIGIA_PORT` si el puerto 8100 está ocupado. El dataset se monta en solo lectura.

Para activar el monitor horario de vulnerabilidades, ejecuta `docker compose --profile inteligencia up -d --build`. El servicio consulta CISA KEV y los deltas de la lista oficial de CVE. El Panel muestra la fecha y el estado de cada fuente. [Fuentes y funcionamiento](../../docs/arquitectura-inteligencia.md)

Para activar OpenAI, añade `OPENAI_API_KEY` al `.env` local de la raíz antes de arrancar. Si ya guardas la clave en otro archivo, define `VIGIA_CONFIG_FILE` con la ruta de ese archivo. Después de cambiar la clave, ejecuta `docker compose up -d --force-recreate vigia`. Comprueba que `/api/estado` devuelve `"openai_disponible": true`. Sin clave, la mesa usa el motor local.

## Probar un lote nuevo

1. En **Triaje**, carga un archivo JSONL de hasta 150 alertas y 1 MB. Usa el mismo formato que `03_alertas/alertas.jsonl` del reto, con un objeto por línea y un identificador único para cada alerta nueva.
2. Selecciona el turno y pulsa **Analizar lote**. Si activas **Contraste de Vigía**, verás cuándo se hacen la propuesta y la revisión. La mesa conserva los resultados, las asignaciones y las decisiones.
3. Despliega una fila para consultar su informe. **Cerrada por Vigía** indica que el cierre ya está registrado. Para alertas nuevas, los perfiles elegibles incluyen inventario SCCM autorizado, correo informativo verificado, solicitudes WAF de resolución comprobada y consultas DNS que coinciden con un patrón de reputación verificado. Se exige corroborar todas las referencias directas. Si pediste contraste remoto, se exige acuerdo validado con esas pruebas y confianza de al menos 80 %. El autocierre guarda la decisión, el criterio y sus citas.

Para ensayar, carga `03_alertas/demo_alertas_comunes.jsonl` del dataset o el [lote de práctica](../../eval/lote-presentacion-091.jsonl). En **Datos de ensayo**, el botón **Alerta nueva de ensayo** prepara una entrada sintética vinculada a un registro de Tarvia.

Vigía usa Luna para proponer y Sol para el contraste cuando hay severidad alta, dudas o discrepancias. El veredicto se coteja con las citas y la evidencia local. Un fallo del proveedor queda en el expediente y el escalado de seguridad sigue la política del SOC. Los cierres elegibles por regla se resuelven localmente. [Modelos en OpenAI Docs](https://developers.openai.com/api/docs/guides/latest-model)

## Datos de presentación

Para mostrar los resultados del barrido completo en Docker, ejecuta el motor local dentro del servicio una vez que el índice esté listo:

```bash
docker compose exec vigia python -m scripts.run_corpus /dataset/03_alertas/alertas.jsonl \
  --output /state/corpus.jsonl --jobs 4
```

Si ya hay un barrido de otra versión, conserva ese archivo y genera el nuevo con otra ruta de salida y su propio checkpoint. Configura `VIGIA_WEB_CORPUS` con la nueva ruta dentro del contenedor y recrea `vigia` para mostrarlo.

En un arranque fuera de Docker, usa las mismas variables de dataset e índice que la web:

```bash
python -m scripts.run_corpus "${VIGIA_DATA_DIR:-data/dataset}/03_alertas/alertas.jsonl" \
  --output out/web/corpus.jsonl --jobs 4
```

También puedes indicar su ruta con `VIGIA_WEB_CORPUS`. La web distingue los cierres elegibles del barrido y los cierres registrados en la mesa. Desde **Casos** puedes buscar por ID. **Descartes** enlaza a expedientes del barrido. Los runbooks y la guía del agente admiten revisiones versionadas para el contraste.

## Aislamiento en el simulador

Para mostrar este recorrido en Docker, añade `VIGIA_SIM_PORT=18080` y una clave de práctica de 10 a 128 caracteres en `VIGIA_WEB_N2_PASSWORD` al archivo local de configuración. Recrea `vigia` y arranca el mock en el mismo contenedor, donde el backend lo consulta por loopback:

```bash
docker compose up -d --force-recreate vigia
docker compose exec -d vigia python -m scripts.serve_simulator --port 18080
```

Analiza `ALR-20261010-011795` en **Triaje**, abre su expediente y selecciona N2. La acción requiere confirmación, justificación y la clave de práctica. El expediente guarda el resultado. El proceso del simulador termina al recrear el contenedor.

[Guía de la web](../../docs/guia-web.md) · [Guion de defensa](../../docs/defensa-web.md) · [Arquitectura](../../docs/arquitectura-vigia.md) · [EPIC](../../EPIC.md)
