# Vigía web

Mesa de triaje de Tarvia en el navegador. **Triaje** recibe lotes nuevos y muestra el progreso y el informe de cada alerta. **Casos** y **Panel** permiten consultar el histórico. La web comparte el motor de triaje y las reglas de escalado con Vigía escritorio.

## Arranque con Docker Compose

Con Git y Docker Compose instalados, ejecuta estos comandos desde la raíz del repositorio:

```bash
git clone https://github.com/dttdfr/DTT-UAB-The-Hack.git data/dataset
git -C data/dataset checkout --detach 5d7569232756eaf0a8723b22c428b70e8f67824f
docker compose up -d --build
docker compose logs -f vigia
```

El primer arranque construye el índice. Con los volúmenes vacíos, la prueba local indexó 814.471 eventos y 11.061 alertas en unos 6 min 44 s. Cuando el log indique que Uvicorn ha arrancado, abre [Vigía web](http://127.0.0.1:8100/#directo). Los volúmenes conservan el índice y el estado de la mesa entre arranques. [Dataset oficial, revisión fijada](https://github.com/dttdfr/DTT-UAB-The-Hack/tree/5d7569232756eaf0a8723b22c428b70e8f67824f)

Si ya tienes el dataset, usa esa misma revisión y define `VIGIA_DATASET_PATH` con su ruta. Puedes ponerla en el `.env` local de la raíz junto con `VIGIA_PORT` si el puerto 8100 está ocupado. El dataset se monta en solo lectura.

Para activar el monitor horario de vulnerabilidades, ejecuta `docker compose --profile inteligencia up -d --build`. El servicio consulta CISA KEV y los deltas de la lista oficial de CVE. El Panel muestra la fecha y el estado de cada fuente. [Fuentes y funcionamiento](../../docs/arquitectura-inteligencia.md)

Para activar OpenAI, añade `OPENAI_API_KEY` al `.env` local de la raíz antes de arrancar. Si ya guardas la clave en otro archivo, define `VIGIA_CONFIG_FILE` con la ruta de ese archivo. Después de cambiar la clave, ejecuta `docker compose up -d --force-recreate vigia`. Comprueba que `/api/estado` devuelve `"openai_disponible": true`. Sin clave, la mesa usa el motor local.

## Probar un lote nuevo

1. En **Triaje**, carga un archivo JSONL de hasta 150 alertas y 1 MB. Usa el mismo formato que `03_alertas/alertas.jsonl` del reto, con un objeto por línea y un identificador único para cada alerta nueva.
2. Selecciona el turno y pulsa **Analizar lote**. Si activas **Contraste de Vigía**, verás cuándo se hacen la propuesta y la revisión. La mesa conserva los resultados, las asignaciones y las decisiones.
3. Despliega una fila para consultar su informe. **Cerrada por Vigía** indica que el cierre ya está registrado y solo queda consultar el informe. Los perfiles de bajo riesgo habilitados para archivos nuevos son inventario SCCM autorizado, correo informativo identificado y solicitudes WAF cuya resolución queda verificada. Se exige corroborar todas las referencias directas. Si pediste contraste remoto, se exige acuerdo validado con esas pruebas y confianza de al menos 80 %. Las críticas se escalan según la política del SOC. El autocierre registra la decisión, el criterio y sus citas.

Para ensayar antes de recibir el archivo del jurado, carga el [lote de ensayo](../../eval/lote-presentacion-091.jsonl) o pulsa **Alerta nueva de ensayo** para usar una entrada sintética que referencia un registro de Tarvia.

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

Para enseñar el aislamiento, arranca el simulador oficial en el mismo entorno de red del backend, configura `VIGIA_SIM_PORT` y una clave de práctica de 10 a 128 caracteres en `VIGIA_WEB_N2_PASSWORD`. Vigía muestra la opción solo si el expediente y el puesto cumplen la política. La acción requiere confirmación, justificación y reautenticación N2.

[Guía de la web](../../docs/guia-web.md) · [Guion de defensa](../../docs/defensa-web.md) · [Arquitectura](../../docs/arquitectura-vigia.md) · [EPIC](../../EPIC.md)
