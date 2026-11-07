# Vigía · Agentic SOC para Tarvia Group

UAB The Hack 2026 · Reto Deloitte de IA para ciberseguridad · Marc's & Co.

Vigía investiga alertas del SOC de Tarvia Group y prepara un expediente con evidencias para que una persona decida si cerrar, corregir o escalar. Tarvia es un retailer ficticio que se prepara para Black Friday. Su SOC cuenta con tres analistas N1 y dos N2 y necesita cubrir las alertas que llegan fuera de horario.

## Instalar y arrancar

Necesitas Docker con Compose v2 o posterior. Desde la raíz del repositorio:

```bash
docker compose up --build -d --wait
```

Abre el [panel de Vigía](http://localhost:8501). La primera compilación descarga la imagen de Python y sus dependencias. La configuración predeterminada procesa seis alertas sintéticas locales con un juez determinista, sin clave de API.

1. En **Cola de alertas**, pulsa **Procesar todas las pendientes**.
2. En **Expediente**, elige una alerta y revisa las evidencias, las consultas y la recomendación.
3. En **Decisión humana**, registra tu nombre y acepta, corrige o escala. Una propuesta de contención de la demo requiere identificación y confirmación explícita.
4. En **Resultados**, consulta el volumen procesado, los casos pendientes y el tiempo observado.

El panel se publica solo en `127.0.0.1`. Es una aplicación web local para un operador. El campo de analista registra un nombre declarado y no autentica la identidad. Si el puerto está ocupado, copia `.env.example` a `.env` y ajusta `VIGIA_PORT`. El volumen `triage` conserva los expedientes y su auditoría al ejecutar `docker compose down` y volver a iniciar.

```bash
docker compose run --rm --no-deps backend python -m unittest discover -s tests -t . -v
docker compose down
```

### Análisis con un modelo

La integración opcional usa `LLM_MODE=anthropic`, `ANTHROPIC_API_KEY` y `ANTHROPIC_MODEL` en `.env`. El modelo recibe el contexto recuperado de la alerta y puede generar costes. Usa datos sintéticos y un modelo habilitado en tu cuenta. La demo predeterminada funciona sin este servicio.

## Flujo de triaje

```text
Alerta → Entender → Contextualizar → Enriquecer → Correlacionar
       → Veredicto propuesto con referencias → Prioridad y SLA
       → Expediente → Decisión humana
```

| Semáforo | Interpretación |
| --- | --- |
| Rojo | Posible ataque real (TP) con evidencias suficientes para escalar o proponer una contención. |
| Amarillo | Caso pendiente de decisión humana por falta de contexto, dudas o fallos de consulta. Requiere corrección o escalado. |
| Verde | Actividad legítima (BTP) o falsa alarma (FP) con evidencia de legitimidad. El analista puede aceptar el cierre. |

El motor comprueba que cada referencia citada corresponda a un dato recuperado. La validación de referencias y el detector de patrones de inyección son controles parciales. El juez propone el veredicto. El código aplica el semáforo y usa la matriz base de Tarvia para la prioridad y el SLA. Los runbooks incluidos son ejemplos del prototipo.

### Componentes y estado

| Componente | Responsabilidad |
| --- | --- |
| `frontend/app.py` | Panel Streamlit para la cola, los expedientes, la revisión y los resultados. |
| `backend/main.py` | API FastAPI interna. Sirve la cola, ejecuta el triaje y recibe las decisiones. Compose arranca un único proceso que serializa las escrituras de la API. |
| `backend/triage/` | Orquestador, herramientas de consulta, trazas, detección de patrones de inyección y jueces. |
| `backend/policies/` | Semáforo, matriz de severidad, runbooks y tokens internos para la contención de la demo. |
| `backend/storage.py` | SQLite en un volumen de Docker. El expediente y su entrada de auditoría se guardan en una misma transacción. Repetir el triaje devuelve el expediente existente. |
| `data/` | Alertas y registros inventados del prototipo, lista de demo y políticas. |
| `tests/` | Pruebas del motor, las políticas y la API. |

Una consulta fallida o una respuesta inválida del juez quedan reflejadas en la traza y pueden dejar el caso pendiente de revisión. La contención se limita al simulador de los datos de ejemplo. Los indicadores, los logs y las respuestas del modelo se tratan como datos de entrada.

## Equipo

| Integrante | Responsabilidades |
| --- | --- |
| Mark Piazuelo | Presentación y comunicación del proyecto |
| Marc Sánchez | Infraestructura e IA nocturna |
| Arnau Paz | IA nocturna y desarrollo web |
| Marc Martí | Diseño del frontend |
| Sergi Mena | Coordinación general del proyecto |

## Dirección del proyecto

La primera vertical del equipo recorre **alerta → flags → enrutamiento → investigación → evidencias → informe → revisión humana**. El código recuperado implementa la investigación y la revisión con un orquestador central. El enrutamiento a agentes especializados y la automatización continua siguen en diseño.

| Línea del reporte inicial | Diseño previsto |
| --- | --- |
| Sistema multi-IA adaptativo | Agentes especializados y control de flujo por carga. Priorizar alertas críticas, investigar en profundidad con poca carga y reducir el esfuerzo por alerta en picos. |
| Flags automáticos | Detectar señales, clasificar eventos, derivarlos al agente correspondiente y activar consultas adicionales. |
| Sistema agéntico principal | Correlacionar registros y evidencias, explicar conclusiones, generar informes y proponer mitigaciones. |
| Agentes periodistas de ciberseguridad | Monitorizar vulnerabilidades y amenazas emergentes en fuentes de inteligencia, estructurar hallazgos y remitirlos al sistema principal. |
| Supervisión humana | Revisar alertas, flags e investigaciones, consultar informes, decidir sobre acciones sensibles y ver la carga del sistema. |
| Skills protegidas | Restringir las modificaciones a agentes de mantenimiento autorizados y conservar trazabilidad. Una skill no puede desactivar por sí sola los controles principales. |
| Auditoría y red teaming | Evaluar comportamiento, configuraciones, vulnerabilidades, autorización y aislamiento en un entorno controlado, con informes de hallazgos. |

El equipo y las responsabilidades están definidos. Quedan por concretar los contratos entre agentes, la adaptación por carga, la inteligencia externa y la auditoría independiente, después de validar la primera vertical con los datos del reto.

## Reto Deloitte y alcance de la demo

El enunciado oficial ofrece 11.061 alertas, 814.471 eventos, una muestra de desarrollo de 150 alertas, inventario, inteligencia, diez runbooks y una API simulada. La defensa exige mostrar visualmente la cola, la investigación, la recomendación y la intervención humana con el conjunto de alertas común que entregue la organización. Algunos indicadores del dataset son reales. El reto permite consultarlos en servicios de reputación y prohíbe visitarlos, descargarlos o escanearlos directamente. [Enunciado y datos de Tarvia](https://github.com/dttdfr/DTT-UAB-The-Hack/tree/5d7569232756eaf0a8723b22c428b70e8f67824f)

La matriz base y los SLA proceden de los apartados 2 y 3 de la política oficial. Faltan los ajustes por ejecución confirmada, privilegios, impacto y bloqueo preventivo, además de la selección de la entidad más crítica cuando hay varias. [Política operativa del SOC](https://github.com/dttdfr/DTT-UAB-The-Hack/blob/5d7569232756eaf0a8723b22c428b70e8f67824f/01_contexto/politica_soc.md)

Quedan pendientes la adaptación del conector HTTP a la API simulada oficial, los runbooks oficiales, la correlación temporal, el formato oficial de tickets y la validación con las alertas de defensa. El conector HTTP del ZIP queda en el código como plantilla. Compose utiliza exclusivamente los datos locales. [Contrato del simulador](https://github.com/dttdfr/DTT-UAB-The-Hack/blob/5d7569232756eaf0a8723b22c428b70e8f67824f/06_herramientas/LEEME_herramientas.md)
