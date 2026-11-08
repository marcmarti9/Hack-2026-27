# Vigía para el comité de Tarvia

**Decisión propuesta.** Ensayar Vigía como analista N1 asistido sobre el entorno ficticio de Tarvia. Validar el piloto con alertas nuevas y medir cuántos casos llegan a la persona con una decisión preparada.

**Qué trabajo asume Vigía.** Reúne la alerta, los registros y el contexto de inventario. Presenta la severidad, las evidencias, la propuesta, las dudas y la acción recomendada en un mismo expediente. Un analista interviene cuando hay indicios de compromiso, falta evidencia o la decisión afecta a sistemas o negocio.

**Qué pasa durante la guardia.** Un caso crítico sigue siendo prioritario. Vigía prepara el expediente y el aviso para N2 de guardia, responsable SOC y CISO. El relevo reúne los casos que requieren decisión, con prioridad y plazo. La demostración permite un aislamiento en el simulador tras aprobación de N2. Las acciones disruptivas quedan sujetas a autorización humana. Las decisiones sobre OT se escalan.

**Cómo evaluarlo.** Triar en directo las diez alertas comunes y abrir dos expedientes con resultados distintos. Registrar tiempo por etapa, alertas procesadas y pendientes, escalados, cierres incorrectos en casos etiquetados y decisiones humanas. Separar las cifras archivadas de las obtenidas en el ensayo. La referencia de 15 minutos por alerta procede de la presentación y es ilustrativa.

**Alcance.** El piloto usa los datos de Tarvia. El nivel de triaje que se declara depende de las pruebas de la versión que se presenta. La demostración y cualquier acción aprobada usan exclusivamente el entorno del reto. [Revisión, evidencia y límites](revision-adversarial.md)

## Antes de presentar

- Instala Vigía en la máquina que se usará ante el jurado. Abre **Vigía · Práctica**, entra con el botón de práctica y carga la carpeta raíz del dataset oficial. Espera a que la cola muestre las 11.061 alertas y deja abierto el índice.
- Prepara un lote de ensayo JSONL y deja abierto el selector **Guardia**. El importador visual admite hasta diez IDs que existan en el índice o alertas nuevas completas. El comando de corpus admite lotes mayores y genera un expediente por entrada.
- Si vas a enseñar contención, arranca el simulador oficial local antes de la exposición y comprueba que el puesto de práctica tiene el botón de aprobación disponible. El flujo registra quién aprobó y el resultado de la acción. [Configuración y ejecución](../README.md#respuesta-en-el-simulador-oficial)

## Recorrido de cuatro minutos

| Tiempo | Qué enseñar | Qué contar |
| --- | --- | --- |
| 0:00–0:30 | Inicio y estado del SOC. | Vigía toma la cola N1, consulta las fuentes de Tarvia y prepara el expediente y el siguiente paso. |
| 0:30–1:15 | Caso SCCM `ALR-20261005-000301`, triaje local, evidencia e historial. | El inventario, el comando y el cambio aprobado justifican un cierre rutinario. Se registra el criterio y el analista puede corregirlo. |
| 1:15–2:30 | LSASS `ALR-20261010-011795`, Línea de tiempo y Acciones. | El mismo incidente vincula nueve alertas, 11 fases, 27 registros y tres equipos. Hay ejecución, movimiento lateral y comandos contra copias. El efecto sobre las copias y el cifrado están por confirmar. |
| 2:30–3:10 | Relevo de guardia y, si está preparado, aislamiento simulado. | El crítico conserva 15 minutos y deriva a N2, responsable SOC y CISO. La contención del puesto se ejecuta en el simulador tras aprobación N2. |
| 3:10–4:00 | Cargar lote de defensa y abrir una alerta inédita. | Mostrar en directo el resultado y las consultas. Si la evidencia no alcanza, abrir las preguntas del expediente y explicar qué falta para decidir. |

## Qué cifras defender

El barrido acredita expedientes generados, cierres elegibles, abstenciones, escalados y tiempos del motor offline. La muestra revisada sirve para comprobar regresiones concretas. Para estimar precisión general se necesita un conjunto etiquetado independiente. El lote real del jurado se valida al recibirlo. Conviene distinguir el resultado local calculado de las hipótesis del modelo y de los expedientes históricos de la práctica. [Enunciado oficial](https://github.com/dttdfr/DTT-UAB-The-Hack) · [Resultados y límites de la versión](revision-adversarial.md)
