# Defensa web de Vigía

Arranca Vigía y espera a que el índice esté listo. Abre **Parte de guardia → Recorrido para el jurado**. Antes de empezar, comprueba que **Analizar en directo** abre la mesa y que **Casos** abre el expediente de LSASS. Si vas a enseñar la revisión remota, confirma que OpenAI está disponible. [Arranque reproducible de la web](../apps/web/README.md#arranque-con-docker-compose)

| Tiempo | Qué enseñar | Qué decir |
| --- | --- | --- |
| 0:00–0:30 | Parte de guardia y embudo del SIEM | «El SOC de Tarvia tiene horario. Las alertas llegan durante todo el día. Vigía prepara el expediente, la evidencia y el siguiente paso para cada una.» |
| 0:30–1:10 | SCCM, registro citado y cambio autorizado | «Esto parece una ejecución sospechosa. Al cruzar el registro con el cambio aprobado, Vigía puede dejar un cierre trazable y ahorrarle esa revisión al analista.» |
| 1:10–2:10 | LSASS, cronología y alcance N2 | «Aquí las alertas aisladas cambian de sentido al relacionarlas. La cadena muestra acceso a credenciales, movimiento lateral y señales contra las copias. El expediente indica lo que se observó y qué falta por confirmar.» |
| 2:10–3:40 | Subir el JSONL del jurado y desplegar una fila en Analizar en directo | «Este lote acaba de llegar. En la mesa se ve qué alerta está en curso y qué decidió el motor al terminar. El informe muestra las consultas, la propuesta, el contraste cuando se usa OpenAI y las citas que respaldan el resultado.» |
| 3:40–4:00 | Relevo, responsables y plazo | «El caso crítico llega a N2 con pruebas, plazo y una acción propuesta. Las decisiones quedan en el historial. Eso es lo que mantiene la guardia operativa.» |

En la mesa, pulsa **Cerradas por Vigía** para enseñar qué trabajo se ha resuelto sin intervención. Abre un informe y muestra el motivo, la cita original y la entrada **Cierre automático** en el historial. Después pulsa **Escaladas** y abre un crítico para mostrar qué decisión sigue en manos de N2.

Si aún no tenéis el JSONL del jurado, pulsa **Alerta nueva de ensayo**. Es una entrada sintética vinculada a un registro verificable de Tarvia. En el informe, señala qué datos venían declarados por el sensor y qué registros recuperó Vigía. Si falta una prueba, muestra qué dato queda por confirmar. Si falla el servicio remoto, el expediente registra el fallo y conserva el análisis local.

En el barrido offline de Vigía 0.9.1 se generaron 11.061 expedientes sin errores de procesamiento. Hubo 8.806 cierres elegibles, 221 escalados y 1.237 alertas sin veredicto por falta de evidencia. El barrido mide cobertura de procesamiento y tiempos del motor local. Las cifras de rendimiento de OpenAI se miden en el ensayo en directo. [Resultados y metodología](revision-adversarial.md#entrega-de-presentación-091)

Si preguntan qué aporta Vigía, abre una cita y enseña el vínculo entre dato, hallazgo y decisión. En un caso sin respaldo suficiente, muestra la pregunta abierta. En un crítico, enseña el escalado y el responsable. Los tres comportamientos se pueden comprobar en la misma web.

## Ensayo real en Chromium

La alerta sintética `ALR-20261010-990901` terminó en 43,9 s de trabajo web. Luna tardó 12,2 s y Sol 19,0 s. Luna propuso un positivo y Sol pidió más información. El veredicto verificable quedó como verdadero positivo crítico con escalado a N2. La discrepancia y la cita `EDR-0123412` quedaron en el expediente. Esta medición corresponde a una alerta.

## Ensayo de la mesa de alertas nuevas

Se cargaron dos alertas sintéticas desde el selector de archivos. La primera se corroboró con `EDR-0123412`. La segunda referenciaba un registro ausente y quedó como crítica sin corroborar, con escalado a N2. La asignación y los dos expedientes siguieron disponibles al recargar. En una prueba remota de la segunda alerta, Luna y Sol devolvieron una hipótesis provisional en un trabajo de 19,7 s. La mesa conservó el resultado sin corroborar.
