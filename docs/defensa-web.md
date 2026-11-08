# Defensa web de Vigía

Arranca Vigía y espera a que el índice esté listo. Abre **Panel → Recorrido para el jurado**. Antes de empezar, comprueba que **Triaje** abre la mesa y que **Casos** abre el expediente de LSASS. Si vas a enseñar la revisión remota, comprueba que puedes activar **Contraste de Vigía**. [Arranque reproducible de la web](../apps/web/README.md#arranque-con-docker-compose)

| Tiempo | Qué enseñar | Qué decir |
| --- | --- | --- |
| 0:00–0:30 | Panel y cifras del SIEM | «El SOC de Tarvia tiene horario. Las alertas llegan durante todo el día. Vigía prepara el expediente, la evidencia y el siguiente paso para cada una.» |
| 0:30–1:10 | SCCM, registro citado y cambio autorizado | «Esto parece una ejecución sospechosa. Al cruzar el registro con el cambio aprobado, Vigía puede dejar un cierre trazable y ahorrarle esa revisión al analista.» |
| 1:10–2:10 | LSASS, cronología y alcance N2 | «Aquí las alertas aisladas cambian de sentido al relacionarlas. La cadena muestra acceso a credenciales, movimiento lateral y señales contra las copias. El expediente indica lo que se observó y qué falta por confirmar.» |
| 2:10–3:40 | Subir el JSONL del jurado y desplegar una fila en Triaje | «Este lote acaba de llegar. En la mesa se ve qué alerta está en curso y qué decidió el motor al terminar. El informe muestra las consultas, la propuesta, el contraste de Vigía cuando se activa y las citas que respaldan el resultado.» |
| 3:40–4:00 | Relevo, responsables y plazo | «El caso crítico llega a N2 con pruebas, plazo y una acción propuesta. Las decisiones quedan en el historial. Eso es lo que mantiene la guardia operativa.» |

En la mesa, pulsa **Cerradas por Vigía** para enseñar qué trabajo se ha resuelto sin intervención. Abre un informe y muestra el motivo, la cita original y la entrada **Cierre automático** en el historial. Después pulsa **Escaladas** y abre un crítico para mostrar qué decisión sigue en manos de N2.

Si aún no tenéis el JSONL del jurado, pulsa **Alerta nueva de ensayo**. Es una entrada sintética vinculada a un registro verificable de Tarvia. En el informe, señala qué datos venían declarados por el sensor y qué registros recuperó Vigía. Si falta una prueba, muestra qué dato queda por confirmar. Si falla el servicio remoto, el expediente registra el fallo y conserva el análisis local.

En el barrido de esta entrega se generaron 11.061 expedientes sin errores de procesamiento. Hubo 8.806 cierres elegibles, 281 escalados y 1.237 abstenciones por falta de evidencia. La mediana fue de 35 ms por expediente y el p95 de 103 ms con cuatro trabajadores en Docker. El barrido mide cobertura de procesamiento y tiempos del motor local. [Arquitectura y verificación](arquitectura-vigia.md#verificación-y-defensa)

Si preguntan cómo se actualiza Vigía, señala **Inteligencia** en el Panel y abre el expediente de Jenkins `ALR-20261006-011825` después de analizarlo. El informe separa la prueba local de la coincidencia `CVE-2024-23897` en el catálogo de CISA. El recolector actualiza las fuentes cada hora y la política SOC sigue gobernando el escalado.

Si preguntan qué aporta Vigía, abre una cita y enseña el vínculo entre dato, hallazgo y decisión. En un caso sin respaldo suficiente, muestra la pregunta abierta. En un crítico, enseña el escalado y el responsable. Los tres comportamientos se pueden comprobar en la misma web.

## Ensayo real en Chromium

La alerta sintética `ALR-20261010-990901` terminó en 43,9 s de trabajo web. Luna tardó 12,2 s y Sol 19,0 s. Luna propuso un positivo y Sol pidió más información. El veredicto verificable quedó como verdadero positivo crítico con escalado a N2. La discrepancia y la cita `EDR-0123412` quedaron en el expediente. Esta medición corresponde a una alerta.

## Ensayo de la mesa de alertas nuevas

Se cargaron dos alertas sintéticas desde el selector de archivos. La primera se corroboró con `EDR-0123412`. La segunda referenciaba un registro ausente y quedó como crítica sin corroborar, con escalado a N2. La asignación y los dos expedientes siguieron disponibles al recargar. En una prueba remota de la segunda alerta, Luna y Sol devolvieron una hipótesis provisional en un trabajo de 19,7 s. La mesa conservó el resultado sin corroborar.
