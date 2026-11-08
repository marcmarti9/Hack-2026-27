# Defensa web de Vigía

Abre **Parte de guardia → Recorrido para el jurado**. Usa la web para toda la defensa. Antes de empezar, comprueba que **Analizar en directo** muestra OpenAI disponible y que **Casos** abre el expediente de LSASS.

| Tiempo | Qué enseñar | Qué decir |
| --- | --- | --- |
| 0:00–0:30 | Parte de guardia y embudo del SIEM | «El SOC de Tarvia tiene horario. Las alertas llegan durante todo el día. Vigía prepara el expediente, la evidencia y el siguiente paso para cada una.» |
| 0:30–1:10 | SCCM, registro citado y cambio autorizado | «Esto parece una ejecución sospechosa. Al cruzar el registro con el cambio aprobado, Vigía puede dejar un cierre trazable y ahorrarle esa revisión al analista.» |
| 1:10–2:10 | LSASS, cronología y alcance N2 | «Aquí las alertas aisladas cambian de sentido al relacionarlas. La cadena muestra acceso a credenciales, movimiento lateral y señales contra las copias. El expediente indica lo que se observó y qué falta por confirmar.» |
| 2:10–3:40 | Analizar en directo con una alerta del jurado | «La alerta acaba de llegar. Vigía recupera los registros, solicita una propuesta a Luna, la contrasta según el riesgo y verifica las citas. En el expediente podemos abrir el registro original y comprobar por qué escaló.» |
| 3:40–4:00 | Relevo, responsables y plazo | «El caso crítico llega a N2 con pruebas, plazo y una acción propuesta. Las decisiones quedan en el historial. Eso es lo que mantiene la guardia operativa.» |

Si aún no tenéis la alerta del jurado, pulsa **Alerta nueva de ensayo**. Es una entrada sintética vinculada a un registro verificable de Tarvia. Si el servicio remoto falla durante la defensa, el expediente muestra el fallo y conserva el análisis local. Explica el estado visible y abre la evidencia que recuperó el motor.

En el barrido offline de Vigía 0.9.1 se generaron 11.061 expedientes sin errores de procesamiento. Hubo 8.806 cierres elegibles, 221 escalados y 1.237 alertas sin veredicto por falta de evidencia. El barrido mide cobertura de procesamiento y tiempos del motor local. Las cifras de rendimiento de OpenAI se miden en el ensayo en directo. [Resultados y metodología](revision-adversarial.md#entrega-de-presentación-091)

Si preguntan qué aporta Vigía, abre una cita y enseña el vínculo entre dato, hallazgo y decisión. En un caso sin respaldo suficiente, muestra la pregunta abierta. En un crítico, enseña el escalado y el responsable. Los tres comportamientos se pueden comprobar en la misma web.

## Ensayo real en Chromium

La alerta sintética `ALR-20261010-990901` terminó en 43,9 s de trabajo web. Luna tardó 12,2 s y Sol 19,0 s. Luna propuso un positivo y Sol pidió más información. El veredicto verificable quedó como verdadero positivo crítico con escalado a N2. La discrepancia y la cita `EDR-0123412` quedaron en el expediente. Esta medición corresponde a una alerta.
