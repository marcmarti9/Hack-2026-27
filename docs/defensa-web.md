# Defensa de Vigía en tres minutos

Deja abiertas las diapositivas y **Triaje**, con el índice listo y el JSONL oficial a mano. El recorrido se ensayó con el motor local. [Arranque reproducible](../apps/web/README.md#arranque-con-docker-compose) · [Lote oficial](https://github.com/dttdfr/DTT-UAB-The-Hack/blob/ea61e70a3c066ff7663c613475f180597d56bd06/03_alertas/demo_alertas_comunes.jsonl)

| Tiempo | Qué enseñar | Qué decir |
| --- | --- | --- |
| 0:00–0:25 | Vigía | «Tarvia recibe alertas incluso cuando el SOC está cerrado. Vigía prepara el expediente para que el analista pueda ver qué ocurrió, qué está probado y qué decisión le toca tomar.» |
| 0:25–1:00 | Qué decide Vigía | «El motor cruza los registros con el inventario y el calendario de cambios. La política del SOC determina el cierre o el escalado. Cada decisión conserva sus citas. Si las pruebas no alcanzan, el informe deja abierta la revisión.» |
| 1:00–1:55 | Cargar el JSONL oficial en Triaje | Pulsa **Ver resultados del lote**. «Son diez alertas. Tres se cierran con pruebas, seis escalan y una queda pendiente». Abre el pentest `ALR-20261008-011833` y señala los registros del WAF y el cambio aprobado. |
| 1:55–2:40 | Preransomware y decisión N2 | Abre `ALR-20261009-011791`. «La cronología enlaza ejecución, acceso a credenciales y comandos contra las copias. El caso crítico tiene un plazo de 15 minutos. Probamos el aislamiento de un puesto en el simulador con aprobación N2». |
| 2:40–3:00 | Barrido local | «En las 11.061 alertas de Tarvia, 8.806 cumplieron criterios de cierre. El lote del jurado concentra amenazas. Para medir el piloto, revisaremos los tiempos, la calidad de los cierres y qué sigue necesitando una decisión humana». |

En la mesa, pulsa **Cerradas por Vigía** para enseñar qué trabajo se ha resuelto sin intervención. Abre un informe y muestra el motivo, la cita original y la entrada **Cierre automático** en el historial. Después pulsa **Escaladas** y abre un crítico para mostrar qué decisión sigue en manos de N2.

Para practicar con una alerta sintética, abre **Datos de ensayo → Alerta nueva de ensayo**. En el informe, señala qué datos venían declarados por el sensor y qué registros recuperó Vigía. Si falta una prueba, muestra qué dato queda por confirmar. Si falla el servicio remoto, el expediente registra el fallo y conserva el análisis local.

En el barrido de esta entrega se generaron 11.061 expedientes sin errores de procesamiento. Hubo 8.806 cierres elegibles, 281 escalados y 1.237 abstenciones por falta de evidencia. La mediana fue de 39 ms por expediente y el p95 de 115 ms con cuatro trabajadores en Docker. El barrido mide cobertura de procesamiento y tiempos del motor local. [Arquitectura y verificación](arquitectura-vigia.md#verificación-y-defensa)

Si preguntan cómo se actualiza Vigía, señala **Inteligencia** en el Panel y abre el expediente de Jenkins `ALR-20261006-011825` después de analizarlo. El informe separa la prueba local de la coincidencia `CVE-2024-23897` en el catálogo de CISA. El recolector actualiza las fuentes cada hora y la política SOC sigue gobernando el escalado.

Si preguntan qué aporta Vigía, abre una cita y enseña el vínculo entre dato, hallazgo y decisión. En un caso sin respaldo suficiente, muestra la pregunta abierta. En un crítico, enseña el escalado y el responsable. Los tres comportamientos se pueden comprobar en la misma web.

## Lote oficial del jurado

El JSONL original produjo 10 expedientes en 0,9 s de servidor con el motor local. Los cierres fueron el pentest autorizado, el inventario SCCM y el falso positivo de túnel DNS. Se escalaron seis amenazas. En «Viaje imposible» el primer registro que corroboraba el historial del móvil era posterior al aviso, por lo que quedó pendiente de revisión. El correo con instrucciones ocultas también se escaló y el expediente cita el mensaje original. [Archivo oficial](https://github.com/dttdfr/DTT-UAB-The-Hack/blob/ea61e70a3c066ff7663c613475f180597d56bd06/03_alertas/demo_alertas_comunes.jsonl)

## Ensayo previo con diez alertas

Se cargaron desde Chromium ocho alertas del dataset con etiqueta previa y dos variantes sintéticas de LSASS. En 0,9 s de trabajo del servidor local, la mesa generó diez expedientes con los veredictos esperados, dos cierres registrados y ocho escalados. Dos escalados se mantuvieron como abstenciones, uno por falta de prueba sobre el contenido de un archivo y otro por un registro de LSASS fuera de la ventana. La muestra comprueba regresiones concretas de casos conocidos.

| Resultado | IDs de ensayo |
| --- | --- |
| Falso positivo y cierre | `ALR-20261005-000099` |
| Positivo benigno y cierre | `ALR-20261007-001090` |
| Positivo y escalado | `ALR-20261007-011785`, `ALR-20261011-011877`, `ALR-20261018-005422`, `ALR-20261016-011821`, `ALR-20261006-011826`, `ALR-20261010-990901` |
| Abstención y escalado | `ALR-20261007-001237`, `ALR-20261101-990902` |

Para repetir, usa los registros originales del JSONL oficial y añade las dos alertas `990901` y `990902` del lote de presentación. Importa en modo **Guardia** con el contraste remoto desactivado. El caso VPN `011877` confirma acceso al túnel fuera de la ventana y tráfico permitido hacia WMS01. El caso de comercio `005422` muestra intentos limitados. El expediente mantiene abierta la comprobación de accesos posteriores. [Etiquetas de desarrollo](../eval/etiquetas.csv) · [Variantes sintéticas](../eval/lote-presentacion-091.jsonl)

En un segundo recorrido abrimos la alerta oficial de LSASS, aprobamos el aislamiento de `WS-BCN-1770` como N2 y recargamos el expediente. El simulador registró una sola ejecución y el segundo intento se rechazó. Para enseñarlo durante la defensa, prepara el simulador en la máquina del jurado y comprueba la ruta antes de empezar. [Configuración](../apps/web/README.md#aislamiento-en-el-simulador)

## Ensayos históricos con contraste remoto

La alerta sintética `ALR-20261010-990901` terminó en 43,9 s de trabajo web. Luna tardó 12,2 s y Sol 19,0 s. Luna propuso un positivo y Sol pidió más información. El veredicto verificable quedó como verdadero positivo crítico con escalado a N2. La discrepancia y la cita `EDR-0123412` quedaron en el expediente. Esta medición corresponde a una alerta.

Se cargaron dos alertas sintéticas desde el selector de archivos. La primera se corroboró con `EDR-0123412`. La segunda referenciaba un registro ausente y quedó como crítica sin corroborar, con escalado a N2. La asignación y los dos expedientes siguieron disponibles al recargar. En una prueba remota de la segunda alerta, Luna y Sol devolvieron una hipótesis provisional en un trabajo de 19,7 s. La mesa conservó el resultado sin corroborar.
