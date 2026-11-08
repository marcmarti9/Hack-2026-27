# Vigía para el comité de Tarvia

**Decisión propuesta.** Ensayar Vigía como analista N1 del SOC de Tarvia. El equipo revisa las excepciones, confirma las decisiones de impacto y puede corregir un cierre si aparece nueva evidencia.

**Qué trabajo asume Vigía.** Cada alerta genera un expediente con veredicto o abstención, severidad, registros, consultas y siguiente paso. Los cierres de rutina exigen evidencia verificable. En guardia se prepara el relevo con plazos y responsables. Una alerta crítica queda escalada en la mesa en cuanto termina el triaje, con un SLA de 15 minutos para N2 de guardia.

**Qué hemos demostrado.** Nivel 1 en el lote de ensayo de diez alertas. Nivel 2 en cambios autorizados e incidentes con vínculo acreditado. Nivel 3 en preransomware, con once hitos reconstruidos, 27 registros citados y tres equipos. Nivel 4 para el aislamiento de un puesto en la API simulada, con confirmación, clave de práctica N2 y un resultado en el historial. Las acciones sobre OT se escalan.

**Qué medimos.** El barrido local produjo 11.061 expedientes, 281 escalados, 1.237 abstenciones y 8.806 cierres elegibles. Los cierres registrados se cuentan por separado. La muestra de diez entradas comprueba casos ya conocidos. El piloto con alertas nuevas debe medir errores de cierre, decisiones humanas y latencia por etapa.

**Límite del piloto.** Los resultados corresponden al entorno ficticio de Tarvia. En preransomware quedan por confirmar la extracción de credenciales y el cifrado. La comprobación con las diez alertas inéditas queda para la defensa.

[Guion y ensayo web](defensa-web.md) · [Arquitectura](arquitectura-vigia.md) · [Enunciado oficial](https://github.com/dttdfr/DTT-UAB-The-Hack/blob/5d7569232756eaf0a8723b22c428b70e8f67824f/README.md)
