# Guía de Vigía web

Abre [Vigía](http://127.0.0.1:8100/#panel). El menú lateral se puede plegar. Los iconos **?** explican los controles al pasar el ratón, con el teclado o al tocarlos.

| Sección | Qué puedes ver o hacer |
| --- | --- |
| **Panel** | Cifras del SIEM y de la mesa, casos graves escalados, escenarios para el DPO y alertas fuera de horario. **Inteligencia** muestra cuándo se consultó con éxito cada fuente pública. También enlaza al relevo y al recorrido del jurado. |
| **Triaje** | Carga un JSON o JSONL, pega IDs o usa el lote de ensayo. Elige el turno y, si está disponible, el contraste de Vigía. Al terminar, pulsa **Ver resultados del lote**. La cola guarda cada informe, permite buscar por ID, nombre o archivo y filtrar por escalado o autocierre. Las nuevas entradas aparecen primero por orden de importación. **Hora de la alerta** muestra el momento del aviso original. |
| **Casos** | Expedientes con prioridad, veredicto, decisión e historial. Una intrusión acreditada aparece como un caso. Puedes buscar por ID para recuperar el expediente individual de una alerta. |
| **Descartes** | Alertas del barrido local elegibles para cierre, agrupadas por motivo. Los ejemplos llevan a expedientes con sus citas. Los cierres registrados en la mesa se consultan en Triaje. |
| **Playbooks** | Los diez runbooks del SOC, con reglas, comprobaciones, decisiones y ejemplos. Abre el texto operativo completo y su revisión, o selecciona **Guía general** para consultar la SKILL. N1 lee y N2 o Responsable pueden guardar una revisión en esta mesa. |
| **Mapa** | Reproducción horaria del escenario de Tarvia. Usa el deslizador para elegir una hora y consulta las zonas y los casos señalados. |
| **Chat** | Preguntas sobre los registros de Tarvia. La respuesta muestra los identificadores de los eventos recuperados. |
| **Relevo** | Investigación del turno de guardia, cierres, revisiones y escalados con responsables y plazos. Se abre desde Panel. |

En un **expediente**, empieza por la decisión. Abre la cronología, los hallazgos y el contraste para comprobar cómo se llegó al veredicto. Las citas de la IA y los registros verificados aparecen diferenciados. Una coincidencia de inteligencia pública aporta contexto de exposición. Para corregir un veredicto se guarda un motivo. La acción de aislamiento del recorrido LSASS requiere aprobación N2 en el simulador de práctica.

[Arranque con Docker](../apps/web/README.md) · [Guion de defensa](defensa-web.md) · [Arquitectura](arquitectura-vigia.md)
