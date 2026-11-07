# Marc's & Co. — Reporte de equipo #1

**Evento:** UAB The Hack 2026  
**Proyecto:** Sistema SOC multiagente adaptativo  
**Estado:** Arquitectura conceptual definida — Inicio del desarrollo

## 1. Organización del equipo

| Integrante | Responsabilidades |
|---|---|
| Mark Piazuelo | Presentación y comunicación del proyecto |
| Marc Sánchez | Infraestructura e IA nocturna |
| Arnau Paz | IA nocturna y desarrollo web |
| Marc Martí | Diseño del frontend |
| Sergi Mena | Coordinación general del proyecto |

## 2. Visión del proyecto

Desarrollar un sistema autónomo de operaciones de ciberseguridad basado en una **arquitectura modular multi-IA**, capaz de analizar alertas, identificar amenazas, consultar inteligencia externa y proponer acciones correctivas, manteniendo siempre la supervisión humana.

El sistema tendrá capacidad para adaptar su consumo computacional a la carga del servidor, priorizando la velocidad y disponibilidad cuando aumente la demanda.

## 3. Componentes de la arquitectura

### A. Sistema multi-IA con control de flujo adaptativo

- Arquitectura modular compuesta por agentes especializados.
- Sistema de control de flujo basado en la carga del servidor.
- Con poca carga: investigaciones más profundas y especializadas.
- Con mucha carga: modelos o procesos más rápidos, con menor profundidad de análisis.
- Priorización automática de alertas críticas.

**Objetivo:** mantener la capacidad de respuesta ante picos de actividad.

### B. Sistema automático de flags

- Detección y clasificación automática de eventos sospechosos.
- Generación de flags según características de las alertas.
- Priorización y derivación de eventos al agente correspondiente.
- Activación de investigaciones adicionales cuando sea necesario.

### C. Sistema agéntico principal

- Análisis de alertas, registros y evidencias.
- Correlación de información entre distintas fuentes.
- Generación de reportes de seguridad.
- Propuesta de acciones de mitigación y respuesta.
- Presentación de conclusiones justificadas para revisión humana.

### D. Agentes periodistas de ciberseguridad

Sistema paralelo de agentes dedicado a consultar fuentes externas de noticias y vulnerabilidades.

Funciones:

- Monitorizar fuentes relevantes de inteligencia de amenazas.
- Identificar vulnerabilidades y amenazas emergentes.
- Generar informes estructurados.
- Enviar los hallazgos al sistema principal para evaluar su relevancia en el entorno protegido.

### E. Frontend de supervisión humana

Interfaz web desde la que los operadores podrán:

- Monitorizar el estado del sistema multiagente.
- Visualizar alertas, flags e investigaciones.
- Consultar informes y evidencias.
- Supervisar decisiones de los agentes.
- Revisar y autorizar acciones sensibles.
- Consultar el estado de carga y funcionamiento del sistema.

### F. Skills protegidas y actualizables

Los agentes utilizarán parcialmente habilidades especializadas (*skills*) para realizar tareas concretas.

- Las modificaciones estarán restringidas a agentes autorizados específicamente para su mantenimiento.
- Se establecerán controles para evitar modificaciones malintencionadas.
- Las actualizaciones deberán ser trazables y verificables.

**Requisito de seguridad:** ninguna skill podrá desactivar unilateralmente los controles principales del sistema.

### G. Agente de auditoría y red teaming

Agente independiente encargado de evaluar la seguridad de la propia arquitectura.

Funciones:

- Revisar el comportamiento de los agentes.
- Detectar configuraciones incorrectas.
- Identificar posibles vulnerabilidades del sistema.
- Buscar fallos de autorización o aislamiento.
- Generar informes de debilidades y recomendaciones.

Las pruebas deberán realizarse en un entorno controlado.

## 4. Ventajas competitivas

**Adaptabilidad:** ajuste dinámico del esfuerzo computacional según carga.

**Especialización:** distintos agentes para tareas concretas.

**Inteligencia proactiva:** detección de amenazas emergentes mediante fuentes externas.

**Seguridad interna:** auditoría continua y control de las capacidades de los agentes.

**Human-in-the-loop:** supervisión y autorización humana de acciones críticas.

**Explicabilidad:** informes con evidencias y recomendaciones verificables.

## 5. Estado actual

- [x] Equipo y responsabilidades definidos.
- [x] Arquitectura general consensuada.
- [x] Concepto de IA adaptativa definido.
- [x] Subsistemas principales identificados.
- [ ] Contratos de comunicación entre agentes.
- [ ] Implementación del pipeline de alertas.
- [ ] Integración de herramientas y fuentes de datos.
- [ ] Prototipo funcional del frontend.
- [ ] Validación y pruebas integradas.
- [ ] Preparación de la demo final.

## 6. Próximo objetivo

**Conseguir un flujo completo de investigación funcional:**

Alerta → Flags → Enrutamiento → Agente investigador → Evidencias → Informe → Revisión humana.

Una vez operativo, integrar la adaptación por carga, la inteligencia externa y la auditoría de seguridad.
