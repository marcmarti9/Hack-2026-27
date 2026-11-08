# Contexto compartido de Vigía

Resumen de lo que el equipo ha descubierto y decidido sobre el reto. Sirve para que cualquier persona o IA que trabaje en el
repositorio parta del mismo punto. Las cifras de filtrado, grupos y caza de esta nota describen el prototipo del equipo y su archivo de referencia. Para la versión actual, consulta la [arquitectura](arquitectura-vigia.md). El código vigente está en
`apps/` y el estado de cada trabajo, en [EPIC.md](../EPIC.md).

Las guías de la etapa inicial están en la [revisión histórica del repositorio](https://github.com/marcmarti9/Hack-2026-27/tree/d6e83a6).

## 1. El reto y la idea

- UAB THE HACK! 2026, reto de Deloitte Cyber: un analista SOC N1 con agentes de IA para Tarvia, retailer ficticio de Barcelona. Equipo de 5 y 32 horas frente a 18 equipos.
- El problema: unas 4.000 alertas al día, 3 analistas N1 y un SOC abierto de lunes a viernes de 8:00 a 20:00. Fuera de horario solo hay un N2 de guardia por teléfono.
- Vigía es **el SOC que no se apaga**. De día entrega cada alerta ya investigada y de noche hace la guardia. Lema: **la IA investiga, la persona decide**.
- Dato gancho: el **62,1 %** de las alertas que llegan a la IA (tras el filtro) saltó fuera de horario, frente al 31,7 % del total. Frase: "Los atacantes de Tarvia trabajan cuando el SOC duerme".
- Formatos de referencia opcionales: `01_contexto/ticket_salida.schema.json` (ticket N1) e `informe_incidente.schema.json` (informe N2, fase 2).

## 2. Cifras medidas

| Medida | Valor |
| --- | --- |
| Eventos de log (18 fuentes) | 814.471 |
| Entidades extraídas de los logs | 2.467.451 |
| Alertas | 11.061 (del 5/10 al 1/11/2026) |
| Cerradas por un motor de reglas explicable | 10.974 |
| Restantes para la IA | 87 |
| Casos tras agrupar por entidades poco comunes (≤ 10 días) | 17 |
| Alertas con intento de manipular a la IA | 18, todas en escenarios reales, sin falsas alarmas |
| Hallazgos de caza sin alerta propia | 5 |

Ruido principal: UC-WEB-001 (3.406 escaneos bloqueados), UC-EML-001 (2.295 reportes; la mayoría newsletters legítimas o spam sin clics), UC-EDR-002 (1.349 alertas de SCCM, CHG-2026-1031), UC-IDP-001 (901), UC-NET-001 (746), UC-NET-005 (561 CDN), UC-EDR-001 (532 Excel > saplogon firmado), UC-AI-001 (unas 413 correcciones de clientes; solo 2 inyecciones reales) y UC-EDR-003 (411 PUA bloqueadas).

## 3. Los 12 incidentes del dataset

| # | Incidente | Fechas | Cadena |
| --- | --- | --- | --- |
| 1 | AiTM y fraude de IBAN | 7-8/10 | Sesión de laura.ferrer2 robada desde hosting > regla de buzón que oculta "Montroig/IBAN" > petición de 148.320 € a Lituania (jordi.serra2) |
| 2 | Latrodectus hasta el preransomware | 9-18/10 | Adjunto .js a marta.puig (WS-BCN-1770) > C2 aplihartom.com > Cobalt Strike > LSASS (adm.aortega) > PsExec a FS01 > borrado de shadow copies (bloqueado) > PRINT01 > svc_print_upd en Domain Admins y EDR detenido |
| 3 | Minero | 6/10 | JENKINS-DEV01 expuesto con CVE-2024-23897 > XMRig |
| 4 | Cadena de suministro hasta el CRM | 13-16/10 | tarvia-checkout-utils del registro público lee las claves AWS > uso desde Kali > usuario backup-sync con permisos de administrador > ~112 GB de copias del CRM |
| 5 | Credential stuffing | 10-11/10 | 26 accesos correctos > 12 tomas de cuenta con tarjetas regalo |
| 6 | Proveedor comprometido | 11-29/10 | ext.logisoft desde 77.90.185.20 > wmsupd.exe sin firma en WMS01 (sin alerta propia) > sqlcmd sobre envíos > túnel DNS cdn-wms-metrics |
| 7 | Tienda 7 | 12-21/10 | AnyDesk con control desde Marruecos en LT-T07-02 > RAM scraper possvc.exe en 3 TPV ("instalado por Seguridad", SEC-2210 inexistente) |
| 8 | Insider | 14-15/10 | núria.vidal, que deja la empresa el 16/10: backup_clientes_oct.7z cifrado a mega.nz y 41.200 correos de clientes a su cuenta personal |
| 9 | Cuenta de servicio | 13/10 | Password spraying desde Tor > svc_backup (sin MFA) entra por VPN |
| 10 | Fatiga MFA | 10/10 | 27 notificaciones push a sergio.navarro |
| 11 | Vela | 8/10 | Inyección y revelación de códigos internos de descuento |
| 12 | Phishing packaging-iberia | 20/10 | 45 correos con texto oculto dirigido al clasificador automático; AiTM de lucia.castro |

**Trampas autorizadas** (benignas): pentest del 8 al 10/10 desde 192.0.2.10-12, NESSUS01 los miércoles de 1 a 5, CHG-1057 (PsExec desde JUMP01), CHG-1063 (mantenimiento OT), CHG-1078 (Backup Operators), CHG-1080 (paradas del EDR), CHG-1071 (Logisoft fuera de horario), nóminas a gestoria-pons (FLUJO-0007), viaje de ricard.castells a Nueva York, ENG-WS01 hacia OT, y los paquetes npm puppeteer, sharp y esbuild. Tor, los proxies residenciales y las VPN comerciales son sospechosos, pero no maliciosos por sí mismos.

**Para las alertas en directo:** la sandbox tiene informes de ficheros que no aparecen en los logs: el instalador npp con Lumma Stealer, la web shell cache_helper.php (WEB-ECOM03 tiene pagebuilder-lite vulnerable desde el 15/10) y Actualizacion_nomina_octubre.pdf con QR. Conviene ensayar con alertas sintéticas de esos casos.

## 4. Decisiones de diseño

- **4 agentes de IA y 4 guardarraíles deterministas.** Agentes: investigador N1, fiscal (intenta refutar), N2 (informe) y chat. Guardarraíles: motor de reglas, escudo anti-manipulación, agrupador y cazador.
- **La severidad la calcula la matriz** de `politica_soc.md`. La IA solo propone un ajuste de ±1 con su motivo.
- **Toda prueba citada se comprueba en los logs.** Si no existe, se descarta y la confianza baja.
- **El texto que escribe el atacante es dato, nunca instrucción.** Si intenta manipular a la IA, eso cuenta como prueba contra él.
- **Contenciones según la política.** El rol N1 no aprueba lo que requiere N2, nunca se actúa sobre OT, y aislar, deshabilitar, revocar o desactivar claves necesita token de aprobación de la API simulada.
- **El motor solo cierra casos 100 % claros.** Sus reglas se ajustaron mirando este dataset, y así hay que decirlo ante el jurado.
- **Enriquecimiento CVE** con CISA KEV y EPSS, con caché local. Algunas CVE del dataset parecen inventadas.

## 5. Brief visual: que no parezca un SIEM

Vigía enseña casos ya investigados y decisiones, no listas de alertas.

- Pantallas: parte de guardia (texto de turno, embudo 11.061 > 17, reloj RGPD de 72 h), casos con títulos en lenguaje normal, expediente (razonamiento, pruebas clicables, línea de tiempo, fiscal y aprobación con su impacto), mapa de Tarvia por zonas con "SOC cerrado" de noche y flechas del atacante, lo descartado con su motivo, y chat.
- Estilo: un solo color de marca. Rojo, naranja y amarillo solo para la severidad.
- Evitar: tablas largas de alertas como pantalla principal, JSON a la vista, mapas de calor, gráficos de tarta y efectos "hacker".
- Prueba de los 5 segundos: si alguien dice "son alertas", hay que rehacer la pantalla. Si dice "ya está resuelto y me pide decidir", está bien.

## 6. Prototipo web con Claude (`apps/web/`)

Prototipo web completo construido con la guía técnica: FastAPI en el puerto 8100, la API simulada en el 8000, agentes con `claude-sonnet-5-5` y modo demo sin API (`VIGIA_MOCK=1`). Instrucciones en [apps/web/README.md](../apps/web/README.md).

- Pasa 13 de 13 comprobaciones (`scripts/test_todo.py`) con las cifras de la sección 2.
- Los 17 tickets y los 13 informes N2 que genera en modo demo cumplen los schemas de Deloitte.
- La aprobación con token funciona contra la API simulada.
- Línea de tiempo interactiva por fases, "Lo descartado" con el motivo de cada regla y los 10 runbooks oficiales como playbooks visuales aplicados a cada caso.
- "Analizar en directo": se pegan alertas en JSON y se ve al agente investigar paso a paso; cada caso se puede reinvestigar en vivo.
- Paleta corporativa verde sobre negro como guiño a Deloitte, sin logotipos ajenos.
- Falta probarlo con una clave real de Anthropic (`.env`, nunca en Git).

## 7. Pendiente para ganar, por prioridad

1. Ver razonar a un modelo real sobre los casos estrella (IBAN, ransomware, AWS-CRM, WMS01 y TPV) y revisar los tickets a mano.
2. Ensayar las alertas del directo.
3. Etiquetar a mano las 150 alertas de `alertas_muestra_desarrollo.jsonl`, sin mirar la salida, y publicar métricas honestas junto con lo que no se resuelve.
4. Preparar la presentación "Una noche en Tarvia": cada persona cuenta una parte con un incidente real. Cierre: "De día, Vigía hace más rápidos a vuestros analistas. De noche, hace que el SOC no se apague nunca".
5. Seguir las reglas del reto: no visitar ni descargar los indicadores del dataset y no guardar credenciales en Git.
