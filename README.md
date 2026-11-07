# Vigía · Analista SOC de Tarvia

[Épico y registro de coordinación](https://github.com/marcmarti9/Hack-2026-27/blob/main/EPIC.md) · [Instrucciones para agentes](AGENTS.md)

Vigía es una aplicación de escritorio en español. El flujo empieza con el inicio de sesión, muestra el estado de carga y abre la mesa de trabajo con alertas, expedientes y chat.

Tarvia es una empresa ficticia. Su SOC necesita investigar alertas y mantener cobertura fuera de horario. Vigía prepara evidencias, un veredicto, una prioridad y una recomendación para el analista. [Enunciado, datos y presentación de Deloitte](https://github.com/dttdfr/DTT-UAB-The-Hack/tree/5d7569232756eaf0a8723b22c428b70e8f67824f)

## Instalar Vigía

| Sistema | Paquete |
| --- | --- |
| Linux x86-64 | `Vigia-0.6.0-linux-amd64.deb` para Debian/Ubuntu y derivados. Instala con `sudo apt install ./Vigia-0.6.0-linux-amd64.deb`. |
| Linux x86-64, instalación por usuario | Extrae `Vigia-0.6.0-linux-x86_64.tar.gz` y ejecuta `sh vigia/install.sh`. Crea una entrada en el menú. |
| Windows x64 | Ejecuta `Vigia-0.6.0-windows-x64.exe`, generado por el workflow de instaladores. |
| macOS Apple Silicon e Intel | Abre el `.dmg` de tu arquitectura y arrastra Vigía a Aplicaciones. Los builds de desarrollo carecen de firma de distribución y notarización. |

En el primer inicio, crea la cuenta local y selecciona la carpeta raíz del [dataset de Tarvia](https://github.com/dttdfr/DTT-UAB-The-Hack/tree/5d7569232756eaf0a8723b22c428b70e8f67824f). La importación corre en segundo plano y deja un índice reutilizable en el perfil del sistema operativo. El instalador lleva su runtime de Python y Qt. El dataset se descarga por separado.

En **Inicio**, la cola SIEM permite buscar y filtrar por fecha, severidad y veredicto. El botón junto al logo pliega la navegación y deja accesibles las vistas mediante sus iconos. El chat se puede mostrar, ocultar y redimensionar. Cada expediente muestra el proceso de revisión, los registros originales, las entidades, la línea de tiempo, las acciones y el historial. **Tickets** abre tanto los casos locales como los 17 expedientes de la demo. Los 13 informes N2 y los descartes de la demo aparecen como referencias históricas separadas de las decisiones nuevas. Desde el detalle se puede exportar el expediente en JSON.

**Aceptar propuesta** acepta una propuesta cuando el contraste coincide y ambas respuestas citan eventos recuperados. **Corregir** registra la clasificación humana, incluidos falsos y verdaderos negativos. **Historial** guarda las justificaciones basadas en evidencias, la revisión adversarial, las decisiones y las versiones de guía utilizadas. **Playbooks** permite editar y versionar los diez runbooks y la skill de triaje. Las modificaciones se aplican al siguiente análisis. **Ver guías** abre el runbook correspondiente a la alerta y la skill vigente. La severidad indica la prioridad según la matriz del SOC. La confianza describe el grado de certeza de un análisis disponible. **Positivo benigno** permite registrar que la regla detectó actividad autorizada.

El chat funciona en modo local y admite adjuntos de texto de hasta 16 KB. Para activar el agente, inicia Vigía con `OPENAI_API_KEY` en el entorno. `OPENAI_MODEL` permite elegir el modelo y por defecto usa `gpt-5.4-mini`. Las acciones de OpenAI indican cuándo envían datos fuera del perfil. El análisis envía la alerta, hasta doce eventos, el contexto local y las guías aplicables. El agente propone un resultado y una segunda llamada intenta refutarlo. Si falta evidencia o las pasadas discrepan, Vigía deja el resultado pendiente. La confianza es la menor de las estimaciones de ambas pasadas. El detalle registra el tiempo de recuperación, propuesta, contraste y total. **Preparar 5** puede investigar hasta dos alertas a la vez.

**Estadísticas** muestra la proporción de alertas disparadas fuera del horario de Madrid (lunes a viernes, 08:00–20:00) con sus denominadores para el índice, la demo y las propuestas OpenAI locales. **Informe diario** reproduce la jornada por horas UTC, indica el estado del SOC en cada hora y ofrece **Presentar** a pantalla completa. Admite un fichero JSON o JSONL de hasta 5 MB con `alert_id`, `created_at` con zona horaria, `severity` y, opcionalmente, `source_product`.

El inicio de sesión protege la mesa dentro del perfil del usuario del sistema. La cuenta se guarda con una derivación PBKDF2 y sal aleatoria. Quien controla los archivos del perfil también controla el acceso al índice. Esta versión tiene una cuenta local por perfil y carece de aprobación de contenciones desde la interfaz.

### Entorno de práctica

Abre **Vigía · Práctica** desde el menú en Linux o Windows. En macOS, ejecuta `open -na /Applications/Vigia.app --args --demo` después de instalar la aplicación. En desarrollo, usa `python -m apps.desktop.entry --demo`.

1. En el acceso, usa `analista.demo` y `VigiaDemo2026`, o pulsa **Entrar en modo de práctica**. En el primer ensayo, selecciona el dataset oficial si la app lo solicita.
2. En **Inicio**, abre **Caso LSASS** y pulsa **Cargar análisis de referencia**. La propuesta, el fiscal y la confianza vienen del expediente archivado. Los eventos se recuperan del índice en ese momento. Pulsa **Aceptar** o **Corregir** y abre **Historial** para mostrar el registro de la decisión.
3. En **Informe diario**, pulsa **Presentar** para enseñar la reproducción de la jornada. Para abrir directamente el caso desde terminal, añade `--present` a `--demo`.

El entorno de práctica funciona sin red ni clave de API. Usa un índice independiente y guarda el usuario, los cambios de playbook y las decisiones durante esa ejecución. Al volver a abrirla se puede repetir el recorrido. Para probar el análisis en vivo, inicia **Vigía** en modo normal con tu propia clave OpenAI configurada.

### Desarrollo y empaquetado

```bash
python -m pip install -r requirements.txt -r requirements-desktop.txt
python -m apps.desktop.entry
```

Para generar los paquetes de Linux en `out/installers`:

```bash
mkdir -p out
docker build -f packaging/Dockerfile.linux -t vigia-desktop-builder .
docker run --rm --network none --user "$(id -u):$(id -g)" -e HOME=/tmp \
  -v "$PWD/out:/vigia/out" vigia-desktop-builder sh packaging/linux.sh
```

En Windows el flujo ejecuta `python packaging/build.py` y compila `packaging/windows.iss` con Inno Setup. En macOS ejecuta `sh packaging/macos.sh`. [Workflow de instaladores](https://github.com/marcmarti9/Hack-2026-27/actions)

## Motor disponible

El motor contiene la ingesta del dataset oficial, las consultas de solo lectura y las funciones de severidad y aprobación. El flujo de investigación N1 completo y la ejecución contra el simulador están pendientes. Docker reproduce el entorno de desarrollo y compilación.

1. Coloca el dataset oficial en `data/dataset`, con `01_contexto` a `06_herramientas` en ese nivel. Puedes usar otra carpeta con `VIGIA_DATA_DIR` o `--dataset`.
2. Desde la raíz, con Python 3.11, ejecuta:

   ```bash
   python -m pip install -r requirements.txt
   python -m apps.backend.ingest
   python -m scripts.check_data
   python -m scripts.check_policy
   ```

La ingesta genera `out/tarvia.duckdb`. Construye una base temporal y sustituye la anterior al terminar. Los comandos de consulta abren la base en solo lectura. El directorio del dataset y las salidas se excluyen de Git.

Para verificar el motor en Docker desde Linux, con el dataset en `data/dataset`:

```bash
mkdir -p out
docker build -t vigia-engine:dev .
docker run --rm --network none --read-only --user "$(id -u):$(id -g)" \
  -v "$PWD/data/dataset:/dataset:ro" -v "$PWD/out:/vigia/out" \
  vigia-engine:dev python -m apps.backend.ingest --dataset /dataset
docker run --rm --network none --read-only -v "$PWD/out:/vigia/out:ro" \
  vigia-engine:dev python -m scripts.check_data
docker run --rm --network none --read-only -v "$PWD/out:/vigia/out:ro" \
  vigia-engine:dev python -m scripts.check_policy
```

### Resultados verificados

| Comprobación | Resultado |
| --- | --- |
| Ingesta de logs y alertas | 814.471 eventos, 2.467.451 entidades indexadas y 11.061 alertas en 18 fuentes. |
| Consultas de la guía | CVE-2024-23897 para Jenkins, 100 eventos del equipo de control y familia Latrodectus en el TIP. |
| Referencias | Recuperación de `EDR-0123412` por ID. Los IDs inexistentes no devuelven eventos. |
| Severidad | `ALR-20261005-000172` da `low` en el escenario de prueba con bloqueo sin efecto. La prueba comprueba la denegación 403 en WAF e introduce la premisa de ausencia de efecto para probar el ajuste. |
| Aprobaciones | OT bloqueada por hostname o subred, doble aprobación según el activo y revisión N2 para servicios de uso dual. La función devuelve requisitos; la autenticación y la ejecución quedan pendientes. |

## Contraste de las guías con el reto

La guía técnica define la estructura y el orden de trabajo del motor. En caso de discrepancia, prevalecen los datos, los esquemas y la política oficiales. La indicación más reciente del equipo prevalece para el producto de escritorio y sus pantallas.

| Pieza | Decisión o verificación que falta |
| --- | --- |
| Datos y runbooks | El repositorio oficial contiene diez runbooks y 44 entradas de catálogo. La presentación enumera nueve runbooks y la guía completa habla de 46 reglas. Usaremos el catálogo y los ficheros presentes en el dataset. |
| Filtro de ruido | Las cifras 10.974/87 y 17 grupos son referencias de reproducción. La guía completa excluye el cierre automático de positivos y el código de la guía técnica marca como cerrados algunos positivos bloqueados. Separaremos clasificación, recomendación y decisión. Un dominio corporativo exige igualdad o sufijo con límite de etiqueta. Una lista vacía, una alerta marcada por Vela o un número de cambio citado en el texto no bastan para cerrar. |
| Severidad y SLA | La matriz parte de la entidad más crítica identificada. El ajuste total queda acotado a un nivel y requiere hechos verificados. El orquestador de la guía recorta algunas severidades a `low` al cerrar y eso puede ocultar la prioridad calculada. Conservaremos el cálculo y su explicación. |
| N1 y fiscal | Usar los esquemas oficiales, registrar consultas y verificar que cada referencia se recuperó y corresponde a la fuente citada. Que el ID exista no demuestra el hallazgo. Las discrepancias se muestran al analista. El modo offline debe ejecutar consultas reales y distinguir los hechos recuperados de las conclusiones pendientes. |
| Escudo, agrupación y caza | Evaluar el escudo antes del filtro y tratar sus coincidencias como señales. Agrupar por entidades tipadas y ventana temporal. Los 18 avisos, 17 grupos y cinco hallazgos son resultados de la guía pendientes de reproducir en esta rama. |
| N2 | Validar el informe y su línea temporal. Las fechas se recuperan del evento citado. La guía produce un informe incompleto sin campos obligatorios si el modelo agota sus turnos; la aplicación debe mostrar un estado pendiente en ese caso. |
| Chat | Consultas de solo lectura, respuestas con referencias y distinción entre hechos y dudas. Mostrar herramientas y resultados observables como traza. |
| Contención | El ejemplo de la guía acepta el nombre del aprobador en el cuerpo y construye una ruta con el ID del ticket. La aplicación debe verificar identidad, roles, acción y objetivo contra una propuesta registrada antes de pedir el token al simulador. Toda ejecución queda vinculada a la decisión humana. OT solo se escala. |
| Escritorio | Inicio de sesión local, carga y área de trabajo con alertas, expediente y chat. Los detalles de mapa y métricas quedan pendientes del diseño del equipo. |
| Métricas y defensa | Comparar con etiquetas revisadas y registrar tiempos medidos. Los 15 minutos de las diapositivas son una estimación del proceso manual. El contador de la demo debe distinguir una estimación de una medición. |

La política de prioridad y los permisos se implementan con los apartados 2 a 5 de la política del SOC. El simulador ofrece un contrato propio de aprobación y contención. El código de esta rama aún carece de operaciones contra ese simulador. [Política del SOC](https://github.com/dttdfr/DTT-UAB-The-Hack/blob/5d7569232756eaf0a8723b22c428b70e8f67824f/01_contexto/politica_soc.md) · [API simulada](https://github.com/dttdfr/DTT-UAB-The-Hack/blob/5d7569232756eaf0a8723b22c428b70e8f67824f/06_herramientas/LEEME_herramientas.md)

Los indicadores reales del dataset solo se pueden consultar en servicios de reputación. Durante las comprobaciones de esta rama, los contenedores que leen los datos se ejecutan sin red y con el dataset montado en solo lectura.

La guía de triaje del equipo también describe tags, un score de 1 a 100 y agrupación de incidentes. Vigía muestra la severidad calculada, la evidencia y la confianza por separado. El score y el gestor de copias de seguridad se mantienen como referencias de diseño para otras iteraciones. [Guía de triaje](https://github.com/marcmarti9/Hack-2026-27/blob/9ddb430/Triaje%20SOC%20Tarvia%20-%20tags%20y%20score__(TRIATGE).pdf) · [Boceto de copias de seguridad](https://github.com/marcmarti9/Hack-2026-27/blob/9ddb430/BACKUP%20MANAGER.png)

## Equipo

| Integrante | Responsabilidades |
| --- | --- |
| Mark Piazuelo | Presentación y comunicación del proyecto |
| Marc Sánchez | Infraestructura e IA nocturna |
| Arnau Paz | IA nocturna y desarrollo web |
| Marc Martí | Diseño del frontend |
| Sergi Mena | Coordinación general del proyecto |

El reporte inicial del equipo define una investigación modular, con flags para clasificar señales y enrutar consultas, ajuste de profundidad según carga e inteligencia externa de amenazas. La supervisión humana cubre evidencias, decisiones y acciones sensibles. El plan contempla skills con actualizaciones restringidas y auditables, así como un agente de auditoría y red teaming para pruebas en un entorno controlado. Estas líneas pertenecen al diseño del proyecto. La prioridad de implementación es completar primero el flujo de alerta, investigación, evidencia, ticket y revisión humana.
