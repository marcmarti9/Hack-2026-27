# Vigía · Analista SOC de Tarvia

UAB The Hack 2026 · Reto Deloitte de IA para ciberseguridad · Marc's & Co.

Vigía es una aplicación de escritorio en español. El flujo empieza con el inicio de sesión, muestra el estado de carga y abre la mesa de trabajo con alertas, expedientes y chat.

Tarvia es una empresa ficticia. Su SOC necesita investigar alertas y mantener cobertura fuera de horario. Vigía prepara evidencias, un veredicto, una prioridad y una recomendación para el analista. El reto exige mostrar el triaje en directo con las alertas comunes de la defensa. [Enunciado, datos y presentación de Deloitte](https://github.com/dttdfr/DTT-UAB-The-Hack/tree/5d7569232756eaf0a8723b22c428b70e8f67824f)

## Instalar Vigía

| Sistema | Paquete |
| --- | --- |
| Linux x86-64 | `Vigia-0.2.0-linux-amd64.deb` para Debian/Ubuntu y derivados. Instala con `sudo apt install ./Vigia-0.2.0-linux-amd64.deb`. |
| Linux x86-64, instalación por usuario | Extrae `Vigia-0.2.0-linux-x86_64.tar.gz` y ejecuta `sh vigia/install.sh`. Crea una entrada en el menú. |
| Windows x64 | Ejecuta `Vigia-0.2.0-windows-x64.exe`, generado por el workflow de instaladores. |
| macOS Apple Silicon e Intel | Abre el `.dmg` de tu arquitectura y arrastra Vigía a Aplicaciones. Los builds de desarrollo carecen de firma de distribución y notarización. |

En el primer inicio, crea la cuenta local y selecciona la carpeta raíz del [dataset de Tarvia](https://github.com/dttdfr/DTT-UAB-The-Hack/tree/5d7569232756eaf0a8723b22c428b70e8f67824f). La importación corre en segundo plano y deja un índice reutilizable en el perfil del sistema operativo. El instalador lleva su runtime de Python y Qt. El dataset se descarga por separado.

La mesa tiene una cola SIEM con búsqueda, calendario, filtros y orden. Si Claude está configurado, **Preparar 5** envía hasta cinco alertas visibles para que el analista pueda revisarlas desde la cola. El detalle separa el proceso de revisión de los datos recuperados. `✓` acepta una propuesta vigente que ha superado la segunda pasada. `×` permite registrar una clasificación propia. Vigía guarda la decisión, el usuario, la fecha y la propuesta original en el perfil local. Las alertas del dataset empiezan sin veredicto. Un falso negativo o verdadero negativo requiere una referencia independiente del analista, por lo que esas etiquetas se registran manualmente.

El chat puede consultar la alerta activa y los IDs de evento en modo local. Tiene preguntas sugeridas, adjuntos de texto de hasta 16 KB y un acceso al dictado del sistema operativo. Para activar Claude, inicia Vigía con `ANTHROPIC_API_KEY` y `ANTHROPIC_MODEL` en el entorno. Una consulta con Claude envía la pregunta, la alerta, los eventos recuperados y el adjunto seleccionado. El análisis de una alerta envía su contexto a dos llamadas separadas, una para proponer y otra para intentar refutar. Si las dos pasadas discrepan, faltan eventos o se citan IDs ajenos a los datos recuperados, la propuesta queda pendiente. El porcentaje es la menor estimación declarada por el modelo en ambas pasadas. El porcentaje y las citas no certifican la exactitud de la conclusión.

**Estadísticas** desglosa la cola por fuente y severidad, además de las decisiones locales. **Informe diario** resume las alertas por fecha y reproduce la jornada por horas UTC. Admite un fichero JSON o JSONL de hasta 5 MB con `alert_id`, `created_at` con zona horaria, `severity` y, opcionalmente, `source_product`.

El inicio de sesión protege la mesa dentro del perfil del usuario del sistema. La cuenta se guarda con una derivación PBKDF2 y sal aleatoria. Quien controla los archivos del perfil también controla el acceso al índice. Esta versión tiene una cuenta local por perfil y carece de aprobación de contenciones desde la interfaz.

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

## Equipo

| Integrante | Responsabilidades |
| --- | --- |
| Mark Piazuelo | Presentación y comunicación del proyecto |
| Marc Sánchez | Infraestructura e IA nocturna |
| Arnau Paz | IA nocturna y desarrollo web |
| Marc Martí | Diseño del frontend |
| Sergi Mena | Coordinación general del proyecto |

El reporte inicial del equipo define una investigación modular, con flags para clasificar señales y enrutar consultas, ajuste de profundidad según carga e inteligencia externa de amenazas. La supervisión humana cubre evidencias, decisiones y acciones sensibles. El plan contempla skills con actualizaciones restringidas y auditables, así como un agente de auditoría y red teaming para pruebas en un entorno controlado. Estas líneas pertenecen al diseño del proyecto. La prioridad de implementación es completar primero el flujo de alerta, investigación, evidencia, ticket y revisión humana.
