# Inteligencia de vulnerabilidades en Vigía

El perfil `inteligencia` de Docker Compose arranca un recolector que consulta **CISA KEV y los deltas de CVE List cada hora**. CISA KEV aporta explotación observada y su señal de uso en ransomware. CVE List aporta avisos publicados o rechazados. Cada descarga se valida y se incorpora al snapshot por fuente. Si una consulta falla, Vigía conserva la última copia válida y el Panel muestra su estado. [CISA KEV](https://github.com/cisagov/kev-data) · [CVE List](https://github.com/CVEProject/cvelistV5#releases)

```bash
docker compose --profile inteligencia up -d --build
curl -fsS http://127.0.0.1:8100/api/inteligencia
```

El servicio usa un volumen separado con permiso de escritura. La web lo lee en solo lectura. El recolector consulta datos públicos y arranca sin una clave de IA. El triaje puede operar con el dataset si el perfil está desactivado o las fuentes están caídas. Para iniciar una nueva consulta sin esperar al siguiente ciclo, reinicia el recolector:

```bash
docker compose --profile inteligencia restart inteligencia
```

El primer arranque incorpora los deltas recientes disponibles, sin descargar la base histórica completa. Conserva hasta siete días de deltas incorporados. La consulta horaria describe la frecuencia de consulta del servicio. La fecha de publicación y la cobertura las marca cada fuente. Para descubrir exposición a vulnerabilidades nuevas se necesitan versiones de productos o paquetes, además de los CVE presentes en el inventario de Tarvia. [OSV](https://osv.dev/) · [EPSS](https://www.first.org/epss/data)

Cuando hay una coincidencia por CVE, Vigía adjunta el activo, la señal, la fuente y sus fechas al contexto de la propuesta y del contraste. Un aviso externo requiere un registro original reciente que vincule el activo con la alerta. Los datos quedan en el informe de esa investigación, separados de las revisiones de los playbooks. Si un aviso exige cambiar un procedimiento, el responsable puede editar el runbook en **Playbooks** y guardar una revisión. Las guías y la política de respuesta tienen su propio flujo de decisión.

[Arquitectura completa](arquitectura-vigia.md) · [Arranque y operación](../apps/web/README.md)
