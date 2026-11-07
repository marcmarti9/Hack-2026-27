# Épico de Vigía

Este archivo coordina a quienes trabajan en Vigía desde distintas máquinas. La copia de referencia vive en [main](https://github.com/marcmarti9/Hack-2026-27/blob/main/EPIC.md). Cada rama puede tener cambios aún sin integrar. Usa los commits y los PR de las entradas para localizar la versión probada.

## Objetivo compartido

Entregar Vigía como aplicación de escritorio para el SOC de Tarvia. La mesa reúne alertas, chat, estadísticas, informe diario, tickets, historial y guías de triaje. La revisión conserva la evidencia, el contraste y la decisión humana.

## Fuentes y ramas

| Fuente | Uso |
| --- | --- |
| [Aplicación de escritorio](apps/desktop), [README](README.md) y [PR #2](https://github.com/marcmarti9/Hack-2026-27/pull/2) | Aplicación Qt e instaladores para Linux, Windows y macOS. |
| [Revisión adversarial](docs/revision-adversarial.md) y [página del comité](docs/comite-tarvia.md) | Requisitos del reto, evidencia, límites de la guardia y criterios de defensa. |
| [PR #1 histórico](https://github.com/marcmarti9/Hack-2026-27/pull/1) y el ZIP en `main` | Prototipo web anterior. La versión de escritorio y su documentación se mantienen en `main`. |
| [Repositorio de Deloitte](https://github.com/dttdfr/DTT-UAB-The-Hack/tree/5d7569232756eaf0a8723b22c428b70e8f67824f) | Dataset, política del SOC y diez runbooks oficiales. |
| [Contexto compartido](docs/contexto-vigia.md) | Cifras medidas, los 12 incidentes y las trampas autorizadas del dataset, decisiones de diseño, brief visual y lo pendiente. Léelo antes de empezar. |
| [Boceto original de escritorio](docs/diseno-escritorio.pdf), guías y archivos de diseño en `main` | Referencias para triaje, puntuación y copias de seguridad. El estado de cada función se comprueba en el código y sus pruebas. |

## Protocolo entre máquinas

- Al empezar, ejecuta `git fetch origin` y `git show origin/main:EPIC.md`. Si coincides con una intervención abierta, coordina el alcance antes de editar los mismos archivos.
- Para trabajos que puedan solaparse, añade primero una entrada **En curso**. Usa un identificador de sesión sin datos privados y señala la rama y el área reservada.
- Al terminar, añade una entrada **Entregado** o **Bloqueado** en el registro. Enlaza el commit o PR y di qué se comprobó. Indica el siguiente paso si queda trabajo.
- Publica las entradas en `main` con un commit pequeño o un PR de coordinación. Si `main` avanzó, incorpórala y conserva ambas entradas. La copia local de una rama sirve para preparar cambios y la copia remota de `main` sirve para compartir el estado.

## Registro

La última entrada de cada sesión indica su estado actual.

| Fecha | Sesión | Estado | Trabajo y alcance | Evidencia o siguiente paso |
| --- | --- | --- | --- | --- |
| 2026-11-07 | Codex · Escritorio | Entregado | Vigía 0.5.0, cola de alertas, expediente LSASS, modo de práctica y guías. | [Commit 2cd0614](https://github.com/marcmarti9/Hack-2026-27/commit/2cd061429b69b619f0d77009a546e6d5d24e5c0e) y [CI de los cuatro instaladores](https://github.com/marcmarti9/Hack-2026-27/actions/runs/42412663833). |
| 2026-11-07 | Codex · Producto | En curso | Estilo sin neón, logo original, navegación plegable y limpieza de textos del producto. Archivos en `apps/desktop/` y `packaging/`. | Rama `codex/vigia-desktop`. Verificar acceso, las tres vistas del boceto y la apertura del expediente. |
| 2026-11-07 | Codex · Producto | Entregado | Vigía 0.6.0 con logo original, menú plegable, paleta clara y textos de producto. Boceto original y protocolo de coordinación en `main`. | [Código 71d1a29](https://github.com/marcmarti9/Hack-2026-27/commit/71d1a29e41c8bab24ead2839e5a14dd0e1f85f8c), [instaladores](https://github.com/marcmarti9/Hack-2026-27/actions/runs/42414893972) y acceso y navegación comprobados en Fedora. La demo y las decisiones de LSASS se probaron en Qt con las 11.061 alertas oficiales. |
| 2026-11-07 | Codex · Copias y apariencia | En curso | Gestor de copias, temas claro y oscuro, espaciado y microanimaciones. Cambios en el escritorio y su empaquetado. | Rama `codex/vigia-desktop`. |
| 2026-11-07 | Codex · Copias y apariencia | Entregado | Vigía 0.7.0 en main con los dos temas, microanimaciones, cola compacta y copias locales, USB y S3. Cinco subagentes trabajaron por vista y un revisor verificó el escritorio integrado. | [PR #2](https://github.com/marcmarti9/Hack-2026-27/pull/2), [instaladores](https://github.com/marcmarti9/Hack-2026-27/actions/runs/42417426562), recorrido Qt con 11.061 alertas, Fedora y recuperación de una copia SQLite. S3 comprobado con un doble de AWS CLI; queda por comprobar contra un bucket real. |
| 2026-11-07 | Codex · Defensa del reto | En curso | Revisión adversarial del reto y del escritorio, expedientes visuales, triaje y guardia con límites de autorización. | Auditoría inicial y matriz de aceptación en `docs/`. Se validará con el dataset y el simulador oficiales. |
| 2026-11-07 | Claude · Contexto | Entregado | Contexto compartido del reto en `docs/contexto-vigia.md` y `CLAUDE.md` que remite a AGENTS.md y al contexto. Solo documentación: no toca `apps/`. | Cifras comprobadas sobre el dataset oficial con el prototipo web local (13/13 comprobaciones). Siguiente paso: validar los casos estrella con un modelo real y etiquetar la muestra de desarrollo. |
| 2026-11-07 | Codex · Defensa del reto | En curso | Lote de diez, vigilancia priorizada, expedientes visuales, cierre de rutina documentado y contraste Luna/Sol. | En Docker pasaron el flujo Qt y el ensayo de diez alertas oficiales más una externa, sin archivo de referencia. Quedan respuesta simulada, paquete y prueba de OpenAI en vivo al final. |
| 2026-11-08 | Codex · Defensa del reto | Entregado | Vigía 0.8.0 con lote de defensa, vigilancia de índice y carpeta, relevo y expedientes visuales. Un recorrido de aislamiento requiere aprobación N2 de práctica y registra el efecto en el simulador oficial. | Pasaron los loops de Docker, diez casos más uno externo, prueba Qt, simulador HTTP e instalación Fedora. Falta el ensayo en vivo con la API de OpenAI y las diez alertas del jurado. |
| 2026-11-08 | Codex · Defensa del reto | Entregado | Vigía 0.8.1 incorpora cuatro escalados que faltaban en la muestra revisada a ciegas. Las 15 etiquetas y la metodología están en el repositorio. | La regresión reprodujo los cinco escalados esperados. Pasó el loop de triaje, Qt y simulador. OpenAI en vivo queda aplazado por petición del equipo. |
| 2026-11-08 | Codex · Defensa del reto | Entregado | Barrido offline final de Vigía 0.8.1, lote visual de ensayo y documentación. GitHub conserva solo `main`. | 11.061 alertas sin errores, 1.331 autocierres elegibles y 267 escalados. [Instaladores comprobados](https://github.com/marcmarti9/Hack-2026-27/actions/runs/42424325479). Siguiente paso acordado: validar Luna/Sol con la cuenta del equipo y ensayar las entradas del jurado. |
