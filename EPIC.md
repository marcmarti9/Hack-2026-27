# Épico de Vigía

Este archivo coordina a quienes trabajan en Vigía desde distintas máquinas. La copia de referencia vive en [main](https://github.com/marcmarti9/Hack-2026-27/blob/main/EPIC.md). Cada rama puede tener cambios aún sin integrar. Usa los commits y los PR de las entradas para localizar la versión probada.

## Objetivo compartido

Entregar Vigía como aplicación de escritorio para el SOC de Tarvia. La mesa reúne alertas, chat, estadísticas, informe diario, tickets, historial y guías de triaje. La revisión conserva la evidencia, el contraste y la decisión humana.

## Fuentes y ramas

| Fuente | Uso |
| --- | --- |
| [Rama de escritorio](https://github.com/marcmarti9/Hack-2026-27/tree/codex/vigia-desktop) y [PR #2](https://github.com/marcmarti9/Hack-2026-27/pull/2) | Aplicación Qt e instaladores para Linux, Windows y macOS. |
| [PR #1](https://github.com/marcmarti9/Hack-2026-27/pull/1) y el ZIP en `main` | Prototipo previo y contexto técnico del equipo. |
| [Repositorio de Deloitte](https://github.com/dttdfr/DTT-UAB-The-Hack/tree/5d7569232756eaf0a8723b22c428b70e8f67824f) | Dataset, política del SOC y diez runbooks oficiales. |
| Guías y archivos de diseño en `main` | Referencias para triaje, puntuación y copias de seguridad. El estado de cada función se comprueba en el código y sus pruebas. |

## Protocolo entre máquinas

- Al empezar, ejecuta `git fetch origin` y `git show origin/main:EPIC.md`. Si coincides con una intervención abierta, coordina el alcance antes de editar los mismos archivos.
- Para trabajos que puedan solaparse, añade primero una entrada **En curso**. Usa un identificador de sesión sin datos privados y señala la rama y el área reservada.
- Al terminar, añade una entrada **Entregado** o **Bloqueado** en el registro. Enlaza el commit o PR y di qué se comprobó. Indica el siguiente paso si queda trabajo.
- Publica las entradas en `main` con un commit pequeño o un PR de coordinación. Si `main` avanzó, incorpórala y conserva ambas entradas. La copia local de una rama sirve para preparar cambios y la copia remota de `main` sirve para compartir el estado.

## Registro

| Fecha | Sesión | Estado | Trabajo y alcance | Evidencia o siguiente paso |
| --- | --- | --- | --- | --- |
| 2026-11-07 | Codex · Escritorio | Entregado | Vigía 0.5.0, cola de alertas, expediente LSASS, modo de práctica y guías. | [Commit 2cd0614](https://github.com/marcmarti9/Hack-2026-27/commit/2cd061429b69b619f0d77009a546e6d5d24e5c0e) y [CI de los cuatro instaladores](https://github.com/marcmarti9/Hack-2026-27/actions/runs/42412663833). |
| 2026-11-07 | Codex · Producto | En curso | Estilo sin neón, logo original, navegación plegable y limpieza de textos del producto. Archivos en `apps/desktop/` y `packaging/`. | Rama `codex/vigia-desktop`. Verificar acceso, las tres vistas del boceto y la apertura del expediente. |
