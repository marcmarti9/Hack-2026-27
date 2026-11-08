# Vigía

web: https://marcs-and-co.vercel.app/

**Triaje de alertas para el SOC de Tarvia.** Vigía investiga alertas del SIEM, cruza los registros con el inventario y los cambios autorizados, y guarda un expediente por alerta. Cierra los casos que cumplen criterios verificables y escala los que requieren una decisión humana.

[Guía de uso](docs/guia-web.md) · [Arquitectura](docs/arquitectura-vigia.md) · [Defensa en tres minutos](docs/defensa-web.md) · [Página para el comité](docs/comite-tarvia.md)

## Arranque

Necesitas Git y Docker con Compose. Ejecuta desde la raíz de Vigía:

```bash
git clone https://github.com/dttdfr/DTT-UAB-The-Hack.git data/dataset
git -C data/dataset checkout --detach ea61e70a3c066ff7663c613475f180597d56bd06
docker compose up -d --build
docker compose logs -f vigia
```

El primer arranque indexa el dataset y puede tardar varios minutos. Cuando arranque Uvicorn, abre [Triaje](http://127.0.0.1:8100/#directo), carga `data/dataset/03_alertas/demo_alertas_comunes.jsonl`, pulsa **Analizar lote** y abre **Ver resultados del lote**. El índice y los expedientes se guardan en volúmenes de Docker.

El motor local funciona sin clave. El contraste con IA y el monitor horario de CISA KEV y CVE List se habilitan por separado. [Configuración, simulador y desarrollo](apps/web/README.md)

## Resultados comprobados

| Prueba | Resultado |
| --- | --- |
| Lote oficial del jurado | 10 expedientes en 0,9 s de servidor en Chromium. Hubo 3 autocierres, 6 escalados y 1 revisión pendiente. |
| Barrido del dataset | 11.061 expedientes, 8.806 cierres elegibles, 281 escalados y 1.237 abstenciones. El p95 local fue de 115 ms por alerta. |
| Respuesta simulada | Un aislamiento de puesto aprobado desde la web por N2. El resultado quedó en el historial y se rechazó un segundo intento. |

La elegibilidad del barrido es una decisión calculada. Los cierres registrados corresponden a los lotes de la mesa. La cobertura y la latencia del motor local se miden por separado del contraste remoto. [Lote oficial](https://github.com/dttdfr/DTT-UAB-The-Hack/blob/ea61e70a3c066ff7663c613475f180597d56bd06/03_alertas/demo_alertas_comunes.jsonl) · [Verificación](docs/defensa-web.md)

## Estructura del repositorio

| Carpeta | Contenido |
| --- | --- |
| [`apps/backend/`](apps/backend) | Ingesta y consultas DuckDB, reglas de triaje, política SOC e inteligencia de vulnerabilidades. |
| [`apps/engine/`](apps/engine) | Investigación, informes, contraste opcional, playbooks versionados y respuesta simulada. |
| [`apps/web/`](apps/web) | API FastAPI, interfaz web y contenedor que ejecuta Vigía. |
| [`docs/`](docs) | Guía de uso, arquitectura, defensa, página para el comité y evaluación del reto. |
| [`eval/`](eval) | Lotes de práctica y etiquetas de desarrollo. |
| [`scripts/`](scripts) | Barrido reproducible, simulador y comprobaciones del motor y de la web. |
| [`.github/workflows/`](.github/workflows) | Verificación automatizada de la web. |
| `data/dataset/` | Dataset oficial, descargado localmente y excluido de Git. |

## Equipo y colaboración

Mark Piazuelo, Marc Sánchez, Arnau Paz, Marc Martí y Sergi Mena. El [épico](EPIC.md) recoge decisiones y entregas. Para trabajar desde otra sesión o máquina, consulta las [instrucciones de coordinación](AGENTS.md).

Proyecto para el [reto Deloitte Cyber de The Hack UAB](https://github.com/dttdfr/DTT-UAB-The-Hack).
