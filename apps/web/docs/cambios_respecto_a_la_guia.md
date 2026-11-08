# Cambios respecto a la guía técnica

1. `config.py`: rutas configurables con VIGIA_DATA, VIGIA_OUT y VIGIA_DB, y `llm_client()` que devuelve Claude o el cliente simulado (VIGIA_MOCK=1).
2. `ingest.py`: borra también el fichero `.wal` antiguo antes de crear la base, para evitar errores al regenerarla.
3. `db.py`: mensaje claro si no existe la base de datos.
4. `n1.py`: recorte de resultados de herramientas por elementos (siempre JSON válido) en vez de cortar el texto; herramienta `get_cve` registrada.
5. `fiscal.py`, `n2.py`, `chat.py`: usan el cliente común (Claude o demo).
6. `shield.py`: acepta tanto una alerta como un evento de correo.
7. `run_all.py`: opción `--salida`; limpia los tickets e informes de pasadas anteriores.
8. `main.py`: endpoints nuevos `/api/estado` y `/api/rgpd`; posición fija de cada equipo en el mapa; el caso incluye su informe N2; control de rol en `/api/aprobar` (N1/N2) y mensajes claros si la API de Deloitte está parada.
9. Frontend rehecho según el brief visual: parte de guardia, embudo animado, reloj RGPD con las horas ganadas, casos en tarjetas, mapa con nombres de zona, flechas con título y horas de vigilancia cubiertas, línea de tiempo N2, descarga de JSON, vista "Lo descartado" y selector de rol.
10. Nuevos: `mock_llm.py`, `test_todo.py`, `arrancar.ps1`, `arrancar.sh` y este README.
