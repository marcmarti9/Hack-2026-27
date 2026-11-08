"""Crea alertas sintéticas parecidas a las que probablemente salgan en el directo (ficheros de la sandbox sin logs)."""
import json
from apps.backend.config import OUT
from apps.backend.tools import db

def sb(nombre):
    return next(s for s in db._rows("SELECT sha256, file_name FROM sandbox") if s["file_name"].startswith(nombre))

ALERTAS = [
    {"alert_id": "ALR-DIRECTO-0001", "created_at": "2026-10-30T23:12:00.000Z", "source_product": "EDR", "rule_id": "UC-EDR-010",
     "rule_name": "Robo de credenciales de navegador", "severity": "high", "status": "new",
     "mitre": {"tactic": "Credential Access", "technique_id": "T1555.003", "technique": "Credentials from Web Browsers"},
     "description": "Un proceso no navegador accede a las bases de datos de credenciales de Chrome/Edge.",
     "entities": {"hosts": [{"hostname": "WS-BCN-1336", "ip": "10.10.1.97"}], "files": [{"name": sb("npp")["file_name"], "sha256": sb("npp")["sha256"]}]},
     "evidence": {"process": sb("npp")["file_name"], "downloaded_from": "notepad-plus-plus-download.example", "edr_action": "detected_only"},
     "related_events": [], "runbook": "RB-02"},
    {"alert_id": "ALR-DIRECTO-0002", "created_at": "2026-10-31T02:40:00.000Z", "source_product": "EDR", "rule_id": "UC-EDR-009",
     "rule_name": "Proceso sospechoso lanzado por servidor web", "severity": "critical", "status": "new",
     "mitre": {"tactic": "Persistence", "technique_id": "T1505.003", "technique": "Web Shell"},
     "description": "nginx/php-fpm/java lanzan una shell o herramienta del sistema.",
     "entities": {"hosts": [{"hostname": "WEB-ECOM03", "ip": "10.50.1.13"}], "files": [{"name": "cache_helper.php", "sha256": sb("cache_helper")["sha256"]}],
                  "urls": ["https://www.tarvia.example/wp-content/plugins/pagebuilder-lite/ajax/upload.php"]},
     "evidence": {"parent_chain": "php-fpm > sh > cat /var/www/.env", "edr_action": "detected_only"}, "related_events": [], "runbook": "RB-05"},
    {"alert_id": "ALR-DIRECTO-0003", "created_at": "2026-10-29T07:05:00.000Z", "source_product": "EMAIL_GW", "rule_id": "UC-EML-002",
     "rule_name": "Adjunto potencialmente malicioso entregado", "severity": "medium", "status": "new",
     "mitre": {"tactic": "Initial Access", "technique_id": "T1566.001", "technique": "Spearphishing Attachment"},
     "description": "La pasarela clasificó el adjunto como sospechoso pero lo entregó.",
     "entities": {"users": [{"upn": "marina.munoz@tarvia.example"}], "files": [{"name": "Actualizacion_nomina_octubre.pdf", "sha256": sb("Actualizacion")["sha256"]}]},
     "evidence": {"sender": "rrhh@tarvia-nominas.example", "subject": "Actualización de su nómina de octubre", "gateway_verdict": "suspicious", "action": "delivered"},
     "related_events": [], "runbook": "RB-01"},
]

if __name__ == "__main__":
    OUT.mkdir(exist_ok=True)
    with open(OUT / "alertas_directo.jsonl", "w", encoding="utf-8") as f:
        for a in ALERTAS:
            f.write(json.dumps(a, ensure_ascii=False) + "\n")
    print("Creado", OUT / "alertas_directo.jsonl", len(ALERTAS), "alertas")
