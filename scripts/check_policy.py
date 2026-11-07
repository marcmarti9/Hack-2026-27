"""Comprueba la política contra alertas y activos del reto."""
from apps.backend.rules.approvals import aprobacion
from apps.backend.rules.engine import fuera_de_horario, madrid, severidad
from apps.backend.tools import db


def main() -> None:
    alert = db.get_alert("ALR-20261005-000172")
    event = db.get_event(alert["related_events"][0])
    assert event["source"] == "waf" and event["action"] == "blocked" and event["status"] == 403
    severity = severidad(alert, "true_positive", verified_prevention="bloqueo sin efecto (caso de prueba)")
    assert severity.level == "low"
    print("ALR-20261005-000172:", severity.level, "|", severity.rationale)
    assert severidad(alert, "true_positive").level == "medium"
    assert severidad(alert, "true_positive", verified_impact="acceso confirmado",
                     verified_prevention="bloqueo previo").level == "high"

    assert not aprobacion("isolate_host", "PLC-SORT01").permitted
    assert not aprobacion("block_ioc", "10.40.16.100").permitted
    assert not aprobacion("block_ioc", "::ffff:10.40.16.100").permitted
    assert not aprobacion("block_ioc", "https://mega.nz/file").permitted
    assert not aprobacion("isolate_host", "unknown").permitted
    assert aprobacion("isolate_host", "WEB-ECOM03").roles == ("N2", "Negocio")
    assert aprobacion("isolate_host", "JENKINS-DEV01").roles == ("N2", "Responsable del servicio")
    assert aprobacion("block_ioc", "files.mega.nz.").roles == ("N2",)
    assert aprobacion("block_ioc", "fakemega.nz").roles == ("N1",)
    assert not aprobacion("inventada", "JENKINS-DEV01").permitted
    assert madrid("2026-10-25T00:59:00Z").isoformat() == "2026-10-25T02:59:00+02:00"
    assert madrid("2026-10-25T01:00:00Z").isoformat() == "2026-10-25T02:00:00+01:00"
    assert fuera_de_horario("2026-10-25T01:00:00Z")
    assert not fuera_de_horario("2026-10-26T07:00:00Z")
    print("Política: OT bloqueada, aprobadores por activo, uso dual y cambio horario verificados.")


if __name__ == "__main__":
    main()
