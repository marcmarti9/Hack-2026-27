"""Verifica la importación y el ensayo offline de la defensa con datos oficiales."""
import io
import json
from collections import Counter
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from apps.backend.config import DATA
from apps.backend.tools import db
from apps.desktop import defense


def write_batch(path, entries):
    path.write_text("".join(json.dumps(entry) + "\n" for entry in entries), encoding="utf-8")


def rejected(path, message):
    try:
        defense.load_alerts(path)
    except ValueError as error:
        assert message in str(error), str(error)
    else:
        raise AssertionError("El lote inválido fue aceptado.")


def run_cli(path, mode="guardia"):
    output = io.StringIO()
    with (patch("sys.argv", ["defense", str(path), "--mode", mode]),
          patch("gzip.open", side_effect=AssertionError("El ensayo leyó el archivo de referencia.")),
          patch("apps.desktop.review.openai_message", side_effect=AssertionError("El ensayo llamó a OpenAI.")),
          redirect_stdout(output)):
        defense.main()
    return [json.loads(line) for line in output.getvalue().splitlines()]


def verify_incident_membership(path):
    recovery = db.get_alert("ALR-20261010-011798")
    external_ids = ("ALR-20261010-999991", "ALR-20261010-999992")
    variants = [{**recovery, "alert_id": identifier, "related_events": [event]}
                for identifier, event in zip(external_ids, ("EDR-0123415", "EDR-0123416"))]
    sccm = "ALR-20261005-000301"
    write_batch(path, [recovery["alert_id"], variants[0], sccm, variants[1]])
    for mode in ("diurno", "guardia"):
        canonical, first, unrelated, second = run_cli(path, mode)
        assert [row["alert_id"] for row in (canonical, first, unrelated, second)] == [
            recovery["alert_id"], external_ids[0], sccm, external_ids[1],
        ]
        assert unrelated["alert_ids"] == [sccm] and unrelated["incident"] is None
        for report in (canonical, first, second):
            assert report["ticket_id"] == "VIG-INC-FW-0025321"
            assert set(external_ids) <= set(report["alert_ids"])
            assert report["alert_ids"] == report["incident"]["alert_ids"] == canonical["alert_ids"]
            assert report["routing"]["mode"] == mode


def official_cases():
    chosen = {}
    with (DATA / "03_alertas" / "alertas.jsonl").open(encoding="utf-8") as stream:
        for line in stream:
            alert = json.loads(line)
            runbook = alert["runbook"]
            previous = chosen.get(runbook)
            if previous is None or (alert["severity"] == "critical" and previous["severity"] != "critical"):
                chosen[runbook] = alert
    assert len(chosen) == defense.MAX_ALERTS and any(row["severity"] == "critical" for row in chosen.values())
    return list(chosen.values())


def main():
    official = official_cases()
    ids = [row["alert_id"] for row in official]
    tampered = {**official[0], "description": "Campo adulterado", "external": True}
    external_id = "ALR-20991231-999999"
    assert db.get_alert(external_id) is None
    benign = db.get_alert("ALR-20261005-000301")
    external = {**benign, "alert_id": external_id, "external": False, "routing": {"automatic": True}}
    external["mitre"] = {"technique_id": "T1059.001", "notes": "Texto externo sin verificar"}

    with TemporaryDirectory(prefix="vigia-defense-") as folder:
        path = Path(folder) / "lote.jsonl"
        write_batch(path, [tampered, {"alert_id": ids[1]}, *ids[2:]])
        assert defense.load_alerts(path) == official
        tickets = run_cli(path)
        assert all(identifier in row["alert_ids"] for row, identifier in zip(tickets, ids))
        assert all(row["routing"]["mode"] == "guardia" and not row["external"] for row in tickets)
        assert all(row["provider"] == "Reglas locales" and 0 <= row["confidence"] <= 1 for row in tickets)
        assert all(row["summary"] and row["timing_ms"] >= 0 for row in tickets)
        assert all(ticket["escalation"]["escalate"] and not ticket["routing"]["automatic"]
                   for alert, ticket in zip(official, tickets) if alert["severity"] == "critical")

        write_batch(path, [external])
        loaded, = defense.load_alerts(path)
        assert loaded["external"] is True and loaded["rule_id"] == benign["rule_id"]
        assert not {"routing", "evidence"} & loaded.keys()
        assert loaded["mitre"] == {"technique_id": "T1059.001"}
        ticket, = run_cli(path)
        assert ticket["external"] is True and ticket["alert_ids"] == [external_id]
        assert ticket["mitre"] == ["T1059.001"]
        assert ticket["routing"]["mode"] == "guardia" and ticket["routing"]["automatic"]
        write_batch(path, [{**external, "mitre": {"technique_id": "T1059.001 extra"}}])
        assert "mitre" not in defense.load_alerts(path)[0]
        verify_incident_membership(path)

        for extreme in ("0001-01-01T00:00:00Z", "9999-12-31T23:59:59Z"):
            write_batch(path, [ids[0], {**external, "created_at": extreme}, ids[-1]])
            rejected(path, "Línea 2")
            output, errors = io.StringIO(), io.StringIO()
            with (redirect_stdout(output), redirect_stderr(errors),
                  patch("sys.argv", ["defense", str(path), "--mode", "guardia"])):
                try:
                    defense.main()
                except SystemExit as error:
                    assert error.code == 2
                else:
                    raise AssertionError("El CLI aceptó una fecha fuera del rango operativo.")
            assert not output.getvalue() and "fuera del rango operativo" in errors.getvalue()

        lsass = db.get_alert("ALR-20261010-011795")
        stale = {**lsass, "alert_id": external_id, "created_at": "2026-11-01T12:00:00Z"}
        write_batch(path, [stale])
        old_reference, = run_cli(path)
        assert old_reference["verdict"] == "needs_more_info" and not old_reference["routing"]["automatic"]
        assert old_reference["routing"]["recommendation"] == "escalate"
        assert not any(row["cited"] for row in old_reference["evidence"])
        write_batch(path, [{**stale, "created_at": "2026-10-09T23:30:00Z"}])
        future_reference, = run_cli(path)
        assert future_reference["verdict"] == "needs_more_info"
        assert not any(row["cited"] for row in future_reference["evidence"])

        for items, expected in (
            ([ids[0], {"alert_id": ids[0]}], "Alerta repetida"),
            ([ids[0], external_id], external_id),
            ([{"alert_id": external_id}], external_id),
            ([*ids, external_id], "hasta 10"),
            ([{key: value for key, value in external.items() if key != "rule_id"}], "rule_id"),
            ([{**external, "created_at": "2026-10-05T09:55:30+02:00"}], "UTC"),
            ([{**external, "created_at": "2026-02-30T00:00:00Z"}], "fecha"),
            ([{**external, "entities": {"hosts": [{"ip": 42}]}}], "Campo ip"),
            ([{**external, "related_events": benign["related_events"] * 2}], "repetidas"),
        ):
            write_batch(path, items)
            rejected(path, expected)
        path.write_text('{"alert_id": "' + ids[0] + '", "alert_id": "' + ids[1] + '"}', encoding="utf-8")
        rejected(path, "campo JSON repetido")
        path.write_bytes(b"\xff")
        rejected(path, "UTF-8")
        path.write_bytes(b" " * (defense.MAX_BYTES + 1))
        rejected(path, "1 MB")

    outcomes = dict(Counter(ticket["verdict"] for ticket in tickets))
    print(f"Defensa: {len(tickets)} tickets oficiales y uno externo, en orden, sin archivo ni OpenAI.")
    print(f"Guardia: {outcomes}; {sum(row['escalation']['escalate'] for row in tickets)} escalados; "
          f"{sum(row['timing_ms'] for row in tickets)} ms acumulados de triaje oficial; "
          f"{ticket['timing_ms']} ms para el externo.")
    print("Validación: canónico intacto, externo corroborado, IDs ausentes/repetidos y entradas inválidas rechazados.")
    print("Incidente: membresía externa compartida con una fila por alerta, en ambos turnos.")


if __name__ == "__main__":
    main()
