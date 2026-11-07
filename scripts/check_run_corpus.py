"""Verifica el CLI de corpus con el índice oficial de solo lectura."""
import io
import json
import os
import sqlite3
import tempfile
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from apps.backend.tools import db
from scripts import run_corpus

LSASS = "ALR-20261010-011795"
SCCM = "ALR-20261005-000301"
EXTERNAL = "ALR-20991231-999997"


def _invoke(source, output, *flags):
    output_text = io.StringIO()
    with redirect_stdout(output_text), redirect_stderr(io.StringIO()):
        try:
            code = run_corpus.main([str(source), "--output", str(output), *flags])
        except SystemExit as error:
            code = error.code
    return code, json.loads(output_text.getvalue()) if output_text.getvalue() else {}


def _records(output):
    return [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]


def _verify_inputs(root):
    original = db.get_alert(SCCM)
    imported = {**original, "alert_id": EXTERNAL, "mitre": {"technique_id": "T1059.001"}}
    payload = [
        json.dumps(LSASS),
        "",
        json.dumps({**original, "description": "Alteración de prueba del texto canónico."}),
        "{malformado",
        json.dumps(imported),
        json.dumps(LSASS),
        json.dumps("ALR-20991231-999998"),
    ]
    source = root / "mixed.jsonl"
    output = root / "reports.jsonl"
    source.write_text("\n".join(payload) + "\n", encoding="utf-8")
    code, summary = _invoke(source, output, "--jobs", "4")
    reports = _records(output)
    assert code == 1 and summary["reports"] == 6 and summary["errors"] == 3, summary
    assert [row["entrada"]["linea"] for row in reports] == [1, 3, 4, 5, 6, 7]
    assert reports[0]["routing"]["recommendation"] == "escalate"
    assert not reports[0]["routing"]["automatic"]
    assert reports[1]["routing"]["automatic"]
    assert "Alteración de prueba" not in json.dumps(reports[1], ensure_ascii=False)
    assert reports[2]["estado"] == "error" and reports[2]["verdict"] == "needs_more_info"
    assert reports[3]["external"] and reports[3]["mitre"] == ["T1059.001"]
    assert reports[4]["estado"] == "error" and "repetido" in reports[4]["summary"]
    assert reports[5]["estado"] == "error" and "no está en el índice" in reports[5]["summary"]
    for ticket in (reports[0], reports[1], reports[3]):
        assert ticket["consultas"] and ticket["timeline"] and ticket["tiempos_ms"]
        assert ticket["estado"] == "investigada"
    with patch.object(run_corpus, "investigate", side_effect=AssertionError("Repitió una fila persistida.")):
        assert _invoke(source, output, "--jobs", "1")[0] == 1
        assert _records(output) == reports
    with run_corpus._locked_state(output.with_name(output.name + ".sqlite3")):
        assert _invoke(source, output)[0] == 2
    source.write_text(json.dumps(LSASS) + "\n", encoding="utf-8")
    assert _invoke(source, output)[0] == 2
    assert _records(output) == reports


def _verify_remote_budget(root):
    source = root / "paid.jsonl"
    source.write_text(json.dumps(LSASS) + "\n" + json.dumps(SCCM) + "\n", encoding="utf-8")
    output = root / "paid-reports.jsonl"
    flags = ("--remote", "--remote-limit", "1", "--jobs", "1")
    assert _invoke(source, output, "--remote")[0] == 2
    with patch.object(run_corpus, "available_model", return_value=""):
        assert _invoke(source, output, *flags)[0] == 2
    assert not output.exists()
    actual = run_corpus.investigate
    calls = []

    def mock_investigate(alert, remote, guidance, **kwargs):
        calls.append(remote)
        return actual(alert, False, None, **kwargs)

    class Interrupted(BaseException):
        pass

    with patch.object(run_corpus, "available_model", return_value="mock-model"):
        with patch.object(run_corpus, "investigate", side_effect=Interrupted):
            try:
                _invoke(source, output, *flags)
            except Interrupted:
                pass
            else:
                raise AssertionError("No se simuló la interrupción después de la reserva.")
        state = output.with_name(output.name + ".sqlite3")
        with sqlite3.connect(state) as connection:
            assert connection.execute("SELECT reserved, report FROM rows").fetchall() == [(1, None)]
        with patch.object(run_corpus, "investigate", side_effect=mock_investigate):
            code, summary = _invoke(source, output, *flags)
            assert code == 0 and summary["remote_max_calls"] == 2
            assert calls == [False, False]
            assert _records(output)[0]["consulta_remota"]["reanudada_sin_reenvio"]
            calls.clear()
            code, summary = _invoke(source, root / "paid-new.jsonl", *flags)
            assert code == 0 and summary["remote_max_calls"] == 2 and calls == [True, False]


def _verify_boundaries(root):
    assert len(list(run_corpus._entries(io.BytesIO(b"x" * (run_corpus.MAX_BYTES + 30) + b'\n"ALR-20261005-000301"\n')))) == 2
    source = root / "protected.jsonl"
    source.write_text(json.dumps(SCCM) + "\n", encoding="utf-8")
    output = root / "protected-report.jsonl"
    output.write_text("otro archivo\n", encoding="utf-8")
    assert _invoke(source, output)[0] == 2
    assert output.read_text(encoding="utf-8") == "otro archivo\n"
    state = root / "alias.sqlite3"
    os.link(source, state)
    assert _invoke(source, root / "alias-out.jsonl", "--state", str(state))[0] == 2
    output = root / "shared-report.jsonl"
    state = root / "other.sqlite3"
    with run_corpus._exclusive_lock(output.with_name(output.name + ".lock"), "bloqueo de prueba"):
        assert _invoke(source, output, "--state", str(state))[0] == 2
    assert not output.exists() and not state.exists()


def main():
    with tempfile.TemporaryDirectory(prefix="vigia-corpus-test-") as folder:
        root = Path(folder)
        _verify_inputs(root)
        _verify_remote_budget(root)
        _verify_boundaries(root)
    print("Corpus: orden, informes de error, entrada externa, idempotencia, reserva remota y límites verificados.")


if __name__ == "__main__":
    main()
