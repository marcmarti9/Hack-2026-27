"""Procesa alertas JSONL y genera un expediente por entrada con reanudación."""
import argparse
import hashlib
import json
import os
import sqlite3
import sys
import tempfile
from collections import Counter
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from contextlib import closing, contextmanager
from dataclasses import dataclass
from itertools import islice
from pathlib import Path
from time import perf_counter

import duckdb

from apps.backend.config import DB, ROOT
from apps.backend.rules.engine import fuera_de_horario
from apps.backend.tools import db
from apps.engine.assistant import available_model, review_model
from apps.engine.defense import ALERT_ID, MAX_BYTES, _external, _object, _ticket
from apps.engine.review import PLAYBOOKS, investigate
from apps.engine.triage_report import merge_incident_memberships


@dataclass(frozen=True)
class Entry:
    number: int
    line: int
    alert_id: str | None
    data: dict | None
    error: str = ""


def _entries(stream):
    seen = set()
    number = 0
    line = 0
    while raw := stream.readline(MAX_BYTES + 1):
        line += 1
        oversized = len(raw) > MAX_BYTES
        while oversized and raw and not raw.endswith(b"\n"):
            raw = stream.readline(MAX_BYTES + 1)
        if line == 1 and not oversized:
            raw = raw.removeprefix(b"\xef\xbb\xbf")
        if not oversized and not raw.strip():
            continue
        number += 1
        key = None
        try:
            if oversized:
                raise ValueError("La línea supera 1 MB.")
            data = json.loads(raw.decode("utf-8"), object_pairs_hook=_object)
            candidate = data.get("alert_id") if isinstance(data, dict) else data
            if not isinstance(candidate, str) or not ALERT_ID.fullmatch(candidate):
                raise ValueError("ID de alerta inválido.")
            key = candidate
            if key in seen:
                raise ValueError("ID repetido en el archivo.")
            seen.add(key)
            yield Entry(number, line, key, data if isinstance(data, dict) else None)
        except UnicodeError:
            yield Entry(number, line, key, None, "La línea debe estar en UTF-8.")
        except (json.JSONDecodeError, RecursionError):
            yield Entry(number, line, key, None, "JSON no válido o demasiado anidado.")
        except ValueError as error:
            yield Entry(number, line, key, None, str(error))


def _encode(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str)


def _guidance(runbook):
    directory = ROOT / "apps" / "engine" / "resources" / "playbooks"
    names = ("SKILL", runbook) if runbook in PLAYBOOKS else ("SKILL",)
    return {name: {"revision": 0, "text": (directory / f"{name}.md").read_text(encoding="utf-8")}
            for name in names}


def _error(entry, message):
    return {
        "ticket_id": f"VIG-ERROR-{entry.line}", "alert_ids": [entry.alert_id] if entry.alert_id else [],
        "title": "Alerta pendiente de investigación", "verdict": "needs_more_info", "confidence": None,
        "severity": None, "summary": message, "evidence": [], "recommended_actions": [],
        "open_questions": ["¿Puede validarse la entrada y consultarse el índice?"],
        "escalation": {"escalate": False, "to": "", "reason": "Fallo de entrada o de investigación."},
        "routing": {"recommendation": "review", "automatic": False}, "provider": "",
        "consultas": [], "propuesta": {}, "contraste": {}, "criterio_verificado": {},
        "estado": "error",
    }


def _report(alert, analysis):
    report = dict(analysis.get("report") or _ticket(alert, analysis))
    for key in ("alert_id", "created_at", "source_product", "rule_id", "rule_name", "runbook"):
        report.setdefault(key, alert[key])
    report.setdefault("routing", analysis["routing"])
    report.setdefault("consultas", analysis.get("trace", []))
    report.setdefault("criterio_verificado", analysis.get("decision_basis") or analysis.get("verified_finding") or {})
    report.setdefault("propuesta", analysis.get("proposal") or {})
    report.setdefault("contraste", analysis.get("challenge") or {})
    report.setdefault("contexto", analysis.get("context", {}))
    report.setdefault("entidades", alert.get("entities", {}))
    technique = (alert.get("mitre") or {}).get("technique_id")
    report.setdefault("mitre", [technique] if technique else [])
    report.setdefault("timeline", [
        {"event_id": event["event_id"], "source": event["source"], "timestamp": event.get("timestamp", "")}
        for event in sorted(analysis.get("events", []), key=lambda item: item.get("timestamp") or "")
    ])
    if incident := analysis.get("incident") or (analysis.get("verified_finding") or {}).get("incident"):
        report.setdefault("incident", incident)
    report.setdefault("executed_actions", [])
    report.setdefault("sla", analysis.get("sla"))
    report.setdefault("tiempos_ms", analysis.get("timing", {}))
    report.setdefault("timing_ms", analysis.get("timing", {}).get("total_ms"))
    report.setdefault("triage_seconds", (report["timing_ms"] or 0) / 1000)
    report["estado"] = "investigada"
    return report


def _investigate(entry, mode, remote):
    if entry.error:
        return _error(entry, entry.error)
    try:
        alert = db.get_alert(entry.alert_id)
        if alert is None:
            if entry.data is None or len(entry.data) == 1:
                raise ValueError("La alerta no está en el índice. Aporta el objeto completo.")
            alert = _external(entry.data)
    except ValueError as error:
        return _error(entry, str(error))
    try:
        chosen = ("guardia" if fuera_de_horario(alert["created_at"]) else "diurno") if mode == "auto" else mode
        analysis = investigate(alert, remote, _guidance(alert["runbook"]) if remote else None, triage=True, mode=chosen)
        return _report(alert, analysis)
    except Exception as error:
        return _error(entry, f"Fallo de investigación ({type(error).__name__}).")


def _process(work, mode):
    reports = []
    with db.read_session():
        for entry, remote, resumed in work:
            try:
                report = _investigate(entry, mode, remote)
            except Exception as error:
                report = _error(entry, f"Fallo del índice ({type(error).__name__}).")
            report["entrada"] = {"orden": entry.number, "linea": entry.line, "alert_id": entry.alert_id}
            report["consulta_remota"] = {"asignada": remote or resumed, "reanudada_sin_reenvio": resumed}
            reports.append((_encode(report), entry.number))
    return reports


@contextmanager
def _exclusive_lock(lock, message):
    with closing(sqlite3.connect(lock, timeout=0)) as hold:
        try:
            hold.execute("BEGIN EXCLUSIVE")
        except sqlite3.OperationalError:
            raise ValueError(message) from None
        yield


@contextmanager
def _locked_state(state):
    lock = state.with_name(state.name + ".lock")
    with _exclusive_lock(lock, "Otro proceso está usando este punto de reanudación."):
        descriptor = os.open(state, os.O_WRONLY | os.O_CREAT, 0o600)
        os.close(descriptor)
        with closing(sqlite3.connect(state)) as connection:
            yield connection


def _signature(input_hash, mode, limit, output):
    index = DB.stat()
    paths = [*sorted((ROOT / "apps" / "backend").rglob("*.py")),
             *(ROOT / "apps" / "engine" / f"{name}.py" for name in ("assistant", "defense", "review", "triage_report")
               if (ROOT / "apps" / "engine" / f"{name}.py").is_file()),
             *sorted((ROOT / "apps" / "engine" / "resources" / "playbooks").glob("*.md")),
             Path(__file__)]
    code = hashlib.sha256()
    for path in paths:
        code.update(path.read_bytes())
    return _encode([input_hash, str(output), str(DB), index.st_size, index.st_mtime_ns, index.st_ino, code.hexdigest(),
                    mode, limit, available_model() if limit else "", review_model() if limit else ""])


def _initialize(connection, signature, output):
    with connection:
        connection.execute("CREATE TABLE IF NOT EXISTS manifest (id INTEGER PRIMARY KEY, signature TEXT NOT NULL)")
        existing = connection.execute("SELECT signature FROM manifest WHERE id=1").fetchone()
        if existing and existing[0] != signature:
            raise ValueError("El punto de reanudación pertenece a otra entrada, índice, versión o configuración.")
        if not existing:
            if output.exists():
                raise ValueError("La salida ya existe sin un checkpoint asociado. Elige otro archivo.")
            connection.execute("INSERT INTO manifest VALUES (1, ?)", (signature,))
        connection.execute("""
            CREATE TABLE IF NOT EXISTS rows (
                number INTEGER PRIMARY KEY, reserved INTEGER NOT NULL, report TEXT
            )
        """)


def _pending(stream, connection, limit):
    for entry in _entries(stream):
        saved = connection.execute("SELECT reserved, report IS NOT NULL FROM rows WHERE number=?",
                                   (entry.number,)).fetchone()
        if saved and saved[1]:
            continue
        resumed = bool(saved and saved[0])
        remote = not resumed and not entry.error and entry.number <= limit
        if remote:
            with connection:
                connection.execute("INSERT OR IGNORE INTO rows VALUES (?, 1, NULL)", (entry.number,))
        yield entry, remote, resumed


def _collect(done, connection, progress):
    saved = []
    for future in done:
        saved.extend(future.result())
    with connection:
        connection.executemany("""
            INSERT INTO rows(report, number, reserved) VALUES (?, ?, 0)
            ON CONFLICT(number) DO UPDATE SET report=excluded.report
        """, saved)
    progress(len(saved))


def _run(stream, connection, mode, limit, jobs, progress_every):
    processed = connection.execute("SELECT count(*) FROM rows WHERE report IS NOT NULL").fetchone()[0]

    def progress(count):
        nonlocal processed
        previous = processed
        processed += count
        if processed // progress_every != previous // progress_every:
            print(f"Expedientes registrados: {processed}", file=sys.stderr, flush=True)

    pending = iter(_pending(stream, connection, limit))
    active = set()
    with ThreadPoolExecutor(max_workers=jobs) as executor:
        while work := tuple(islice(pending, 1 if limit else 16)):
            active.add(executor.submit(_process, work, mode))
            if len(active) == jobs:
                done, active = wait(active, return_when=FIRST_COMPLETED)
                _collect(done, connection, progress)
        if active:
            _collect(active, connection, progress)
    return processed


def _incident_memberships(connection):
    # Recupera solo las pertenencias, sin cargar los cuerpos del corpus en memoria.
    reports = [
        {"ticket_id": ticket, "alert_ids": json.loads(alert_ids),
         "incident": {"incident_id": incident, "alert_ids": json.loads(incident_alert_ids)}}
        for ticket, alert_ids, incident, incident_alert_ids in connection.execute("""
            SELECT json_extract(report, '$.ticket_id'), json_extract(report, '$.alert_ids'),
                   json_extract(report, '$.incident.incident_id'), json_extract(report, '$.incident.alert_ids')
            FROM rows
            WHERE json_type(report, '$.incident') = 'object'
            ORDER BY number
        """)
    ]
    merge_incident_memberships(reports)
    return {report["ticket_id"]: report["alert_ids"] for report in reports
            if report["ticket_id"] == report["incident"]["incident_id"]}


def _publish(connection, output, processed):
    counts = Counter()
    verdicts = Counter()
    dispositions = Counter()
    rules = {}
    timings = []
    memberships = _incident_memberships(connection)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="\n", delete=False,
                                         prefix=f".{output.name}.", dir=output.parent) as stream:
            temporary = Path(stream.name)
            for document, reserved in connection.execute("SELECT report, reserved FROM rows ORDER BY number"):
                if document is None:
                    raise ValueError("Hay entradas sin expediente. Reanuda el proceso.")
                report = json.loads(document)
                incident = report.get("incident")
                if incident and incident["incident_id"] == report["ticket_id"]:
                    report["alert_ids"] = incident["alert_ids"] = memberships[report["ticket_id"]]
                    document = _encode(report)
                stream.write(document + "\n")
                counts["errors"] += report["estado"] == "error"
                counts["remote_alerts_reserved"] += reserved
                verdicts[report["verdict"]] += 1
                routing = report["routing"]
                dispositions["automatic" if routing["automatic"] else routing["recommendation"]] += 1
                if rule := report.get("rule_id"):
                    rules.setdefault(rule, Counter())[report["verdict"]] += 1
                if report.get("timing_ms") is not None:
                    timings.append(report["timing_ms"])
            stream.flush()
            os.fsync(stream.fileno())
        if not verdicts:
            raise ValueError("El archivo no contiene alertas.")
        if sum(verdicts.values()) != processed:
            raise ValueError("El número de expedientes no coincide con el checkpoint.")
        temporary.replace(output)
    finally:
        if temporary and temporary.exists():
            temporary.unlink()
    timings.sort()
    return {
        "reports": sum(verdicts.values()), **counts,
        "remote_max_calls": 2 * counts["remote_alerts_reserved"], "verdicts": verdicts, "dispositions": dispositions,
        "verdicts_by_rule": rules,
        "p50_ms": timings[len(timings) // 2] if timings else None,
        "p95_ms": timings[int(len(timings) * .95)] if timings else None,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="Archivo JSONL con un ID u objeto por línea")
    parser.add_argument("--output", type=Path, required=True, help="Ruta del JSONL final")
    parser.add_argument("--state", type=Path, help="Checkpoint SQLite (por defecto, junto al JSONL final)")
    parser.add_argument("--mode", choices=("auto", "diurno", "guardia"), default="auto")
    parser.add_argument("--jobs", type=int, default=2, choices=range(1, 9))
    parser.add_argument("--progress-every", type=int, default=250)
    parser.add_argument("--remote", action="store_true", help="Permite enviar evidencia a OpenAI")
    parser.add_argument("--remote-limit", type=int, help="Entradas máximas elegibles, hasta dos llamadas por entrada")
    args = parser.parse_args(argv)
    if args.remote != bool(args.remote_limit) or (args.remote_limit is not None and args.remote_limit <= 0):
        parser.error("Usa --remote junto con --remote-limit N, donde N es positivo.")
    if args.remote and not available_model():
        parser.error("Configura OPENAI_API_KEY para usar --remote.")
    if args.progress_every <= 0:
        parser.error("--progress-every debe ser positivo.")
    source, output = args.input.resolve(), args.output.resolve()
    state = (args.state or output.with_name(output.name + ".sqlite3")).resolve()
    output_lock = output.with_name(output.name + ".lock").resolve()
    state_lock = state.with_name(state.name + ".lock").resolve()
    paths = (source, output, state, output_lock, state_lock, DB.resolve())
    if len(set(paths)) != len(paths):
        parser.error("Entrada, salida, checkpoint, bloqueo e índice deben ser archivos distintos.")
    existing = [path.stat() for path in paths if path.is_file()]
    if len({(info.st_dev, info.st_ino) for info in existing}) != len(existing):
        parser.error("Entrada, salida, checkpoint, bloqueo e índice no pueden ser enlaces al mismo archivo.")
    if not source.is_file():
        parser.error("Selecciona un archivo JSONL de entrada.")
    limit = args.remote_limit or 0
    started = perf_counter()
    try:
        output.parent.mkdir(parents=True, exist_ok=True)
        state.parent.mkdir(parents=True, exist_ok=True)
        with (source.open("rb") as stream,
              _exclusive_lock(output_lock, "Otro proceso está escribiendo este archivo de salida."),
              _locked_state(state) as connection):
            before = os.fstat(stream.fileno())
            input_hash = hashlib.file_digest(stream, "sha256").hexdigest()
            stream.seek(0)
            signature = _signature(input_hash, args.mode, limit, output)
            _initialize(connection, signature, output)
            with db.read_session():
                pass
            processed = _run(stream, connection, args.mode, limit, args.jobs, args.progress_every)
            after = os.fstat(stream.fileno())
            if ((before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns)
                    or signature != _signature(input_hash, args.mode, limit, output)):
                with connection:
                    connection.execute("UPDATE manifest SET signature='invalidado'")
                raise ValueError("La entrada, el índice o el motor cambió durante el procesamiento. Usa otro checkpoint.")
            summary = _publish(connection, output, processed)
    except (ValueError, OSError, sqlite3.Error) as error:
        parser.exit(2, f"{error}\n")
    except duckdb.Error:
        parser.exit(2, "No se pudo abrir o consultar el índice de Tarvia.\n")
    print(_encode({**summary, "elapsed_seconds": round(perf_counter() - started, 2), "output": str(output)}))
    return int(bool(summary["errors"]))


if __name__ == "__main__":
    raise SystemExit(main())
