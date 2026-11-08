"""Actualiza señales CVE públicas en un snapshot local. No modifica expedientes ni guías."""

import argparse
import json
import os
import re
import tempfile
import time
import zlib
from datetime import date, datetime, timedelta, timezone
from functools import lru_cache
from io import BytesIO
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener
from zipfile import BadZipFile, ZipFile

KEV_URL = "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"
CVE_RELEASES = "https://api.github.com/repos/CVEProject/cvelistV5/releases?per_page=30"
CVE_DOWNLOAD = "https://github.com/CVEProject/cvelistV5/releases/download/"
SOURCE_URLS = {"kev": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
               "cve": "https://github.com/CVEProject/cvelistV5#releases"}
INTERVAL = 3600
SNAPSHOT_LIMIT = 4 * 1024 * 1024
ARCHIVE_LIMIT = 12 * 1024 * 1024
EXPANDED_LIMIT = 32 * 1024 * 1024
MEMBER_LIMIT = 512 * 1024
CVE_LIMIT = 12000
CVE_ID = re.compile(r"CVE-\d{4}-\d{4,12}", re.ASCII)
TAG = re.compile(r"cve_(\d{4}-\d{2}-\d{2})_((?:[01]\d|2[0-3])00Z|at_end_of_day)", re.ASCII)
MEMBER = re.compile(r"deltaCves/(CVE-\d{4}-\d{4,12})\.json", re.ASCII)


class _AssetRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        target = urlsplit(newurl)
        if (req.full_url.startswith(CVE_DOWNLOAD) and target.scheme == "https"
                and target.netloc in {"release-assets.githubusercontent.com", "objects.githubusercontent.com"}):
            return super().redirect_request(req, fp, code, msg, headers, newurl)
        return None


def _fetch(url: str, limit: int) -> bytes:
    request = Request(url, headers={"User-Agent": "Vigia-Threat-Intel/1"})
    with build_opener(_AssetRedirect()).open(request, timeout=15) as response:
        data = response.read(limit + 1)
    if len(data) > limit:
        raise ValueError("Fuente demasiado grande")
    return data


def _timestamp(value: str) -> str:
    if not isinstance(value, str) or len(value) > 40:
        raise ValueError("Fecha inválida")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.utcoffset() is None:
        raise ValueError("Fecha sin zona horaria")
    return parsed.astimezone(timezone.utc).isoformat(timespec="microseconds")


def _identifier(value: str) -> str:
    if not isinstance(value, str) or not CVE_ID.fullmatch(value):
        raise ValueError("Identificador CVE inválido")
    return value


def _kev_fields(added, ransomware):
    if ransomware not in {"known", "unknown"}:
        raise ValueError("Señal de ransomware inválida")
    return {"date_added": date.fromisoformat(added).isoformat(), "ransomware": ransomware}


def _cve_fields(modified, state):
    if state not in {"PUBLISHED", "REJECTED"}:
        raise ValueError("Estado CVE inválido")
    return {"modified_at": _timestamp(modified), "state": state}


def _kev(fetch):
    body = json.loads(fetch(KEV_URL, SNAPSHOT_LIMIT))
    rows = body["vulnerabilities"]
    if not isinstance(rows, list) or not rows or len(rows) != body["count"] or len(rows) > CVE_LIMIT:
        raise ValueError("Catálogo KEV incompleto")
    records = {_identifier(row["cveID"]): _kev_fields(row["dateAdded"], row["knownRansomwareCampaignUse"].lower())
               for row in rows}
    if len(records) != len(rows):
        raise ValueError("Identificadores KEV repetidos")
    return {"published_at": _timestamp(body["dateReleased"]), "records": records}


def _cve_archives(releases):
    if not isinstance(releases, list) or len(releases) > 30:
        raise ValueError("Lista de publicaciones CVE inválida")
    archives = []
    for release in releases:
        if release["draft"] or release["prerelease"] or not (tag := TAG.fullmatch(release["tag_name"])):
            continue
        day, hour = tag.groups()
        day = date.fromisoformat(day).isoformat()
        name = f"{day}_delta_CVEs_{hour if hour == 'at_end_of_day' else 'at_' + hour}.zip"
        expected = f"{CVE_DOWNLOAD}{tag.group()}/{name}"
        asset = next((item for item in release["assets"] if item["name"] == name), None)
        if asset is None:
            continue
        if asset["browser_download_url"] != expected or not 0 < asset["size"] <= ARCHIVE_LIMIT:
            raise ValueError("URL o tamaño de archivo CVE inválido")
        archives.append((_timestamp(release["published_at"]), day, hour, expected))
    if not archives:
        raise ValueError("Publicación de deltas CVE ausente")
    # Cada ZIP horario acumula los cambios desde medianoche. Basta el último por fecha.
    # Al cambiar de día, se prefiere el ZIP de cierre del anterior si ya está publicado.
    by_day = {}
    for item in sorted(archives, key=lambda item: (item[1], item[2] == "at_end_of_day", item[0])):
        by_day[item[1]] = item
    return list(by_day.values())[-2:]


def _cve_records(payload: bytes):
    with ZipFile(BytesIO(payload)) as archive:
        entries = archive.infolist()
        if len(entries) > CVE_LIMIT or sum(member.file_size for member in entries) > EXPANDED_LIMIT:
            raise ValueError("Contenido CVE demasiado grande")
        records = {}
        for member in entries:
            if member.filename == "deltaCves/" and member.is_dir():
                continue
            name = MEMBER.fullmatch(member.filename)
            if not name or not 0 < member.file_size <= MEMBER_LIMIT or name[1] in records:
                raise ValueError("Entrada de archivo CVE inválida")
            with archive.open(member) as file:
                payload = file.read(MEMBER_LIMIT + 1)
            if len(payload) != member.file_size:
                raise ValueError("Registro CVE de tamaño inválido")
            metadata = json.loads(payload)["cveMetadata"]
            if metadata["cveId"] != name[1]:
                raise ValueError("Nombre de archivo CVE incoherente")
            records[name[1]] = _cve_fields(metadata["dateUpdated"], metadata["state"])
    return records


def _cve(fetch, previous, now):
    archives = _cve_archives(json.loads(fetch(CVE_RELEASES, SNAPSHOT_LIMIT)))
    records = dict(previous.get("records", {}))
    cursors = [url for _, _, _, url in archives]
    for url in cursors:
        if url in previous.get("cursors", []):
            continue
        for identifier, item in _cve_records(fetch(url, ARCHIVE_LIMIT)).items():
            if item["modified_at"] >= records.get(identifier, {}).get("modified_at", ""):
                records[identifier] = item
    cutoff = (now - timedelta(days=7)).isoformat(timespec="microseconds")
    records = {key: item for key, item in records.items() if item["modified_at"] >= cutoff}
    if len(records) > CVE_LIMIT:
        raise ValueError("Demasiados registros CVE")
    return {"published_at": max(item[0] for item in archives), "cursors": cursors, "records": records}


def read_snapshot(path: Path | None = None) -> dict:
    """Lee el snapshot local sin tocar la red. Devuelve {} si falta o es inválido."""
    if path is None:
        configured = os.environ.get("VIGIA_THREAT_INTEL_PATH")
        if not configured:
            return {}
        path = Path(configured)
    try:
        with Path(path).open("rb") as file:
            data = file.read(SNAPSHOT_LIMIT + 1)
        if len(data) > SNAPSHOT_LIMIT:
            return {}
        body = json.loads(data)
        if body.get("schema") != 1 or not isinstance(body.get("sources"), dict):
            return {}
        sources = {}
        for name, url in SOURCE_URLS.items():
            src = body["sources"].get(name)
            if src is None:
                continue
            rows = src["records"]
            if not isinstance(rows, dict) or len(rows) > CVE_LIMIT:
                return {}
            records = {_identifier(key): (_kev_fields(row["date_added"], row["ransomware"]) if name == "kev"
                                         else _cve_fields(row["modified_at"], row["state"]))
                       for key, row in rows.items()}
            sources[name] = {"url": url, "records": records, "checked_at": _timestamp(src["checked_at"]),
                             "fetched_at": _timestamp(src["fetched_at"]) if src.get("fetched_at") else None,
                             "published_at": _timestamp(src["published_at"]) if src.get("published_at") else None,
                             "error": "unavailable" if src.get("error") else None}
            if name == "cve":
                cursors = src.get("cursors", [])
                if not isinstance(cursors, list) or len(cursors) > 2 or any(
                        not isinstance(item, str) or len(item) > 200 or not item.startswith(CVE_DOWNLOAD)
                        for item in cursors):
                    return {}
                sources[name]["cursors"] = cursors
        return {"schema": 1, "updated_at": _timestamp(body["updated_at"]), "sources": sources}
    except (AttributeError, KeyError, OSError, OverflowError, TypeError, ValueError, RecursionError):
        return {}


@lru_cache(maxsize=4)
def _snapshot_version(path: Path, version: tuple) -> dict:
    return read_snapshot(path)


def current_snapshot() -> dict:
    """Lee una versión por sustitución atómica. Los consumidores no modifican el resultado."""
    configured = os.environ.get("VIGIA_THREAT_INTEL_PATH")
    if not configured:
        return {}
    path = Path(configured)
    try:
        stat = path.stat()
    except OSError:
        return {}
    return _snapshot_version(path, (stat.st_dev, stat.st_ino, stat.st_mtime_ns, stat.st_size))


def match_snapshot(snapshot: dict, cve_ids) -> list[dict]:
    """Proyecta únicamente coincidencias exactas de CVE con su fuente y fechas."""
    matches = []
    identifiers = dict.fromkeys(value for value in cve_ids if isinstance(value, str) and CVE_ID.fullmatch(value))
    for identifier in identifiers:
        for name, src in snapshot.get("sources", {}).items():
            item = src["records"].get(identifier)
            if item is not None:
                url = (f"https://www.cve.org/CVERecord?id={identifier}" if name == "cve" else SOURCE_URLS[name])
                matches.append({"cve": identifier, "source": name, "url": url, "fetched_at": src["fetched_at"],
                                "published_at": src["published_at"], "error": src["error"], **item})
    return matches


def _write_snapshot(path: Path, snapshot: dict):
    data = json.dumps(snapshot, ensure_ascii=True, separators=(",", ":")).encode()
    if len(data) > SNAPSHOT_LIMIT:
        raise ValueError("Snapshot demasiado grande")
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".intel-", delete=False) as file:
            temp = Path(file.name)
            file.write(data)
            file.flush()
            os.fsync(file.fileno())
        temp.replace(path)
    finally:
        if temp is not None:
            temp.unlink(missing_ok=True)


def update(path: Path, fetch=_fetch, now: datetime | None = None) -> dict:
    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    checked = _timestamp(now.isoformat())
    previous = read_snapshot(path).get("sources", {})
    sources = {}
    for name, url in SOURCE_URLS.items():
        prior = previous.get(name, {"records": {}, "published_at": None, "fetched_at": None})
        try:
            fresh = _kev(fetch) if name == "kev" else _cve(fetch, prior, now)
            if prior["published_at"] and fresh["published_at"] < prior["published_at"]:
                raise ValueError("La fuente retrocedió")
            src = {**fresh, "fetched_at": checked, "error": None}
        except (AttributeError, BadZipFile, KeyError, OSError, OverflowError, RuntimeError,
                TypeError, ValueError, zlib.error):
            src = {**prior, "error": "unavailable"}
        sources[name] = {**src, "url": url, "checked_at": checked}
    snapshot = {"schema": 1, "updated_at": checked, "sources": sources}
    _write_snapshot(path, snapshot)
    return snapshot


def main() -> int:
    parser = argparse.ArgumentParser(description="Recolector horario de inteligencia pública de Vigía")
    parser.add_argument("--once", action="store_true", help="Consulta ambas fuentes y termina")
    parser.add_argument("--output", type=Path, default=os.environ.get("VIGIA_THREAT_INTEL_PATH"))
    args = parser.parse_args()
    if args.output is None:
        parser.error("Configura VIGIA_THREAT_INTEL_PATH o indica --output")
    while True:
        started = time.monotonic()
        snapshot = update(args.output)
        states = {name: src["error"] or "ok" for name, src in snapshot["sources"].items()}
        print(f"Inteligencia {snapshot['updated_at']}: {states}", flush=True)
        if args.once:
            return 0 if all(state == "ok" for state in states.values()) else 1
        time.sleep(max(0, INTERVAL - (time.monotonic() - started)))


if __name__ == "__main__":
    raise SystemExit(main())
