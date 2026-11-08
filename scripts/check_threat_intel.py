"""Comprueba el recolector con fuentes controladas, sin acceso a red."""

import json
from datetime import datetime, timedelta, timezone
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
from zipfile import ZipFile

from apps.backend.tools import threat_intel as intel


NOW = datetime(2026, 11, 8, 3, 30, tzinfo=timezone.utc)
STAMP = "2026-11-08T03:28:00+00:00"
ID = "CVE-2024-23897"
OTHER = "CVE-2026-12345"
TAG = "cve_2026-11-08_0300Z"
NAME = "2026-11-08_delta_CVEs_at_0300Z.zip"
URL = f"{intel.CVE_DOWNLOAD}{TAG}/{NAME}"


def archive(records):
    stream = BytesIO()
    with ZipFile(stream, "w") as output:
        for filename, row in records.items():
            output.writestr(filename, json.dumps({"cveMetadata": row}))
    return stream.getvalue()


def kev(stamp=STAMP, identifier=ID):
    return json.dumps({"dateReleased": stamp, "count": 1, "vulnerabilities": [
        {"cveID": identifier, "dateAdded": "2026-11-08", "knownRansomwareCampaignUse": "Known",
         "shortDescription": "Este texto libre queda fuera del snapshot."},
    ]}).encode()


def release(url=URL, tag=TAG, name=NAME, stamp=STAMP):
    return {"tag_name": tag, "published_at": stamp, "draft": False, "prerelease": False, "assets": [
        {"name": name, "browser_download_url": url, "size": 150},
        {"name": "2026-11-08_all_CVEs_at_midnight.zip.zip", "browser_download_url": "https://invalid.test",
         "size": 650000000},
    ]}


def verify():
    previous_tag = "cve_2026-11-07_at_end_of_day"
    previous_name = "2026-11-07_delta_CVEs_at_end_of_day.zip"
    previous_url = f"{intel.CVE_DOWNLOAD}{previous_tag}/{previous_name}"
    yesterday = "2026-11-07T23:50:00+00:00"
    files = {
        intel.KEV_URL: kev(),
        intel.CVE_RELEASES: json.dumps([release(), release(previous_url, previous_tag, previous_name, yesterday)]).encode(),
        previous_url: archive({f"deltaCves/{ID}.json": {"cveId": ID, "dateUpdated": yesterday, "state": "PUBLISHED"}}),
        URL: archive({f"deltaCves/{ID}.json": {"cveId": ID, "dateUpdated": STAMP, "state": "REJECTED"}}),
    }
    calls = []

    def fetch(url, limit):
        calls.append(url)
        data = files[url]
        if isinstance(data, Exception):
            raise data
        assert len(data) <= limit
        return data

    with TemporaryDirectory() as temp:
        path = Path(temp) / "snapshot.json"
        assert intel.read_snapshot(path) == {}
        first = intel.update(path, fetch, NOW)
        assert first == intel.read_snapshot(path)
        with patch.dict("os.environ", {"VIGIA_THREAT_INTEL_PATH": str(path)}):
            assert intel.current_snapshot() == first
            assert intel.current_snapshot() is intel.current_snapshot()
        assert calls == [intel.KEV_URL, intel.CVE_RELEASES, previous_url, URL]
        assert first["sources"]["kev"]["records"][ID] == {"date_added": "2026-11-08", "ransomware": "known"}
        matches = intel.match_snapshot(first, [ID, OTHER, ID, "CVE inválida"])
        assert [(item["cve"], item["source"]) for item in matches] == [(ID, "kev"), (ID, "cve")]
        assert matches[-1]["state"] == "REJECTED"
        assert "shortDescription" not in path.read_text()
        assert not list(path.parent.glob(".intel-*"))

        calls.clear()
        intel.update(path, fetch, NOW + timedelta(hours=1))
        assert calls == [intel.KEV_URL, intel.CVE_RELEASES]
        files[intel.KEV_URL] = OSError("fallo de red")
        files[intel.CVE_RELEASES] = json.dumps([release()]).encode()
        degraded = intel.update(path, fetch, NOW + timedelta(hours=2))
        with patch.dict("os.environ", {"VIGIA_THREAT_INTEL_PATH": str(path)}):
            assert intel.current_snapshot() == degraded
        assert degraded["sources"]["kev"]["error"] == "unavailable"
        assert degraded["sources"]["kev"]["fetched_at"] != degraded["sources"]["kev"]["checked_at"]
        assert ID in degraded["sources"]["kev"]["records"]
        assert degraded["sources"]["cve"]["error"] is None

        files[intel.KEV_URL] = kev("2026-11-08T05:00:00+00:00", OTHER)
        files[intel.CVE_RELEASES] = json.dumps([release("https://127.0.0.1/file.zip")]).encode()
        calls.clear()
        recovered = intel.update(path, fetch, NOW + timedelta(hours=3))
        assert calls == [intel.KEV_URL, intel.CVE_RELEASES]
        assert ID not in recovered["sources"]["kev"]["records"]
        assert OTHER in recovered["sources"]["kev"]["records"]
        assert recovered["sources"]["cve"]["records"] == degraded["sources"]["cve"]["records"]
        assert recovered["sources"]["cve"]["error"] == "unavailable"

        files[intel.KEV_URL] = kev()  # Un catálogo anterior no pisa la última versión.
        files[intel.CVE_RELEASES] = b"{}"
        older = intel.update(path, fetch, NOW + timedelta(hours=4))
        assert older["sources"]["kev"]["error"] == "unavailable"
        assert OTHER in older["sources"]["kev"]["records"]
        path.write_text('{"schema":2}')
        assert intel.read_snapshot(path) == {}

    for payload in (archive({"../escape.json": {}}),
                    archive({f"deltaCves/{ID}.json": {"cveId": OTHER, "dateUpdated": STAMP, "state": "PUBLISHED"}})):
        try:
            intel._cve_records(payload)
        except ValueError:
            pass
        else:
            raise AssertionError("Aceptó una entrada ZIP inválida")


if __name__ == "__main__":
    verify()
    print("Inteligencia: deltas, rechazos, datos estructurados y recuperación de fuentes comprobados")
