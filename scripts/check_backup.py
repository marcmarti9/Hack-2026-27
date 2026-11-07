"""Comprueba instantáneas, destinos y contrato S3 sin realizar envíos externos."""
import base64
import hashlib
import json
import sqlite3
import subprocess
import sys
import zipfile
from contextlib import closing
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from apps.desktop import backup


def main():
    with TemporaryDirectory() as directory:
        root = Path(directory)
        profile = root / "perfil con espacios"
        profile.mkdir()
        local = root / "copias locales"
        local.mkdir()
        missing_usb = root / "usb desconectada"
        with closing(sqlite3.connect(profile / "session.sqlite")) as account:
            account.execute("PRAGMA journal_mode=WAL")
            account.execute("CREATE TABLE account (name TEXT)")
            account.execute("INSERT INTO account VALUES ('analista')")
            account.commit()
            with closing(sqlite3.connect(profile / "review.sqlite")) as reviews:
                reviews.execute("CREATE TABLE review (id INT)")
                reviews.commit()
            (profile / "settings.ini").write_text("[General]\ntheme=dark\n")
            (profile / ".env").write_text("NO_INCLUIR=fixture")
            plan = {"model": "Personalizado", "local": [str(local)], "usb": [str(missing_usb)],
                    "cloud": "", "immutable": "", "days": 30}
            rows = backup.run_backup(profile, plan)
        assert [row[:2] for row in rows] == [("Local", "Verificada"), ("USB", "Revisar")]
        archive = Path(rows[0][2])
        assert archive.is_file() and not missing_usb.exists()
        with zipfile.ZipFile(archive) as bundle:
            manifest = json.loads(bundle.read("manifest.json"))
            assert set(manifest["sha256"]) == {"session.sqlite", "review.sqlite", "settings.ini"}
            assert set(bundle.namelist()) == set(manifest["sha256"]) | {"manifest.json"}
            for filename, checksum in manifest["sha256"].items():
                assert hashlib.sha256(bundle.read(filename)).hexdigest() == checksum
            recovered = root / "session.sqlite"
            recovered.write_bytes(bundle.read("session.sqlite"))
            with closing(sqlite3.connect(recovered)) as connection:
                assert connection.execute("SELECT name FROM account").fetchone() == ("analista",)

        code = subprocess.check_output([sys.executable, str(backup.CLOUD_HELPER), "example-bucket"], text=True)
        assert backup.cloud_destination(code) == ("example-bucket", "vigia")
        invalid = ("https://example.org/path", "s3://--flag/path", "s3://example-bucket/../escape", "VIGIA-S3:@")
        for value in invalid:
            try:
                backup.cloud_destination(value)
            except ValueError:
                pass
            else:
                raise AssertionError(value)

        with patch.object(backup.shutil, "which", return_value="/mock/aws"):
            checksum = base64.b64encode(backup.digest(archive)).decode()
            response = json.dumps({"ChecksumSHA256": checksum, "VersionId": "version-de-prueba"})
            with patch.object(backup.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, response, "")) as run:
                from datetime import datetime, timezone
                retain = datetime(2030, 1, 1, tzinfo=timezone.utc)
                remote = backup.upload_archive(archive, ("example-bucket", "vigia"), backup.digest(archive), retain)
                assert remote.startswith("s3://example-bucket/vigia/Vigia-")
                arguments = run.call_args.args[0]
                for name, expected in (("--object-lock-mode", "COMPLIANCE"), ("--if-none-match", "*"),
                                       ("--checksum-sha256", checksum),
                                       ("--object-lock-retain-until-date", retain.isoformat())):
                    assert arguments[arguments.index(name) + 1] == expected
                assert run.call_args.kwargs["env"]["AWS_IGNORE_CONFIGURED_ENDPOINT_URLS"] == "true"
        print("Copias: instantánea WAL, manifiesto, fallo parcial USB, código S3 y contrato de retención verificados.")


if __name__ == "__main__":
    main()
