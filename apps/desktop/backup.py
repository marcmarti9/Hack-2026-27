"""Instantáneas del perfil de Vigía y destinos de copia."""
import base64
import hashlib
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import uuid
import zipfile
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

MODELS = ("3-2-1", "3-2-1-1", "Personalizado")
CLOUD_HELPER = Path(__file__).with_name("resources") / "vigia_codigo_s3.py"


def cloud_destination(code):
    try:
        uri = code.strip()
        if uri.startswith("VIGIA-S3:"):
            uri = base64.b64decode(uri.removeprefix("VIGIA-S3:"), validate=True).decode("ascii")
        address = urlsplit(uri)
        bucket, prefix = address.netloc, address.path.strip("/")
        valid_bucket = re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", bucket)
        valid_prefix = not prefix or all(re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*", segment)
                                         for segment in prefix.split("/"))
        if (address.scheme != "s3" or not valid_bucket or not valid_prefix or address.query
                or address.fragment or ".." in bucket or len(uri) > 850):
            raise ValueError
        return bucket, prefix
    except (UnicodeError, ValueError) as exc:
        raise ValueError("Introduce un código de conexión Vigía o una ruta s3://bucket/carpeta.") from exc


def destinations(plan, profile):
    model = plan["model"]
    if model not in MODELS:
        raise ValueError("Selecciona una plantilla de copia.")
    folders = []
    for key, label in (("local", "Local"), ("usb", "USB")):
        for entry in plan[key]:
            path = Path(entry).expanduser().resolve()
            if path.is_relative_to(profile.resolve()) or (path.exists() and not path.is_dir()):
                raise ValueError("Elige una carpeta de destino fuera del perfil de Vigía.")
            if any(path == previous for _, previous in folders):
                raise ValueError("Hay una carpeta repetida en los destinos.")
            folders.append((label, path))
    cloud = cloud_destination(plan["cloud"]) if plan["cloud"] else None
    immutable = cloud_destination(plan["immutable"]) if plan["immutable"] else None
    if cloud and immutable and cloud[0] == immutable[0]:
        raise ValueError("La copia en nube y la inmutable necesitan buckets distintos.")
    if model != "Personalizado" and not (folders and cloud):
        raise ValueError(f"{model} requiere al menos una carpeta local o USB y un destino en la nube.")
    if model == "3-2-1-1" and not immutable:
        raise ValueError("3-2-1-1 requiere también un depósito con Object Lock.")
    if not (folders or cloud or immutable):
        raise ValueError("Añade al menos un destino.")
    days = plan["days"]
    if not isinstance(days, int) or not 1 <= days <= 3650:
        raise ValueError("La retención debe estar entre 1 y 3.650 días.")
    return folders, cloud, immutable


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").digest()


def make_archive(profile, workdir, stamp):
    contents = []
    # La API de SQLite incluye transacciones confirmadas que aún estén en el WAL.
    for name in ("session.sqlite", "review.sqlite"):
        original = profile / name
        snapshot = workdir / name
        with closing(sqlite3.connect(original.resolve().as_uri() + "?mode=ro", uri=True)) as source:
            with closing(sqlite3.connect(snapshot)) as target:
                source.backup(target)
        contents.append(snapshot)
    settings = profile / "settings.ini"
    if settings.is_file():
        copy = workdir / settings.name
        shutil.copyfile(settings, copy)
        contents.append(copy)
    archive = workdir / f"Vigia-{stamp:%Y%m%d-%H%M%S}-{uuid.uuid4().hex[:12]}.zip"
    manifest = {"format": 1, "created_at": stamp.isoformat(),
                "sha256": {path.name: digest(path).hex() for path in contents}}
    with zipfile.ZipFile(archive, "x", compression=zipfile.ZIP_DEFLATED) as bundle:
        for path in contents:
            bundle.write(path, path.name)
        bundle.writestr("manifest.json", json.dumps(manifest, indent=2))
    return archive


def copy_archive(archive, folder, checksum):
    if not folder.is_dir():
        raise ValueError("La carpeta de destino no está disponible. Comprueba la unidad.")
    root = folder / "Vigia"
    root.mkdir(mode=0o700, exist_ok=True)
    if root.is_symlink() or not root.is_dir():
        raise ValueError("La carpeta Vigia del destino debe ser un directorio normal.")
    slot = root / archive.stem
    slot.mkdir(mode=0o700)
    pending = slot / ".copia-parcial"
    final = slot / archive.name
    try:
        with archive.open("rb") as source, os.fdopen(os.open(pending, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), "wb") as output:
            shutil.copyfileobj(source, output)
            output.flush()
            os.fsync(output.fileno())
        if digest(pending) != checksum:
            raise ValueError("La copia no coincide con la suma SHA-256 del original.")
        pending.rename(final)
    except (OSError, ValueError):
        pending.unlink(missing_ok=True)
        slot.rmdir()
        raise
    return str(final)


def upload_archive(archive, destination, checksum, retain_until=None):
    aws = shutil.which("aws")
    if not aws:
        raise ValueError("Instala AWS CLI v2 y configura un perfil con acceso al bucket.")
    bucket, prefix = destination
    key = f"{prefix}/{archive.name}" if prefix else archive.name
    encoded = base64.b64encode(checksum).decode("ascii")
    command = [aws, "s3api", "put-object", "--bucket", bucket, "--key", key, "--body", str(archive),
               "--if-none-match", "*", "--checksum-algorithm", "SHA256", "--checksum-sha256", encoded,
               "--output", "json", "--no-cli-pager", "--cli-connect-timeout", "10", "--cli-read-timeout", "40"]
    if retain_until:
        command += ["--object-lock-mode", "COMPLIANCE", "--object-lock-retain-until-date", retain_until.isoformat()]
    env = dict(os.environ, AWS_IGNORE_CONFIGURED_ENDPOINT_URLS="true", AWS_CLI_AUTO_PROMPT="off", AWS_MAX_ATTEMPTS="2")
    if "LD_LIBRARY_PATH_ORIG" in env:
        env["LD_LIBRARY_PATH"] = env["LD_LIBRARY_PATH_ORIG"]
    elif getattr(sys, "frozen", False):
        env.pop("LD_LIBRARY_PATH", None)
    result = subprocess.run(command, capture_output=True, text=True, env=env, timeout=180, check=False)
    if result.returncode:
        raise ValueError("S3 rechazó la copia. Revisa el acceso del perfil y Object Lock si aplica.")
    try:
        response = json.loads(result.stdout)
        verified = response.get("ChecksumSHA256") == encoded and (not retain_until or response.get("VersionId"))
    except (AttributeError, ValueError):
        verified = False
    if not verified:
        raise ValueError("S3 recibió la solicitud pero no se pudo verificar la copia. Revisa el bucket.")
    suffix = f" · Retenida hasta {retain_until:%d/%m/%Y UTC}" if retain_until else ""
    return f"s3://{bucket}/{key}{suffix}"


def run_backup(profile, plan):
    folders, cloud, immutable = destinations(plan, profile)
    stamp = datetime.now(timezone.utc)
    rows = []
    with tempfile.TemporaryDirectory(prefix="vigia-backup-") as temporary:
        archive = make_archive(profile, Path(temporary), stamp)
        checksum = digest(archive)

        def record(label, target, operation):
            try:
                rows.append((label, "Verificada", operation()))
            except (OSError, ValueError, subprocess.SubprocessError) as exc:
                rows.append((label, "Revisar", f"{target} · {exc}"))

        for label, folder in folders:
            record(label, folder, lambda: copy_archive(archive, folder, checksum))
        if cloud:
            record("Nube", cloud[0], lambda: upload_archive(archive, cloud, checksum))
        if immutable:
            retain = stamp + timedelta(days=plan["days"])
            record("Inmutable", immutable[0], lambda: upload_archive(archive, immutable, checksum, retain))
    return rows
