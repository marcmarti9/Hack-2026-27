"""Genera la aplicación congelada para el sistema operativo de compilación."""
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "out" / "packaging"
VERSION = "0.5.0"


def main() -> None:
    # https://pyinstaller.org/en/stable/usage.html
    subprocess.run([
        sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean",
        "--name", "Vigia", "--onedir", "--windowed",
        "--paths", str(ROOT), "--collect-data", "tzdata",
        # DuckDB importa estos tipos en su extensión nativa al convertir parámetros.
        "--hidden-import", "uuid", "--hidden-import", "decimal",
        "--add-data", f"{ROOT / 'apps' / 'desktop' / 'brand'}:apps/desktop/brand",
        "--add-data", f"{ROOT / 'apps' / 'desktop' / 'resources'}:apps/desktop/resources",
        "--distpath", str(OUT / "dist"), "--workpath", str(OUT / "work"),
        "--specpath", str(OUT), str(ROOT / "apps" / "desktop" / "entry.py"),
    ], check=True, cwd=ROOT)


if __name__ == "__main__":
    main()
