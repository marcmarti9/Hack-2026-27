"""Rutas del motor de Vigía; las instalaciones pueden pasar rutas absolutas."""
import os
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[2]
load_dotenv(ROOT / ".env")
DATA = Path(os.getenv("VIGIA_DATA_DIR") or ROOT / "data" / "dataset").expanduser().resolve()
OUT = Path(os.getenv("VIGIA_OUT_DIR") or ROOT / "out").expanduser().resolve()
DB = OUT / "tarvia.duckdb"
