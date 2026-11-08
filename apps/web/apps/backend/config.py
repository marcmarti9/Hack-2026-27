"""Configuración del servidor web y carga de la clave de contraste."""
import os
from pathlib import Path
from dotenv import dotenv_values, load_dotenv

ROOT = Path(__file__).resolve().parents[2]
USER_CONFIG = Path(os.getenv("XDG_CONFIG_HOME") or Path.home() / ".config") / "vigia" / ".env"
CONFIG_FILES = (USER_CONFIG, ROOT.parent.parent / ".env", ROOT / ".env")


def _valida(valor, prefijo):
    valor = (valor or "").strip()
    return valor.startswith(prefijo) and len(valor) > len(prefijo) and not valor.endswith("...")


def _clave(nombre, prefijo):
    return _valida(os.getenv(nombre), prefijo)


for path in CONFIG_FILES:
    load_dotenv(path)

# Un valor vacío o de ejemplo no debe ocultar la clave de otro archivo.
if not _clave("OPENAI_API_KEY", "sk-"):
    for path in CONFIG_FILES:
        key = dotenv_values(path).get("OPENAI_API_KEY")
        if _valida(key, "sk-"):
            os.environ["OPENAI_API_KEY"] = key.strip()
            break
    else:
        os.environ.pop("OPENAI_API_KEY", None)

OUT = Path(os.getenv("VIGIA_OUT", ROOT / "out"))
