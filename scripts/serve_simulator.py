"""Arranca la API oficial montada en solo lectura y separa su registro de efectos."""
import argparse
import sys
from pathlib import Path

import uvicorn


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bind", default="127.0.0.1", choices=("127.0.0.1", "0.0.0.0"))
    parser.add_argument("--port", default=8765, type=int)
    args = parser.parse_args()
    sys.path.insert(0, "/dataset/06_herramientas")
    import mock_soc_api

    mock_soc_api.LOGFILE = str(Path("/tmp/containment_log.jsonl"))
    uvicorn.run(mock_soc_api.app, host=args.bind, port=args.port, access_log=False)


if __name__ == "__main__":
    main()
