"""Genera un código de destino para Vigía. No instala servicios ni usa credenciales."""
import argparse
import base64

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("bucket", help="Nombre del bucket de destino")
parser.add_argument("--carpeta", default="vigia", help="Prefijo dentro del bucket")
args = parser.parse_args()
uri = f"s3://{args.bucket}/{args.carpeta.strip('/')}"
print("VIGIA-S3:" + base64.b64encode(uri.encode("ascii")).decode("ascii"))
