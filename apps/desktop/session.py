"""Cuenta local de Vigía, separada de los datos del reto."""
import hashlib
import hmac
import secrets
import sqlite3
from contextlib import closing
from pathlib import Path

ITERATIONS = 600_000


class Account:
    def __init__(self, directory: Path):
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.path = directory / "session.sqlite"
        with closing(sqlite3.connect(self.path)) as connection, connection:
            connection.execute("""
                CREATE TABLE IF NOT EXISTS account (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    name TEXT NOT NULL, salt BLOB NOT NULL, digest BLOB NOT NULL
                )
            """)

    def name(self) -> str | None:
        with closing(sqlite3.connect(self.path)) as connection:
            row = connection.execute("SELECT name FROM account WHERE id = 1").fetchone()
        return row[0] if row else None

    @staticmethod
    def _hash(password: str, salt: bytes) -> bytes:
        return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, ITERATIONS)

    def create(self, name: str, password: str) -> None:
        name = name.strip()
        if not 1 <= len(name) <= 80 or not 10 <= len(password) <= 128:
            raise ValueError("Indica un nombre y una contraseña de entre 10 y 128 caracteres.")
        salt = secrets.token_bytes(32)
        try:
            with closing(sqlite3.connect(self.path)) as connection, connection:
                connection.execute("INSERT INTO account VALUES (1, ?, ?, ?)",
                                   (name, salt, self._hash(password, salt)))
        except sqlite3.IntegrityError as exc:
            raise ValueError("Ya existe una cuenta local. Vuelve a abrir Vigía para iniciar sesión.") from exc

    def verify(self, password: str) -> bool:
        if len(password) > 128:
            return False
        with closing(sqlite3.connect(self.path)) as connection:
            row = connection.execute("SELECT salt, digest FROM account WHERE id = 1").fetchone()
        return bool(row and hmac.compare_digest(row[1], self._hash(password, row[0])))
