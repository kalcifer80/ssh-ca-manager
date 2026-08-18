"""Index ueber den Dateibaum.

Wahrheit bleibt das Dateisystem — das Bash-Skript soll weiter parallel nutzbar
sein. Die SQLite-Datei ist nur ein Cache, damit die Listenansicht nicht bei
jedem Oeffnen n-mal ``ssh-keygen -L`` aufrufen muss. Ein Eintrag wird neu
gelesen, sobald sich Groesse oder mtime der Zertifikatsdatei aendern; ein
vollstaendiger Neuaufbau ist jederzeit gefahrlos moeglich.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from pathlib import Path

from .model import CertInfo

_SCHEMA = """
CREATE TABLE IF NOT EXISTS certs (
    path            TEXT PRIMARY KEY,
    user            TEXT,
    host            TEXT,
    key_id          TEXT,
    serial          TEXT,
    cert_type       TEXT,
    principals      TEXT,
    valid_from      TEXT,
    valid_to        TEXT,
    forever         INTEGER,
    pubkey_fp       TEXT,
    ca_fp           TEXT,
    extensions      TEXT,
    critical        TEXT,
    revoked         INTEGER,
    stored          INTEGER,
    parse_error     TEXT,
    file_mtime      REAL,
    file_size       INTEGER
);
CREATE INDEX IF NOT EXISTS certs_user ON certs(user);
"""


def _iso(value: datetime | None) -> str:
    return value.isoformat() if value else ""


def _dt(value: str) -> datetime | None:
    try:
        return datetime.fromisoformat(value) if value else None
    except ValueError:
        return None


class CertIndex:
    def __init__(self, db_path: Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(_SCHEMA)
        self.conn.commit()
        try:
            self.db_path.chmod(0o600)
        except OSError:
            pass

    def close(self) -> None:
        self.conn.close()

    # ------------------------------------------------------------ Schreiben
    def put(self, info: CertInfo) -> None:
        stat = info.cert_path.stat() if info.cert_path.is_file() else None
        self.conn.execute(
            """
            INSERT INTO certs VALUES (
                :path, :user, :host, :key_id, :serial, :cert_type, :principals,
                :valid_from, :valid_to, :forever, :pubkey_fp, :ca_fp,
                :extensions, :critical, :revoked, :stored, :parse_error,
                :file_mtime, :file_size
            )
            ON CONFLICT(path) DO UPDATE SET
                user=excluded.user, host=excluded.host, key_id=excluded.key_id,
                serial=excluded.serial, cert_type=excluded.cert_type,
                principals=excluded.principals, valid_from=excluded.valid_from,
                valid_to=excluded.valid_to, forever=excluded.forever,
                pubkey_fp=excluded.pubkey_fp, ca_fp=excluded.ca_fp,
                extensions=excluded.extensions, critical=excluded.critical,
                revoked=excluded.revoked, stored=excluded.stored,
                parse_error=excluded.parse_error,
                file_mtime=excluded.file_mtime, file_size=excluded.file_size
            """,
            {
                "path": str(info.cert_path),
                "user": info.user,
                "host": info.host,
                "key_id": info.key_id,
                "serial": info.serial,
                "cert_type": info.cert_type,
                "principals": json.dumps(info.principals),
                "valid_from": _iso(info.valid_from),
                "valid_to": _iso(info.valid_to),
                "forever": int(info.forever),
                "pubkey_fp": info.pubkey_fp,
                "ca_fp": info.ca_fp,
                "extensions": json.dumps(info.extensions),
                "critical": json.dumps(info.critical_options),
                "revoked": int(info.revoked),
                "stored": int(info.stored),
                "parse_error": info.parse_error,
                "file_mtime": stat.st_mtime if stat else 0.0,
                "file_size": stat.st_size if stat else 0,
            },
        )
        self.conn.commit()

    def drop(self, path: Path) -> None:
        self.conn.execute("DELETE FROM certs WHERE path = ?", (str(path),))
        self.conn.commit()

    def clear(self) -> None:
        self.conn.execute("DELETE FROM certs")
        self.conn.commit()

    # --------------------------------------------------------------- Lesen
    def is_current(self, cert_path: Path) -> bool:
        """True, wenn der Index den aktuellen Dateistand kennt."""
        if not cert_path.is_file():
            return False
        row = self.conn.execute(
            "SELECT file_mtime, file_size FROM certs WHERE path = ?",
            (str(cert_path),),
        ).fetchone()
        if row is None:
            return False
        stat = cert_path.stat()
        return (
            abs(row["file_mtime"] - stat.st_mtime) < 1e-6
            and row["file_size"] == stat.st_size
        )

    def get(self, cert_path: Path) -> CertInfo | None:
        row = self.conn.execute(
            "SELECT * FROM certs WHERE path = ?", (str(cert_path),)
        ).fetchone()
        return self._to_info(row) if row else None

    def all(self, include_stored: bool = False) -> list[CertInfo]:
        query = "SELECT * FROM certs"
        if not include_stored:
            query += " WHERE stored = 0"
        query += " ORDER BY user, host"
        return [self._to_info(row) for row in self.conn.execute(query)]

    @staticmethod
    def _to_info(row: sqlite3.Row) -> CertInfo:
        info = CertInfo(cert_path=Path(row["path"]))
        info.user = row["user"] or ""
        info.host = row["host"] or ""
        info.key_id = row["key_id"] or "-"
        info.serial = row["serial"] or "-"
        info.cert_type = row["cert_type"] or "-"
        info.principals = json.loads(row["principals"] or "[]")
        info.valid_from = _dt(row["valid_from"])
        info.valid_to = _dt(row["valid_to"])
        info.forever = bool(row["forever"])
        info.pubkey_fp = row["pubkey_fp"] or "-"
        info.ca_fp = row["ca_fp"] or "-"
        info.extensions = json.loads(row["extensions"] or "{}")
        info.critical_options = json.loads(row["critical"] or "{}")
        info.revoked = bool(row["revoked"])
        info.stored = bool(row["stored"])
        info.parse_error = row["parse_error"] or ""
        return info


def refresh_index(ca, index: CertIndex, force: bool = False) -> list[CertInfo]:
    """Gleicht den Index mit dem Dateibaum ab und liefert die aktiven Zertifikate."""
    cert_paths = list(ca.iter_active_certificates())
    seen = {str(path) for path in cert_paths}

    # Der Widerrufsstatus haengt an der KRL, nicht an der Datei — er muss also
    # auch fuer Treffer im Cache neu ermittelt werden. Das geschieht fuer alle
    # Zertifikate in einem einzigen ssh-keygen-Aufruf; sonst haette der Cache
    # zwar 'ssh-keygen -L' eingespart, dafuer aber je Zertifikat weiterhin ein
    # 'ssh-keygen -Q' gekostet.
    revoked = ca.revoked_paths(cert_paths)

    result: list[CertInfo] = []
    for cert_path in cert_paths:
        if not force and index.is_current(cert_path):
            cached = index.get(cert_path)
            if cached is not None:
                cached.revoked = cert_path in revoked
                result.append(cached)
                continue
        info = ca.load_certificate(cert_path, revoked=cert_path in revoked)
        index.put(info)
        result.append(info)

    for known in index.all():
        if str(known.cert_path) not in seen:
            index.drop(known.cert_path)
    return result
