"""Pfade und Konstanten.

Das Layout ist absichtlich identisch zu ssh-ca-tool.sh, damit das Bash-Skript
und die GUI auf demselben Datenbestand arbeiten koennen.

    ~/.ssh-ca/
        ca/                     CA-Key, KRL, Seriennummernzaehler
        <user>/<host>/          Key, Public Key, Zertifikat
        <user>/<host>/archive/  jeweils die letzte abgeloeste Version
        revoked/<user>/<host>/<zeitstempel>/
        backups/
        principals.conf
        templates.json          (neu: Vorlagen der GUI)
        index.sqlite            (neu: Index der GUI)
        ssh-ca.log
"""

from __future__ import annotations

import os
from pathlib import Path

APP_NAME = "SSH-CA Manager"
APP_VERSION = "0.3.4"


class CaError(RuntimeError):
    """Fachlicher Fehler, dessen Text direkt anzeigbar ist.

    Liegt in der untersten Schicht, damit auch die Pfadbildung ihn werfen kann;
    ``sshca.ca`` exportiert ihn weiter, alle bisherigen Importe bleiben gueltig.
    """

#: Dateiformat der erzeugten Schluessel. ed25519 mit 100 KDF-Runden.
KEY_TYPE = "ed25519"
KDF_ROUNDS = 100

DEFAULT_VALIDITY = "+1h"

#: Verzeichnisnamen, die direkt unter der Basis liegen und keine Benutzer sind.
RESERVED_NAMES = {"ca", "backups", "revoked"}

#: Namen, aus denen kein Verzeichnis unterhalb der Basis werden darf.
_FORBIDDEN_NAMES = {"", ".", ".."}
_FORBIDDEN_CHARS = {"/", "\\", "\0"}


def validate_name(label: str, value: str) -> str:
    """Prueft einen Benutzer- oder Hostnamen, bevor daraus ein Pfad wird.

    Absichtlich eine Sperrliste und keine Zeichen-Whitelist: was das
    Bash-Skript angelegt hat, soll lesbar bleiben — auch Namen mit Umlauten.
    Verboten ist nur, was aus dem Datenverzeichnis herausfuehrt (``..``) oder
    einen Pfad zerlegt. Die Pruefung sitzt hier und nicht nur in
    :meth:`CertRequest.validate`, weil auch CLI und TUI Pfade direkt ueber
    :class:`Paths` bilden.
    """
    if value in _FORBIDDEN_NAMES:
        raise CaError(f"{label} ist ungültig: '{value}'.")
    for char in value:
        if char in _FORBIDDEN_CHARS or char.isspace() or ord(char) < 32:
            raise CaError(
                f"{label} darf keine Leerzeichen, '/' oder Steuerzeichen "
                f"enthalten: '{value}'."
            )
    return value


class Paths:
    """Alle Pfade der Anwendung, abgeleitet von einem Basisverzeichnis."""

    def __init__(self, base: Path | str | None = None) -> None:
        if base is None:
            base = os.environ.get("SSH_CA_HOME", Path.home() / ".ssh-ca")
        self.base = Path(base).expanduser()

    # -- CA ---------------------------------------------------------------
    @property
    def ca_dir(self) -> Path:
        return self.base / "ca"

    @property
    def ca_key(self) -> Path:
        return self.ca_dir / "ca_key"

    @property
    def ca_pub(self) -> Path:
        return self.ca_dir / "ca_key.pub"

    @property
    def krl(self) -> Path:
        return self.ca_dir / "revoked_keys.krl"

    @property
    def serial_file(self) -> Path:
        return self.ca_dir / "serial.counter"

    # -- Ablagen ----------------------------------------------------------
    @property
    def revoked_dir(self) -> Path:
        return self.base / "revoked"

    @property
    def backup_dir(self) -> Path:
        return self.base / "backups"

    @property
    def principals_file(self) -> Path:
        return self.base / "principals.conf"

    @property
    def templates_file(self) -> Path:
        return self.base / "templates.json"

    @property
    def index_db(self) -> Path:
        return self.base / "index.sqlite"

    @property
    def log_file(self) -> Path:
        return self.base / "ssh-ca.log"

    # -- Ableitungen ------------------------------------------------------
    def user_dir(self, user: str) -> Path:
        return self.base / validate_name("Benutzername", user)

    def host_dir(self, user: str, host: str) -> Path:
        return (
            self.base
            / validate_name("Benutzername", user)
            / validate_name("Hostname", host)
        )

    def key_path(self, user: str, host: str) -> Path:
        """Namensschema des Skripts: <host>_<user>_ed25519."""
        return self.host_dir(user, host) / f"{host}_{user}_{KEY_TYPE}"

    def ensure_layout(self) -> None:
        for d in (self.base, self.ca_dir, self.backup_dir, self.revoked_dir):
            d.mkdir(parents=True, exist_ok=True)
            d.chmod(0o700)
        if not self.principals_file.exists():
            self.principals_file.write_text(
                "# principals.conf\n"
                "# Eine Zeile pro vordefiniertem Prinzipalnamen.\n"
                "# Leere Zeilen und Zeilen mit '#' werden ignoriert.\n",
                encoding="utf-8",
            )
            self.principals_file.chmod(0o600)
        if not self.serial_file.exists():
            self.serial_file.write_text("1\n", encoding="utf-8")
            self.serial_file.chmod(0o600)

    def read_principals_conf(self) -> list[str]:
        if not self.principals_file.exists():
            return []
        out: list[str] = []
        for line in self.principals_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                out.append(line)
        return out


#: Anleitung zur Einrichtung auf den Zielsystemen (CLI und GUI).
DEPLOYMENT_HELP = """\
CA auf den Zielsystemen bekannt machen
======================================

1) CA-Public-Key übertragen

   scp {ca_pub} user@zielhost:/tmp/ca_key.pub

2) Auf dem Zielsystem installieren

   Linux (Ubuntu, Rocky):
       sudo install -o root -g root -m 644 /tmp/ca_key.pub /etc/ssh/ca_key.pub
       echo "TrustedUserCAKeys /etc/ssh/ca_key.pub" \\
           | sudo tee /etc/ssh/sshd_config.d/10-ssh-ca.conf
       sudo systemctl reload sshd

   OpenBSD:
       doas install -o root -g wheel -m 644 /tmp/ca_key.pub /etc/ssh/ca_key.pub
       doas sh -c 'echo "TrustedUserCAKeys /etc/ssh/ca_key.pub" >> /etc/ssh/sshd_config'
       doas rcctl reload sshd

3) Widerrufsliste hinterlegen und nach jedem Widerruf neu verteilen

   scp {krl} user@zielhost:/tmp/revoked_keys.krl
   sudo install -o root -g root -m 644 /tmp/revoked_keys.krl /etc/ssh/revoked_keys.krl
   echo "RevokedKeys /etc/ssh/revoked_keys.krl" \\
       | sudo tee -a /etc/ssh/sshd_config.d/10-ssh-ca.conf
   sudo systemctl reload sshd

4) Anmeldung auf dem Client

   Key und Zertifikat liegen nebeneinander, OpenSSH findet das Zertifikat
   anhand des Namens automatisch:

       ssh -i {base}/<user>/<host>/<host>_<user>_ed25519 user@zielhost
"""
