"""Konfiguration des Signierdienstes.

Eine INI-Datei, Vorgabe ``/etc/ssh-ca-server/server.conf``. Sie enthaelt keine
Geheimnisse: die CA-Passphrase steht — wenn ueberhaupt — in einer eigenen,
getrennt berechtigten Datei, und der bevorzugte Weg ist der ssh-agent.
"""

from __future__ import annotations

import configparser
from dataclasses import dataclass, field
from pathlib import Path

from ..config import CaError
from ..protocol import DEFAULT_PORT

#: Ort der Konfiguration, wenn nichts anderes angegeben wird.
DEFAULT_CONFIG = Path("/etc/ssh-ca-server/server.conf")

#: Zustand des Dienstes: Tokens und registrierte Clients. Bewusst NICHT im
#: CA-Datenverzeichnis — dessen Layout ist der Vertrag mit dem Bash-Skript und
#: bleibt unberuehrt.
DEFAULT_STATE_DIR = Path("/var/lib/ssh-ca-server")

#: Signaturwege der CA. 'agent' ist der vorgesehene Betriebsfall: die
#: Passphrase verlaesst den Agent nie und liegt nirgends auf der Platte.
SIGNING_MODES = ("agent", "passphrase-file", "none")

CONFIG_TEMPLATE = """\
# Konfiguration des SSH-CA-Signierdienstes.
# Diese Datei enthält keine Geheimnisse.

[server]
# Adresse und Port. Über 1024, damit der Dienst ohne Capability auskommt.
listen = 0.0.0.0
port = {port}

# Serverzertifikat aus der bestehenden X.509-PKI.
# tls_cert erwartet das Serverzertifikat samt Zwischenzertifikaten.
tls_cert = /etc/ssl/certs/ssh-ca-server.pem
tls_key = /etc/ssl/private/ssh-ca-server.key

# Optional: zusätzlich Client-Zertifikate aus derselben PKI verlangen
# (mutual TLS). Leer lassen, wenn die SSH-Signatur der Anfragen genügt.
tls_client_ca =

# Datenverzeichnis der CA (dasselbe wie für ssh-ca-manager --base).
ca_base = {ca_base}

# Zustand des Dienstes: Enrollment-Tokens und registrierte Clients.
state_dir = {state_dir}

# Wie signiert die CA?
#   agent           — CA-Schlüssel liegt im ssh-agent (empfohlen)
#   passphrase-file — Passphrase steht in ca_passphrase_file (nur root lesbar)
#   none            — CA-Schlüssel ohne Passphrase
signing = agent
ca_passphrase_file =

# Obergrenze für die Gültigkeit, die ein Client anfordern darf.
# Ein Enrollment-Token kann strenger sein, nie großzügiger.
max_validity = +9h
"""


@dataclass
class ServerConfig:
    """Alle Stellschrauben des Dienstes."""

    listen: str = "0.0.0.0"
    port: int = DEFAULT_PORT
    tls_cert: Path | None = None
    tls_key: Path | None = None
    tls_client_ca: Path | None = None
    ca_base: Path | None = None
    state_dir: Path = field(default_factory=lambda: DEFAULT_STATE_DIR)
    signing: str = "agent"
    ca_passphrase_file: Path | None = None
    max_validity: str = "+9h"
    source: Path | None = None

    # ------------------------------------------------------------------ Lesen
    @classmethod
    def load(cls, path: Path | str | None = None) -> "ServerConfig":
        path = Path(path or DEFAULT_CONFIG)
        if not path.is_file():
            raise CaError(
                f"Konfiguration nicht gefunden: {path}\n"
                "Eine Vorlage legt 'ssh-ca-server install --apply' an."
            )
        parser = configparser.ConfigParser()
        parser.read(path, encoding="utf-8")
        if not parser.has_section("server"):
            raise CaError(f"In {path} fehlt der Abschnitt [server].")
        section = parser["server"]

        def as_path(name: str) -> Path | None:
            value = section.get(name, "").strip()
            return Path(value).expanduser() if value else None

        config = cls(
            listen=section.get("listen", "0.0.0.0").strip() or "0.0.0.0",
            port=section.getint("port", DEFAULT_PORT),
            tls_cert=as_path("tls_cert"),
            tls_key=as_path("tls_key"),
            tls_client_ca=as_path("tls_client_ca"),
            ca_base=as_path("ca_base"),
            state_dir=as_path("state_dir") or DEFAULT_STATE_DIR,
            signing=section.get("signing", "agent").strip() or "agent",
            ca_passphrase_file=as_path("ca_passphrase_file"),
            max_validity=section.get("max_validity", "+9h").strip() or "+9h",
            source=path,
        )
        config.validate()
        return config

    def validate(self) -> None:
        """Prueft, was sich ohne Netzbetrieb pruefen laesst."""
        if self.signing not in SIGNING_MODES:
            raise CaError(
                f"signing muss eines von {', '.join(SIGNING_MODES)} sein, "
                f"nicht '{self.signing}'."
            )
        if not 1 <= self.port <= 65535:
            raise CaError(f"Ungültiger Port: {self.port}")
        if self.tls_cert is None or self.tls_key is None:
            raise CaError(
                "tls_cert und tls_key sind erforderlich — der Dienst läuft "
                "ausschließlich über HTTPS."
            )
        if self.signing == "passphrase-file" and self.ca_passphrase_file is None:
            raise CaError(
                "signing = passphrase-file verlangt einen Pfad in "
                "ca_passphrase_file."
            )

    def check_files(self) -> list[str]:
        """Liefert Klartextbefunde zu den referenzierten Dateien.

        Getrennt von :meth:`validate`, damit ``ssh-ca-server check`` alle
        Befunde auf einmal zeigen kann statt beim ersten abzubrechen.
        """
        problems: list[str] = []
        for label, path in (
            ("tls_cert", self.tls_cert),
            ("tls_key", self.tls_key),
            ("tls_client_ca", self.tls_client_ca),
        ):
            if path is not None and not path.is_file():
                problems.append(f"{label}: Datei fehlt — {path}")
        if self.tls_key is not None and self.tls_key.is_file():
            mode = self.tls_key.stat().st_mode & 0o077
            if mode:
                problems.append(
                    f"tls_key ist für andere lesbar oder schreibbar: {self.tls_key}"
                )
        if self.signing == "passphrase-file":
            path = self.ca_passphrase_file
            if path is None or not path.is_file():
                problems.append(f"ca_passphrase_file: Datei fehlt — {path}")
            elif path.stat().st_mode & 0o077:
                problems.append(f"ca_passphrase_file ist zu großzügig: {path}")
        return problems

    def read_ca_passphrase(self) -> str:
        """Liest die Passphrase einmalig beim Start.

        Nur die erste Zeile, ohne Zeilenende — so laesst sich die Datei mit
        ``echo … > datei`` erzeugen, ohne dass ein ``\\n`` Teil der Passphrase
        wird.
        """
        if self.signing != "passphrase-file" or self.ca_passphrase_file is None:
            return ""
        path = self.ca_passphrase_file
        if not path.is_file():
            raise CaError(f"Passphrasendatei nicht gefunden: {path}")
        if path.stat().st_mode & 0o077:
            raise CaError(
                f"Die Passphrasendatei {path} ist für andere zugänglich. "
                "Erwartet werden 0600 oder strenger."
            )
        lines = path.read_text(encoding="utf-8").splitlines()
        return lines[0] if lines else ""
