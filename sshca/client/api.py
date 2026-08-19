"""Clientseite: lokaler Zustand und HTTPS-Aufrufe.

Der Client haelt drei Dinge:

    ~/.ssh-ca-client/
        client.json           Serveradresse, Client-ID, CA-Bundle
        client_ed25519        Identitätsschlüssel für die API (0600)
        client_ed25519.pub
        ca_key.pub            öffentlicher CA-Schlüssel, beim Enrollment geholt
        keys/<host>_<user>_ed25519[.pub|-cert.pub]

Der Identitaetsschluessel und die SSH-Schluessel der Zertifikate sind
absichtlich verschieden. Der Identitaetsschluessel beweist nur „ich bin dieser
registrierte Client" und hat deshalb keine Passphrase — sonst waere kein
automatischer Bezug moeglich. Die Zertifikatsschluessel duerfen und sollen eine
Passphrase haben; sie sind es, mit denen man sich spaeter anmeldet.
"""

from __future__ import annotations

import json
import os
import socket
import ssl
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from ..config import CaError
from ..keygen import Ssh
from ..protocol import (
    API_PREFIX,
    HDR_CLIENT,
    HDR_NONCE,
    HDR_SIGNATURE,
    HDR_TIMESTAMP,
    canonical_request,
    new_nonce,
    sign_message,
)

#: Vorgabe des Datenverzeichnisses; ueberschreibbar mit SSH_CA_CLIENT_HOME.
DEFAULT_CLIENT_HOME = "~/.ssh-ca-client"

#: Zeitlimit fuer HTTPS-Aufrufe. Signieren dauert auf der Serverseite
#: Millisekunden; laenger als das hier ist ein Netz- oder Dienstproblem.
TIMEOUT = 30


@dataclass
class ClientState:
    """Inhalt von ``client.json``."""

    server: str = ""
    client_id: str = ""
    user: str = ""
    host: str = ""
    ca_bundle: str = ""
    ca_fingerprint: str = ""
    enrolled_at: str = ""
    principals: list[str] = field(default_factory=list)
    templates: list[str] = field(default_factory=list)


class ClientPaths:
    """Pfade des Clients, abgeleitet von einem Basisverzeichnis."""

    def __init__(self, base: Path | str | None = None) -> None:
        if base is None:
            base = os.environ.get("SSH_CA_CLIENT_HOME", DEFAULT_CLIENT_HOME)
        self.base = Path(base).expanduser()

    @property
    def state_file(self) -> Path:
        return self.base / "client.json"

    @property
    def identity(self) -> Path:
        return self.base / "client_ed25519"

    @property
    def identity_pub(self) -> Path:
        return self.base / "client_ed25519.pub"

    @property
    def ca_pub(self) -> Path:
        return self.base / "ca_key.pub"

    @property
    def krl(self) -> Path:
        return self.base / "revoked_keys.krl"

    @property
    def key_dir(self) -> Path:
        return self.base / "keys"

    def key_path(self, user: str, host: str) -> Path:
        """Namensschema des Projekts: ``<host>_<user>_ed25519``."""
        return self.key_dir / f"{host}_{user}_ed25519"

    def ensure_layout(self) -> None:
        for directory in (self.base, self.key_dir):
            directory.mkdir(parents=True, exist_ok=True)
            directory.chmod(0o700)

    # ------------------------------------------------------------- Zustand
    def load_state(self) -> ClientState:
        if not self.state_file.is_file():
            return ClientState()
        try:
            payload = json.loads(self.state_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return ClientState()
        try:
            return ClientState(**payload)
        except TypeError:
            return ClientState()

    def save_state(self, state: ClientState) -> None:
        self.ensure_layout()
        self.state_file.write_text(
            json.dumps(asdict(state), indent=2, ensure_ascii=False, sort_keys=True),
            encoding="utf-8",
        )
        self.state_file.chmod(0o600)


class ServerError(CaError):
    """Der Server hat die Anfrage abgelehnt; der Text stammt von ihm."""


class Connection:
    """Die HTTPS-Verbindung zum Signierdienst."""

    def __init__(
        self,
        server: str,
        ca_bundle: str | Path | None = None,
        ssh: Ssh | None = None,
        insecure: bool = False,
    ) -> None:
        self.server = server.rstrip("/")
        if not self.server.startswith("https://"):
            raise CaError(
                "Die Serveradresse muss mit https:// beginnen — der Dienst "
                "spricht ausschließlich TLS."
            )
        self.ssh = ssh or Ssh()
        self.context = ssl.create_default_context(
            cafile=str(ca_bundle) if ca_bundle else None
        )
        if insecure:
            # Nur fuer den Test einer frisch aufgesetzten Instanz gedacht.
            # Jeder Aufrufer sagt es dem Benutzer deutlich.
            self.context.check_hostname = False
            self.context.verify_mode = ssl.CERT_NONE

    # ------------------------------------------------------------- Aufrufe
    def _request(
        self,
        method: str,
        path: str,
        payload: dict | None = None,
        identity: Path | None = None,
        client_id: str = "",
    ) -> dict:
        body = (
            json.dumps(payload, ensure_ascii=False).encode("utf-8")
            if payload is not None
            else b""
        )
        request = urllib.request.Request(
            self.server + path, data=body if body else None, method=method
        )
        request.add_header("Accept", "application/json")
        if body:
            request.add_header("Content-Type", "application/json; charset=utf-8")

        if identity is not None:
            timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
            nonce = new_nonce()
            message = canonical_request(
                method, path, client_id, timestamp, nonce, body
            )
            request.add_header(HDR_CLIENT, client_id)
            request.add_header(HDR_TIMESTAMP, timestamp)
            request.add_header(HDR_NONCE, nonce)
            request.add_header(
                HDR_SIGNATURE, sign_message(self.ssh, identity, message)
            )

        try:
            with urllib.request.urlopen(
                request, timeout=TIMEOUT, context=self.context
            ) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = ""
            try:
                detail = json.loads(exc.read().decode("utf-8")).get("error", "")
            except Exception:
                pass
            raise ServerError(
                detail or f"Der Server antwortete mit {exc.code}."
            ) from exc
        except urllib.error.URLError as exc:
            # urllib verpackt TLS-Fehler in URLError. Der Unterschied ist fuer
            # den Benutzer wesentlich: „nicht erreichbar" schickt ihn zur
            # Firewall, „Zertifikat" zur PKI.
            reason = getattr(exc, "reason", None)
            if isinstance(reason, ssl.SSLCertVerificationError):
                raise CaError(
                    "Das Serverzertifikat wurde nicht akzeptiert: "
                    f"{reason.verify_message or reason}. Passt --ca-bundle zur "
                    "PKI, und steht im Zertifikat der Name, unter dem der "
                    "Server angesprochen wird?"
                ) from exc
            if isinstance(reason, ssl.SSLError):
                raise CaError(f"TLS-Fehler: {reason}") from exc
            raise CaError(f"Der Server ist nicht erreichbar: {exc.reason}") from exc
        except (socket.timeout, OSError) as exc:
            raise CaError(f"Der Server ist nicht erreichbar: {exc}") from exc
        except json.JSONDecodeError as exc:
            raise CaError("Die Antwort des Servers ist kein gültiges JSON.") from exc

    # ---------------------------------------------------------- Endpunkte
    def info(self) -> dict:
        return self._request("GET", f"{API_PREFIX}/info")

    def enroll(self, token: str, pubkey: str, host: str) -> dict:
        return self._request(
            "POST",
            f"{API_PREFIX}/enroll",
            {"token": token, "pubkey": pubkey, "host": host},
        )

    def principals(self, identity: Path, client_id: str) -> dict:
        return self._request(
            "GET", f"{API_PREFIX}/principals", None, identity, client_id
        )

    def templates(self, identity: Path, client_id: str) -> dict:
        return self._request(
            "GET", f"{API_PREFIX}/templates", None, identity, client_id
        )

    def ca_material(self, identity: Path, client_id: str) -> dict:
        return self._request("GET", f"{API_PREFIX}/ca", None, identity, client_id)

    def certificates(self, identity: Path, client_id: str) -> dict:
        return self._request(
            "GET", f"{API_PREFIX}/certificates", None, identity, client_id
        )

    def sign(self, identity: Path, client_id: str, payload: dict) -> dict:
        return self._request(
            "POST", f"{API_PREFIX}/sign", payload, identity, client_id
        )


def generate_identity(ssh: Ssh, paths: ClientPaths, comment: str) -> str:
    """Erzeugt den Identitaetsschluessel des Clients und liefert den Public Key.

    Ohne Passphrase, mit 0600 — siehe Modulkopf. Ein vorhandener Schluessel
    wird nicht ueberschrieben; ein erneutes Enrollment behaelt die Identitaet,
    solange sie noch da ist.
    """
    paths.ensure_layout()
    if not paths.identity.is_file():
        ssh.run(
            [
                "-t", "ed25519",
                "-a", "100",
                "-f", str(paths.identity),
                "-C", comment,
                "-N", "",
            ]
        )
        paths.identity.chmod(0o600)
        paths.identity_pub.chmod(0o644)
    return paths.identity_pub.read_text(encoding="utf-8").strip()


def generate_key(
    ssh: Ssh, paths: ClientPaths, user: str, host: str, passphrase: str
) -> Path:
    """Erzeugt den ed25519-Schluessel, dessen Public Key signiert werden soll.

    Der private Teil entsteht hier und verlaesst den Client nie — an den Server
    geht ausschliesslich die ``.pub``-Zeile.
    """
    paths.ensure_layout()
    key_path = paths.key_path(user, host)
    if key_path.exists():
        archive = paths.key_dir / "archive"
        archive.mkdir(parents=True, exist_ok=True)
        archive.chmod(0o700)
        for old in archive.iterdir():
            if old.is_file() and old.name.startswith(key_path.name):
                old.unlink()
        for suffix in ("", ".pub", "-cert.pub"):
            item = Path(str(key_path) + suffix)
            if item.is_file():
                item.replace(archive / item.name)
    ssh.run(
        [
            "-t", "ed25519",
            "-a", "100",
            "-f", str(key_path),
            "-C", f"{user}@{host}",
        ],
        passphrases=[passphrase, passphrase],
    )
    key_path.chmod(0o600)
    Path(str(key_path) + ".pub").chmod(0o644)
    return key_path
