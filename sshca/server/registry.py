"""Enrollment-Tokens und registrierte Clients.

Wie im Rest des Projekts ist der Dateibaum die Wahrheit — kein Index, keine
Datenbank. Ein Blick mit ``ls`` und ``cat`` genuegt, um zu sehen, wer sich
registriert hat und welche Tokens offen sind.

    <state_dir>/
        .lock                       Sperrdatei fuer schreibende Zugriffe
        enroll/<id>.json            ein Token (0600)
        clients/<user>/<host>.json  ein registrierter Client (0600)

Schreibende Zugriffe laufen ueber eine ``flock``-Sperre und ``os.replace``.
Beides zusammen haelt den Zustand konsistent, wenn der Dienst und das
Token-Werkzeug gleichzeitig arbeiten — das ist der Regelfall, denn Tokens legt
der Administrator waehrend des Betriebs an.
"""

from __future__ import annotations

import fcntl
import hmac
import json
import os
import secrets
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

from ..config import CaError, validate_name
from ..protocol import secret_hash, split_token

#: Einheiten fuer Angaben wie '24h' oder '30d' bei der Token-Laufzeit.
_UNITS = {"m": 60, "h": 3600, "d": 86400, "w": 604800}


def parse_duration(text: str) -> int:
    """'90m', '24h', '30d', '2w' → Sekunden."""
    text = text.strip().lower()
    if not text or text[-1] not in _UNITS or not text[:-1].isdigit():
        raise CaError(
            f"Laufzeit '{text}' nicht verstanden. Erlaubt: 90m, 24h, 30d, 2w."
        )
    return int(text[:-1]) * _UNITS[text[-1]]


def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _parse(value: str) -> datetime | None:
    try:
        return datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError):
        return None


@dataclass
class Token:
    """Ein Enrollment-Token. Gespeichert wird nur der Hash des Geheimnisses."""

    id: str
    secret_hash: str
    user: str
    host: str = ""                       # leer = Client bringt seinen Hostnamen mit
    principals: list[str] = field(default_factory=list)   # leer = alle erlaubten
    templates: list[str] = field(default_factory=list)    # leer = alle Vorlagen
    max_validity: str = ""               # leer = Vorgabe des Servers
    expires_at: str = ""
    uses_left: int = 1
    created_at: str = field(default_factory=_now)
    created_by: str = ""
    used_at: str = ""
    used_by: str = ""
    comment: str = ""

    @property
    def expired(self) -> bool:
        moment = _parse(self.expires_at)
        return moment is not None and datetime.now() >= moment

    @property
    def state(self) -> str:
        if self.uses_left <= 0:
            return "verbraucht"
        if self.expired:
            return "abgelaufen"
        return "offen"


@dataclass
class Client:
    """Ein registrierter Client."""

    client_id: str
    user: str
    host: str
    pubkey: str
    enrolled_at: str = field(default_factory=_now)
    enrolled_from: str = ""
    token_id: str = ""
    principals: list[str] = field(default_factory=list)
    templates: list[str] = field(default_factory=list)
    max_validity: str = ""
    disabled: bool = False
    last_seen: str = ""
    comment: str = ""


class Registry:
    """Zugriff auf Tokens und Clients unterhalb von ``state_dir``."""

    def __init__(self, state_dir: Path | str) -> None:
        self.state_dir = Path(state_dir).expanduser()
        self.enroll_dir = self.state_dir / "enroll"
        self.clients_dir = self.state_dir / "clients"
        self.lock_file = self.state_dir / ".lock"

    def ensure_layout(self) -> None:
        for directory in (self.state_dir, self.enroll_dir, self.clients_dir):
            directory.mkdir(parents=True, exist_ok=True)
            directory.chmod(0o700)
        if not self.lock_file.exists():
            self.lock_file.touch()
            self.lock_file.chmod(0o600)

    # ------------------------------------------------------------- Werkzeuge
    @contextmanager
    def _locked(self):
        """Exklusive Sperre fuer schreibende Zugriffe.

        Der Dienst und ``ssh-ca-enroll-token`` sind zwei Prozesse; ohne Sperre
        koennte ein Token zweimal verbraucht werden, wenn zwei Enrollments
        exakt zusammenfallen.
        """
        self.ensure_layout()
        with self.lock_file.open("r+b") as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

    @staticmethod
    def _write_json(path: Path, payload: dict) -> None:
        """Atomar schreiben: erst daneben, dann umbenennen."""
        path.parent.mkdir(parents=True, exist_ok=True)
        path.parent.chmod(0o700)
        tmp = path.with_name(path.name + f".tmp{os.getpid()}")
        tmp.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True),
            encoding="utf-8",
        )
        tmp.chmod(0o600)
        os.replace(tmp, path)

    @staticmethod
    def _read_json(path: Path) -> dict | None:
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None

    # ---------------------------------------------------------------- Tokens
    def token_path(self, token_id: str) -> Path:
        if not token_id.isalnum():
            raise CaError(f"Ungültige Token-ID: '{token_id}'")
        return self.enroll_dir / f"{token_id}.json"

    def create_token(
        self,
        user: str,
        host: str = "",
        principals: list[str] | None = None,
        templates: list[str] | None = None,
        max_validity: str = "",
        lifetime: str = "24h",
        uses: int = 1,
        comment: str = "",
    ) -> tuple[Token, str]:
        """Legt ein Token an und liefert (Token, Klartext).

        Der Klartext wird genau einmal zurueckgegeben — hier und nirgends
        sonst. Auf der Platte liegt nur sein SHA-256.
        """
        validate_name("Benutzername", user)
        if host:
            validate_name("Hostname", host)
        if uses < 1:
            raise CaError("Ein Token braucht mindestens eine Verwendung.")
        seconds = parse_duration(lifetime)

        token_id = secrets.token_hex(4)
        secret = secrets.token_urlsafe(32)
        token = Token(
            id=token_id,
            secret_hash=secret_hash(secret),
            user=user,
            host=host,
            principals=list(principals or []),
            templates=list(templates or []),
            max_validity=max_validity,
            expires_at=(datetime.now() + timedelta(seconds=seconds)).strftime(
                "%Y-%m-%d %H:%M:%S"
            ),
            uses_left=uses,
            created_by=os.environ.get("SUDO_USER") or os.environ.get("USER", ""),
            comment=comment,
        )
        with self._locked():
            self._write_json(self.token_path(token_id), asdict(token))
        return token, f"{token_id}.{secret}"

    def list_tokens(self) -> list[Token]:
        if not self.enroll_dir.is_dir():
            return []
        result = []
        for path in sorted(self.enroll_dir.glob("*.json")):
            payload = self._read_json(path)
            if payload:
                try:
                    result.append(Token(**payload))
                except TypeError:
                    continue
        return result

    def revoke_token(self, token_id: str) -> None:
        path = self.token_path(token_id)
        if not path.is_file():
            raise CaError(f"Kein Token mit der ID '{token_id}'.")
        with self._locked():
            path.unlink()

    def consume_token(self, token_text: str, client_id: str) -> Token:
        """Prueft und verbraucht ein Token. Wirft :class:`CaError` bei Fehlern.

        Der Vergleich laeuft ueber :func:`hmac.compare_digest`, damit die
        Laufzeit nichts ueber das Geheimnis verraet. Die Fehlermeldung ist fuer
        alle Faelle dieselbe — ein Angreifer soll nicht erfahren, ob eine
        Token-ID existiert.
        """
        token_id, secret = split_token(token_text)
        generic = CaError("Token ist unbekannt, abgelaufen oder verbraucht.")
        try:
            path = self.token_path(token_id)
        except CaError:
            raise generic from None

        with self._locked():
            payload = self._read_json(path) if path.is_file() else None
            if payload is None:
                raise generic
            try:
                token = Token(**payload)
            except TypeError:
                raise generic from None
            if not hmac.compare_digest(token.secret_hash, secret_hash(secret)):
                raise generic
            if token.uses_left <= 0 or token.expired:
                raise generic

            token.uses_left -= 1
            token.used_at = _now()
            token.used_by = client_id
            self._write_json(path, asdict(token))
        return token

    # --------------------------------------------------------------- Clients
    def client_path(self, user: str, host: str) -> Path:
        return (
            self.clients_dir
            / validate_name("Benutzername", user)
            / f"{validate_name('Hostname', host)}.json"
        )

    @staticmethod
    def client_id(user: str, host: str) -> str:
        return f"{user}@{host}"

    def register_client(
        self,
        user: str,
        host: str,
        pubkey: str,
        token: Token,
        peer: str = "",
    ) -> Client:
        """Traegt einen Client ein — auch erneut.

        Eine Wiederholung ersetzt den hinterlegten Schluessel. Das ist der
        Fall „Client neu aufgesetzt": der Administrator gibt ein neues Token
        aus, der Client meldet sich damit erneut an. Ohne Token geht das
        nicht, ein bestehender Eintrag ist also kein Selbstbedienungsladen.
        """
        client = Client(
            client_id=self.client_id(user, host),
            user=user,
            host=host,
            pubkey=pubkey.strip(),
            enrolled_from=peer,
            token_id=token.id,
            principals=list(token.principals),
            templates=list(token.templates),
            max_validity=token.max_validity,
            comment=token.comment,
        )
        with self._locked():
            self._write_json(self.client_path(user, host), asdict(client))
        return client

    def get_client(self, client_id: str) -> Client | None:
        user, _, host = client_id.partition("@")
        if not user or not host:
            return None
        try:
            path = self.client_path(user, host)
        except CaError:
            return None
        payload = self._read_json(path) if path.is_file() else None
        if payload is None:
            return None
        try:
            return Client(**payload)
        except TypeError:
            return None

    def list_clients(self) -> list[Client]:
        if not self.clients_dir.is_dir():
            return []
        result = []
        for user_dir in sorted(self.clients_dir.iterdir()):
            if not user_dir.is_dir():
                continue
            for path in sorted(user_dir.glob("*.json")):
                payload = self._read_json(path)
                if payload:
                    try:
                        result.append(Client(**payload))
                    except TypeError:
                        continue
        return result

    def set_client_disabled(self, client_id: str, disabled: bool) -> Client:
        client = self.get_client(client_id)
        if client is None:
            raise CaError(f"Kein registrierter Client '{client_id}'.")
        client.disabled = disabled
        with self._locked():
            self._write_json(
                self.client_path(client.user, client.host), asdict(client)
            )
        return client

    def remove_client(self, client_id: str) -> None:
        client = self.get_client(client_id)
        if client is None:
            raise CaError(f"Kein registrierter Client '{client_id}'.")
        with self._locked():
            self.client_path(client.user, client.host).unlink(missing_ok=True)

    def touch_client(self, client: Client) -> None:
        """Haelt den Zeitpunkt der letzten Anfrage fest (nur Protokoll)."""
        client.last_seen = _now()
        try:
            with self._locked():
                self._write_json(
                    self.client_path(client.user, client.host), asdict(client)
                )
        except OSError:
            pass
