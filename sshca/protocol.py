"""Protokoll zwischen Client und Signierdienst.

Beide Seiten binden dieses Modul ein, damit die Kanonisierung einer Anfrage an
genau einer Stelle steht: weicht sie auseinander, schlaegt jede Signatur fehl
statt still falsch zu gelten.

Zwei Schichten sichern den Weg:

* **Transport** — HTTPS mit einem Zertifikat aus der bestehenden X.509-PKI.
  Der Client prueft die Kette gegen das mitgegebene CA-Bundle.
* **Herkunft** — jede Anfrage nach dem Enrollment traegt eine SSHSIG-Signatur
  des bei der Registrierung hinterlegten Client-Schluessels
  (``ssh-keygen -Y sign`` / ``-Y verify``). Damit haengt die Authentisierung
  an SSH-Schluesseln und nicht an einer zweiten PKI mit eigener Verwaltung.

Signiert wird nie der Rumpf allein, sondern Methode, Pfad, Client, Zeit, Nonce
und der SHA-256 des Rumpfes zusammen — ein abgefangener Signaturblock laesst
sich so weder auf einen anderen Endpunkt noch auf einen anderen Inhalt setzen.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import secrets
import tempfile
from pathlib import Path

from .keygen import Ssh

#: Praefix aller API-Pfade. Eine Versionsziffer, damit spaetere Aenderungen
#: nebeneinander laufen koennen, statt alte Clients stumm zu brechen.
API_PREFIX = "/v1"

#: Namensraum der SSHSIG-Signaturen. ssh-keygen bindet ihn in die Signatur
#: ein; eine Signatur aus einem anderen Kontext (z. B. git) ist hier wertlos.
SIG_NAMESPACE = "ssh-ca-manager-api"

#: Vorgabeport. Ueber 1024, damit der Dienst keine Capability braucht.
DEFAULT_PORT = 8443

#: Groesster akzeptierter Rumpf. Ein Public Key mit Metadaten bleibt weit
#: darunter; alles Groessere ist ein Fehler oder ein Versuch.
MAX_BODY = 64 * 1024

#: Zulaessige Abweichung der Client-Uhr in Sekunden.
MAX_SKEW = 300

HDR_CLIENT = "X-SSHCA-Client"
HDR_TIMESTAMP = "X-SSHCA-Timestamp"
HDR_NONCE = "X-SSHCA-Nonce"
HDR_SIGNATURE = "X-SSHCA-Signature"


class ProtocolError(RuntimeError):
    """Anfrage oder Antwort verletzt das Protokoll. Text ist anzeigbar."""


def body_digest(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def new_nonce() -> str:
    return secrets.token_hex(16)


def canonical_request(
    method: str,
    path: str,
    client_id: str,
    timestamp: str,
    nonce: str,
    body: bytes,
) -> bytes:
    """Die Bytes, ueber die signiert wird.

    Feste Reihenfolge, ein Feld je Zeile, abschliessender Zeilenumbruch. Die
    Felder selbst duerfen kein ``\\n`` enthalten — dafuer sorgen die Pruefungen
    der aufrufenden Seiten (Client-IDs und Nonces sind zeichenbeschraenkt).
    """
    fields = [method.upper(), path, client_id, timestamp, nonce, body_digest(body)]
    for field in fields:
        if "\n" in field:
            raise ProtocolError("Unerlaubter Zeilenumbruch in einem Anfragefeld.")
    return ("\n".join(fields) + "\n").encode("utf-8")


def sign_message(ssh: Ssh, key_path: Path, message: bytes) -> str:
    """Signiert Bytes mit einem SSH-Schluessel; liefert Base64 der SSHSIG.

    ``ssh-keygen -Y sign`` schreibt die Signatur neben die Eingabedatei. Beides
    liegt in einem temporaeren Verzeichnis, das mit dem Aufruf wieder
    verschwindet — die zu signierende Nachricht ist unkritisch, der Umweg ueber
    stdin waere hier aber ohnehin nicht portabel.
    """
    with tempfile.TemporaryDirectory(prefix="sshca-sign-") as tmp:
        message_file = Path(tmp) / "request"
        message_file.write_bytes(message)
        ssh.run(
            [
                "-Y", "sign",
                "-f", str(key_path),
                "-n", SIG_NAMESPACE,
                str(message_file),
            ]
        )
        signature = (Path(tmp) / "request.sig").read_bytes()
    return base64.b64encode(signature).decode("ascii")


def verify_message(
    ssh: Ssh,
    pubkey_line: str,
    client_id: str,
    message: bytes,
    signature_b64: str,
) -> None:
    """Prueft eine Signatur gegen genau einen Public Key.

    Die ``allowed_signers``-Datei wird je Pruefung frisch aus dem registrierten
    Schluessel gebaut und danach verworfen. Es gibt bewusst keine dauerhafte
    Sammeldatei: sonst entschiede eine Datei ueber alle Clients, und ein
    stehengebliebener Eintrag waere ein Zugang, den niemand mehr sieht.

    Wirft :class:`ProtocolError`, wenn die Signatur nicht passt.
    """
    try:
        signature = base64.b64decode(signature_b64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ProtocolError("Signaturkopf ist kein gültiges Base64.") from exc
    if not signature:
        raise ProtocolError("Signaturkopf ist leer.")

    with tempfile.TemporaryDirectory(prefix="sshca-verify-") as tmp:
        directory = Path(tmp)
        allowed = directory / "allowed_signers"
        allowed.write_text(
            f"{client_id} {pubkey_line.strip()}\n", encoding="utf-8"
        )
        allowed.chmod(0o600)
        sig_file = directory / "request.sig"
        sig_file.write_bytes(signature)
        message_file = directory / "request"
        message_file.write_bytes(message)

        result = ssh.run(
            [
                "-Y", "verify",
                "-f", str(allowed),
                "-I", client_id,
                "-n", SIG_NAMESPACE,
                "-s", str(sig_file),
            ],
            stdin_file=message_file,
            check=False,
        )
    if result.returncode != 0:
        raise ProtocolError(
            "Signatur passt nicht zum registrierten Schlüssel dieses Clients."
        )


def split_token(token: str) -> tuple[str, str]:
    """Zerlegt ``<id>.<secret>``. Beide Teile muessen vorhanden sein."""
    token_id, _, secret = token.strip().partition(".")
    if not token_id or not secret:
        raise ProtocolError(
            "Das Enrollment-Token hat nicht die Form <ID>.<Geheimnis>."
        )
    return token_id, secret


def secret_hash(secret: str) -> str:
    """Der Server speichert nur diesen Hash, nie das Geheimnis selbst."""
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def validity_seconds(spec: str) -> int:
    """Sekunden einer ``-V``-Angabe. Nur relative Angaben sind erlaubt.

    Absolute Zeitfenster (``20200101120000:20210101120000``) und
    ``always:forever`` bleiben dem lokalen Betrieb vorbehalten: ueber das Netz
    soll niemand ein unbegrenztes Zertifikat anfordern koennen.
    """
    from .model import parse_validity_spec

    span = parse_validity_spec(spec)
    if span is None:
        raise ProtocolError(
            f"Gültigkeit '{spec}' wird über die API nicht akzeptiert. "
            "Erlaubt sind relative Angaben wie +30m, +1h, +9h, +7d."
        )
    return int((span[1] - span[0]).total_seconds())


def seconds_to_spec(seconds: int) -> str:
    """Sekunden zurueck in eine ``-V``-Angabe, moeglichst grob."""
    seconds = max(60, int(seconds))
    for size, suffix in ((604800, "w"), (86400, "d"), (3600, "h"), (60, "m")):
        if seconds % size == 0:
            return f"+{seconds // size}{suffix}"
    return f"+{seconds}s"


def cap_validity(spec: str, limit_seconds: int) -> str:
    """Kuerzt eine Gueltigkeit auf die Obergrenze.

    Gedacht fuer den Fall, dass die Angabe aus einer Vorlage stammt und der
    Client sie gar nicht selbst gewaehlt hat — dann ist Kuerzen die richtige
    Antwort. Fordert ein Client ausdruecklich mehr an, weist der Server das
    ab, statt still etwas anderes auszustellen.
    """
    return (
        seconds_to_spec(limit_seconds)
        if validity_seconds(spec) > limit_seconds
        else spec
    )


__all__ = [
    "API_PREFIX",
    "DEFAULT_PORT",
    "HDR_CLIENT",
    "HDR_NONCE",
    "HDR_SIGNATURE",
    "HDR_TIMESTAMP",
    "MAX_BODY",
    "MAX_SKEW",
    "SIG_NAMESPACE",
    "ProtocolError",
    "body_digest",
    "canonical_request",
    "cap_validity",
    "new_nonce",
    "secret_hash",
    "seconds_to_spec",
    "sign_message",
    "split_token",
    "validity_seconds",
    "verify_message",
]
