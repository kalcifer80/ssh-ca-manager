"""HTTPS-Schicht: Routen, Signaturpruefung, TLS.

Bewusst auf ``http.server`` aufgebaut — die Regel „keine neuen
Laufzeitabhaengigkeiten" gilt auch hier. Die API ist klein und
zustandslos; ein Framework braucht es dafuer nicht.

Was diese Schicht leistet und was nicht:

* Sie prueft **Form** — Methode, Pfad, Groesse, JSON, Kopfzeilen, Zeitfenster,
  Nonce, SSHSIG. Erst danach sieht ``api.py`` die Anfrage.
* Sie entscheidet **nichts** ueber Rechte. Diese Trennung ist der Grund,
  warum sich die Rechtevergabe ohne Netz testen laesst.
"""

from __future__ import annotations

import json
import ssl
import sys
import threading
from collections import OrderedDict
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from ..config import CaError
from ..keygen import SshKeygenError
from ..protocol import (
    API_PREFIX,
    HDR_CLIENT,
    HDR_NONCE,
    HDR_SIGNATURE,
    HDR_TIMESTAMP,
    MAX_BODY,
    MAX_SKEW,
    ProtocolError,
    canonical_request,
)
from .api import Api


class NonceCache:
    """Merkt sich benutzte Nonces innerhalb des Zeitfensters.

    Ohne sie liesse sich eine mitgeschnittene Anfrage innerhalb von
    :data:`MAX_SKEW` Sekunden wiederholen. Der Cache ist bewusst im Speicher:
    ein Neustart macht das Fenster fuer wenige Minuten wieder offen, und das
    ist gegenueber einer persistenten Datei die bessere Abwaegung — eine
    wiederholte Signaturanfrage kostet ein Zertifikat, kein Recht.
    """

    def __init__(self, limit: int = 4096) -> None:
        self._entries: OrderedDict[str, float] = OrderedDict()
        self._limit = limit
        self._lock = threading.Lock()

    def check_and_store(self, nonce: str, now: float) -> bool:
        """True, wenn die Nonce neu war."""
        with self._lock:
            for key, stamp in list(self._entries.items()):
                if now - stamp > MAX_SKEW * 2:
                    self._entries.pop(key, None)
                else:
                    break
            if nonce in self._entries:
                return False
            self._entries[nonce] = now
            while len(self._entries) > self._limit:
                self._entries.popitem(last=False)
            return True


class Handler(BaseHTTPRequestHandler):
    """Ein Request. ``api`` und ``nonces`` haengen an der Server-Instanz."""

    server_version = "ssh-ca-manager"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    # BaseHTTPRequestHandler kennt nur ``self.server``; die Dienste haengen
    # dort, damit je Verbindung kein neues Objekt entsteht.
    @property
    def api(self) -> Api:
        return self.server.api

    @property
    def nonces(self) -> NonceCache:
        return self.server.nonces

    # ---------------------------------------------------------------- Ausgabe
    def _send(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _fail(self, status: int, message: str) -> None:
        self._send(status, {"error": message})

    def log_message(self, fmt: str, *args) -> None:
        """Nach stderr — systemd nimmt das ins Journal auf."""
        sys.stderr.write(
            f"{datetime.now():%Y-%m-%d %H:%M:%S} {self.address_string()} "
            f"{fmt % args}\n"
        )

    # ---------------------------------------------------------------- Eingabe
    def _read_body(self) -> bytes:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            raise ProtocolError("Content-Length ist keine Zahl.") from None
        if length < 0 or length > MAX_BODY:
            raise ProtocolError("Rumpf fehlt oder ist zu groß.")
        return self.rfile.read(length) if length else b""

    @staticmethod
    def _as_json(body: bytes) -> dict:
        if not body:
            return {}
        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ProtocolError("Rumpf ist kein gültiges JSON.") from None
        if not isinstance(payload, dict):
            raise ProtocolError("Rumpf muss ein JSON-Objekt sein.")
        return payload

    def _authenticate(self, method: str, path: str, body: bytes):
        """Prueft die SSHSIG-Signatur und liefert den Client.

        Reihenfolge mit Absicht: erst die billigen Pruefungen (Kopfzeilen,
        Zeitfenster, Nonce, Registrierung), dann die teure Signaturpruefung,
        die einen Prozess startet. Wer ohne gueltige Kopfzeilen anklopft,
        kostet den Dienst nichts.
        """
        client_id = self.headers.get(HDR_CLIENT, "").strip()
        timestamp = self.headers.get(HDR_TIMESTAMP, "").strip()
        nonce = self.headers.get(HDR_NONCE, "").strip()
        signature = self.headers.get(HDR_SIGNATURE, "").strip()
        if not (client_id and timestamp and nonce and signature):
            raise ProtocolError("Die Anfrage ist nicht signiert.")
        if len(nonce) > 64 or not nonce.isalnum():
            raise ProtocolError("Ungültige Nonce.")

        try:
            sent = datetime.fromisoformat(timestamp)
        except ValueError:
            raise ProtocolError("Zeitstempel ist nicht ISO-8601.") from None
        if sent.tzinfo is None:
            sent = sent.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        if abs((now - sent).total_seconds()) > MAX_SKEW:
            raise ProtocolError(
                "Zeitstempel liegt außerhalb des zulässigen Fensters — "
                "Uhr des Clients prüfen."
            )

        client = self.api.registry.get_client(client_id)
        if client is None:
            raise ProtocolError(
                "Unbekannter Client. Zuerst 'ssh-ca-client enroll' ausführen."
            )
        if client.disabled:
            raise ProtocolError("Dieser Client ist gesperrt.")

        if not self.nonces.check_and_store(nonce, now.timestamp()):
            raise ProtocolError("Diese Anfrage wurde bereits gestellt.")

        from ..protocol import verify_message

        message = canonical_request(method, path, client_id, timestamp, nonce, body)
        verify_message(self.api.ca.ssh, client.pubkey, client_id, message, signature)
        return client

    # ---------------------------------------------------------------- Routing
    def _route(self, method: str) -> None:
        path = self.path.split("?", 1)[0].rstrip("/") or "/"
        try:
            body = self._read_body()
        except ProtocolError as exc:
            self._fail(400, str(exc))
            return

        try:
            if method == "GET" and path == f"{API_PREFIX}/info":
                self._send(200, self.api.info())
                return
            if method == "POST" and path == f"{API_PREFIX}/enroll":
                payload = self._as_json(body)
                self._send(
                    200, self.api.enroll(payload, peer=self.address_string())
                )
                return

            if path.startswith(API_PREFIX + "/"):
                client = self._authenticate(method, path, body)
                if method == "GET" and path == f"{API_PREFIX}/principals":
                    self._send(200, self.api.principals(client))
                elif method == "GET" and path == f"{API_PREFIX}/templates":
                    self._send(200, self.api.template_list(client))
                elif method == "GET" and path == f"{API_PREFIX}/ca":
                    self._send(200, self.api.ca_material())
                elif method == "GET" and path == f"{API_PREFIX}/certificates":
                    self._send(200, self.api.certificates(client))
                elif method == "POST" and path == f"{API_PREFIX}/sign":
                    result = self.api.sign(client, self._as_json(body))
                    self.api.registry.touch_client(client)
                    self._send(200, result)
                else:
                    self._fail(404, f"Unbekannter Endpunkt: {method} {path}")
                return

            self._fail(404, f"Unbekannter Endpunkt: {method} {path}")
        except ProtocolError as exc:
            self._fail(401, str(exc))
        except CaError as exc:
            self._fail(400, str(exc))
        except SshKeygenError as exc:
            # Der genaue ssh-keygen-Text kann Pfade der CA enthalten; er
            # gehoert ins Journal, nicht zum Client.
            self.log_message("ssh-keygen fehlgeschlagen: %s", exc)
            self._fail(500, "Die CA konnte den Vorgang nicht ausführen.")
        except Exception as exc:  # pragma: no cover - letzter Riegel
            self.log_message("unerwarteter Fehler: %r", exc)
            self._fail(500, "Interner Fehler.")

    def do_GET(self) -> None:  # noqa: N802 - von BaseHTTPRequestHandler vorgegeben
        self._route("GET")

    def do_POST(self) -> None:  # noqa: N802
        self._route("POST")


class Server(ThreadingHTTPServer):
    """ThreadingHTTPServer mit TLS und den Diensten am Objekt."""

    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, api: Api, address: tuple[str, int]) -> None:
        super().__init__(address, Handler)
        self.api = api
        self.nonces = NonceCache()


def build_ssl_context(
    cert: Path, key: Path, client_ca: Path | None = None
) -> ssl.SSLContext:
    """TLS-Kontext aus Zertifikaten der bestehenden PKI.

    TLS 1.2 als Untergrenze, Client-Zertifikate optional. Wird ``client_ca``
    gesetzt, verlangt der Dienst zusaetzlich ein Clientzertifikat aus dieser
    Kette — die SSH-Signatur der Anfragen bleibt davon unberuehrt, sie ist die
    Ebene, die den Client fachlich identifiziert.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=str(cert), keyfile=str(key))
    if client_ca is not None:
        context.load_verify_locations(cafile=str(client_ca))
        context.verify_mode = ssl.CERT_REQUIRED
    return context


def serve(api: Api) -> int:
    """Startet den Dienst. Kehrt erst bei SIGINT/SIGTERM zurueck."""
    config = api.config
    problems = api.startup_check()
    if problems:
        for problem in problems:
            sys.stderr.write(f"Start abgebrochen: {problem}\n")
        return 1

    context = build_ssl_context(
        config.tls_cert, config.tls_key, config.tls_client_ca
    )
    server = Server(api, (config.listen, config.port))
    server.socket = context.wrap_socket(server.socket, server_side=True)

    mode = "mutual TLS" if config.tls_client_ca else "TLS"
    sys.stderr.write(
        f"ssh-ca-server hört auf https://{config.listen}:{config.port} "
        f"({mode}), CA {api.ca.ca_fingerprint()}\n"
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        sys.stderr.write("ssh-ca-server beendet.\n")
    finally:
        server.server_close()
    return 0
